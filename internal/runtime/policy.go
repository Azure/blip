// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package runtime

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Azure/blip/internal/netpolicy"
)

// addrMatch renders the address, exceptions, and protocol part of a rule. It
// deliberately omits ports: a reply to a connection may use an ephemeral
// source port, so a peer check cannot match the rule's destination port on
// that packet.
func addrMatch(r netpolicy.Rule, addr string) string {
	cidr := r.CIDRPrefix()
	match := "ip " + addr + " " + cidr.String()
	for _, value := range r.Except {
		// Separate negative matches also handle nested/duplicate exceptions;
		// anonymous interval sets reject overlapping CIDRs on some kernels.
		p, _ := netip.ParsePrefix(value)
		match += " ip " + addr + " != " + p.Masked().String()
	}
	if proto := strings.ToLower(r.Protocol); proto != "" {
		match += " meta l4proto " + proto
	}
	return match
}

// portMatch renders the rule's port or range, for either the destination port
// of egress traffic or the destination port of a new inbound connection.
func portMatch(r netpolicy.Rule, port string) string {
	if r.Port == 0 {
		return ""
	}
	proto := strings.ToLower(r.Protocol)
	match := " " + proto + " " + port + " " + strconv.Itoa(int(r.Port))
	if r.EndPort > r.Port {
		match += "-" + strconv.Itoa(int(r.EndPort))
	}
	return match
}

// ruleMatch renders one rule. The rule must already have passed
// netpolicy.Rule.Validate; only parsed addresses, numeric ports, and a fixed
// protocol vocabulary enter nft syntax.
func ruleMatch(r netpolicy.Rule, reverse bool) string {
	addr, port := "daddr", "dport"
	if reverse {
		addr, port = "saddr", "sport"
	}
	return addrMatch(r, addr) + portMatch(r, port)
}

// inboundMatch admits a new inbound connection only from the rule's peer and
// only to the rule's protocol and destination port. The egress port names the
// remote service, but it is the closest match an egress-only policy can give
// for a connection arriving from that peer; it must not turn an allow for one
// remote port into an allow for every guest port.
func inboundMatch(r netpolicy.Rule) string {
	return addrMatch(r, "saddr") + portMatch(r, "dport")
}

// relatedMatch renders the return terms a related_<i> chain uses for one rule.
// A related ICMP error can quote either direction of a flow:
//
//   - A guest-initiated flow has the egress peer as its ORIGINAL destination.
//     That destination is what a stale flow would otherwise carry an ICMP
//     error for after the policy is narrowed, so it must pass the same layers
//     as the original packet.
//   - An inbound DNAT flow (the guest is the server) has the pod IP as its
//     ORIGINAL destination and the peer that inbound_<i> admitted as its
//     ORIGINAL source. Matching the original destination alone would compare
//     the pod's own IP against egress destinations and drop PMTUD or transport
//     errors for an allowed peer.
//
// The inbound path mirrors inbound_<i>: a wildcard rule names no peer and
// therefore grants neither a new inbound connection nor its related errors.
// The egress path excludes flows whose original destination is the pod itself
// (an inbound DNAT conntrack), so an egress allowance that happens to cover
// the pod IP cannot stand in for a peer check.
// Ports and protocol are omitted deliberately: they describe the quoted
// packet, not the outer ICMP packet, and ct original l4proto/proto-dst are
// newer than the minimum nft supports.
func relatedMatch(r netpolicy.Rule, podIP string) []string {
	dest := "ct original ip daddr " + r.CIDRPrefix().String()
	for _, value := range r.Except {
		p, _ := netip.ParsePrefix(value)
		dest += " ct original ip daddr != " + p.Masked().String()
	}
	dest += " ct original ip daddr != " + podIP
	matches := []string{dest}
	if r.CIDRPrefix().Bits() == 0 {
		return matches
	}
	src := "ct original ip daddr " + podIP + " ct original ip saddr " + r.CIDRPrefix().String()
	for _, value := range r.Except {
		p, _ := netip.ParsePrefix(value)
		src += " ct original ip saddr != " + p.Masked().String()
	}
	return append(matches, src)
}

// relatedICMPAllowed reports whether some policy layer grants related ICMP
// errors at all. An empty layer is default deny, so no related error can pass
// every layer; omitting the whole path keeps deny-all scripts free of ICMP
// accept rules.
func relatedICMPAllowed(policy *netpolicy.Policy) bool {
	if policy == nil || len(policy.Layers) == 0 {
		return false
	}
	for _, layer := range policy.Layers {
		if len(layer) == 0 {
			return false
		}
	}
	return true
}

func (p *podNet) policyScript(policy *netpolicy.Policy, active bool) (string, error) {
	if err := policy.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	// 'add' is idempotent. Deleting/recreating ONLY our table in the same
	// transaction also works on first boot and leaves no unfiltered window.
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", nftTable, nftTable, nftTable)
	for _, direction := range []string{"egress", "reply"} {
		if policy != nil {
			for i, layer := range policy.Layers {
				fmt.Fprintf(&b, " chain %s_%d {\n", direction, i)
				for _, rule := range layer {
					match := ruleMatch(rule, direction == "reply")
					// Return passes this OR layer; the caller checks the next
					// layer. An accept here would incorrectly bypass the AND.
					fmt.Fprintf(&b, "  %s counter return\n", match)
				}
				b.WriteString("  counter drop\n }\n")
			}
		}
		fmt.Fprintf(&b, " chain %s {\n", direction)
		if policy == nil || len(policy.Layers) == 0 {
			b.WriteString("  counter drop\n")
		} else {
			for i := range policy.Layers {
				fmt.Fprintf(&b, "  jump %s_%d\n", direction, i)
			}
			b.WriteString("  counter accept\n")
		}
		b.WriteString(" }\n")
	}
	// A new inbound connection may reach the guest only when its peer is an
	// explicitly named destination in every layer and the connection targets
	// the rule's protocol and port. A wildcard rule (0.0.0.0/0, with or
	// without private exceptions) names no peer and is an egress allowance,
	// not an ingress policy, so it admits no new inbound connections.
	// Replies to an inbound connection check the peer address only, because
	// that peer's source port is ephemeral. The same peer set checks replies
	// to an inbound connection, so narrowing a policy also stops an
	// established flow from carrying replies to a now-denied peer. Related
	// ICMP errors get their own layer chains below.
	if policy != nil && len(policy.Layers) > 0 {
		for i, layer := range policy.Layers {
			fmt.Fprintf(&b, " chain inbound_%d {\n", i)
			for _, rule := range layer {
				if rule.CIDRPrefix().Bits() == 0 {
					continue
				}
				fmt.Fprintf(&b, "  %s counter return\n", inboundMatch(rule))
			}
			b.WriteString("  counter drop\n }\n")
			fmt.Fprintf(&b, " chain inbound_reply_%d {\n", i)
			for _, rule := range layer {
				fmt.Fprintf(&b, "  %s counter return\n", addrMatch(rule, "daddr"))
			}
			b.WriteString("  counter drop\n }\n")
		}
	}
	// Related ICMP errors (PMTUD and transport errors) are only delivered when
	// the conntrack entry they quote still passes EVERY policy layer. Each
	// related_<i> chain returns only if the original flow's destination is
	// allowed by that layer (guest-initiated egress) or, for an inbound DNAT
	// flow, the original peer is allowed by that layer and drops otherwise.
	// Either way the chain mirrors the layer AND for the flow that the error
	// quotes. The dispatcher then accepts only after all layers have returned.
	if relatedICMPAllowed(policy) {
		for i, layer := range policy.Layers {
			fmt.Fprintf(&b, " chain related_%d {\n", i)
			for _, rule := range layer {
				for _, match := range relatedMatch(rule, p.podIP) {
					fmt.Fprintf(&b, "  %s counter return\n", match)
				}
			}
			b.WriteString("  counter drop\n }\n")
		}
		b.WriteString(" chain related {\n")
		for i := range policy.Layers {
			fmt.Fprintf(&b, "  jump related_%d\n", i)
		}
		b.WriteString("  counter accept\n }\n")
	}
	iface, tap := strconv.Quote(p.iface), strconv.Quote(tapName)
	fmt.Fprintf(&b, ` chain from_guest {
  meta nfproto != ipv4 counter drop
  ip saddr != %s counter drop
  oifname != %s counter drop
  ct state invalid counter drop
`, p.guestIP, iface)
	if active {
		// Only replies to externally initiated pod-IP DNAT connections bypass
		// the egress chain, and only when the peer is still allowed. This is
		// ingress return traffic, not a blanket established-flow exception
		// for VM-initiated connections. Excluding ICMP keeps an unsolicited
		// echo request from provoking an echo reply to a denied destination;
		// ICMP errors are handled separately.
		replyMatch := fmt.Sprintf("ct direction reply ct status dnat ct original ip daddr %s ct state established meta l4proto != icmp", p.podIP)
		if policy != nil && len(policy.Layers) > 0 {
			for i := range policy.Layers {
				fmt.Fprintf(&b, "  %s jump inbound_reply_%d\n", replyMatch, i)
			}
			fmt.Fprintf(&b, "  %s counter accept\n", replyMatch)
		}
		b.WriteString("  ct direction original jump egress\n")
	}
	b.WriteString("  counter drop\n }\n")
	fmt.Fprintf(&b, ` chain to_guest {
  meta nfproto != ipv4 counter drop
  ip daddr != %s counter drop
  iifname != %s counter drop
  ct state invalid counter drop
`, p.guestIP, iface)
	if active {
		// Deliver a new inbound pod-IP connection only from an allowed peer.
		// Without this, any source could make the guest answer a denied
		// destination (kernel TCP RST/SYN-ACK or an application UDP reply)
		// and the from_guest return path would bypass egress policy. ICMP is
		// excluded so an unsolicited echo request never reaches the guest.
		inboundMatch := fmt.Sprintf("ct direction original ct status dnat ct original ip daddr %s meta l4proto != icmp", p.podIP)
		if policy != nil && len(policy.Layers) > 0 {
			for i := range policy.Layers {
				fmt.Fprintf(&b, "  %s jump inbound_%d\n", inboundMatch, i)
			}
			fmt.Fprintf(&b, "  %s counter accept\n", inboundMatch)
		}
		// Path-MTU discovery and transport errors travel as ICMP
		// destination-unreachable messages RELATED to an allowed flow.
		// Without these the guest keeps sending full-size segments after a
		// router asks it to shrink (a PMTUD blackhole), and a UDP socket
		// never learns that an allowed destination port is closed (no
		// ECONNREFUSED) or that a route is unusable. RELATED ties the
		// acceptance to a permitted conntrack entry, so unsolicited ICMP,
		// echo, and router advertisements remain denied. The policy layers
		// are still consulted through the original flow: its destination for
		// guest-initiated egress, and its peer for the inbound DNAT direction
		// whose destination is the pod itself. A stale conntrack entry
		// therefore cannot deliver an error after the policy is narrowed;
		// with deny-all no ICMP is admitted at all. Type and code
		// must stay symbolic: nftables rejects numeric ICMP selectors on
		// some versions.
		if relatedICMPAllowed(policy) {
			for _, code := range []string{
				"net-unreachable", "host-unreachable", "prot-unreachable",
				"port-unreachable", "frag-needed",
			} {
				fmt.Fprintf(&b, "  ct state related icmp type destination-unreachable icmp code %s jump related\n", code)
			}
			b.WriteString("  ct state related icmp type time-exceeded jump related\n")
		}
		// NAT already restored the private destination. Check CURRENT remote
		// source/port on every reply; stale conntrack cannot defeat revocation.
		b.WriteString("  ct direction reply ct state established jump reply\n")
	}
	b.WriteString("  counter drop\n }\n")
	fmt.Fprintf(&b, ` chain input {
  type filter hook input priority -10; policy accept;
  iifname %s counter drop
 }
 chain output {
  type filter hook output priority -10; policy accept;
  oifname %s meta nfproto != ipv4 counter drop
 }
 chain forward {
  type filter hook forward priority -10; policy accept;
  iifname %s jump from_guest
  oifname %s jump to_guest
 }
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  iifname %s ip daddr %s dnat ip to %s
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  iifname %s oifname %s ip saddr %s snat ip to %s
 }
}
`, tap, tap, tap, tap, iface, p.podIP, p.guestIP, tap, iface, p.guestIP, p.podIP)
	return b.String(), nil
}
