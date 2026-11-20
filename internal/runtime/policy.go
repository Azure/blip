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

// portMatch renders the rule's port or range.
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

// relatedMatch renders the terms a related_<i> chain uses for one rule. An
// ICMP error quotes the original packet, whose destination is the egress peer.
// Flows towards the pod itself are excluded: they can only be inbound DNAT,
// which this egress-only policy never admits.
func relatedMatch(r netpolicy.Rule, podIP string) []string {
	dest := "ct original ip daddr " + r.CIDRPrefix().String()
	for _, value := range r.Except {
		p, _ := netip.ParsePrefix(value)
		dest += " ct original ip daddr != " + p.Masked().String()
	}
	dest += " ct original ip daddr != " + podIP
	return []string{dest}
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
	// Related ICMP errors (PMTUD and transport errors) are only delivered when
	// the conntrack entry they quote passes EVERY policy layer. Each
	// related_<i> chain returns only if the original flow's destination is
	// allowed by that layer and drops otherwise. The dispatcher then accepts
	// only after all layers have returned.
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
		// The guest may only originate new flows. There is no inbound
		// admission, so no flow has the guest as its server side.
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
		// Path-MTU discovery and transport errors travel as ICMP
		// destination-unreachable messages RELATED to an allowed flow.
		// Without these the guest keeps sending full-size segments after a
		// router asks it to shrink (a PMTUD blackhole), and a UDP socket
		// never learns that an allowed destination port is closed (no
		// ECONNREFUSED) or that a route is unusable. RELATED ties the
		// acceptance to a permitted conntrack entry, so unsolicited ICMP,
		// echo, and router advertisements remain denied. Type and code must
		// stay symbolic: nftables rejects numeric ICMP selectors on some
		// versions.
		if relatedICMPAllowed(policy) {
			for _, code := range []string{
				"net-unreachable", "host-unreachable", "prot-unreachable",
				"port-unreachable", "frag-needed",
			} {
				fmt.Fprintf(&b, "  ct state related icmp type destination-unreachable icmp code %s jump related\n", code)
			}
			b.WriteString("  ct state related icmp type time-exceeded jump related\n")
		}
		// Only replies to flows the guest originated enter. NAT already
		// restored the private destination. Check CURRENT remote source/port
		// on every reply; stale conntrack cannot defeat revocation.
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
