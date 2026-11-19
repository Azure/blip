package runtime

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Azure/blip/internal/netpolicy"
)

// addrMatch renders the address and protocol part of a rule. Ports are
// omitted so a peer check can ignore the ephemeral source port of an inbound
// connection.
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

// ruleMatch renders one rule. The rule must already have passed
// netpolicy.Rule.Validate; only parsed addresses, numeric ports, and a fixed
// protocol vocabulary enter nft syntax.
func ruleMatch(r netpolicy.Rule, reverse bool) string {
	addr, port := "daddr", "dport"
	if reverse {
		addr, port = "saddr", "sport"
	}
	match := addrMatch(r, addr)
	if r.Port != 0 {
		proto := strings.ToLower(r.Protocol)
		match += " " + proto + " " + port + " " + strconv.Itoa(int(r.Port))
		if r.EndPort > r.Port {
			match += "-" + strconv.Itoa(int(r.EndPort))
		}
	}
	return match
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
	// allowed destination in every layer. Ports are intentionally ignored:
	// the source port of an inbound connection is ephemeral, so a policy's
	// destination port cannot describe it. The same peer set checks replies
	// to an inbound connection, so narrowing a policy also stops an
	// established flow from carrying replies to a now-denied peer.
	if policy != nil && len(policy.Layers) > 0 {
		for i, layer := range policy.Layers {
			for _, check := range []struct{ chain, addr string }{
				{"inbound", "saddr"},
				{"inbound_reply", "daddr"},
			} {
				fmt.Fprintf(&b, " chain %s_%d {\n", check.chain, i)
				for _, rule := range layer {
					fmt.Fprintf(&b, "  %s counter return\n", addrMatch(rule, check.addr))
				}
				b.WriteString("  counter drop\n }\n")
			}
		}
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
		// echo, and router advertisements remain denied. Type and code must
		// stay symbolic: nftables rejects numeric ICMP selectors on some
		// versions.
		for _, code := range []string{
			"net-unreachable", "host-unreachable", "prot-unreachable",
			"port-unreachable", "frag-needed",
		} {
			fmt.Fprintf(&b, "  ct state related icmp type destination-unreachable icmp code %s counter accept\n", code)
		}
		b.WriteString("  ct state related icmp type time-exceeded counter accept\n")
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
