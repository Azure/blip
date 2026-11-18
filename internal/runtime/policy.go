package runtime

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Azure/blip/internal/netpolicy"
)

// ruleMatch renders one rule. The rule must already have passed
// netpolicy.Rule.Validate; only parsed addresses, numeric ports, and a fixed
// protocol vocabulary enter nft syntax.
func ruleMatch(r netpolicy.Rule, reverse bool) string {
	cidr := r.CIDRPrefix()
	addr, port := "daddr", "dport"
	if reverse {
		addr, port = "saddr", "sport"
	}
	match := "ip " + addr + " " + cidr.String()
	for _, value := range r.Except {
		// Separate negative matches also handle nested/duplicate exceptions;
		// anonymous interval sets reject overlapping CIDRs on some kernels.
		p, _ := netip.ParsePrefix(value)
		match += " ip " + addr + " != " + p.Masked().String()
	}
	proto := strings.ToLower(r.Protocol)
	if proto != "" {
		match += " meta l4proto " + proto
	}
	if r.Port != 0 {
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
	iface, tap := strconv.Quote(p.iface), strconv.Quote(tapName)
	fmt.Fprintf(&b, ` chain from_guest {
  meta nfproto != ipv4 counter drop
  ip saddr != %s counter drop
  oifname != %s counter drop
  ct state invalid counter drop
`, p.guestIP, iface)
	if active {
		// Only replies to externally initiated pod-IP DNAT connections bypass
		// egress policy. This is ingress return traffic, not a blanket
		// established-flow exception for VM-initiated connections.
		fmt.Fprintf(&b, "  ct direction reply ct status dnat ct original ip daddr %s ct state established counter accept\n", p.podIP)
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
		fmt.Fprintf(&b, "  ct direction original ct status dnat ct original ip daddr %s counter accept\n", p.podIP)
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
