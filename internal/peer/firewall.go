// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Firewall admits node traffic to the HTTPS export service and NVMe/TCP.
// Its rules stay installed across shutdown so kernel NVMe sessions survive.
type Firewall struct {
	hostIP string
}

// NewFirewall installs the rules with only this node's IPv4 address admitted.
// Established connections remain admitted while peer discovery catches up
// after a restart. The entire ruleset replacement is one nftables transaction.
func NewFirewall(hostIP string) (*Firewall, error) {
	ip, err := netip.ParseAddr(hostIP)
	if err != nil || !ip.Unmap().Is4() {
		return nil, fmt.Errorf("peer: invalid host IPv4 address %q", hostIP)
	}
	f := &Firewall{hostIP: ip.Unmap().String()}
	if err := applyFirewall(firewall(f.hostIP)); err != nil {
		return nil, err
	}
	return f, nil
}

func firewall(hostIP string) string {
	return fmt.Sprintf(`table inet blip
delete table inet blip
table inet blip {
	set nodes {
		type ipv4_addr
		elements = { %s }
	}
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport { %d, %d } ip saddr @nodes accept
		tcp dport { %[2]d, %[3]d } ct state established accept
		tcp dport { %[2]d, %[3]d } drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp dport { %[2]d, %[3]d } drop
	}
}
`, hostIP, ExportPort, NVMePort)
}

// SetPeers atomically replaces the endpoint allowlist. Invalid peer records
// are ignored and this node's address is always retained. FORWARD drops run
// before postrouting masquerade can turn a pod's source into a node address.
func (f *Firewall) SetPeers(peers []Peer) error {
	return applyFirewall(f.peerRules(peers))
}

func (f *Firewall) peerRules(peers []Peer) string {
	ips := []string{f.hostIP}
	for _, p := range peers {
		if !p.Valid() {
			continue
		}
		ip, err := netip.ParseAddr(p.Endpoint)
		if err == nil && ip.Unmap().Is4() {
			ips = append(ips, ip.Unmap().String())
		}
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)
	return fmt.Sprintf("flush set inet blip nodes\nadd element inet blip nodes { %s }\n", strings.Join(ips, ", "))
}

func applyFirewall(rules string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("peer: nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
