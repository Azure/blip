// Package netpolicy holds the network policy value types shared by the
// controller, the node agent, and the VM runtime. It deliberately imports
// nothing from Kubernetes so the runtime binary does not link the API server
// client just to describe rules.
package netpolicy

import (
	"fmt"
	"net/netip"
	"strings"
)

// Policy is an intersection of layers, each containing an OR of rules.
// No layers, or any empty layer, denies all traffic.
type Policy struct {
	Revision string   `json:"revision"`
	Layers   [][]Rule `json:"layers"`
}

// Rule matches an IPv4 destination excluding Except. Empty Protocol matches
// all IP protocols; Port zero matches all ports; EndPort zero means only Port.
type Rule struct {
	CIDR     string   `json:"cidr"`
	Except   []string `json:"except,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Port     int32    `json:"port,omitempty"`
	EndPort  int32    `json:"endPort,omitempty"`
}

// Validate reports whether the rule can be rendered safely. It is called both
// where rules are compiled and again at the runtime's desired.json boundary.
func (r Rule) Validate() error {
	cidr, err := netip.ParsePrefix(r.CIDR)
	if err != nil || !cidr.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 CIDR %q", r.CIDR)
	}
	cidr = cidr.Masked()
	for _, value := range r.Except {
		p, err := netip.ParsePrefix(value)
		if err != nil || !p.Addr().Is4() || p.Bits() < cidr.Bits() || !cidr.Contains(p.Masked().Addr()) {
			return fmt.Errorf("exception %q is not inside %s", value, cidr)
		}
	}
	proto := strings.ToLower(r.Protocol)
	switch proto {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("unsupported protocol %q", r.Protocol)
	}
	if r.Port < 0 || r.Port > 65535 || r.EndPort < 0 || r.EndPort > 65535 ||
		(r.EndPort != 0 && (r.Port == 0 || r.EndPort < r.Port)) ||
		(r.Port != 0 && proto == "") {
		return fmt.Errorf("invalid %q port range %d-%d", r.Protocol, r.Port, r.EndPort)
	}
	return nil
}

// Validate reports whether every rule in the policy is valid.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if strings.TrimSpace(p.Revision) == "" {
		return fmt.Errorf("network policy revision is empty")
	}
	for i, layer := range p.Layers {
		for j, rule := range layer {
			if err := rule.Validate(); err != nil {
				return fmt.Errorf("layer %d rule %d: %w", i, j, err)
			}
		}
	}
	return nil
}

// CIDR returns the rule's masked IPv4 prefix.
func (r Rule) CIDRPrefix() netip.Prefix {
	prefix, _ := netip.ParsePrefix(r.CIDR)
	return prefix.Masked()
}
