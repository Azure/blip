// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// blockedCIDRs are never reachable from a guest, whatever a policy allows:
// the unspecified range, the Alibaba metadata address, loopback, link-local
// (cloud metadata such as 169.254.169.254), the Azure WireServer at
// 168.63.129.16, the OCI metadata address, multicast, and reserved space. The
// compiler appends this as its own layer, so a policy cannot override it.
var blockedCIDRs = []string{
	"0.0.0.0/8",
	"100.100.100.200/32",
	"127.0.0.0/8",
	"168.63.129.16/32",
	"169.254.0.0/16",
	"192.0.0.192/32",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// DefaultNameservers are used when a BlipPool omits spec.dns. Public resolvers
// keep workload lookups away from cluster DNS, which is not reachable from a
// guest by default.
var DefaultNameservers = []string{"1.1.1.1", "1.0.0.1"}

// Compile returns the intersection of the pool and Blip policies plus the
// always-on blocked-destination layer. A layer that allows any egress also
// gets port 53 to the configured nameservers; the grant is implicit, so it
// applies even when the layer's own rules except a resolver. A deny-all layer
// stays deny-all, so DNS cannot be used as an exfiltration channel. Invalid
// input returns an
// empty, denying policy.
func Compile(pool, blip *v1alpha1.NetworkPolicy, nameservers []string) (Policy, error) {
	return CompileNamed(pool, blip, nameservers, "blip network")
}

// CompileNamed is Compile with a diagnostic name for the Blip layer. The node
// agent passes "state network" when the policy is inherited from a BlipState,
// so an operator edits the object that actually holds the invalid rules.
func CompileNamed(pool, blip *v1alpha1.NetworkPolicy, nameservers []string, blipLayer string) (Policy, error) {
	dns, err := nameserverRules(nameservers)
	if err != nil {
		return Policy{}, err
	}
	poolRules, err := layer(pool, dns)
	if err != nil {
		return Policy{}, fmt.Errorf("pool network: %w", err)
	}
	policy := Policy{Layers: [][]Rule{poolRules}}
	if blip != nil {
		blipRules, err := layer(blip, dns)
		if err != nil {
			return Policy{}, fmt.Errorf("%s: %w", blipLayer, err)
		}
		policy.Layers = append(policy.Layers, blipRules)
	}
	policy.Layers = append(policy.Layers, []Rule{{
		CIDR:   "0.0.0.0/0",
		Except: slices.Clone(blockedCIDRs),
	}})
	data, err := json.Marshal(policy.Layers)
	if err != nil {
		return Policy{}, fmt.Errorf("encode network policy: %w", err)
	}
	digest := sha256.Sum256(data)
	policy.Revision = hex.EncodeToString(digest[:])
	return policy, nil
}

// nameserverRules validates the configured resolvers and returns the UDP and
// TCP port 53 rules added to every egress-allowing layer.
func nameserverRules(nameservers []string) ([]Rule, error) {
	rules := make([]Rule, 0, 2*len(nameservers))
	for i, value := range nameservers {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("nameservers[%d]: %q is not an IPv4 address", i, value)
		}
		for _, blocked := range blockedCIDRs {
			if prefix, _ := netip.ParsePrefix(blocked); prefix.Contains(addr) {
				return nil, fmt.Errorf("nameservers[%d]: %q is in blocked range %s", i, value, blocked)
			}
		}
		cidr := netip.PrefixFrom(addr, 32).String()
		rules = append(rules,
			Rule{CIDR: cidr, Protocol: string(corev1.ProtocolUDP), Port: 53},
			Rule{CIDR: cidr, Protocol: string(corev1.ProtocolTCP), Port: 53})
	}
	return rules, nil
}

func layer(policy *v1alpha1.NetworkPolicy, dns []Rule) ([]Rule, error) {
	rules := []Rule{}
	if policy == nil {
		return rules, nil
	}
	for i, egress := range policy.Egress {
		ports, err := compilePorts(egress.Ports)
		if err != nil {
			return nil, fmt.Errorf("egress[%d]: %w", i, err)
		}
		peers := []Rule{}
		if len(egress.To) == 0 {
			peers = append(peers, Rule{CIDR: "0.0.0.0/0"})
		}
		for j, peer := range egress.To {
			resolved, err := compilePeer(peer)
			if err != nil {
				return nil, fmt.Errorf("egress[%d].to[%d]: %w", i, j, err)
			}
			peers = append(peers, resolved...)
		}
		for _, peer := range peers {
			for _, port := range ports {
				rule := peer
				rule.Protocol, rule.Port, rule.EndPort = port.Protocol, port.Port, port.EndPort
				rules = append(rules, rule)
			}
		}
	}
	// DNS is implicit only where a layer permits some egress. A layer with no
	// rules denies everything, including port 53.
	if len(rules) > 0 {
		rules = append(rules, dns...)
	}
	// JSON is also the wire representation; using it as a key keeps ordering and
	// deduplication consistent for exceptions, protocols, ports, and ranges.
	byKey := make(map[string]Rule, len(rules))
	keys := make([]string, 0, len(rules))
	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		key := string(data)
		if _, ok := byKey[key]; !ok {
			byKey[key] = rule
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	rules = make([]Rule, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, byKey[key])
	}
	return rules, nil
}

func compilePorts(ports []v1alpha1.NetworkPort) ([]Rule, error) {
	if len(ports) == 0 {
		return []Rule{{}}, nil
	}
	rules := make([]Rule, 0, len(ports))
	for i, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		if protocol != corev1.ProtocolTCP && protocol != corev1.ProtocolUDP {
			return nil, fmt.Errorf("ports[%d]: protocol must be TCP or UDP", i)
		}
		if port.Port < 1 || port.Port > 65535 {
			return nil, fmt.Errorf("ports[%d]: port must be between 1 and 65535", i)
		}
		rule := Rule{Protocol: string(protocol), Port: port.Port}
		if port.EndPort != nil {
			if *port.EndPort < port.Port || *port.EndPort > 65535 {
				return nil, fmt.Errorf("ports[%d]: endPort must be between port and 65535", i)
			}
			if *port.EndPort != port.Port {
				rule.EndPort = *port.EndPort
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func compilePeer(peer v1alpha1.NetworkPeer) ([]Rule, error) {
	if peer.IPBlock == nil {
		return nil, fmt.Errorf("peer must select an IP block")
	}
	prefix, err := ipv4Prefix(peer.IPBlock.CIDR)
	if err != nil {
		return nil, err
	}
	rule := Rule{CIDR: prefix.String()}
	for _, except := range peer.IPBlock.Except {
		excluded, err := ipv4Prefix(except)
		if err != nil {
			return nil, err
		}
		if excluded.Bits() <= prefix.Bits() || !prefix.Contains(excluded.Addr()) {
			return nil, fmt.Errorf("exception %q must be strictly inside %q", except, peer.IPBlock.CIDR)
		}
		rule.Except = append(rule.Except, excluded.String())
	}
	slices.Sort(rule.Except)
	rule.Except = slices.Compact(rule.Except)
	return []Rule{rule}, nil
}

func ipv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid IPv4 CIDR", value)
	}
	return prefix.Masked(), nil
}
