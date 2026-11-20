// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package network

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestDefaultDenyInheritanceAndIntersection(t *testing.T) {
	allowAll := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}
	web := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}}, v1alpha1.NetworkPort{Port: 443})
	for _, tt := range []struct {
		name       string
		pool, blip *v1alpha1.NetworkPolicy
		allowed    bool
	}{
		{"nil pool", nil, nil, false},
		{"empty pool", &v1alpha1.NetworkPolicy{}, nil, false},
		{"blip cannot widen nil pool", nil, allowAll, false},
		{"inherit pool", web, nil, true},
		{"empty blip denies", allowAll, &v1alpha1.NetworkPolicy{}, false},
		{"blip narrows pool", allowAll, web, true},
		{"blip cannot widen pool", web, allowAll, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mustCompile(t, tt.pool, tt.blip, nil)
			if allows(got, "10.1.2.3", "TCP", 443) != tt.allowed {
				t.Fatalf("unexpected web access: %+v", got)
			}
			if allows(got, "10.1.2.3", "UDP", 443) || allows(got, "192.0.2.1", "TCP", 443) || allows(got, "10.1.2.3", "TCP", 80) {
				t.Fatalf("policy widened access: %+v", got)
			}
		})
	}
	all := mustCompile(t, allowAll, nil, nil)
	if !allows(all, "192.0.2.1", "ICMP", 0) || allows(Policy{}, "192.0.2.1", "TCP", 80) {
		t.Fatal("empty rule must allow all IP protocols; empty policy must deny")
	}
}

// TestBlockedDestinationsAreUnoverridable guards the always-on layer: even an
// explicit 0.0.0.0/0 rule cannot reach link-local metadata, the WireServer,
// loopback, multicast, or reserved space.
func TestBlockedDestinationsAreUnoverridable(t *testing.T) {
	policy := mustCompile(t, &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}, nil, nil)
	for _, address := range []string{
		"0.0.0.1", "100.100.100.200", "127.0.0.1", "168.63.129.16",
		"169.254.169.254", "192.0.0.192", "224.0.0.1", "240.0.0.1",
	} {
		if allows(policy, address, "TCP", 80) || allows(policy, address, "TCP", 53) {
			t.Errorf("blocked destination %s allowed", address)
		}
	}
	if !allows(policy, "1.1.1.1", "TCP", 80) {
		t.Error("public destination denied")
	}
	// A rule that names a blocked address directly still loses.
	for _, address := range []string{"169.254.169.254", "168.63.129.16", "192.0.0.192", "127.0.0.1"} {
		named := mustCompile(t, policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: address + "/32"}}), nil, nil)
		if allows(named, address, "TCP", 80) {
			t.Errorf("pool rule overrode blocked destination %s", address)
		}
	}
}

// TestDNSIsImplicitForEgressLayers covers the resolver contract: an
// egress-allowing layer gets UDP and TCP 53 to the configured nameservers, and
// a deny-all layer gets nothing.
func TestDNSIsImplicitForEgressLayers(t *testing.T) {
	allowAll := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}
	web := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "0.0.0.0/0"}}, v1alpha1.NetworkPort{Port: 443})
	nameservers := []string{"9.9.9.9", "149.112.112.112"}
	got := mustCompile(t, web, nil, nameservers)
	for _, nameserver := range nameservers {
		if !allows(got, nameserver, "UDP", 53) || !allows(got, nameserver, "TCP", 53) {
			t.Errorf("DNS to %s not allowed: %+v", nameserver, got)
		}
		if allows(got, nameserver, "TCP", 80) {
			t.Errorf("DNS rule widened %s beyond port 53", nameserver)
		}
	}
	if allows(got, "8.8.8.8", "UDP", 53) {
		t.Error("unconfigured resolver allowed")
	}

	// The port-53 allowance does not survive a deny-all layer.
	denied := mustCompile(t, nil, allowAll, nameservers)
	if allows(denied, nameservers[0], "UDP", 53) || allows(denied, nameservers[0], "TCP", 53) {
		t.Errorf("deny-all layer still allowed DNS: %+v", denied)
	}

	// Blip narrowing a pool keeps DNS only when its own layer allows egress.
	narrow := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}}, v1alpha1.NetworkPort{Port: 443})
	combined := mustCompile(t, allowAll, narrow, nameservers)
	if !allows(combined, nameservers[0], "UDP", 53) {
		t.Error("egress-allowing blip layer did not get DNS")
	}
	closed := mustCompile(t, allowAll, &v1alpha1.NetworkPolicy{}, nameservers)
	if allows(closed, nameservers[0], "UDP", 53) {
		t.Error("empty blip layer did not deny DNS")
	}

	// No configured nameservers means no implicit rules.
	none := mustCompile(t, web, nil, nil)
	if allows(none, "9.9.9.9", "UDP", 53) {
		t.Error("compiler invented a resolver")
	}
}

func TestInvalidNameserversFailClosed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		servers []string
	}{
		{"empty entry", []string{""}},
		{"not an address", []string{"dns.example.com"}},
		{"CIDR", []string{"1.1.1.1/32"}},
		{"IPv6", []string{"2606:4700:4700::1111"}},
		{"loopback", []string{"127.0.0.1"}},
		{"link-local", []string{"169.254.169.254"}},
		{"WireServer", []string{"168.63.129.16"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compile(&v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}, nil, tt.servers)
			if err == nil || len(got.Layers) != 0 {
				t.Fatalf("invalid resolver returned %+v, %v", got, err)
			}
		})
	}
}

func TestCIDRExceptionsAndPortRanges(t *testing.T) {
	policy := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{
		CIDR: "10.2.3.4/8", Except: []string{"10.2.0.1/16", "10.1.0.0/16", "10.2.0.0/16"},
	}}, v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 8000, EndPort: int32ptr(8010)}, v1alpha1.NetworkPort{Port: 443})
	got := mustCompile(t, policy, nil, nil)
	for _, rule := range got.Layers[0] {
		if rule.CIDR != "10.0.0.0/8" || !reflect.DeepEqual(rule.Except, []string{"10.1.0.0/16", "10.2.0.0/16"}) {
			t.Fatalf("not canonical: %+v", rule)
		}
	}
	for _, tt := range []struct {
		ip, protocol string
		port         int32
		want         bool
	}{
		{"10.3.1.2", "UDP", 8000, true}, {"10.3.1.2", "UDP", 8010, true},
		{"10.3.1.2", "UDP", 7999, false}, {"10.3.1.2", "UDP", 8011, false},
		{"10.3.1.2", "TCP", 8005, false}, {"10.3.1.2", "TCP", 443, true},
		{"10.1.1.2", "TCP", 443, false}, {"10.2.1.2", "UDP", 8005, false},
		{"11.3.1.2", "UDP", 8005, false},
	} {
		if got := allows(got, tt.ip, tt.protocol, tt.port); got != tt.want {
			t.Errorf("%s %s/%d = %v, want %v", tt.ip, tt.protocol, tt.port, got, tt.want)
		}
	}
}

func TestInvalidPoliciesFailClosed(t *testing.T) {
	block := func(cidr string, except ...string) v1alpha1.NetworkPeer {
		return v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: cidr, Except: except}}
	}
	for _, tt := range []struct {
		name   string
		policy *v1alpha1.NetworkPolicy
	}{
		{"empty peer", policyFor(v1alpha1.NetworkPeer{})},
		{"invalid CIDR", policyFor(block("10.0.0.1"))},
		{"IPv6 CIDR", policyFor(block("fd00::/64"))},
		{"mapped IPv6 CIDR", policyFor(block("::ffff:10.0.0.0/104"))},
		{"invalid exception", policyFor(block("10.0.0.0/8", "bad"))},
		{"IPv6 exception", policyFor(block("10.0.0.0/8", "fd00::/64"))},
		{"outside exception", policyFor(block("10.0.0.0/8", "192.168.0.0/16"))},
		{"equal exception", policyFor(block("10.0.0.0/8", "10.0.0.0/8"))},
		{"containing exception", policyFor(block("10.0.0.0/8", "0.0.0.0/0"))},
		{"zero port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{})},
		{"negative port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: -1})},
		{"large port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 65536})},
		{"unsupported protocol", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Protocol: corev1.ProtocolSCTP, Port: 80})},
		{"reversed range", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 80, EndPort: int32ptr(79)})},
		{"large endPort", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 80, EndPort: int32ptr(65536)})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, pool := range []*v1alpha1.NetworkPolicy{nil, {Egress: []v1alpha1.NetworkEgressRule{{}}}} {
				got, err := Compile(pool, tt.policy, nil)
				if err == nil || len(got.Layers) != 0 {
					t.Fatalf("invalid policy returned %+v, %v", got, err)
				}
			}
		})
	}
}

func TestStableRevisionsAndNoInputMutation(t *testing.T) {
	policy := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}},
		v1alpha1.NetworkPort{Port: 443}, v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 53})
	before, _ := json.Marshal(policy)
	first := mustCompile(t, policy, nil, DefaultNameservers)
	after, _ := json.Marshal(policy)
	if string(before) != string(after) {
		t.Fatal("compiler mutated its input")
	}
	slices.Reverse(policy.Egress[0].Ports)
	policy.Egress[0].Ports[1].Protocol = corev1.ProtocolTCP
	policy.Egress[0].Ports[1].EndPort = int32ptr(443)
	policy.Egress = append(policy.Egress, policy.Egress[0])
	second := mustCompile(t, policy, nil, DefaultNameservers)
	if !reflect.DeepEqual(first, second) || len(first.Revision) != 64 {
		t.Fatalf("equivalent inputs changed revision: %+v vs %+v", first, second)
	}
	third := mustCompile(t, policy, nil, []string{"9.9.9.9"})
	if third.Revision == first.Revision {
		t.Fatal("new resolver did not change revision")
	}
	// Default deny recompiles to the same revision, so warm pods do not
	// rewrite desired.json unless the policy actually changes.
	if deny := mustCompile(t, nil, nil, nil); deny.Revision != mustCompile(t, nil, nil, nil).Revision {
		t.Fatal("default deny revision is unstable")
	}
}

// TestCompileIntersectionNeverWidens checks the security property that a Blip
// layer can only narrow the pool layer. The grid deliberately includes
// addresses and ports that appear in neither rule, so a broken intersection
// that falls back to allow-all is caught.
func TestCompileIntersectionNeverWidens(t *testing.T) {
	allowAll := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}
	web := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}},
		v1alpha1.NetworkPort{Port: 443})
	udpRange := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}},
		v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 8000, EndPort: int32ptr(8010)})
	empty := &v1alpha1.NetworkPolicy{}

	pools := []*v1alpha1.NetworkPolicy{nil, allowAll, web, udpRange, empty}
	blips := []*v1alpha1.NetworkPolicy{nil, allowAll, web, udpRange, empty}
	addresses := []string{"10.0.0.1", "10.0.0.2", "10.1.2.3", "192.0.2.1", "127.0.0.1", "1.1.1.1"}
	protocols := []string{"TCP", "UDP", "ICMP"}
	ports := []int32{0, 53, 80, 443, 7999, 8000, 8005, 8010, 8011, 65535}

	for _, pool := range pools {
		base := mustCompile(t, pool, nil, DefaultNameservers)
		for _, blip := range blips {
			combined := mustCompile(t, pool, blip, DefaultNameservers)
			for _, address := range addresses {
				for _, protocol := range protocols {
					for _, port := range ports {
						if !allows(combined, address, protocol, port) {
							continue
						}
						if !allows(base, address, protocol, port) {
							t.Fatalf("blip widened pool: address=%s protocol=%s port=%d", address, protocol, port)
						}
					}
				}
			}
		}
	}
}

// TestCompiledPoliciesPassRuntimeValidation guards the wire contract between
// the compiler and the node runtime's desired.json boundary.
func TestCompiledPoliciesPassRuntimeValidation(t *testing.T) {
	allowAll := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}
	cidr := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{
		CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"},
	}}, v1alpha1.NetworkPort{Port: 443}, v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 8000, EndPort: int32ptr(8010)})
	for _, tc := range []struct {
		name       string
		pool, blip *v1alpha1.NetworkPolicy
	}{
		{"nil", nil, nil},
		{"allow all", allowAll, nil},
		{"cidr and ports", cidr, nil},
		{"both", allowAll, cidr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustCompile(t, tc.pool, tc.blip, DefaultNameservers)
			if err := got.Validate(); err != nil {
				t.Fatalf("compiled policy failed runtime validation: %v\n%+v", err, got)
			}
		})
	}
}

// TestCompileNamedLabelsPolicyLayer keeps a compile failure attributed to the
// object that holds the invalid rules. A Blip that inherits spec.runtime.network
// from its state must not report a "blip network" error.
func TestCompileNamedLabelsPolicyLayer(t *testing.T) {
	invalid := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.1"}})
	for _, label := range []string{"blip network", "state network"} {
		got, err := CompileNamed(nil, invalid, nil, label)
		if err == nil || len(got.Layers) != 0 {
			t.Fatalf("%s: invalid policy returned %+v, %v", label, got, err)
		}
		if !strings.HasPrefix(err.Error(), label+": egress[0].to[0]:") {
			t.Errorf("%s: error %q does not name the layer", label, err)
		}
	}
}

func policyFor(peer v1alpha1.NetworkPeer, ports ...v1alpha1.NetworkPort) *v1alpha1.NetworkPolicy {
	return &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{To: []v1alpha1.NetworkPeer{peer}, Ports: ports}}}
}

func int32ptr(value int32) *int32 { return &value }

func mustCompile(t *testing.T, pool, blip *v1alpha1.NetworkPolicy, nameservers []string) Policy {
	t.Helper()
	policy, err := Compile(pool, blip, nameservers)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// Evaluate the wire contract independently of the compiler.
func allows(policy Policy, address, protocol string, port int32) bool {
	if len(policy.Layers) == 0 {
		return false
	}
	ip := netip.MustParseAddr(address)
	for _, layer := range policy.Layers {
		matched := false
		for _, rule := range layer {
			if !netip.MustParsePrefix(rule.CIDR).Contains(ip) || (rule.Protocol != "" && rule.Protocol != protocol) {
				continue
			}
			if slices.ContainsFunc(rule.Except, func(value string) bool { return netip.MustParsePrefix(value).Contains(ip) }) {
				continue
			}
			end := rule.EndPort
			if end == 0 {
				end = rule.Port
			}
			if rule.Port != 0 && (port < rule.Port || port > end) {
				continue
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}
