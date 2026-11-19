// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package network

import (
	"os"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
)

func TestDefaultAllowsInternetAndKubeDNS(t *testing.T) {
	destinations := Destinations{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{
			Name:   "kube-system",
			Labels: map[string]string{corev1.LabelMetadataName: "kube-system"},
		}}},
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "kube-dns",
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}}},
	}
	policy := mustCompile(t, "apps", Default(), nil, destinations)
	if policy.Revision == "" || len(policy.Layers) != 1 {
		t.Fatalf("default must compile to one versioned layer: %+v", policy)
	}
	for _, tt := range []struct {
		address  string
		protocol string
		port     int32
		allowed  bool
	}{
		{"8.8.8.8", "TCP", 443, true},
		{"8.8.8.8", "UDP", 123, true},
		{"1.1.1.1", "ICMP", 0, true},
		{"10.0.0.1", "TCP", 443, false},
		{"10.96.0.10", "TCP", 53, true},
		{"10.96.0.10", "UDP", 53, true},
		{"10.96.0.10", "TCP", 443, false},
		{"169.254.10.10", "UDP", 53, true},
		{"169.254.10.10", "TCP", 53, true},
		{"169.254.10.11", "UDP", 53, true},
		{"169.254.20.10", "UDP", 53, true},
		{"169.254.20.11", "UDP", 53, false},
		{"169.254.10.12", "UDP", 53, false},
		{"169.254.10.10", "TCP", 443, false},
		{"169.254.10.10", "UDP", 123, false},
		{"169.254.169.254", "UDP", 53, false},
		{"172.16.0.1", "TCP", 443, false},
		{"192.168.1.1", "TCP", 443, false},
		{"169.254.169.254", "TCP", 80, false},
		{"192.0.0.192", "TCP", 80, false},
		{"192.0.0.192", "TCP", 443, false},
		{"192.0.0.170", "TCP", 80, false},
		{"192.0.1.1", "TCP", 443, true},
		{"192.0.2.1", "TCP", 443, false},
		{"192.88.99.1", "TCP", 443, false},
		{"198.18.0.1", "TCP", 443, false},
		{"198.19.255.254", "TCP", 443, false},
		{"198.51.100.1", "TCP", 443, false},
		{"203.0.113.9", "TCP", 443, false},
		{"168.63.129.16", "TCP", 80, false},
		{"168.63.129.16", "TCP", 443, false},
		{"127.0.0.1", "TCP", 443, false},
		{"100.100.100.200", "TCP", 80, false},
	} {
		if got := allows(policy, tt.address, tt.protocol, tt.port); got != tt.allowed {
			t.Errorf("allows(%s, %s/%d) = %v, want %v", tt.address, tt.protocol, tt.port, got, tt.allowed)
		}
	}
}

// TestDefaultAllowsOnlyKnownLocalDNS pins the node-local resolver exception.
// AKS LocalDNS (169.254.10.10/.11) and NodeLocal DNSCache (169.254.20.10) can
// be the nameserver in a pod's resolv.conf, so they must be reachable on 53.
// The rest of link-local, including cloud metadata, and non-DNS ports stay
// denied.
func TestDefaultAllowsOnlyKnownLocalDNS(t *testing.T) {
	policy := mustCompile(t, "apps", Default(), nil, Destinations{})
	for _, tt := range []struct {
		address  string
		protocol string
		port     int32
		allowed  bool
	}{
		{"169.254.10.10", "UDP", 53, true},
		{"169.254.10.11", "UDP", 53, true},
		{"169.254.20.10", "UDP", 53, true},
		{"169.254.10.10", "TCP", 53, true},
		{"169.254.10.11", "TCP", 53, true},
		{"169.254.20.10", "TCP", 53, true},
		{"169.254.20.11", "UDP", 53, false},
		{"169.254.10.12", "UDP", 53, false},
		{"169.254.10.10", "TCP", 443, false},
		{"169.254.169.254", "UDP", 53, false},
		{"168.63.129.16", "UDP", 53, false},
	} {
		if got := allows(policy, tt.address, tt.protocol, tt.port); got != tt.allowed {
			t.Errorf("allows(%s, %s/%d) = %v, want %v", tt.address, tt.protocol, tt.port, got, tt.allowed)
		}
	}
}

// TestExamplePoolsUseDefaultPrivateRanges keeps the kind example pool in sync
// with the product default policy: an explicit 0.0.0.0/0 rule bypasses
// Default(), so it must repeat the same LAN and platform exceptions.
func TestExamplePoolsUseDefaultPrivateRanges(t *testing.T) {
	data, err := os.ReadFile("../../deploy/kind/pools.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var pool v1alpha1.BlipPool
	if err := yaml.Unmarshal(data, &pool); err != nil {
		t.Fatal(err)
	}
	if pool.Spec.Network == nil {
		t.Fatal("example pool has no network policy")
	}
	var got []string
	for _, egress := range pool.Spec.Network.Egress {
		for _, peer := range egress.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				got = append(got, peer.IPBlock.Except...)
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("example pool allows 0.0.0.0/0 without private-range exceptions")
	}
	slices.Sort(got)
	want := slices.Clone(privateCIDRs)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("example pool exceptions = %v, want the default policy list %v", got, want)
	}
}
