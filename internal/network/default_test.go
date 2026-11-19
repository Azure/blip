package network

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		{"172.16.0.1", "TCP", 443, false},
		{"192.168.1.1", "TCP", 443, false},
		{"169.254.169.254", "TCP", 80, false},
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
