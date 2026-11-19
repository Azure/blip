package network

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
)

// privateCIDRs are loopback, link-local, shared address space, and the private
// IPv4 ranges. They also cover the cloud metadata endpoint at 169.254.169.254
// and the Azure WireServer at 168.63.129.16, which looks public but serves
// host metadata to guests. Multicast and reserved space are excluded too
// because neither is internet.
var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"168.63.129.16/32",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// Default is the policy used when a BlipPool omits spec.network: public
// internet egress on any protocol and port, with LAN and other non-public
// ranges excluded. Cluster DNS usually lives in a private service CIDR, so
// kube-dns is explicitly allowed on both TCP and UDP port 53.
func Default() *v1alpha1.NetworkPolicy {
	return &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{
		{
			To: []v1alpha1.NetworkPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					corev1.LabelMetadataName: "kube-system",
				}},
				ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"k8s-app": "kube-dns",
				}},
			}},
			Ports: []v1alpha1.NetworkPort{
				{Protocol: corev1.ProtocolUDP, Port: 53},
				{Protocol: corev1.ProtocolTCP, Port: 53},
			},
		},
		{
			To: []v1alpha1.NetworkPeer{{
				IPBlock: &v1alpha1.NetworkIPBlock{
					CIDR:   "0.0.0.0/0",
					Except: privateCIDRs,
				},
			}},
		},
	}}
}
