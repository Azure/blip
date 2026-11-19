package network

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
)

// privateCIDRs are loopback, link-local, shared address space, the private
// IPv4 ranges, and IANA special-purpose ranges that are not internet. They
// also cover the cloud metadata endpoint at 169.254.169.254, the Azure
// WireServer at 168.63.129.16, which looks public but serves host metadata to
// guests, and the OCI metadata service in 192.0.0.0/24 (for example
// 192.0.0.192). The benchmarking range 198.18.0.0/15, the TEST-NET
// documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, and
// the 6to4 relay anycast range 192.88.99.0/24 are reserved too, so they are
// not treated as public internet. Multicast and the remaining reserved space
// are excluded because neither is internet.
var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"168.63.129.16/32",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// localDNSCIDRs are node-local cluster DNS addresses that pods can find in
// resolv.conf instead of the kube-dns Service ClusterIP: AKS LocalDNS uses
// 169.254.10.10 and 169.254.10.11, and NodeLocal DNSCache uses
// 169.254.20.10. The rest of the link-local range stays excluded, including
// cloud metadata.
var localDNSCIDRs = []string{
	"169.254.10.10/32",
	"169.254.10.11/32",
	"169.254.20.10/32",
}

// Default is the policy used when a BlipPool omits spec.network: public
// internet egress on any protocol and port, with LAN and other non-public
// ranges excluded. Cluster DNS usually lives in a private service CIDR, so
// kube-dns is explicitly allowed on both TCP and UDP port 53. Node-local DNS
// proxies sit in link-local space and are allowed by their exact addresses.
func Default() *v1alpha1.NetworkPolicy {
	var dnsPeers []v1alpha1.NetworkPeer
	for _, cidr := range localDNSCIDRs {
		dnsPeers = append(dnsPeers, v1alpha1.NetworkPeer{
			IPBlock: &v1alpha1.NetworkIPBlock{CIDR: cidr},
		})
	}
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
			To: dnsPeers,
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
