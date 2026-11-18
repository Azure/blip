package network

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDefaultDenyInheritanceAndIntersection(t *testing.T) {
	allowAll := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{}}}
	web := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "10.0.0.0/8"}}, v1alpha1.NetworkPort{Port: 443})
	for _, tt := range []struct {
		name       string
		pool, blip *v1alpha1.NetworkPolicy
		layers     int
		allowed    bool
	}{
		{"nil pool", nil, nil, 1, false},
		{"empty pool", &v1alpha1.NetworkPolicy{}, nil, 1, false},
		{"blip cannot widen nil pool", nil, allowAll, 2, false},
		{"inherit pool", web, nil, 1, true},
		{"empty blip denies", allowAll, &v1alpha1.NetworkPolicy{}, 2, false},
		{"blip narrows pool", allowAll, web, 2, true},
		{"blip cannot widen pool", web, allowAll, 2, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mustCompile(t, "apps", tt.pool, tt.blip, Destinations{})
			if len(got.Layers) != tt.layers {
				t.Fatalf("layers = %d, want %d", len(got.Layers), tt.layers)
			}
			if allows(got, "10.1.2.3", "TCP", 443) != tt.allowed {
				t.Fatalf("unexpected web access: %+v", got)
			}
			if allows(got, "10.1.2.3", "UDP", 443) || allows(got, "192.0.2.1", "TCP", 443) || allows(got, "10.1.2.3", "TCP", 80) {
				t.Fatalf("policy widened access: %+v", got)
			}
		})
	}
	all := mustCompile(t, "apps", allowAll, nil, Destinations{})
	if !allows(all, "192.0.2.1", "ICMP", 0) || allows(Policy{}, "192.0.2.1", "TCP", 80) {
		t.Fatal("empty rule must allow all IP protocols; empty policy must deny")
	}
}

func TestCIDRExceptionsAndPortRanges(t *testing.T) {
	policy := policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{
		CIDR: "10.2.3.4/8", Except: []string{"10.2.0.1/16", "10.1.0.0/16", "10.2.0.0/16"},
	}}, v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 8000, EndPort: int32ptr(8010)}, v1alpha1.NetworkPort{Port: 443})
	got := mustCompile(t, "apps", policy, nil, Destinations{})
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

func TestPodAndNamespaceSelectors(t *testing.T) {
	d := Destinations{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"team": "app"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "data", Labels: map[string]string{"team": "data"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"team": "other"}}},
		},
		Pods: []corev1.Pod{
			pod("apps", "db", "10.0.0.1"), pod("data", "db", "10.0.0.2"),
			pod("data", "web", "10.0.0.3"), pod("other", "db", "10.0.0.4"),
			pod("unknown", "db", "10.0.0.5"), pod("data", "db", "10.0.0.6"),
		},
	}
	d.Pods[5].Spec.HostNetwork = true
	d.Pods[1].Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.2"}, {IP: "fd00::2"}}
	for _, tt := range []struct {
		name string
		peer v1alpha1.NetworkPeer
		want []string
	}{
		{"local pods", v1alpha1.NetworkPeer{PodSelector: match("app", "db")}, []string{"10.0.0.1/32"}},
		{"namespace AND pod", v1alpha1.NetworkPeer{NamespaceSelector: match("team", "data"), PodSelector: match("app", "db")}, []string{"10.0.0.2/32"}},
		{"namespace alone", v1alpha1.NetworkPeer{NamespaceSelector: match("team", "data")}, []string{"10.0.0.2/32", "10.0.0.3/32"}},
		{"all known namespaces", v1alpha1.NetworkPeer{NamespaceSelector: &metav1.LabelSelector{}, PodSelector: match("app", "db")}, []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.4/32"}},
		{"no match denies", v1alpha1.NetworkPeer{PodSelector: match("app", "missing")}, []string{}},
		{"expressions", v1alpha1.NetworkPeer{NamespaceSelector: match("team", "data"), PodSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"web"}}}}}, []string{"10.0.0.2/32"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mustCompile(t, "apps", policyFor(tt.peer), nil, d)
			if actual := cidrs(got.Layers[0]); !reflect.DeepEqual(actual, tt.want) {
				t.Fatalf("destinations = %v, want %v", actual, tt.want)
			}
		})
	}
}

func TestServiceAndHeadlessSelectors(t *testing.T) {
	d := Destinations{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "data", Labels: map[string]string{"team": "data"}}}},
		Services: []corev1.Service{
			service("apps", "cluster", "10.96.0.1"), service("apps", "headless", corev1.ClusterIPNone),
			service("other", "cluster", "10.96.0.2"), service("data", "cluster", "10.96.0.3"),
			service("apps", "external", ""),
		},
		EndpointSlices: []discoveryv1.EndpointSlice{
			endpointSlice("apps", "headless", "10.2.0.1", "10.2.0.2"),
			endpointSlice("other", "headless", "10.2.0.3"),
			endpointSlice("apps", "unselected", "10.2.0.4"),
			endpointSlice("apps", "headless", "fd00::5"),
		},
	}
	d.Services[0].Spec.ClusterIPs = []string{"10.96.0.1", "fd00::1"}
	d.Services[0].Spec.Ports = []corev1.ServicePort{{Port: 80}}
	d.Services[4].Spec.Type = corev1.ServiceTypeExternalName
	d.Services[4].Spec.ExternalName = "example.com"
	d.EndpointSlices[3].AddressType = discoveryv1.AddressTypeIPv6
	for _, tt := range []struct {
		name string
		peer v1alpha1.NetworkPeer
		want []string
	}{
		{"local services", v1alpha1.NetworkPeer{ServiceSelector: match("app", "db")}, []string{"10.2.0.1/32", "10.2.0.2/32", "10.96.0.1/32"}},
		{"namespace AND service", v1alpha1.NetworkPeer{ServiceSelector: match("app", "db"), NamespaceSelector: match("team", "data")}, []string{"10.96.0.3/32"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mustCompile(t, "apps", policyFor(tt.peer, v1alpha1.NetworkPort{Port: 8080}), nil, d)
			if actual := cidrs(got.Layers[0]); !reflect.DeepEqual(actual, tt.want) {
				t.Fatalf("destinations = %v, want %v", actual, tt.want)
			}
			for _, rule := range got.Layers[0] {
				if rule.Port != 8080 || rule.Protocol != "TCP" {
					t.Fatalf("numeric destination port was translated: %+v", rule)
				}
			}
		})
	}
}

func TestPodSelectorsExcludeReusedHistoricalAddresses(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed, corev1.PodRunning} {
		name := string(phase)
		if phase == corev1.PodRunning {
			name = "deleting"
		}
		t.Run(name, func(t *testing.T) {
			const reusedIP = "10.0.0.9"
			oldPod := pod("apps", "db", reusedIP)
			oldPod.Status.Phase = phase
			oldPod.Status.PodIPs = []corev1.PodIP{{IP: reusedIP}}
			if phase == corev1.PodRunning {
				now := metav1.Now()
				oldPod.DeletionTimestamp = &now
			}
			unselected := pod("apps", "web", reusedIP)
			current := pod("apps", "db", "10.0.0.10")
			d := Destinations{Pods: []corev1.Pod{oldPod, unselected, current}}
			got := mustCompile(t, "apps", policyFor(v1alpha1.NetworkPeer{PodSelector: match("app", "db")}), nil, d)
			if allows(got, reusedIP, "TCP", 443) {
				t.Fatal("historical matching PodIP granted access to an unselected replacement pod")
			}
			if !allows(got, "10.0.0.10", "TCP", 443) {
				t.Fatal("running selected pod was excluded")
			}
		})
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
		{"mixed IP and selector", policyFor(v1alpha1.NetworkPeer{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "0.0.0.0/0"}, PodSelector: &metav1.LabelSelector{}})},
		{"mixed pod and service", policyFor(v1alpha1.NetworkPeer{PodSelector: &metav1.LabelSelector{}, ServiceSelector: &metav1.LabelSelector{}})},
		{"invalid pod selector", policyFor(v1alpha1.NetworkPeer{PodSelector: match("bad/key/key", "v")})},
		{"invalid namespace selector", policyFor(v1alpha1.NetworkPeer{NamespaceSelector: match("x", "bad/value")})},
		{"invalid service selector", policyFor(v1alpha1.NetworkPeer{ServiceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "x", Operator: "Invalid"}}}})},
		{"zero port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{})},
		{"negative port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: -1})},
		{"large port", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 65536})},
		{"unsupported protocol", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Protocol: corev1.ProtocolSCTP, Port: 80})},
		{"reversed range", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 80, EndPort: int32ptr(79)})},
		{"large endPort", policyFor(block("0.0.0.0/0"), v1alpha1.NetworkPort{Port: 80, EndPort: int32ptr(65536)})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, pool := range []*v1alpha1.NetworkPolicy{nil, {Egress: []v1alpha1.NetworkEgressRule{{}}}} {
				got, err := Compile("apps", pool, tt.policy, Destinations{})
				if err == nil || len(got.Layers) != 0 {
					t.Fatalf("invalid policy returned %+v, %v", got, err)
				}
			}
		})
	}
}

func TestStableRevisionsAndNoInputMutation(t *testing.T) {
	d := Destinations{Pods: []corev1.Pod{pod("apps", "db", "10.0.0.2"), pod("apps", "db", "10.0.0.1")}}
	policy := policyFor(v1alpha1.NetworkPeer{PodSelector: match("app", "db")}, v1alpha1.NetworkPort{Port: 443}, v1alpha1.NetworkPort{Protocol: corev1.ProtocolUDP, Port: 53})
	before, _ := json.Marshal(struct {
		Policy       *v1alpha1.NetworkPolicy
		Destinations Destinations
	}{policy, d})
	first := mustCompile(t, "apps", policy, nil, d)
	after, _ := json.Marshal(struct {
		Policy       *v1alpha1.NetworkPolicy
		Destinations Destinations
	}{policy, d})
	if string(before) != string(after) {
		t.Fatal("compiler mutated its inputs")
	}
	slices.Reverse(d.Pods)
	d.Pods = append(d.Pods, d.Pods[0])
	d.Pods[0].ResourceVersion = "changed"
	slices.Reverse(policy.Egress[0].Ports)
	policy.Egress[0].Ports[1].Protocol = corev1.ProtocolTCP
	policy.Egress[0].Ports[1].EndPort = int32ptr(443)
	policy.Egress = append(policy.Egress, policy.Egress[0])
	second := mustCompile(t, "apps", policy, nil, d)
	if !reflect.DeepEqual(first, second) || len(first.Revision) != 64 {
		t.Fatalf("equivalent inputs changed revision: %+v vs %+v", first, second)
	}
	d.Pods = append(d.Pods, pod("apps", "db", "10.0.0.3"))
	third := mustCompile(t, "apps", policy, nil, d)
	if third.Revision == first.Revision {
		t.Fatal("new destination did not change revision")
	}
}

func TestInvalidDestinationAddressFailsClosed(t *testing.T) {
	got, err := Compile("apps", policyFor(v1alpha1.NetworkPeer{PodSelector: &metav1.LabelSelector{}}), nil, Destinations{Pods: []corev1.Pod{pod("apps", "db", "not-an-ip")}})
	if err == nil || len(got.Layers) != 0 {
		t.Fatalf("invalid PodIP returned %+v, %v", got, err)
	}
}

func policyFor(peer v1alpha1.NetworkPeer, ports ...v1alpha1.NetworkPort) *v1alpha1.NetworkPolicy {
	return &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{To: []v1alpha1.NetworkPeer{peer}, Ports: ports}}}
}

func match(key, value string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{key: value}}
}

func pod(namespace, app, ip string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Labels: map[string]string{"app": app}}, Status: corev1.PodStatus{PodIP: ip, Phase: corev1.PodRunning}}
}

func service(namespace, name, ip string) corev1.Service {
	return corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{"app": "db"}}, Spec: corev1.ServiceSpec{ClusterIP: ip}}
}

func endpointSlice(namespace, service string, addresses ...string) discoveryv1.EndpointSlice {
	return discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Labels: map[string]string{discoveryv1.LabelServiceName: service}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: addresses}}}
}

func int32ptr(value int32) *int32 { return &value }

func mustCompile(t *testing.T, namespace string, pool, blip *v1alpha1.NetworkPolicy, destinations Destinations) Policy {
	t.Helper()
	policy, err := Compile(namespace, pool, blip, destinations)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func cidrs(rules []Rule) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.CIDR)
	}
	slices.Sort(result)
	return result
}

// Evaluate the wire contract independently of compiler selector resolution.
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
