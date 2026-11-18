package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

func allowCIDR(cidr string) *v1alpha1.NetworkPolicy {
	return &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{
		To: []v1alpha1.NetworkPeer{{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: cidr}}},
	}}}
}

func requireDeny(t *testing.T, policy *network.Policy) {
	t.Helper()
	if policy == nil || policy.Revision == "" {
		t.Fatalf("default deny must be a versioned policy: %+v", policy)
	}
	if len(policy.Layers) == 0 {
		return
	}
	for _, layer := range policy.Layers {
		if len(layer) == 0 {
			return
		}
	}
	t.Fatalf("policy grants traffic: %+v", policy)
}

func policyHasCIDR(policy *network.Policy, cidr string) bool {
	if policy != nil {
		for _, layer := range policy.Layers {
			for _, rule := range layer {
				if rule.CIDR == cidr {
					return true
				}
			}
		}
	}
	return false
}

func TestNetworkPolicyBeforeRootReady(t *testing.T) {
	v := newView()
	b, d := durableBlip(v)
	v.pools[ns+"/default"].Spec.Network = allowCIDR("10.0.0.0/8")
	b.Spec.Network = allowCIDR("10.1.0.0/16")
	p := compute(v)
	got := p.desired[pkey("p")]
	if got.Claim != nil || len(p.prepares) != 1 || got.Network == nil || got.Network.Revision == "" {
		t.Fatalf("network must be written before root preparation completes: %+v, prepares=%+v", got, p.prepares)
	}
	if len(got.Network.Layers) != 2 || !policyHasCIDR(got.Network, "10.0.0.0/8") || !policyHasCIDR(got.Network, "10.1.0.0/16") {
		t.Fatalf("missing pool upper bound or Blip narrowing: %+v", got.Network)
	}
	// Unchanged policy does not churn desired.json while the root is pending.
	d.desired = &got
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("unchanged policy rewritten: %+v", p.desired)
	}
	v.pools[ns+"/default"].Spec.Network = nil
	b.Spec.Network = nil
	got = compute(v).desired[pkey("p")]
	if got.Network == nil || !policyHasCIDR(got.Network, "0.0.0.0/0") {
		t.Fatalf("omitted pool policy did not apply the internet default: %+v", got.Network)
	}
	if got.Claim != nil {
		t.Fatal("root claim written while preparation is pending")
	}
}

func TestNetworkPolicyFailureRevokesGrantsAndPreservesDisks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*view, *v1alpha1.Blip)
	}{
		{"invalid pool", func(v *view, _ *v1alpha1.Blip) {
			v.pools[ns+"/default"].Spec.Network = allowCIDR("invalid")
		}},
		{"invalid Blip", func(_ *view, b *v1alpha1.Blip) { b.Spec.Network = allowCIDR("invalid") }},
		{"invalid state", func(v *view, _ *v1alpha1.Blip) {
			v.states[0].Spec.Runtime = &v1alpha1.RuntimeDefaults{Network: allowCIDR("invalid")}
		}},
		{"missing state", func(v *view, _ *v1alpha1.Blip) { v.states = nil }},
		{"missing pool", func(v *view, _ *v1alpha1.Blip) { delete(v.pools, ns+"/default") }},
		{"missing Blip", func(v *view, _ *v1alpha1.Blip) { v.blips = nil }},
		{"wrong pool namespace", func(v *view, _ *v1alpha1.Blip) {
			pool := v.pools[ns+"/default"]
			delete(v.pools, ns+"/default")
			pool.Namespace = "other"
			v.pools["other/default"] = pool
		}},
		{"pool mismatch", func(v *view, _ *v1alpha1.Blip) { v.pods[pkey("p")].Labels[v1alpha1.LabelPool] = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			b, d := durableBlip(v)
			v.pools[ns+"/default"].Spec.Network = allowCIDR("0.0.0.0/0")
			readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)
			readyDev(v, d, storage.Volume{ID: "m1", ReadOnly: true}, 8)
			b.Status.Mounts = []v1alpha1.MountStatus{{State: "data", Path: "/data", AttachmentID: "m1", Phase: v1alpha1.MountMounted}}
			v.freezes = map[string][]string{pkey("p"): {"r1"}}
			prev := compute(v).desired[pkey("p")]
			if prev.Claim == nil || !policyHasCIDR(prev.Network, "0.0.0.0/0") {
				t.Fatalf("initial claim = %+v", prev)
			}
			prev.Stop = true
			d.desired = &prev
			tc.change(v, b)
			p := compute(v)
			got := p.desired[pkey("p")]
			requireDeny(t, got.Network)
			if !got.Stop || !sameJSON(got.Claim, prev.Claim) || !sameJSON(got.Mounts, prev.Mounts) || !sameJSON(got.Freeze, prev.Freeze) {
				t.Fatalf("policy failure changed disks, freeze, or sticky stop: before=%+v after=%+v", prev, got)
			}
			if len(p.podErrs) != 1 || !strings.HasPrefix(p.podErrs[0].err, "network policy: ") {
				t.Fatalf("missing preparation error: %+v", p.podErrs)
			}
		})
	}
}

func TestLiveStateNetworkPrecedence(t *testing.T) {
	v := newView()
	b, d := durableBlip(v)
	root := v.states[0]
	root.Spec.Runtime = &v1alpha1.RuntimeDefaults{Network: allowCIDR("10.1.0.0/16")}
	v.pools[ns+"/default"].Spec.Network = allowCIDR("10.0.0.0/8")
	readyDev(v, d, storage.Volume{ID: "r1", StateUID: string(root.UID)}, 7)
	initial := compute(v).desired[pkey("p")]
	if initial.Claim == nil || !policyHasCIDR(initial.Network, "10.0.0.0/8") || !policyHasCIDR(initial.Network, "10.1.0.0/16") {
		t.Fatalf("state policy must narrow the pool at claim: %+v", initial)
	}
	d.desired = &initial
	d.observed.Phase = podapi.PhaseRunning
	apply := func() podapi.Desired {
		t.Helper()
		got, changed := compute(v).desired[pkey("p")]
		if !changed {
			t.Fatal("live policy change did not update desired")
		}
		if !sameJSON(got.Claim, initial.Claim) {
			t.Fatal("live policy change replaced the startup claim")
		}
		d.desired = &got
		return got
	}
	root.Spec.Runtime.Network = allowCIDR("10.2.0.0/16")
	if got := apply(); policyHasCIDR(got.Network, "10.1.0.0/16") || !policyHasCIDR(got.Network, "10.2.0.0/16") {
		t.Fatalf("state edit did not replace live policy: %+v", got.Network)
	}
	b.Spec.Network = allowCIDR("10.3.0.0/16")
	if got := apply(); policyHasCIDR(got.Network, "10.2.0.0/16") || !policyHasCIDR(got.Network, "10.3.0.0/16") || !policyHasCIDR(got.Network, "10.0.0.0/8") {
		t.Fatalf("execution policy must replace state policy within the pool bound: %+v", got.Network)
	}
	root.Spec.Runtime.Network = &v1alpha1.NetworkPolicy{}
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("state policy affected an execution override: %+v", p.desired)
	}
	b.Spec.Network = nil
	requireDeny(t, apply().Network)
	root.Spec.Runtime.Network = nil
	if got := apply(); len(got.Network.Layers) != 1 || !policyHasCIDR(got.Network, "10.0.0.0/8") {
		t.Fatalf("omitted state and execution policies must inherit pool: %+v", got.Network)
	}
	b.Spec.Network = &v1alpha1.NetworkPolicy{}
	requireDeny(t, apply().Network)
	root.Spec.Runtime.Network = allowCIDR("10.4.0.0/16")
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("state policy broadened explicit execution deny: %+v", p.desired)
	}
}

func TestUnclaimedWarmNetworkDenied(t *testing.T) {
	v := newView()
	pod := vmPod("p", "")
	v.pods[pkey("p")] = pod
	v.pools[ns+"/default"].Spec.Network = allowCIDR("0.0.0.0/0")
	d := dir(podapi.PhaseWarm)
	old, err := network.Compile(ns, v.pools[ns+"/default"].Spec.Network, nil, network.Destinations{})
	if err != nil {
		t.Fatal(err)
	}
	d.desired = &podapi.Desired{Network: &old}
	v.dirs[pkey("p")] = d
	p := compute(v)
	got := p.desired[pkey("p")]
	requireDeny(t, got.Network)
	if got.Claim != nil || len(p.podErrs) != 0 {
		t.Fatalf("warm desired/error = %+v, %+v", got, p.podErrs)
	}
	d.desired = &got
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("unchanged warm policy rewritten: %+v", p.desired)
	}
}

func TestNetworkSnapshotAndLiveUpdates(t *testing.T) {
	ctx := context.Background()
	b := blip("b") // Empty pool name must resolve to default.
	root := state("root")
	pod := vmPod("p", string(b.UID))
	pool := &v1alpha1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
		Spec:       v1alpha1.BlipPoolSpec{Network: allowCIDR("0.0.0.0/0")},
	}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "target"}}
	nsSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "backend"}}
	b.Spec.Network = &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{To: []v1alpha1.NetworkPeer{
		{PodSelector: selector, NamespaceSelector: nsSelector},
		{ServiceSelector: selector, NamespaceSelector: nsSelector},
	}}}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"team": "backend"}}}
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "backend", Name: "target", Labels: map[string]string{"app": "target"}},
		Spec:       corev1.PodSpec{NodeName: "remote"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.1.0.1", PodIPs: []corev1.PodIP{{IP: "10.1.0.1"}}},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "backend", Name: "service", Labels: map[string]string{"app": "target"}},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.1"},
	}
	headless := service.DeepCopy()
	headless.Name, headless.Spec.ClusterIP = "headless", corev1.ClusterIPNone
	endpoints := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "backend", Name: "headless-1", Labels: map[string]string{discoveryv1.LabelServiceName: "headless"}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.2.0.1"}}},
	}
	remoteVM, plainLocal := vmPod("remote-vm", ""), vmPod("plain-local", "")
	remoteVM.Spec.NodeName = "remote"
	delete(plainLocal.Labels, v1alpha1.LabelPool)
	// If either pod entered the management view, podMetaFor would clear this.
	remoteVM.Labels[v1alpha1.LabelWarm], plainLocal.Labels[v1alpha1.LabelWarm] = "true", "true"
	a, _, _ := testAgent(t, b, root, pod, pool, namespace, target, service, headless, endpoints, remoteVM, plainLocal)
	dir := a.podDirFor(pkey("p"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(dir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
		t.Fatal(err)
	}
	syncPolicy := func() *network.Policy {
		t.Helper()
		if err := a.sync(ctx); err != nil {
			t.Fatal(err)
		}
		var d podapi.Desired
		if err := podapi.ReadJSON(filepath.Join(dir, podapi.DesiredFile), &d); err != nil {
			t.Fatal(err)
		}
		if d.Network == nil || d.Network.Revision == "" || d.Claim != nil {
			t.Fatalf("network must be published before root preparation: %+v", d)
		}
		return d.Network
	}
	update := func(obj client.Object) {
		t.Helper()
		if err := a.client.Update(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	got := syncPolicy()
	for _, cidr := range []string{"10.1.0.1/32", "10.96.0.1/32", "10.2.0.1/32"} {
		if !policyHasCIDR(got, cidr) {
			t.Fatalf("cluster-wide destination %s missing from %+v", cidr, got)
		}
	}
	v, err := a.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.pods) != 1 || v.pods[pkey("p")] == nil || len(v.destinations.Pods) != 4 {
		t.Fatalf("managed pods=%v, destinations=%v", v.pods, v.destinations.Pods)
	}
	for _, original := range []*corev1.Pod{remoteVM, plainLocal} {
		var current corev1.Pod
		if err := a.client.Get(ctx, client.ObjectKeyFromObject(original), &current); err != nil {
			t.Fatal(err)
		}
		if current.Labels[v1alpha1.LabelWarm] != "true" || len(current.Annotations) != 0 {
			t.Fatalf("unmanaged pod was reconciled: %+v", current.ObjectMeta)
		}
	}
	if again := syncPolicy(); again.Revision != got.Revision {
		t.Fatalf("stable snapshot changed revision: %s -> %s", got.Revision, again.Revision)
	}

	// Pod IP changes replace the old grant, including pods on other nodes.
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
		t.Fatal(err)
	}
	target.Status.PodIP, target.Status.PodIPs = "10.1.0.2", []corev1.PodIP{{IP: "10.1.0.2"}}
	if err := a.client.Status().Update(ctx, target); err != nil {
		t.Fatal(err)
	}
	prev := got.Revision
	got = syncPolicy()
	if got.Revision == prev || policyHasCIDR(got, "10.1.0.1/32") || !policyHasCIDR(got, "10.1.0.2/32") {
		t.Fatalf("PodIP change did not replace grant: %+v", got)
	}

	service.Labels["app"] = "other"
	update(service)
	got = syncPolicy()
	if policyHasCIDR(got, "10.96.0.1/32") || !policyHasCIDR(got, "10.2.0.1/32") {
		t.Fatalf("Service selector update did not remove grant: %+v", got)
	}
	endpoints.Endpoints[0].Addresses = []string{"10.2.0.2"}
	update(endpoints)
	got = syncPolicy()
	if policyHasCIDR(got, "10.2.0.1/32") || !policyHasCIDR(got, "10.2.0.2/32") {
		t.Fatalf("EndpointSlice update did not replace grant: %+v", got)
	}
	namespace.Labels["team"] = "other"
	update(namespace)
	requireDeny(t, syncPolicy())
	namespace.Labels["team"] = "backend"
	update(namespace)
	if got = syncPolicy(); !policyHasCIDR(got, "10.1.0.2/32") {
		t.Fatalf("Namespace selector update did not restore grant: %+v", got)
	}
	pool.Spec.Network = nil
	update(pool)
	if got = syncPolicy(); !policyHasCIDR(got, "0.0.0.0/0") {
		t.Fatalf("omitted pool policy did not apply the internet default: %+v", got)
	}
	pool.Spec.Network = allowCIDR("0.0.0.0/0")
	update(pool)
	b.Spec.Network = &v1alpha1.NetworkPolicy{}
	update(b)
	requireDeny(t, syncPolicy())

	// An invalid update replaces the previously written grants with deny and
	// reports the error on the Pod; repairing the policy clears the error.
	b.Spec.Network = nil
	update(b)
	if got = syncPolicy(); !policyHasCIDR(got, "0.0.0.0/0") {
		t.Fatalf("omitted Blip policy did not inherit pool policy: %+v", got)
	}
	b.Spec.Network = allowCIDR("invalid")
	update(b)
	requireDeny(t, syncPolicy())
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	if msg := pod.Annotations[v1alpha1.AnnotationPrepareError]; !strings.Contains(msg, "network policy:") {
		t.Fatalf("compile failure not reported: %q", msg)
	}
	b.Spec.Network = nil
	update(b)
	syncPolicy()
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	if msg := pod.Annotations[v1alpha1.AnnotationPrepareError]; msg != "" {
		t.Fatalf("repaired policy still has error: %q", msg)
	}
}
