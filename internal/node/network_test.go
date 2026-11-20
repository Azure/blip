// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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

func policyHasRule(policy *network.Policy, cidr, protocol string, port int32) bool {
	if policy != nil {
		for _, layer := range policy.Layers {
			for _, rule := range layer {
				if rule.CIDR == cidr && rule.Protocol == protocol && rule.Port == port {
					return true
				}
			}
		}
	}
	return false
}

func policyHasPort(policy *network.Policy, port int32) bool {
	if policy != nil {
		for _, layer := range policy.Layers {
			for _, rule := range layer {
				if rule.Port == port {
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
	// The pool layer, the Blip layer, and the compiler's hard-deny layer.
	if len(got.Network.Layers) != 3 || !policyHasCIDR(got.Network, "10.0.0.0/8") || !policyHasCIDR(got.Network, "10.1.0.0/16") {
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
	requireDeny(t, got.Network)
	if got.Claim != nil {
		t.Fatal("root claim written while preparation is pending")
	}
}

// TestOmittedPoolNetworkDeniesAllEvenWithBlipGrant guards the new default: a
// pool that omits spec.network contributes an empty deny-all layer. A Blip
// layer cannot widen that intersection, so its grant must not take effect.
func TestOmittedPoolNetworkDeniesAllEvenWithBlipGrant(t *testing.T) {
	v := newView()
	b, _ := durableBlip(v)
	v.pools[ns+"/default"].Spec.Network = nil
	b.Spec.Network = allowCIDR("0.0.0.0/0")
	got := compute(v).desired[pkey("p")]
	if got.Network == nil || len(got.Network.Layers) == 0 {
		t.Fatalf("missing policy: %+v", got.Network)
	}
	if len(got.Network.Layers[0]) != 0 {
		t.Fatalf("omitted pool network produced an allowing first layer: %+v", got.Network.Layers[0])
	}
	if len(got.Network.Layers) < 2 || !slices.ContainsFunc(got.Network.Layers[1], func(r network.Rule) bool {
		return r.CIDR == "0.0.0.0/0"
	}) {
		t.Fatalf("Blip grant missing from its layer: %+v", got.Network)
	}
	requireDeny(t, got.Network)
}

// TestInheritedStateNetworkErrorNamesState guards the diagnostic for an
// invalid policy inherited from spec.runtime.network: the Blip has no
// spec.network, so the error must point at the state rather than claim the
// Blip network is invalid.
func TestInheritedStateNetworkErrorNamesState(t *testing.T) {
	for _, tt := range []struct {
		name  string
		blip  bool
		label string
	}{
		{"inherited state", false, "state network"},
		{"blip override", true, "blip network"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := newView()
			b, _ := durableBlip(v)
			v.states[0].Spec.Runtime = &v1alpha1.RuntimeDefaults{Network: allowCIDR("invalid")}
			if tt.blip {
				b.Spec.Network = allowCIDR("invalid")
			}
			v.index()
			_, err := v.networkFor(v.pods[pkey("p")], b)
			if err == nil {
				t.Fatal("invalid network policy was accepted")
			}
			if !strings.Contains(err.Error(), tt.label+":") {
				t.Errorf("error %q does not name %q", err, tt.label)
			}
			if other := "blip network"; tt.label != other && strings.Contains(err.Error(), other) {
				t.Errorf("error %q wrongly blames the Blip network", err)
			}
		})
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
	if got := apply(); len(got.Network.Layers) != 2 || !policyHasCIDR(got.Network, "10.0.0.0/8") {
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
	old, err := network.Compile(v.pools[ns+"/default"].Spec.Network, nil, nil)
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

// TestNameserversFromPodEnvAddDNSRules checks that the resolvers the
// controller wrote into the VM pod become UDP/TCP port 53 rules in an
// egress-allowing layer. A deny-all layer must not get them: DNS would then be
// an exfiltration channel.
func TestNameserversFromPodEnvAddDNSRules(t *testing.T) {
	v := newView()
	b, _ := durableBlip(v)
	v.index()
	pod := v.pods[pkey("p")]
	pod.Spec.Containers = []corev1.Container{{
		Name: podapi.VMContainer,
		Env:  []corev1.EnvVar{{Name: podapi.NameserversEnv, Value: " 9.9.9.9 , 8.8.8.8 , "}},
	}}
	if got, want := podNameservers(pod), []string{"9.9.9.9", "8.8.8.8"}; !slices.Equal(got, want) {
		t.Fatalf("podNameservers = %v, want %v", got, want)
	}

	v.pools[ns+"/default"].Spec.Network = allowCIDR("0.0.0.0/0")
	policy, err := v.networkFor(pod, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"9.9.9.9/32", "8.8.8.8/32"} {
		if !policyHasRule(policy, ip, string(corev1.ProtocolUDP), 53) {
			t.Errorf("missing UDP DNS rule for %s: %+v", ip, policy)
		}
		if !policyHasRule(policy, ip, string(corev1.ProtocolTCP), 53) {
			t.Errorf("missing TCP DNS rule for %s: %+v", ip, policy)
		}
	}

	v.pools[ns+"/default"].Spec.Network = nil
	b.Spec.Network = nil
	deny, err := v.networkFor(pod, b)
	if err != nil {
		t.Fatal(err)
	}
	requireDeny(t, deny)
	if policyHasPort(deny, 53) {
		t.Fatalf("deny-all policy carries DNS rules: %+v", deny)
	}
}

// TestNetworkSnapshotAndLiveUpdates exercises the node agent's live path: the
// desired policy is published before root preparation, surviving an unchanged
// snapshot, and following Blip and pool edits. Policies are IP-block based
// now, so the revision must change only when the compiled rules do.
func TestNetworkSnapshotAndLiveUpdates(t *testing.T) {
	ctx := context.Background()
	b := blip("b") // Empty pool name must resolve to default.
	root := state("root")
	pod := vmPod("p", string(b.UID))
	pod.Spec.Containers = []corev1.Container{{
		Name: podapi.VMContainer,
		Env:  []corev1.EnvVar{{Name: podapi.NameserversEnv, Value: "9.9.9.9"}},
	}}
	pool := &v1alpha1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
		Spec:       v1alpha1.BlipPoolSpec{Network: allowCIDR("0.0.0.0/0")},
	}
	b.Spec.Network = allowCIDR("10.1.0.0/16")
	a, _, _ := testAgent(t, b, root, pod, pool)
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
	if !policyHasCIDR(got, "10.1.0.0/16") || !policyHasRule(got, "9.9.9.9/32", string(corev1.ProtocolUDP), 53) {
		t.Fatalf("initial policy missing Blip grant or DNS rule: %+v", got)
	}
	if again := syncPolicy(); again.Revision != got.Revision {
		t.Fatalf("stable snapshot changed revision: %s -> %s", got.Revision, again.Revision)
	}

	// A Blip policy edit replaces the grant without changing its layer.
	prev := got.Revision
	b.Spec.Network = allowCIDR("10.2.0.0/16")
	update(b)
	got = syncPolicy()
	if got.Revision == prev || policyHasCIDR(got, "10.1.0.0/16") || !policyHasCIDR(got, "10.2.0.0/16") {
		t.Fatalf("Blip policy update did not replace the grant: %+v", got)
	}

	// A pool that drops spec.network denies all egress, even though the Blip
	// still has an allowing layer.
	pool.Spec.Network = nil
	update(pool)
	requireDeny(t, syncPolicy())
	pool.Spec.Network = allowCIDR("0.0.0.0/0")
	update(pool)
	if got = syncPolicy(); !policyHasCIDR(got, "10.2.0.0/16") {
		t.Fatalf("restored pool policy did not restore the Blip grant: %+v", got)
	}

	b.Spec.Network = &v1alpha1.NetworkPolicy{}
	update(b)
	requireDeny(t, syncPolicy())

	// An omitted Blip policy inherits the pool policy.
	b.Spec.Network = nil
	update(b)
	if got = syncPolicy(); !policyHasCIDR(got, "0.0.0.0/0") {
		t.Fatalf("omitted Blip policy did not inherit pool policy: %+v", got)
	}

	// An invalid update replaces the previously written grants with deny and
	// reports the error on the Pod; repairing the policy clears the error.
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
