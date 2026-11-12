package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/testing/fakenode"
)

func newPool(t *testing.T, ns, name, sku string, minFree, maxFree int32, delay time.Duration) *v1.BlipPool {
	t.Helper()
	p := &v1.BlipPool{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: v1.BlipPoolSpec{
		SKU: sku, CPUs: 1, Memory: resource.MustParse("512Mi"), MinFree: minFree, MaxFree: maxFree,
		ScaleDownDelay: &metav1.Duration{Duration: delay},
	}}
	if err := env.k.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func getPool(t *testing.T, ns, name string) *v1.BlipPool {
	t.Helper()
	var p v1.BlipPool
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func patchPool(t *testing.T, ns, name string, mut func(*v1.BlipPool)) {
	t.Helper()
	p := getPool(t, ns, name)
	mut(p)
	if err := env.k.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

// poolPods lists the live (not deleting) pods carrying the pool label.
func poolPods(t *testing.T, ns, pool string) []corev1.Pod {
	t.Helper()
	var l corev1.PodList
	if err := env.k.List(context.Background(), &l, client.InNamespace(ns), client.MatchingLabels{api.LabelPool: pool}); err != nil {
		t.Fatal(err)
	}
	var out []corev1.Pod
	for _, p := range l.Items {
		if p.DeletionTimestamp == nil {
			out = append(out, p)
		}
	}
	return out
}

func freePods(t *testing.T, ns, pool string) []corev1.Pod {
	var out []corev1.Pod
	for _, p := range poolPods(t, ns, pool) {
		if p.Labels[api.LabelSlot] == api.SlotFree {
			out = append(out, p)
		}
	}
	return out
}

// bindReady stands in for the scheduler and kubelet.
func bindReady(t *testing.T, p *corev1.Pod, node string) {
	t.Helper()
	ctx := context.Background()
	if p.Spec.NodeName == "" {
		b := &corev1.Binding{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name}, Target: corev1.ObjectReference{Kind: "Node", Name: node}}
		if err := env.k.SubResource("binding").Create(ctx, p, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.k.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
		t.Fatal(err)
	}
	makeReady(t, p)
}

// bindAll binds and readies every unbound free pod of the pool, spread
// over the compute nodes.
func bindAll(t *testing.T, ns, pool string) {
	t.Helper()
	nodes := []string{"s1", "s2", "s3"}
	for i, p := range freePods(t, ns, pool) {
		if p.Spec.NodeName == "" || !podReady(&p) {
			bindReady(t, &p, nodes[i%len(nodes)])
		}
	}
}

func poolReady(p *v1.BlipPool) string {
	c := meta.FindStatusCondition(p.Status.Conditions, api.CondReady)
	if c == nil {
		return ""
	}
	return string(c.Status) + "/" + c.Reason
}

func TestPoolMinFree(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pl := newPool(t, ns, "p", "small", 2, 4, time.Hour)
	eventually(t, 10*time.Second, "2 pods", func() bool { return len(poolPods(t, ns, "p")) == 2 })
	time.Sleep(500 * time.Millisecond)
	pods := poolPods(t, ns, "p")
	if len(pods) != 2 {
		t.Fatalf("%d pods", len(pods))
	}
	p := &pods[0]
	if p.Labels[api.LabelSKU] != "small" || p.Labels[api.LabelSlot] != api.SlotFree || p.Labels[api.LabelTemplateHash] == "" ||
		!poolOwned(p, pl) || p.Spec.Containers[0].Image != "slot:test" {
		t.Fatalf("pod %+v", p.ObjectMeta)
	}
	eventually(t, 10*time.Second, "scaling", func() bool {
		s := getPool(t, ns, "p")
		return poolReady(s) == "False/Scaling" && s.Status.Booting == 2 && s.Status.TemplateHash == p.Labels[api.LabelTemplateHash]
	})
	bindAll(t, ns, "p")
	eventually(t, 10*time.Second, "ready", func() bool {
		s := getPool(t, ns, "p")
		return poolReady(s) == "True/Ready" && s.Status.Free == 2 && s.Status.Booting == 0 && s.Status.DesiredFree == 2
	})
}

func TestPoolClaimRefillAndBurst(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	newPool(t, ns, "p", "burst", 1, 1, time.Hour)
	eventually(t, 10*time.Second, "1 pod", func() bool { return len(poolPods(t, ns, "p")) == 1 })
	bindAll(t, ns, "p")
	emptyVol(t, ns, "ws")
	setWork(ns, "a", fakenode.Succeed(3*time.Second))
	newBlip(t, ns, "a", "ws", "burst", nil)
	b := waitBlip(t, ns, "a", 20*time.Second, func(b *v1.Blip) bool { return b.Status.Allocation != nil })
	var claimed corev1.Pod
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: b.Status.Allocation.PodName}, &claimed); err != nil {
		t.Fatal(err)
	}
	if len(claimed.OwnerReferences) != 0 || claimed.Labels[api.LabelPool] != "p" || claimed.Labels[api.LabelSlot] != api.SlotAssigned {
		t.Fatalf("claimed pod %+v", claimed.ObjectMeta)
	}
	// The pool refills.
	eventually(t, 10*time.Second, "refill", func() bool { return len(freePods(t, ns, "p")) == 1 })
	eventually(t, 10*time.Second, "assigned", func() bool { return getPool(t, ns, "p").Status.Assigned == 1 })
	complete(t, ns, "a")

	// Burst: Blips waiting with NoCapacity scale the pool up.
	for _, n := range []string{"b1", "b2", "b3"} {
		emptyVol(t, ns, "ws-"+n)
		newBlip(t, ns, n, "ws-"+n, "burst", nil)
	}
	eventually(t, 20*time.Second, "burst pods", func() bool {
		bindAll(t, ns, "p")
		for _, n := range []string{"b1", "b2", "b3"} {
			if b := getBlip(ns, n); b == nil || b.Status.Allocation == nil {
				return false
			}
		}
		return true
	})
	for _, n := range []string{"b1", "b2", "b3"} {
		complete(t, ns, n)
	}
}

func TestPoolScaleDownSkipsAssumed(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	newPool(t, ns, "p", "down", 3, 3, time.Second)
	eventually(t, 10*time.Second, "3 pods", func() bool { return len(poolPods(t, ns, "p")) == 3 })
	time.Sleep(300 * time.Millisecond)
	pods := poolPods(t, ns, "p")
	// Two Ready, one never scheduled: the unscheduled one goes first.
	bindReady(t, &pods[0], "s1")
	bindReady(t, &pods[1], "s2")
	unscheduled, keep := pods[2].Name, pods[0].Name
	// A pending Blip stands in for an in-flight claim of pods[0].
	emptyVol(t, ns, "ws")
	holder := newBlip(t, ns, "holder", "ws", "nosuchsku", nil)
	key := podKey(ns, keep)
	env.ctrl.schedMu.Lock()
	env.ctrl.assumed[key] = assumedClaim{blip: types.NamespacedName{Namespace: ns, Name: "holder"}, uid: holder.UID, namespace: ns, sku: "nosuchsku", allocID: "x", at: time.Now()}
	env.ctrl.schedMu.Unlock()
	defer func() {
		env.ctrl.schedMu.Lock()
		delete(env.ctrl.assumed, key)
		env.ctrl.schedMu.Unlock()
	}()
	patchPool(t, ns, "p", func(p *v1.BlipPool) { p.Spec.MinFree, p.Spec.MaxFree = 0, 0 })
	start := time.Now()
	eventually(t, 15*time.Second, "unscheduled pod deleted", func() bool { return podGone(ns, unscheduled) })
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("scaled down before scaleDownDelay")
	}
	eventually(t, 15*time.Second, "second pod deleted", func() bool { return podGone(ns, pods[1].Name) })
	time.Sleep(2 * time.Second)
	if podGone(ns, keep) {
		t.Fatal("deleted a pod with an assumed claim")
	}
	env.ctrl.schedMu.Lock()
	delete(env.ctrl.assumed, key)
	env.ctrl.schedMu.Unlock()
	eventually(t, 15*time.Second, "last pod deleted", func() bool { return podGone(ns, keep) })
}

func TestPoolRollout(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	newPool(t, ns, "p", "roll", 2, 2, time.Hour)
	eventually(t, 10*time.Second, "2 pods", func() bool { return len(poolPods(t, ns, "p")) == 2 })
	bindAll(t, ns, "p")
	// Simulate a claim of one pod.
	pods := poolPods(t, ns, "p")
	as := pods[0].DeepCopy()
	as.Labels[api.LabelSlot] = api.SlotAssigned
	as.OwnerReferences = []metav1.OwnerReference{}
	if err := env.k.Patch(context.Background(), as, client.MergeFrom(&pods[0])); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "refill", func() bool {
		bindAll(t, ns, "p")
		s := getPool(t, ns, "p")
		return s.Status.Free == 2 && s.Status.Assigned == 1 && len(freePods(t, ns, "p")) == 2
	})
	oldHash := getPool(t, ns, "p").Status.TemplateHash
	old := map[string]bool{}
	for _, p := range freePods(t, ns, "p") {
		old[p.Name] = true
	}
	patchPool(t, ns, "p", func(p *v1.BlipPool) { p.Spec.CPUs = 2 })
	eventually(t, 10*time.Second, "new shape pods", func() bool {
		n := 0
		for _, p := range freePods(t, ns, "p") {
			if !old[p.Name] {
				n++
			}
		}
		return n == 2 && getPool(t, ns, "p").Status.TemplateHash != oldHash
	})
	// Old free pods stay until the new ones are Ready.
	for n := range old {
		if podGone(ns, n) {
			t.Fatalf("old pod %s deleted before replacements are ready", n)
		}
	}
	bindAll(t, ns, "p")
	eventually(t, 10*time.Second, "old pods replaced", func() bool {
		for n := range old {
			if !podGone(ns, n) {
				return false
			}
		}
		return true
	})
	if podGone(ns, as.Name) {
		t.Fatal("assigned pod deleted")
	}
	eventually(t, 10*time.Second, "ready", func() bool {
		s := getPool(t, ns, "p")
		return poolReady(s) == "True/Ready" && s.Status.Free == 2 && s.Status.Assigned == 1
	})
}

func TestPoolDuplicateSKU(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	newPool(t, ns, "a", "dup", 1, 1, time.Hour)
	eventually(t, 10*time.Second, "pod", func() bool { return len(poolPods(t, ns, "a")) == 1 })
	time.Sleep(1100 * time.Millisecond) // creationTimestamp has second resolution
	newPool(t, ns, "b", "dup", 1, 1, time.Hour)
	eventually(t, 10*time.Second, "duplicate", func() bool { return poolReady(getPool(t, ns, "b")) == "False/DuplicateSKU" })
	time.Sleep(time.Second)
	if n := len(poolPods(t, ns, "b")); n != 0 {
		t.Fatalf("duplicate pool created %d pods", n)
	}
	// The winner goes away: the other pool takes over.
	if err := env.k.Delete(context.Background(), getPool(t, ns, "a")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "takeover", func() bool { return len(poolPods(t, ns, "b")) == 1 })
}

func TestPoolUnknownSKU(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	emptyVol(t, ns, "ws")
	newBlip(t, ns, "x", "ws", "later", nil)
	waitBlip(t, ns, "x", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonUnknownSKU
	})
	newPool(t, ns, "later", "later", 0, 1, time.Hour)
	eventually(t, 20*time.Second, "scheduled", func() bool {
		bindAll(t, ns, "later")
		b := getBlip(ns, "x")
		return b != nil && b.Status.Allocation != nil
	})
	complete(t, ns, "x")
}

// A free pod the kubelet rejected (phase Failed) never restarts; the pool
// deletes and replaces it.
func TestPoolReplacesFailedPod(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	newPool(t, ns, "p", "failed", 1, 1, time.Hour)
	eventually(t, 10*time.Second, "1 pod", func() bool { return len(poolPods(t, ns, "p")) == 1 })
	p := poolPods(t, ns, "p")[0]
	p.Status.Phase = corev1.PodFailed
	p.Status.Reason = "UnexpectedAdmissionError"
	if err := env.k.Status().Update(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "replaced", func() bool {
		pods := poolPods(t, ns, "p")
		return len(pods) == 1 && pods[0].UID != p.UID && pods[0].Status.Phase != corev1.PodFailed
	})
	bindAll(t, ns, "p")
	eventually(t, 10*time.Second, "ready", func() bool { return poolReady(getPool(t, ns, "p")) == "True/Ready" })
}
