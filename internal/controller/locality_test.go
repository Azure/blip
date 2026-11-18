package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// localSetup creates state data held by one node and a pool with one ready
// VM on the other node. It returns the node holding the data and the other.
func localSetup(t *testing.T, warm, max int32) (e *env, home, away string) {
	e = newEnv(t)
	e.addNodes("n1", "n2")
	home = e.readyState("data", "n1").Status.Placements[0]
	away = map[string]string{"n1": "n2", "n2": "n1"}[home]
	e.newPool("default", warm, max)
	e.run(e.pool, ns, "default")
	e.warmOn(away)
	return e, home, away
}

func pinnedPods(e *env, node string) []corev1.Pod {
	var out []corev1.Pod
	for _, p := range e.pods() {
		if p.Annotations[v1.AnnotationPinnedNode] == node {
			out = append(out, p)
		}
	}
	return out
}

func TestBlipWaitsForVMOnDataNode(t *testing.T) {
	e, home, _ := localSetup(t, 1, 0)
	e.newBlip("b", withRoot("data"))

	res := e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if loc := b.Status.Locality; loc == nil || loc.Node != home || loc.Since == nil || loc.Fallback {
		t.Fatalf("locality %+v", loc)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > localWait {
		t.Fatalf("requeue after %v", res.RequeueAfter)
	}
	if w := e.getState("data").Status.Writer; w != nil {
		t.Fatalf("writer held while waiting: %+v", w)
	}

	e.run(e.pool, ns, "default")
	pinned := pinnedPods(e, home)
	if len(pinned) != 1 {
		t.Fatalf("pinned pods %+v", e.pods())
	}
	term := pinned[0].Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0]
	if term.Key != "metadata.name" || term.Operator != corev1.NodeSelectorOpIn || len(term.Values) != 1 || term.Values[0] != home {
		t.Fatalf("pinned pod affinity %+v", term)
	}
	// A second pool pass does not pin another pod for the same Blip.
	e.run(e.pool, ns, "default")
	if n := len(pinnedPods(e, home)); n != 1 {
		t.Fatalf("%d pinned pods", n)
	}

	e.warmOn(home)
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != home || b.Status.Pod != pinned[0].Name {
		t.Fatalf("started on %s/%s, want %s/%s", b.Status.Node, b.Status.Pod, home, pinned[0].Name)
	}

	// The pool is back to its warm count; the remote VM was not touched.
	e.run(e.pool, ns, "default")
	if vacant := len(e.pods()) - 1; vacant != 1 {
		t.Fatalf("%d vacant pods", vacant)
	}
}

func TestBlipClaimsLocalVMAtOnce(t *testing.T) {
	e, home, away := localSetup(t, 2, 0)
	e.warmOn(home)
	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != home {
		t.Fatalf("started on %s, not %s (away %s)", b.Status.Node, home, away)
	}
}

func TestLocalWaitTimesOut(t *testing.T) {
	e, _, away := localSetup(t, 1, 0)
	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	e.run(e.pool, ns, "default")

	e.now = e.now.Add(localWait)
	e.heartbeat()
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != away || !b.Status.Locality.Fallback {
		t.Fatalf("node %s locality %+v", b.Status.Node, b.Status.Locality)
	}
}

func TestLocalWaitEndsWhenPinnedPodUnschedulable(t *testing.T) {
	e, home, away := localSetup(t, 1, 0)
	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	e.run(e.pool, ns, "default")
	pinned := pinnedPods(e, home)
	if len(pinned) != 1 {
		t.Fatalf("pinned pods %+v", e.pods())
	}
	p := &pinned[0]
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable}}
	e.must(e.c.Status().Update(e.ctx, p))

	if reqs := e.blip.podBlips(e.ctx, p); len(reqs) != 1 || reqs[0].Name != "b" {
		t.Fatalf("unschedulable pinned pod enqueued %v", reqs)
	}
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != away || !b.Status.Locality.Fallback {
		t.Fatalf("node %s locality %+v", b.Status.Node, b.Status.Locality)
	}

	// Nobody waits for the stuck pod any more; the pool replaces it.
	e.run(e.pool, ns, "default")
	if !e.podGone(p.Name) {
		t.Fatal("unschedulable pinned pod kept")
	}
	if n := len(e.pods()); n != 2 {
		t.Fatalf("%d pods, want the claimed one and a new warm one", n)
	}
}

func TestLocalWaitSkippedAtMaxCount(t *testing.T) {
	e, _, away := localSetup(t, 1, 1)
	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != away || !b.Status.Locality.Fallback {
		t.Fatalf("node %s locality %+v", b.Status.Node, b.Status.Locality)
	}
}

func TestLocalWaitSkippedWhenDataNodeDrains(t *testing.T) {
	e, home, away := localSetup(t, 1, 0)
	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	e.setDrain(home)
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != away || !b.Status.Locality.Fallback {
		t.Fatalf("node %s locality %+v", b.Status.Node, b.Status.Locality)
	}
}

// A fork's copy is produced on the source node; the pool boots a VM there
// while the copy is still in progress.
func TestPoolPreBootsForPendingCopy(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.newState("cp", func(st *v1.BlipState) { st.Spec.Replicas = 1 })
	e.run(e.state, ns, "cp")
	p := e.getState("cp").Status.Pending
	if p == nil || len(p.Replicas) != 1 {
		t.Fatalf("pending %+v", p)
	}
	node := p.Replicas[0]

	e.newBlip("b", withRoot("cp"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonStateNotReady)
	if loc := b.Status.Locality; loc == nil || loc.Node != node || loc.Since != nil {
		t.Fatalf("locality %+v", loc)
	}
	e.run(e.pool, ns, "default")
	if pods := e.pods(); len(pods) != 1 || pods[0].Annotations[v1.AnnotationPinnedNode] != node {
		t.Fatalf("pods %+v", pods)
	}

	e.hold("cp", p.CommitID, node)
	e.run(e.state, ns, "cp")
	e.warmOn(node)
	e.run(e.blip, ns, "b")
	if b = e.getBlip("b"); b.Status.Node != node {
		t.Fatalf("started on %q, want %q", b.Status.Node, node)
	}
}

// A fork's Blip is created just before its state, so locality is briefly
// unknown. Booting a generic VM then would double the pool when the pinned
// one appears moments later.
func TestPoolDoesNotBootBeforeLocalityIsKnown(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("b", withRoot("data"))
	e.setBlipStatus("b", func(b *v1.Blip) { b.Status.Phase = v1.BlipPending })

	res := e.run(e.pool, ns, "default")
	if pods := e.pods(); len(pods) != 0 {
		t.Fatalf("booted %d pods before locality was known", len(pods))
	}
	if res.RequeueAfter <= 0 {
		t.Fatal("pool did not requeue while waiting for locality")
	}

	e.setBlipStatus("b", func(b *v1.Blip) {
		b.Status.Locality = &v1.Locality{Node: "n1"}
	})
	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 1 || pods[0].Annotations[v1.AnnotationPinnedNode] != "n1" {
		t.Fatalf("pods %+v, want one pinned to n1", pods)
	}
}

// A durable Blip whose states are ready but which has no usable home node
// must fall back instead of waiting forever with no locality set.
func TestBlipFallsBackWhenNoUsableHome(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("data", "n1")
	e.newPool("default", 0, 0)
	p := e.getPool("default")
	p.Spec.NodeSelector = map[string]string{"blip.dev/node-pool": "other"}
	e.must(e.c.Update(e.ctx, p))

	e.newBlip("b", withRoot("data"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if b.Status.Locality == nil || !b.Status.Locality.Fallback {
		t.Fatalf("locality %+v, want fallback", b.Status.Locality)
	}
}

func TestPoolKeepsPinnedPodsOverExcess(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	pool := &v1.BlipPool{}
	e.must(e.c.Get(e.ctx, req(ns, "default").NamespacedName, pool))
	mk := func(name, node, pinned string, age time.Duration) {
		p := e.pool.podFor(pool, name)
		p.Spec.NodeName = node
		if pinned != "" {
			p.Annotations[v1.AnnotationPinnedNode] = pinned
		}
		p.CreationTimestamp = metav1.NewTime(e.now.Add(-age))
		e.create(p)
	}
	mk("generic", "n2", "", 2*time.Minute)
	mk("pinned", "", "n1", time.Minute)
	e.newBlip("b", e.withImage("reg/img:v1"))
	b := e.getBlip("b")
	b.Status.Phase = v1.BlipPending
	b.Status.Locality = &v1.Locality{Node: "n1"}
	e.must(e.c.Status().Update(e.ctx, b))

	e.run(e.pool, ns, "default")
	if e.podGone("pinned") || !e.podGone("generic") {
		t.Fatalf("pods %+v", e.pods())
	}
}

func TestWarmPodsAvoidOthersPinnedPods(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	pool := &v1.BlipPool{}
	e.must(e.c.Get(e.ctx, req(ns, "default").NamespacedName, pool))
	for name, node := range map[string]string{"a-pinned": "n1", "b-plain": "n2"} {
		p := e.pool.podFor(pool, name)
		p.Spec.NodeName = node
		p.Labels[v1.LabelWarm] = "true"
		if name == "a-pinned" {
			p.Annotations[v1.AnnotationPinnedNode] = node
		}
		e.create(p)
		p.Status.Phase = corev1.PodRunning
		e.must(e.c.Status().Update(e.ctx, p))
	}
	e.newBlip("b", e.withImage("reg/img:v1"))
	if pods := e.warmPods("b", nil); len(pods) != 2 || pods[0].Name != "b-plain" {
		t.Fatalf("warm pods %+v", pods)
	}
}
