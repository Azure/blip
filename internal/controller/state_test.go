package controller

import (
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

func (e *env) setDrain(node string) {
	e.t.Helper()
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, bn))
	bn.Spec.Drain = true
	e.must(e.c.Update(e.ctx, bn))
}

func (e *env) safeToRemove(node string) bool {
	e.t.Helper()
	e.run(e.node, "", node)
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, bn))
	return bn.Status.SafeToRemove
}

func TestStateInitialization(t *testing.T) {
	size20G := resource.MustParse("20Gi")
	tests := []struct {
		name    string
		spec    v1.BlipStateSpec
		size    int64
		nodes   int // pending replicas; default spec.replicas
		message string
		phase   string
	}{
		{name: "empty", spec: v1.BlipStateSpec{Replicas: 2}, size: 10 << 30},
		{name: "image", spec: v1.BlipStateSpec{Image: "reg/img:v1"}, size: 10 << 30, nodes: 2},
		{name: "image size", spec: v1.BlipStateSpec{Image: "reg/img:v1", Size: &size20G}, size: 20 << 30, nodes: 2},
		{name: "missing image", spec: v1.BlipStateSpec{Image: "reg/nope:v1"}, message: "image reg/nope:v1: not found", phase: v1.StateFailed},
		{name: "missing copy source", spec: v1.BlipStateSpec{CopyFrom: "nope", Replicas: 1}, message: `copy source "nope" not found`, phase: v1.StateFailed},
		{name: "no matching nodes", spec: v1.BlipStateSpec{Replicas: 1, NodeSelector: map[string]string{"zone": "x"}}, message: "no healthy node"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1", "n2")
			e.create(&v1.BlipState{ObjectMeta: metadata("s"), Spec: tt.spec})
			e.run(e.state, ns, "s")
			e.run(e.state, ns, "s")
			st := e.getState("s")
			want := v1.StatePending
			if tt.phase != "" {
				want = tt.phase
			}
			if st.Status.Phase != want {
				t.Fatalf("phase %s", st.Status.Phase)
			}
			if tt.message != "" {
				if st.Status.Pending != nil || !strings.Contains(st.Status.Message, tt.message) {
					t.Fatalf("status %+v, want message %q", st.Status, tt.message)
				}
				return
			}
			nodes := int(tt.spec.Replicas)
			if tt.nodes > 0 {
				nodes = tt.nodes
			}
			if p := st.Status.Pending; p == nil || len(p.Replicas) != nodes || st.Status.SizeBytes != tt.size {
				t.Fatalf("status %+v", st.Status)
			}
		})
	}
}

func TestInitialReplicaWaitsForSource(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 2 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	replica := "n1"
	if p.SourceNode == replica {
		replica = "n2"
	}

	// The replica cannot see the commit until the source publishes it.
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = "no healthy holder of commit " + p.CommitID + " (source node " + p.SourceNode + ")"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StatePending || st.Status.Committed != nil {
		t.Fatalf("transient replica error failed the state: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "waiting") {
		t.Fatalf("message %q does not say waiting", st.Status.Message)
	}

	// The source publishes the commit and the replica fetches it.
	e.hold("s", p.CommitID, p.SourceNode)
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = ""
		o.Commits = append(o.Commits, p.CommitID)
	})
	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Phase != v1.StateReady || st.Status.Committed == nil {
		t.Fatalf("state did not become ready: %+v", st.Status)
	}
}

func TestInitialReplicaErrorAfterSourceFailsState(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 2 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	replica := "n1"
	if p.SourceNode == replica {
		replica = "n2"
	}

	// Once the source holds the commit, a replica error is no longer just
	// status lag; it must surface as a failed initialization.
	e.hold("s", p.CommitID, p.SourceNode)
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = "storage: no space left on device"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || !strings.Contains(st.Status.Message, "no space") {
		t.Fatalf("replica error not surfaced: %+v", st.Status)
	}
}

func TestPendingReplicaReplaced(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s")
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	lost := p.Replicas[1]
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: lost}}))
	e.run(e.state, ns, "s")
	p = e.getState("s").Status.Pending
	if slices.Contains(p.Replicas, lost) || len(p.Replicas) != 2 {
		t.Fatalf("replicas %v still contain deleted node %s", p.Replicas, lost)
	}
}

func TestDrainRepair(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	st := e.readyState("s", "n1", "n2")
	id := st.Status.Committed.ID
	drained := st.Status.Placements[0]
	kept := st.Status.Placements[1]
	spare := "n3"

	e.setDrain(drained)
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{drained, kept, spare}) {
		t.Fatalf("placements during repair %v", st.Status.Placements)
	}
	if e.safeToRemove(drained) {
		t.Fatal("draining node safe before replacement holds the commit")
	}
	e.hold("s", id, spare)
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{kept, spare}) {
		t.Fatalf("placements after repair %v", st.Status.Placements)
	}
	if !e.safeToRemove(drained) {
		t.Fatal("drained node not safe to remove")
	}

	// A running VM pod keeps a draining node.
	e.newPool("default", 0, 0)
	b := e.startBlip("b", spare, withImage("reg/img:v1"))
	e.setDrain(spare)
	if e.safeToRemove(spare) {
		t.Fatal("node with a running VM pod is safe to remove")
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	if e.safeToRemove(spare) {
		t.Fatal("safe while still holding a placement without replacement")
	}
}

func TestUnhealthyNodeRepair(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	st := e.readyState("s", "n1", "n2")
	dead := st.Status.Placements[0]

	e.now = e.now.Add(90 * time.Second)
	e.heartbeat(dead)
	res := e.run(e.state, ns, "s")
	if st = e.getState("s"); len(st.Status.Placements) != 2 {
		t.Fatalf("repaired before the unhealthy grace period: %v", st.Status.Placements)
	}
	if res.RequeueAfter == 0 || res.RequeueAfter > repairAfter {
		t.Errorf("requeue after %v", res.RequeueAfter)
	}
	e.now = e.now.Add(time.Minute)
	e.heartbeat(dead)
	e.run(e.state, ns, "s")
	if st = e.getState("s"); !slices.Contains(st.Status.Placements, "n3") {
		t.Fatalf("no replacement: %v", st.Status.Placements)
	}
}

func TestStateDeletionBlockedByBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1")
	b := e.startBlip("b", "n1", withImage("reg/img:v1"), withMount("s", "/s", false))

	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if !strings.Contains(st.Status.Message, "blip b") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked: %+v", st.Status)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "s"}, &v1.BlipState{}); err == nil {
		t.Fatal("state not deleted after the blip finished")
	}
}

func TestWriterNodeDeletedRequiresForceRecover(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1", "n2")
	b := e.startBlip("b", "n1", withRoot("s"))

	e.now = e.now.Add(10 * time.Minute)
	e.heartbeat("n1")
	e.run(e.state, ns, "s")
	if w := e.getState("s").Status.Writer; w == nil {
		t.Fatal("writer released while its node may still run the VM")
	}
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))
	e.must(e.c.Delete(e.ctx, e.getPod(b.Status.Pod)))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Writer == nil {
		t.Fatal("deleted node was treated as proof that the VM stopped")
	}
	if !strings.Contains(st.Status.Message, AnnotationForceRecoverWriter) {
		t.Fatalf("no manual recovery message: %q", st.Status.Message)
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, "")
	if w := e.getState("s").Status.Writer; w == nil {
		t.Fatal("writer released without force recovery")
	}

	// The explicit escape hatch clears the writer and records a failed
	// seal, so the Blip fails instead of reporting a successful save.
	st = e.getState("s")
	if st.Annotations == nil {
		st.Annotations = map[string]string{}
	}
	st.Annotations[AnnotationForceRecoverWriter] = "true"
	e.must(e.c.Update(e.ctx, st))
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Writer != nil {
		t.Fatalf("writer after force recovery: %+v", st.Status.Writer)
	}
	if len(st.Status.Seals) == 0 {
		t.Fatalf("no seal result after force recovery: %+v", st.Status.Seals)
	}
	if _, ok := st.Annotations[AnnotationForceRecoverWriter]; ok {
		t.Error("force-recover annotation was not removed")
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonSaveFailed)
}

func (e *env) label(key, value string, nodes ...string) {
	e.t.Helper()
	for _, n := range nodes {
		k := &corev1.Node{}
		e.must(e.c.Get(e.ctx, types.NamespacedName{Name: n}, k))
		k.Labels[key] = value
		e.must(e.c.Update(e.ctx, k))
	}
}

func TestImageStateOnEveryEligibleNode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3", "n4")
	e.label("zone", "a", "n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 1
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || p.Generation != 1 || !slices.Equal(p.Replicas, []string{"n1", "n2", "n3"}) || p.SourceNode != "n1" {
		t.Fatalf("pending %+v", p)
	}
	e.hold("s", p.CommitID, "n2", "n3")
	e.run(e.state, ns, "s")
	if st := e.getState("s"); st.Status.Committed != nil || !strings.Contains(st.Status.Message, "waiting for n1") {
		t.Fatalf("committed before every eligible node built the image: %+v", st.Status)
	}
	e.hold("s", p.CommitID, "n1")
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Committed == nil || !slices.Equal(st.Status.Placements, []string{"n1", "n2", "n3"}) || st.Status.Message != "" {
		t.Fatalf("commit %+v", st.Status)
	}

	// A new eligible node joins the placements; nothing changes once it holds.
	e.addNodes("n5")
	e.label("zone", "a", "n5")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{"n1", "n2", "n3", "n5"}) || st.Status.Message != "replicating to n5" {
		t.Fatalf("after join %+v", st.Status)
	}
	e.hold("s", p.CommitID, "n5")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	e.run(e.state, ns, "s")
	if again := e.getState("s"); again.ResourceVersion != st.ResourceVersion || st.Status.Message != "" {
		t.Fatalf("status churn: %+v -> %+v", st.Status, again.Status)
	}

	// A drained node leaves the placements and is not added back.
	e.setDrain("n2")
	e.run(e.state, ns, "s")
	e.run(e.state, ns, "s")
	if st = e.getState("s"); !slices.Equal(st.Status.Placements, []string{"n1", "n3", "n5"}) || st.Status.Message != "" {
		t.Fatalf("after drain %+v", st.Status)
	}
}

func TestImageStatePendingDropsFailedNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1"; st.Spec.Replicas = 0 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || p.SourceNode != "n1" || len(p.Replicas) != 3 {
		t.Fatalf("pending %+v", p)
	}
	e.hold("s", p.CommitID, "n3")
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}}))
	e.run(e.state, ns, "s")
	if q := e.getState("s").Status.Pending; q == nil || q.CommitID != p.CommitID || !slices.Equal(q.Replicas, []string{"n1", "n3"}) {
		t.Fatalf("pending after replica loss %+v", q)
	}
	// The source is not special: every node builds generation 1 itself.
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if c := st.Status.Committed; c == nil || c.ID != p.CommitID || !slices.Equal(st.Status.Placements, []string{"n3"}) {
		t.Fatalf("commit after source loss %+v", st.Status)
	}
}
