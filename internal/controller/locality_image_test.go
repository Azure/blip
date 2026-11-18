package controller

import (
	"slices"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// imageOnNode makes the image state "img" ready on the only node its selector
// matches, leaving every other eligible node without a placement.
func imageOnNode(e *env, node string) {
	e.t.Helper()
	e.label("zone", "a", node)
	e.newState("img", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 0
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "img")
	p := e.getState("img").Status.Pending
	if p == nil || !slices.Equal(p.Replicas, []string{node}) {
		e.t.Fatalf("pending %+v, want the image on %s", p, node)
	}
	e.hold("img", p.CommitID, node)
	e.run(e.state, ns, "img")
	if st := e.getState("img"); st.Status.Phase != v1.StateReady {
		e.t.Fatalf("state %+v, want ready", st.Status)
	}
}

// An image state is held by every eligible node even when its nodeSelector
// keeps it off the others. A Blip with only image states therefore has no
// home node and must claim the warm VM on another node at once instead of
// waiting out localWait for a VM the pool deliberately will not pin.
func TestImageStateClaimsAnyWarmVMWithoutWaiting(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n2")
	imageOnNode(e, "n1")

	e.newBlip("b", withRoot("img"))
	res := e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != "n2" {
		t.Fatalf("started on %q, want the warm VM on n2", b.Status.Node)
	}
	if b.Status.Locality != nil {
		t.Fatalf("locality %+v, want none for replicated data", b.Status.Locality)
	}
	if res.RequeueAfter > 0 && res.RequeueAfter <= localWait {
		t.Fatalf("requeue after %v, want an immediate claim", res.RequeueAfter)
	}
}

// A copied state lives on one node, so its Blip still records locality and
// waits for a VM there; the image-state shortcut must not pin generic data.
func TestCopiedStateStillWaitsForLocalVM(t *testing.T) {
	e, home, away := localSetup(t, 1, 0)
	e.newBlip("b", withRoot("data"))

	res := e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if loc := b.Status.Locality; loc == nil || loc.Node != home || loc.Fallback {
		t.Fatalf("locality %+v, want %s", loc, home)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > localWait {
		t.Fatalf("requeue after %v, want to wait for a VM on %s", res.RequeueAfter, home)
	}
	// The warm VM on the other node is not claimed while the local wait runs.
	if b.Status.Pod != "" || b.Status.Node != "" {
		t.Fatalf("claimed %s/%s away from the data on %s", b.Status.Node, b.Status.Pod, away)
	}
}

// With no locality, a Blip whose durable data is all image states is demand
// for a generic VM, not a fork waiting for its data's node. The pool must
// boot one instead of deferring forever.
func TestPoolBootsVMForReplicatedBlipWithoutLocality(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.newState("img", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1" })
	e.newBlip("b", withRoot("img"))

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one generic VM for the replicated Blip", len(pods))
	}
	if pinned := pods[0].Annotations[AnnotationPinnedNode]; pinned != "" {
		t.Fatalf("VM pinned to %q, want an unpinned generic VM", pinned)
	}
}
