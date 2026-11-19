package controller

import (
	"testing"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// claimedButWarm claims a warm VM for b without letting the guest accept the
// claim, leaving the Blip Pending in the preparing phase.
func (e *env) claimedButWarm(name string) *v1.Blip {
	e.t.Helper()
	e.run(e.blip, ns, name)      // record locality
	e.run(e.pool, ns, "default") // boot the VM this Blip demands
	e.warmOn("n1")
	for _, p := range e.pods() {
		if isVacant(&p) {
			e.observe(p.Name, podapi.Observed{Phase: podapi.PhaseWarm})
		}
	}
	e.run(e.blip, ns, name)
	b := e.getBlip(name)
	expectPhase(e.t, b, v1.BlipPending, ReasonStarting)
	return b
}

// TestLostClaimClearsPodAndStartBudget covers a claimed VM pod that is
// force-deleted before its guest reports a claim. The Blip must forget the
// dead pod and give a replacement VM its own start window instead of
// inheriting the dead claim's expired startTime.
func TestLostClaimClearsPodAndStartBudget(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("b", e.withImage("reg/img:v1"))

	b := e.claimedButWarm("b")
	dead := b.Status.Pod
	started := b.Status.StartTime.Time
	e.must(e.c.Delete(e.ctx, e.getPod(dead)))

	// The next reconcile happens after the dead claim's start window.
	e.now = started.Add(startTimeout + time.Minute)
	e.run(e.blip, ns, "b")

	b = e.getBlip("b")
	if b.Status.Pod != "" || b.Status.PodUID != "" || b.Status.Node != "" {
		t.Fatalf("kept a deleted claim: pod=%q uid=%q node=%q", b.Status.Pod, b.Status.PodUID, b.Status.Node)
	}
	if b.Status.StartTime != nil {
		t.Fatalf("kept the dead claim's start time %v", b.Status.StartTime)
	}
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)

	// A replacement VM starts with a fresh window.
	e.heartbeat()
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	for _, p := range e.pods() {
		if p.Name != dead && isVacant(&p) {
			e.observe(p.Name, podapi.Observed{Phase: podapi.PhaseWarm})
		}
	}
	e.run(e.blip, ns, "b")

	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonStarting)
	if b.Status.Pod == "" || b.Status.Pod == dead {
		t.Fatalf("replacement pod = %q, want a new pod", b.Status.Pod)
	}
	if b.Status.StartTime == nil || !b.Status.StartTime.Time.Equal(e.now) {
		t.Fatalf("replacement start time = %v, want %v", b.Status.StartTime, e.now)
	}
	fresh := b.Status.StartTime.Time

	// The replacement keeps its start time while the guest prepares it.
	e.heartbeat()
	e.now = e.now.Add(startTimeout - time.Minute)
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonStarting)
	if !b.Status.StartTime.Time.Equal(fresh) {
		t.Fatalf("start time moved while the same pod prepared: %v", b.Status.StartTime)
	}
}

// TestLostClaimForgottenWhenPodTerminating covers a graceful pod deletion
// before the guest accepts the claim. The pod stays listed with a
// DeletionTimestamp for its termination grace period; that must not be read as
// a started guest. The Blip must forget the claim and wait for a replacement
// instead of running and later failing with no working volume.
func TestLostClaimForgottenWhenPodTerminating(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("b", e.withImage("reg/img:v1"))

	b := e.claimedButWarm("b")
	dead := b.Status.Pod
	pod := e.getPod(dead)
	pod.Finalizers = []string{"lost-claim.test/hold"}
	e.must(e.c.Update(e.ctx, pod))
	e.must(e.c.Delete(e.ctx, pod))

	pod = e.getPod(dead)
	if pod.DeletionTimestamp == nil {
		t.Fatal("pod is not terminating")
	}
	e.run(e.blip, ns, "b")

	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if b.Status.Pod != "" || b.Status.PodUID != "" || b.Status.Node != "" || b.Status.StartTime != nil {
		t.Fatalf("kept a terminating pre-start claim: pod=%q uid=%q node=%q start=%v",
			b.Status.Pod, b.Status.PodUID, b.Status.Node, b.Status.StartTime)
	}

	// Once the pod is gone a replacement VM is claimed with a fresh window.
	pod = e.getPod(dead)
	pod.Finalizers = nil
	e.must(e.c.Update(e.ctx, pod))
	if !e.podGone(dead) {
		e.must(e.c.Delete(e.ctx, pod))
	}
	if !e.podGone(dead) {
		t.Fatal("pod did not vanish")
	}
	// The pool may still count the vanished pod as an in-flight creation; wait
	// out that expectation before it can boot the replacement.
	e.now = e.now.Add(expectTimeout + time.Second)
	e.heartbeat()
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	for _, p := range e.pods() {
		if p.Name != dead && isVacant(&p) {
			e.observe(p.Name, podapi.Observed{Phase: podapi.PhaseWarm})
		}
	}
	e.run(e.blip, ns, "b")

	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonStarting)
	if b.Status.Pod == "" || b.Status.Pod == dead {
		t.Fatalf("replacement pod = %q, want a new pod", b.Status.Pod)
	}
}

// TestRunningPodLossStillReportsPodLost makes sure forgetting a lost claim only
// covers pods that never started: a pod lost after the guest claimed it still
// stops the Blip with PodLost.
func TestRunningPodLossStillReportsPodLost(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))
	state, dead := b.Spec.State, b.Status.Pod
	e.must(e.c.Delete(e.ctx, e.getPod(dead)))

	e.run(e.blip, ns, "b")
	e.saveWriter(state, newID())
	for range 3 {
		e.run(e.blip, ns, "b")
	}
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonPodLost)
}
