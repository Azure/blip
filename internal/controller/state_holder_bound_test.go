package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// pendingSave puts a generation-2 sealed save on the state with source n1 and
// replicas n1/n2, then records that only n2 holds the commit.
func pendingSave(t *testing.T, e *env, saved string) {
	t.Helper()
	st := e.readyState("s", "n1", "n2")
	since := metav1.NewTime(e.now)
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n2")
}

// saveFailed reports whether the pending save was resolved into a failed seal
// instead of being committed or left pending.
func saveFailed(t *testing.T, e *env) (*v1.BlipState, bool) {
	t.Helper()
	st := e.getState("s")
	failed := false
	for _, sr := range st.Status.Seals {
		if sr.AttachmentID == "save" && sr.Error != "" {
			failed = true
		}
	}
	return st, failed
}

// TestSaveFailsWhenOnlyHolderIsGone covers a sealed save whose only surviving
// holder is a node removed from the cluster: its Kubernetes Node is deleted
// but its BlipNode CR lingers and still reports the commit. The holder can
// never finish the save, so it must stop counting before it wedges the state
// forever.
func TestSaveFailsWhenOnlyHolderIsGone(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	pendingSave(t, e, "a621621621621621")
	e.removeNode("n1")
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}}))

	e.now = e.now.Add(24 * time.Hour)
	for range 5 {
		e.run(e.state, ns, "s")
	}
	st, failed := saveFailed(t, e)
	if st.Status.Pending != nil || !failed {
		t.Fatalf("save held only by a removed node was not failed: pending=%v seals=%+v committed=%+v message=%q",
			st.Status.Pending, st.Status.Seals, st.Status.Committed, st.Status.Message)
	}
	if st.Status.Committed == nil || st.Status.Committed.Generation != 1 {
		t.Fatalf("failed save changed the committed version: %+v", st.Status.Committed)
	}
}

// TestSaveFailsWhenOnlyHolderNeverHeartbeats covers a holder that keeps its
// Kubernetes Node but stops heartbeating for good. A brief lag is tolerated,
// but a permanently stale holder cannot complete the save.
func TestSaveFailsWhenOnlyHolderNeverHeartbeats(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	pendingSave(t, e, "b621621621621621")
	e.removeNode("n1")

	e.now = e.now.Add(time.Hour)
	for range 5 {
		e.run(e.state, ns, "s")
	}
	st, failed := saveFailed(t, e)
	if st.Status.Pending != nil || !failed {
		t.Fatalf("save held only by a never-heartbeating node was not failed: pending=%v seals=%+v message=%q",
			st.Status.Pending, st.Status.Seals, st.Status.Message)
	}
}

// TestSaveFailsWhenOnlyHolderIsDrainingUnhealthy covers a drained node that was
// powered off before its replicas fetched the commit. Draining alone must not
// fail the save, but draining plus a permanently stale heartbeat must.
func TestSaveFailsWhenOnlyHolderIsDrainingUnhealthy(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	pendingSave(t, e, "c621621621621621")
	e.setDrain("n2")
	e.removeNode("n1")

	e.now = e.now.Add(24 * time.Hour)
	for range 5 {
		e.run(e.state, ns, "s")
	}
	st, failed := saveFailed(t, e)
	if st.Status.Pending != nil || !failed {
		t.Fatalf("save held only by an unhealthy draining node was not failed: pending=%v placements=%v seals=%+v message=%q",
			st.Status.Pending, st.Status.Placements, st.Status.Seals, st.Status.Message)
	}
}

// TestSaveWaitsForHolderStaleWithinBound is the control for the bound above: a
// holder that is stale but still inside repairAfter keeps the save waiting,
// and completes it once it heartbeats again.
func TestSaveWaitsForHolderStaleWithinBound(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	const saved = "d621621621621621"
	pendingSave(t, e, saved)
	e.removeNode("n1")
	e.now = e.now.Add(repairAfter - time.Second)

	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Pending == nil {
		t.Fatalf("holder inside repairAfter was treated as gone: %+v", st.Status)
	}
	if _, failed := saveFailed(t, e); failed {
		t.Fatalf("holder inside repairAfter failed the save: %+v", st.Status.Seals)
	}

	e.heartbeat()
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("holder did not complete the save after recovering: %+v", st.Status)
	}
}
