// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// failedPendingState is the status shape a state controller leaves behind
// when an initial version is still retrying: phase=Failed surfaces the last
// error, but status.pending stays set so the commit can still land
// (state.pending, workspace.CheckSource).
func failedPendingState(name, commit, msg string, nodes ...string) *v1.BlipState {
	return &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec:       v1.BlipStateSpec{Replicas: 1},
		Status: v1.BlipStateStatus{
			Phase:   v1.StateFailed,
			Message: msg,
			Pending: &v1.PendingCommit{
				CommitID: commit, Generation: 1, SourceNode: nodes[0], Replicas: nodes,
			},
		},
	}
}

// TestPendingBlipWaitsForFailedPendingRoot: a pending Blip must not fail on a
// root whose initial commit is still retrying. The same state can commit a
// moment later, and CheckSource/initialize already wait for exactly this
// shape.
func TestPendingBlipWaitsForFailedPendingRoot(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	const commit = "6236236236236236"
	e.create(failedPendingState("src", commit, "initial version failed: fetch: device busy", "n1"))
	e.newBlip("job", withRoot("src"))

	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	if b.Status.Phase != v1.BlipPending || b.Status.Reason != ReasonStateNotReady {
		t.Fatalf("pending Blip did not wait for failed-but-pending root: phase=%s reason=%s msg=%q",
			b.Status.Phase, b.Status.Reason, b.Status.Message)
	}
	if !strings.Contains(b.Status.Message, "pending commit") {
		t.Fatalf("wait status does not explain the retrying commit: %q", b.Status.Message)
	}

	// The retried commit lands; the Blip may now start.
	e.hold("src", commit, "n1")
	e.run(e.state, ns, "src")
	if st := e.getState("src"); st.Status.Committed == nil || st.Status.Committed.ID != commit {
		t.Fatalf("state did not commit: %+v", st.Status)
	}
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	if b.Status.Phase == v1.BlipFailed {
		t.Fatalf("a recovered root still failed the Blip: %s", b.Status.Message)
	}
	if b.Status.Phase != v1.BlipPending || b.Status.Reason != ReasonWaitingForVM {
		t.Fatalf("Blip did not proceed after the root committed: phase=%s reason=%s", b.Status.Phase, b.Status.Reason)
	}
}

// TestPendingBlipWaitsForFailedPendingMount covers the same shape as a
// writable mount.
func TestPendingBlipWaitsForFailedPendingMount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.readyState("home", "n1")
	const commit = "6236236236236237"
	e.create(failedPendingState("data", commit, "initial version failed: fetch: device busy", "n1"))
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	if b.Status.Phase != v1.BlipPending || b.Status.Reason != ReasonStateNotReady {
		t.Fatalf("pending Blip did not wait for failed-but-pending mount: phase=%s reason=%s msg=%q",
			b.Status.Phase, b.Status.Reason, b.Status.Message)
	}

	e.hold("data", commit, "n1")
	e.run(e.state, ns, "data")
	if st := e.getState("data"); st.Status.Committed == nil || st.Status.Committed.ID != commit {
		t.Fatalf("mount state did not commit: %+v", st.Status)
	}
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	if b.Status.Phase == v1.BlipFailed {
		t.Fatalf("a recovered mount still failed the Blip: %s", b.Status.Message)
	}
}

// TestPendingBlipFailsOnTerminalFailedRoot: a Failed state with no pending
// commit cannot recover, so the Blip must still fail immediately.
func TestPendingBlipFailsOnTerminalFailedRoot(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	st := failedPendingState("src", "6236236236236238", "initial version failed: image too large", "n1")
	st.Status.Pending = nil
	e.create(st)
	e.newBlip("job", withRoot("src"))

	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	if b.Status.Phase != v1.BlipFailed || b.Status.Reason != ReasonStateFailed {
		t.Fatalf("terminal failed root did not fail the Blip: phase=%s reason=%s msg=%q",
			b.Status.Phase, b.Status.Reason, b.Status.Message)
	}
	if !strings.Contains(b.Status.Message, "image too large") {
		t.Fatalf("failure does not surface the state error: %q", b.Status.Message)
	}
}

// TestPendingBlipFailsOnTerminalFailedMount: the same terminal rule applies
// to a mount.
func TestPendingBlipFailsOnTerminalFailedMount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.readyState("home", "n1")
	st := failedPendingState("data", "6236236236236239", "initial version failed: image too large", "n1")
	st.Status.Pending = nil
	e.create(st)
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	if b.Status.Phase != v1.BlipFailed || b.Status.Reason != ReasonStateFailed {
		t.Fatalf("terminal failed mount did not fail the Blip: phase=%s reason=%s msg=%q",
			b.Status.Phase, b.Status.Reason, b.Status.Message)
	}
}
