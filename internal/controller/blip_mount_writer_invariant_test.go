// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// mountedWritable sets up a running Blip with a writable mount attached as
// attachment, returning the env, pod name, and attachment ID.
func mountedWritable(t *testing.T) (*env, string, string) {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	e.startBlip("b", "n1", withRoot("home"), e.withMount("data", "/data", true))
	pod := e.getBlip("b").Status.Pod
	m := mountOf(e.getBlip("b"), "data")
	if m == nil {
		t.Fatalf("setup mount missing")
	}
	attachment := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: "claim", Mounts: []podapi.DiskStatus{
		{ID: attachment, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "b")
	m = mountOf(e.getBlip("b"), "data")
	if m == nil || !m.Writable || m.Phase != v1.MountMounted {
		t.Fatalf("setup mount not mounted: %+v", m)
	}
	return e, pod, attachment
}

// TestMountedWritableMountRestoresMissingWriter covers the w8-07 data loss:
// a concurrent replacement left a mounted writable attachment while the
// state's writer was nil. The next running reconcile must restore the writer
// to exactly that attachment so the node seals it and the stop commits the
// guest's writes.
func TestMountedWritableMountRestoresMissingWriter(t *testing.T) {
	e, pod, attachment := mountedWritable(t)

	// Reproduce the observed divergence: the mount says mounted/writable but
	// the state has no writer, so a stop would never seal this attachment.
	st := e.getState("data")
	st.Status.Writer = nil
	e.must(e.c.Status().Update(e.ctx, st))

	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	m := mountOf(b, "data")
	if m == nil || m.Phase != v1.MountMounted || m.AttachmentID != attachment {
		t.Fatalf("mount changed while repairing its writer: %+v", m)
	}
	st = e.getState("data")
	w := st.Status.Writer
	if w == nil || w.AttachmentID != attachment {
		t.Fatalf("writer not restored to mounted attachment: %+v (mount %s)", w, attachment)
	}
	if w.BlipUID != string(b.UID) || w.PodName != pod || w.PodUID != b.Status.PodUID || w.Node != b.Status.Node {
		t.Fatalf("restored writer does not name this Blip and pod: %+v", w)
	}
	if w.BaseCommit != st.Status.Committed.ID {
		t.Fatalf("restored writer base %q, want committed %q", w.BaseCommit, st.Status.Committed.ID)
	}

	// A stop after the repair seals the restored attachment and commits it.
	before := st.Status.Committed.Generation
	e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, ReasonStopped)

	const commit = "c1c1c1c1c1c1c1c1"
	e.saveWriter("data", commit)
	e.saveWriter("home", "c2c2c2c2c2c2c2c2")
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if strings.Contains(b.Status.Message, "no seal result") {
		t.Fatalf("save failed: %q", b.Status.Message)
	}
	st = e.getState("data")
	if st.Status.Committed.ID != commit || st.Status.Committed.Generation <= before {
		t.Fatalf("mounted attachment was not committed: %+v", st.Status.Committed)
	}
}

// TestMountedWritableMountDoesNotStealOtherWriter asserts that a mounted
// writable disk whose writer is held by another Blip/pod stops the Blip with
// a clear SaveFailed reason instead of taking over the disk and accepting
// writes that it could never seal.
func TestMountedWritableMountDoesNotStealOtherWriter(t *testing.T) {
	e, pod, attachment := mountedWritable(t)

	st := e.getState("data")
	st.Status.Writer = &v1.Writer{
		AttachmentID: "ffffffffffffffff",
		BlipName:     "other",
		BlipUID:      "uid-other",
		PodName:      "other-pod",
		PodUID:       "uid-other-pod",
		Node:         "n1",
		BaseCommit:   st.Status.Committed.ID,
	}
	e.must(e.c.Status().Update(e.ctx, st))

	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	if !b.Spec.Stop {
		t.Fatalf("Blip kept accepting writes on a mount it does not own")
	}
	if b.Status.Reason != ReasonSaveFailed || !strings.Contains(b.Status.Message, "lost its writer") {
		t.Fatalf("stop reason %q message %q, want %q about the lost writer", b.Status.Reason, b.Status.Message, ReasonSaveFailed)
	}
	w := e.getState("data").Status.Writer
	if w == nil || w.AttachmentID != "ffffffffffffffff" || w.BlipUID != "uid-other" {
		t.Fatalf("writer stolen from its owner: %+v", w)
	}
	if m := mountOf(b, "data"); m == nil || m.AttachmentID != attachment || m.Phase != v1.MountMounted {
		t.Fatalf("mount status changed while failing: %+v", m)
	}

	// The command is stopped and the save cannot succeed for the stolen
	// attachment, so the Blip fails instead of reporting success.
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, ReasonSaveFailed)
	e.saveWriter("home", "c3c3c3c3c3c3c3c3")
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonSaveFailed)
}
