// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestStopNeverAttachedWritableMountIsDropped covers w3-11: stopping while a
// hot-added writable mount is still Pending with no observed disk must drop
// the mount and release its writer instead of sealing a filesystem the guest
// never mounted.
func TestStopNeverAttachedWritableMountIsDropped(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	if m == nil || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("writable mount %+v", m)
	}
	attachment := m.AttachmentID
	if w := e.getState("data").Status.Writer; w == nil || w.AttachmentID != attachment {
		t.Fatalf("writer %+v", w)
	}
	generation := e.getState("data").Status.Committed.Generation

	// The VM is fenced before the node ever reports the disk.
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "git")

	b := e.getBlip("git")
	expectPhase(t, b, v1.BlipSaving, ReasonStopped)
	if m = mountOf(b, "data"); m != nil {
		t.Fatalf("never-attached writable mount was kept for saving: %+v", m)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == attachment {
		t.Fatalf("never-attached writable mount still holds writer %+v", w)
	}
	if st := e.getState("data"); st.Status.Pending != nil || len(st.Status.Seals) != 0 || st.Status.Committed.Generation != generation {
		t.Fatalf("never-attached mount was sealed: %+v", st.Status)
	}

	// Only the root has anything to save.
	e.saveWriter(git.Spec.State, newID())
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSucceeded, ReasonStopped)
	if st := e.getState("data"); st.Status.Committed.Generation != generation {
		t.Fatalf("never-attached mount committed a version: %+v", st.Status)
	}
}

// TestStopAttachingWritableMountIsDropped covers the same stop after the node
// reported an attaching disk that never reached Mounted.
func TestStopAttachingWritableMountIsDropped(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	if m == nil || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("writable mount %+v", m)
	}
	attachment := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: attachment, State: "data", Phase: podapi.DiskAttaching},
	}})
	e.run(e.blip, ns, "git")
	generation := e.getState("data").Status.Committed.Generation

	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "git")

	b := e.getBlip("git")
	expectPhase(t, b, v1.BlipSaving, ReasonStopped)
	if m = mountOf(b, "data"); m != nil {
		t.Fatalf("never-attached writable mount was kept for saving: %+v", m)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == attachment {
		t.Fatalf("never-attached writable mount still holds writer %+v", w)
	}
	if st := e.getState("data"); st.Status.Pending != nil || len(st.Status.Seals) != 0 || st.Status.Committed.Generation != generation {
		t.Fatalf("never-attached mount was sealed: %+v", st.Status)
	}

	e.saveWriter(git.Spec.State, newID())
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSucceeded, ReasonStopped)
	if st := e.getState("data"); st.Status.Committed.Generation != generation {
		t.Fatalf("never-attached mount committed a version: %+v", st.Status)
	}
}

// TestStopMountedWritableMountIsSaved guards the never-attached rule: a mount
// the node actually mounted must still be sealed on stop.
func TestStopMountedWritableMountIsSaved(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	if m == nil || !m.Writable {
		t.Fatalf("writable mount %+v", m)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m.Phase != v1.MountMounted {
		t.Fatalf("mount did not attach: %+v", m)
	}

	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "git")
	b := e.getBlip("git")
	expectPhase(t, b, v1.BlipSaving, ReasonStopped)
	if m = mountOf(b, "data"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("attached writable mount was not kept for saving: %+v", m)
	}
	e.saveWriter("data", "c4c4c4c4c4c4c4c4")
	e.saveWriter(git.Spec.State, newID())
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSucceeded, ReasonStopped)
}
