package controller

import (
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestRemovedNeverAttachedWritableMountIsDropped covers C3: changing or
// removing a writable mount before the node ever observed its disk must drop
// the entry and release the writer instead of waiting for a seal that cannot
// happen.
func TestRemovedNeverAttachedWritableMountIsDropped(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	git := e.startBlip("git", "n1", withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateBlip("git", func(b *v1.Blip) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	if m == nil || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("writable mount %+v", m)
	}
	oldAttachment := m.AttachmentID
	if w := e.getState("data").Status.Writer; w == nil || w.AttachmentID != oldAttachment {
		t.Fatalf("writer %+v", w)
	}

	// The user changes the path before the node attaches the disk.
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Mounts[0].Path = "/other" })
	for range 3 {
		e.run(e.blip, ns, "git")
	}
	b := e.getBlip("git")
	m = mountOf(b, "data")
	if m == nil || m.Path != "/other" || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("mount at the new path not created: %+v", m)
	}
	if m.AttachmentID == oldAttachment {
		t.Fatal("stale never-attached attachment was reused")
	}
	w := e.getState("data").Status.Writer
	if w != nil && w.AttachmentID == oldAttachment {
		t.Fatalf("never-attached writable mount still holds writer %s", oldAttachment)
	}
	if w == nil || w.AttachmentID != m.AttachmentID {
		t.Fatalf("new writable mount did not acquire the writer: %+v", w)
	}

	// The new mount works and stops cleanly: the dropped entry must not
	// surface a save failure for an attachment the node never sealed.
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m.Phase != v1.MountMounted {
		t.Fatalf("new mount did not attach: %+v", m)
	}
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSaving, ReasonStopped)
	e.saveWriter("data", "c3c3c3c3c3c3c3c3")
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSucceeded, ReasonStopped)
}

// TestRemovedAttachingWritableMountIsDropped covers the same removal after
// the node reported an attaching disk that disappeared before Detached.
func TestRemovedAttachingWritableMountIsDropped(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	git := e.startBlip("git", "n1", withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateBlip("git", func(b *v1.Blip) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	if m == nil || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("writable mount %+v", m)
	}
	oldAttachment := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: oldAttachment, State: "data", Phase: podapi.DiskAttaching},
	}})
	e.run(e.blip, ns, "git")

	// The path changes while the disk is still attaching; the node then
	// drops the entry before it ever reports Detached.
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Mounts[0].Path = "/other" })
	e.run(e.blip, ns, "git")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning})
	for range 3 {
		e.run(e.blip, ns, "git")
	}
	b := e.getBlip("git")
	m = mountOf(b, "data")
	if m == nil || m.Path != "/other" || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("mount at the new path not created: %+v", m)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == oldAttachment {
		t.Fatalf("never-attached writable mount still holds writer %s", oldAttachment)
	}
}
