package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// dynamicPendingMount starts a running Blip and adds a writable mount at
// runtime, returning the Pending status entry and its attachment ID. It is
// not part of the VM claim (InClaim false), so the guest may never have
// attached it.
func dynamicPendingMount(t *testing.T) (*env, *v1.Blip, *v1.MountStatus, string) {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1", "n2")
	e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	b := e.getBlip("git")
	m := mountOf(b, "data")
	if m == nil || m.Phase != v1.MountPending || !m.Writable || m.InClaim {
		t.Fatalf("setup: want a pending, non-claim writable mount, got %+v", m)
	}
	return e, b, m, m.AttachmentID
}

// TestRemovedNeverAttachedWritableMountDeletingState covers w6-09 F1: a
// dynamic writable mount is still Pending (never observed attached, not in
// the VM claim) when its source state is deleted and the CLI rolls the desired
// entry back. The pre-acquired writer is enough for the deleting-state check
// to force-fail the whole execution with SaveFailed even though nothing was
// ever mounted and the topology was restored. The rollback must instead
// release the writer and drop the entry like any other never-attached mount.
func TestRemovedNeverAttachedWritableMountDeletingState(t *testing.T) {
	e, _, _, oldAttachment := dynamicPendingMount(t)
	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "git")

	b := e.getBlip("git")
	if b.Status.Phase == v1.BlipFailed && b.Status.Reason == ReasonSaveFailed {
		t.Errorf("never-attached rolled-back mount failed the execution: phase=%s reason=%s message=%q mount=%+v",
			b.Status.Phase, b.Status.Reason, b.Status.Message, mountOf(b, "data"))
	}
	if m := mountOf(b, "data"); m != nil {
		t.Errorf("never-attached rolled-back mount still reported: %+v", m)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == oldAttachment {
		t.Errorf("never-attached writable mount still holds writer %s", oldAttachment)
	}
}

// TestRemovedNeverAttachedWritableMountRollbackControl is the control for
// TestRemovedNeverAttachedWritableMountDeletingState: the identical rollback
// without deleting the source must leave the running command alone. It proves
// the release path itself is correct, so only the deleting-state check can
// turn the rollback into a failed save.
func TestRemovedNeverAttachedWritableMountRollbackControl(t *testing.T) {
	e, _, _, oldAttachment := dynamicPendingMount(t)
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	for range 3 {
		e.run(e.blip, ns, "git")
	}
	b := e.getBlip("git")
	expectPhase(t, b, v1.BlipRunning, "")
	if m := mountOf(b, "data"); m != nil {
		t.Errorf("control: rolled-back never-attached mount still reported: %+v", m)
	}
	if strings.Contains(b.Status.Message, "save was discarded") {
		t.Errorf("control: unexpected discarded save: %q", b.Status.Message)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == oldAttachment {
		t.Errorf("control: never-attached writable mount still holds writer %s", oldAttachment)
	}
}

// TestRemovedNeverAttachedWritableMountIsDropped covers C3: changing or
// removing a writable mount before the node ever observed its disk must drop
// the entry and release the writer instead of waiting for a seal that cannot
// happen.
func TestRemovedNeverAttachedWritableMountIsDropped(t *testing.T) {
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
	oldAttachment := m.AttachmentID
	if w := e.getState("data").Status.Writer; w == nil || w.AttachmentID != oldAttachment {
		t.Fatalf("writer %+v", w)
	}

	// The user changes the path before the node attaches the disk.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Path = "/other" })
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
	e.saveWriter(git.Spec.State, newID())
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSucceeded, ReasonStopped)
}

// TestRemovedRejectedWritableMoveDoesNotFailBlip covers a writable mount
// moved to a path the guest rejects. The CLI restores the old path, so the
// failed entry (which never attached at the new path and never sealed) must
// be dropped instead of being reported as a failed save that kills the
// still-running Blip.
func TestRemovedRejectedWritableMoveDoesNotFailBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1")
	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "data")
	oldAttachment := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: oldAttachment, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")

	// Move the mount; the old disk is unmounted and saved, then the new
	// attachment is refused by the guest at the destination.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Path = "/usr/bin/awk" })
	e.run(e.blip, ns, "git")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: oldAttachment, State: "data", Phase: podapi.DiskDetached},
	}})
	e.run(e.blip, ns, "git")
	e.saveWriter("data", "c4c4c4c4c4c4c4c4")
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "data")
	if m == nil || m.Phase != v1.MountPending || m.Path != "/usr/bin/awk" || m.AttachmentID == oldAttachment {
		t.Fatalf("moved mount %+v", m)
	}
	rejected := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: rejected, State: "data", Phase: podapi.DiskFailed, Message: "/usr/bin/awk is a symlink or not a directory"},
	}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m == nil || m.Phase != v1.MountFailed {
		t.Fatalf("rejected move %+v", m)
	}
	// The rejected attachment never attached, so the node has no volume to
	// seal and releases its writer slot. This is the state the live cluster
	// reported when the CLI rolled the path back.
	e.setWriter("data", nil)

	// The CLI restores the previous path after the guest rejection.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Path = "/data" })
	e.run(e.blip, ns, "git")
	b := e.getBlip("git")
	expectPhase(t, b, v1.BlipRunning, "")
	if m = mountOf(b, "data"); m == nil || m.Path != "/data" || m.Phase != v1.MountPending || m.AttachmentID == rejected {
		t.Fatalf("restored mount %+v", m)
	}
	if w := e.getState("data").Status.Writer; w != nil && w.AttachmentID == rejected {
		t.Fatalf("rejected attachment still holds writer %s", rejected)
	}
}

// TestRemovedAttachingWritableMountIsDropped covers the same removal after
// the node reported an attaching disk that disappeared before Detached.
func TestRemovedAttachingWritableMountIsDropped(t *testing.T) {
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
	oldAttachment := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: oldAttachment, State: "data", Phase: podapi.DiskAttaching},
	}})
	e.run(e.blip, ns, "git")

	// The path changes while the disk is still attaching; the node then
	// drops the entry before it ever reports Detached.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Path = "/other" })
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
