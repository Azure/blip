package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestMountSwitchWritableToReadOnly demotes a writable mount without
// restarting the Blip: unmount, save, then remount the saved version
// read-only at the same path.
func TestMountSwitchWritableToReadOnly(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")
	gen1 := e.getState("repo").Status.Committed.ID

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = []v1.Mount{{State: "repo", Path: "/src", Writable: true}} })
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountMounted || !m.Writable || m.CommitID != gen1 {
		t.Fatalf("writable mount %+v", m)
	}

	// Ask for read-only; the old disk must be unmounted before the save.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = false })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountUnmounting || !m.Switching || !m.Writable {
		t.Fatalf("switch start %+v", m)
	}
	oldAttachment := m.AttachmentID

	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: oldAttachment, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountSaving || !m.Switching {
		t.Fatalf("after detach %+v", m)
	}

	const saved = "c3c3c3c3c3c3c3c3"
	e.seal("repo", "n1", v1.SealResult{AttachmentID: oldAttachment, CommitID: saved})
	e.run(e.state, ns, "repo")
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountPending || m.Writable || m.Switching || m.CommitID != saved || m.AttachmentID == oldAttachment {
		t.Fatalf("demoted mount %+v", m)
	}
	// The new read-only mount is usable before the saved version has
	// replicated; the state still has the old committed version.
	if st := e.getState("repo"); st.Status.Committed.ID != gen1 {
		t.Fatalf("state advanced too early: %+v", st.Status)
	}

	e.hold("repo", saved, "n1")
	e.run(e.state, ns, "repo")
	e.hold("repo", saved, "n2")
	e.run(e.state, ns, "repo")
	if st := e.getState("repo"); st.Status.Committed.ID != saved {
		t.Fatalf("state did not commit saved version: %+v", st.Status)
	}

	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountMounted || m.Writable || m.CommitID != saved {
		t.Fatalf("read-only mount %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("demoted mount still holds writer %+v", w)
	}
}

// TestMountSwitchReadOnlyToWritable promotes a read-only mount, taking the
// writer before the old disk is torn down.
func TestMountSwitchReadOnlyToWritable(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")
	gen1 := e.getState("repo").Status.Committed.ID

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	pod := git.Status.Pod
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountPending || m.Writable {
		t.Fatalf("read-only mount %+v", m)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	oldAttachment := m.AttachmentID

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountUnmounting || !m.Switching || m.Writable {
		t.Fatalf("switch start %+v", m)
	}
	w := e.getState("repo").Status.Writer
	if w == nil || w.AttachmentID == "" || w.BlipName != "git" || w.BaseCommit != gen1 {
		t.Fatalf("writer not acquired before teardown %+v", w)
	}
	writerAttachment := w.AttachmentID

	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: oldAttachment, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountPending || !m.Writable || m.Switching || m.AttachmentID != writerAttachment || m.CommitID != gen1 {
		t.Fatalf("promoted mount %+v", m)
	}

	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: writerAttachment, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountMounted || !m.Writable || m.AttachmentID != writerAttachment {
		t.Fatalf("writable mount %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w == nil || w.PodUID != git.Status.PodUID {
		t.Fatalf("writer pod not recorded %+v", w)
	}
}

// TestMountSwitchCancelDuringDemote still saves a writable mount that was
// already detached, even if the spec asks for writable again.
func TestMountSwitchCancelDuringDemote(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", true))
	pod := git.Status.Pod
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	oldAttachment := m.AttachmentID

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = false })
	e.run(e.blip, ns, "git")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: oldAttachment, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountSaving {
		t.Fatalf("after detach %+v", m)
	}

	// Change the spec back while the detached contents are being saved.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountSaving {
		t.Fatalf("cancel dropped the save %+v", m)
	}

	const saved = "a4a4a4a4a4a4a4a4"
	e.seal("repo", "n1", v1.SealResult{AttachmentID: oldAttachment, CommitID: saved})
	e.run(e.state, ns, "repo")
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Writable || m.CommitID != saved || m.Phase != v1.MountPending {
		t.Fatalf("saved mount was not demoted %+v", m)
	}

	// Once the saved version lands, the writable request resumes.
	e.hold("repo", saved, "n1")
	e.run(e.state, ns, "repo")
	e.hold("repo", saved, "n2")
	e.run(e.state, ns, "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountUnmounting || !m.Switching || m.Writable {
		t.Fatalf("writable request did not resume %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w == nil || w.BaseCommit != saved {
		t.Fatalf("resumed writer %+v", w)
	}
}

// TestMountSwitchPromoteRejectsStaleMount leaves the read-only mount in
// place when the state has moved past the version it mounted.
func TestMountSwitchPromoteRejectsStaleMount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(git.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")

	st := e.getState("repo")
	st.Status.Committed.ID = "ffffffffffffffff"
	e.must(e.c.Status().Update(e.ctx, st))

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountMounted || m.Writable || m.Switching || !strings.Contains(m.Message, "newer version") {
		t.Fatalf("stale promotion %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("stale promotion took writer %+v", w)
	}
}

// TestMountSwitchPromoteWaitsForPending avoids promoting a state whose new
// version is still saving.
func TestMountSwitchPromoteWaitsForPending(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(git.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")

	st := e.getState("repo")
	st.Status.Pending = &v1.PendingCommit{CommitID: "dddddddddddddddd", Generation: 2, SourceNode: "n1", AttachmentID: "x", Replicas: []string{"n1", "n2"}}
	e.must(e.c.Status().Update(e.ctx, st))

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountMounted || m.Writable || m.Switching || !strings.Contains(m.Message, "saving a new version") {
		t.Fatalf("pending promotion %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("pending promotion took writer %+v", w)
	}
}

// TestMountSwitchPromoteWriterBlocked leaves the read-only mount alone when
// another Blip still owns the state.
func TestMountSwitchPromoteWriterBlocked(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(git.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")

	st := e.getState("repo")
	st.Status.Writer = &v1.Writer{AttachmentID: "other", BlipName: "other", BlipUID: "other", BaseCommit: st.Status.Committed.ID, PodName: "p", PodUID: "u", Node: "n2"}
	e.must(e.c.Status().Update(e.ctx, st))

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountMounted || m.Writable || m.Switching || !strings.Contains(m.Message, "in use by blip other") {
		t.Fatalf("blocked promotion %+v", m)
	}

	// Removing the mount must not leave a latched Mounted entry.
	oldAttachment := m.AttachmentID
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m == nil || m.Phase != v1.MountUnmounting || m.Switching {
		t.Fatalf("removed blocked mount %+v", m)
	}
	e.observe(git.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: oldAttachment, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	if m := mountOf(e.getBlip("git"), "repo"); m != nil {
		t.Fatalf("blocked mount was not removed %+v", m)
	}
}

// TestMountSwitchPromoteCancelled returns a writer acquired for a promotion
// that never tore down the read-only mount.
func TestMountSwitchPromoteCancelled(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(git.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	before := e.getState("repo").Status.Committed
	e.run(e.blip, ns, "git")
	if w := e.getState("repo").Status.Writer; w == nil {
		t.Fatal("promotion did not acquire writer")
	}

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = false })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || m.Phase != v1.MountMounted || m.Writable || m.Switching {
		t.Fatalf("cancelled promotion %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("cancelled promotion leaked writer %+v", w)
	}
	// The cancellation must not save: the mount stays read-only at the
	// version it had before the promotion.
	if c := e.getState("repo").Status.Committed; c == nil || c.ID != before.ID || c.Generation != before.Generation {
		t.Fatalf("cancelled promotion advanced the state from %+v to %+v", before, c)
	}
}

// TestMountSwitchRemovedDuringPromote cancels a promotion when the mount is
// removed from the spec and returns the pre-acquired writer.
func TestMountSwitchRemovedDuringPromote(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"), e.withMount("repo", "/src", false))
	pod := git.Status.Pod
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	oldAttachment := mountOf(e.getBlip("git"), "repo").AttachmentID

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	if w := e.getState("repo").Status.Writer; w == nil {
		t.Fatal("promotion did not acquire writer")
	}

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "git")
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("removed mount leaked writer %+v", w)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: oldAttachment, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	if m := mountOf(e.getBlip("git"), "repo"); m != nil {
		t.Fatalf("removed mount still present %+v", m)
	}
}

// TestMountSwitchNewReadOnlyWaitsWhileSaving keeps other Blips on the old
// version until the pending commit lands.
func TestMountSwitchNewReadOnlyWaitsWhileSaving(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")

	e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	e.run(e.blip, ns, "git")

	st := e.getState("repo")
	st.Status.Pending = &v1.PendingCommit{CommitID: "eeeeeeeeeeeeeeee", Generation: 2, SourceNode: "n1", AttachmentID: "x", Replicas: []string{"n1", "n2"}}
	e.must(e.c.Status().Update(e.ctx, st))

	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = []v1.Mount{{State: "repo", Path: "/src"}} })
	e.run(e.blip, ns, "git")
	b := e.getBlip("git")
	if m := mountOf(b, "repo"); m != nil {
		t.Fatalf("mounted while saving: %+v", m)
	}
	if !strings.Contains(b.Status.Message, "saving a new version") {
		t.Fatalf("waiting message %q", b.Status.Message)
	}
}
