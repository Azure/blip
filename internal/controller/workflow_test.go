package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestGitWorkflow: create a state, mount it writable in a running sandbox,
// unmount (saves), copy it for workers, and mount their results read-only.
func TestGitWorkflow(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")
	gen1 := e.getState("repo").Status.Committed.ID

	git := e.startBlip("git", "n1", e.withImage("reg/img:v1"))
	pod := git.Status.Pod

	// Mount writable while running.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = []v1.Mount{{State: "repo", Path: "/src", Writable: true}} })
	e.run(e.blip, ns, "git")
	git = e.getBlip("git")
	m := mountOf(git, "repo")
	w := e.getState("repo").Status.Writer
	if m == nil || m.Phase != v1.MountPending || w == nil || w.AttachmentID != m.AttachmentID || w.PodUID != git.Status.PodUID || w.Node != "n1" || m.CommitID != gen1 {
		t.Fatalf("mount %+v writer %+v", m, w)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountMounted {
		t.Fatalf("mount phase %s", m.Phase)
	}

	// Unmount: Unmounting -> Saving (after Detached) -> removed once committed.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m == nil || m.Phase != v1.MountUnmounting {
		t.Fatalf("after unmount request %+v", m)
	}

	// A copy cannot snapshot a writer that is unmounting; it waits.
	e.newState("w1", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo"; st.Spec.Replicas = 1 })
	e.run(e.state, ns, "w1")
	if st := e.getState("w1"); st.Status.Pending != nil || !strings.Contains(st.Status.Message, "writer") {
		t.Fatalf("copy started while source writer is unmounting: %+v", st.Status)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskUnmounting}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountUnmounting {
		t.Fatalf("left Unmounting before detach: %+v", m)
	}
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m.Phase != v1.MountSaving {
		t.Fatalf("after detach %+v", m)
	}
	e.seal("repo", "n1", v1.SealResult{AttachmentID: m.AttachmentID, CommitID: "a2a2a2a2a2a2a2a2"})
	e.hold("repo", "a2a2a2a2a2a2a2a2", "n1")
	e.run(e.state, ns, "repo")
	e.run(e.state, ns, "w1")
	if st := e.getState("w1"); st.Status.Pending != nil || !strings.Contains(st.Status.Message, "saving") {
		t.Fatalf("copy started while source is saving: %+v", st.Status)
	}
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "repo"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("mount left Saving before commit: %+v", m)
	}
	e.hold("repo", "a2a2a2a2a2a2a2a2", "n2")
	e.run(e.state, ns, "repo")
	e.run(e.blip, ns, "git")
	git = e.getBlip("git")
	expectPhase(t, git, v1.BlipRunning, "")
	if len(git.Status.Mounts) != 0 {
		t.Fatalf("mounts after save %+v", git.Status.Mounts)
	}

	// Copy for a worker; it is built from the source's committed version.
	e.run(e.state, ns, "w1")
	w1 := e.getState("w1")
	if c := w1.Status.CopiedFrom; c == nil || c.CommitID != "a2a2a2a2a2a2a2a2" || len(c.Nodes) != 2 || w1.Status.Pending == nil {
		t.Fatalf("copy %+v", w1.Status)
	}
	e.hold("w1", w1.Status.Pending.CommitID, w1.Status.Pending.Replicas...)
	e.run(e.state, ns, "w1")
	if w1 = e.getState("w1"); w1.Status.Phase != v1.StateReady {
		t.Fatalf("copy not ready %+v", w1.Status)
	}

	worker := e.startBlip("worker", "n2", e.withImage("reg/img:v1"), withCommand("make", "test"), e.withMount("w1", "/work", true))
	e.observe(worker.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 0}})
	e.run(e.blip, ns, "worker")
	if m := mountOf(e.getBlip("worker"), "w1"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("worker mount %+v", m)
	}
	e.saveWriter("w1", "b2b2b2b2b2b2b2b2")
	e.saveWriter(worker.Spec.State, newID())
	e.run(e.blip, ns, "worker")
	expectPhase(t, e.getBlip("worker"), v1.BlipSucceeded, "")

	// Mount the results read-only in the running sandbox.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = []v1.Mount{{State: "w1", Path: "/results"}} })
	e.run(e.blip, ns, "git")
	if m := mountOf(e.getBlip("git"), "w1"); m == nil || m.Writable || m.CommitID != "b2b2b2b2b2b2b2b2" || m.Phase != v1.MountPending {
		t.Fatalf("results mount %+v", m)
	}
	if w := e.getState("w1").Status.Writer; w != nil {
		t.Fatalf("read-only mount took writer %+v", w)
	}

	// Invalid edits preserve the existing topology and report an error.
	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = append(b.Spec.Mounts, v1.Mount{State: "repo", Path: "/results/x", Writable: true})
	})
	e.run(e.blip, ns, "git")
	git = e.getBlip("git")
	expectPhase(t, git, v1.BlipRunning, "")
	if m := mountOf(git, "repo"); m != nil || !strings.Contains(git.Status.Message, "overlaps") {
		t.Fatalf("overlapping mount %+v", m)
	}
	if w := e.getState("repo").Status.Writer; w != nil {
		t.Fatalf("failed mount took writer %+v", w)
	}
}
