package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestConcurrentWritableMountReplaceKeepsWriter covers w7-06 F1. Two mount
// commands replace the same writable mount; the controller acquires an
// attachment for the first path and the second path lands before the node
// reported that attachment attached. The replacement moves the state's
// writer slot to a fresh attachment of the same Blip, which the node must
// treat as an intentional replacement rather than a lost writer (see
// node.TestWriterLostToleratesSameBlipReplacement). The Blip must stay
// running and save the chosen mount instead of failing with "no seal result".
func TestConcurrentWritableMountReplaceKeepsWriter(t *testing.T) {
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
	if m == nil || !m.Writable {
		t.Fatalf("setup writable mount: %+v", m)
	}
	old := m.AttachmentID
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: old, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m.Phase != v1.MountMounted {
		t.Fatalf("setup mount not mounted: %+v", m)
	}

	// Both concurrent commands remove the old mount before adding the new
	// path. The removal saves the attached disk normally.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "git")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: old, State: "data", Phase: podapi.DiskDetached},
	}})
	e.run(e.blip, ns, "git")
	e.saveWriter("data", "d1d1d1d1d1d1d1d1")
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m != nil {
		t.Fatalf("detached mount still reported: %+v", m)
	}

	// The first add wins the edit and the controller pre-acquires its writer.
	e.updateRoot("git", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/z1", Writable: true}}
	})
	e.run(e.blip, ns, "git")
	b := e.getBlip("git")
	m = mountOf(b, "data")
	if m == nil || m.Path != "/z1" || m.Phase != v1.MountPending || !m.Writable {
		t.Fatalf("first replacement mount: %+v", m)
	}
	first := m.AttachmentID
	w := e.getState("data").Status.Writer
	if w == nil || w.AttachmentID != first {
		t.Fatalf("first replacement did not hold the writer: %+v", w)
	}

	// The second add lands before the node reports the first path attached.
	e.updateRoot("git", func(b *v1.BlipState) { b.Spec.Mounts[0].Path = "/z2" })
	e.run(e.blip, ns, "git")
	b = e.getBlip("git")
	expectPhase(t, b, v1.BlipRunning, "")
	if strings.Contains(b.Status.Message, "no seal result") {
		t.Fatalf("replacement failed its save: %q", b.Status.Message)
	}
	if len(b.Status.Mounts) != 1 {
		t.Fatalf("replacement left %d mount entries: %+v", len(b.Status.Mounts), b.Status.Mounts)
	}
	if m = mountOf(b, "data"); m == nil || m.Path != "/z2" || !m.Writable {
		t.Fatalf("chosen replacement mount: %+v", m)
	}
	chosen := m.AttachmentID
	// The replacement keeps the state owned by this Blip and pod. The node
	// sees the writer's attachment change and must not fence it as lost.
	w = e.getState("data").Status.Writer
	if w == nil || w.AttachmentID != chosen || w.BlipUID != string(git.UID) || w.PodUID != git.Status.PodUID {
		t.Fatalf("replacement writer: %+v (mount %+v)", w, m)
	}

	// The node attaches the chosen path and the mount becomes usable.
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: chosen, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")
	if m = mountOf(e.getBlip("git"), "data"); m == nil || m.Path != "/z2" || m.Phase != v1.MountMounted {
		t.Fatalf("replacement mount did not attach: %+v", m)
	}

	// A normal stop still saves the single chosen attachment. Before the
	// node-side fix it stopped the VM for the writer change and this save
	// had no seal result.
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "git")
	expectPhase(t, e.getBlip("git"), v1.BlipSaving, ReasonStopped)
	e.saveWriter("data", "d2d2d2d2d2d2d2d2")
	e.saveWriter(git.Spec.State, "d3d3d3d3d3d3d3d3")
	e.run(e.blip, ns, "git")
	b = e.getBlip("git")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if strings.Contains(b.Status.Message, "no seal result") {
		t.Fatalf("final save failed: %q", b.Status.Message)
	}
}
