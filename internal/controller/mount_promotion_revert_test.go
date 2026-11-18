package controller

import (
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestFailedPromotionRevertReleasesWriter covers C4: a read-only -> writable
// promotion whose disk failed has its pre-acquired writer released when the
// user reverts the mount to read-only.
func TestFailedPromotionRevertReleasesWriter(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	gen1 := e.readyState("repo", "n1", "n2").Status.Committed.ID
	git := e.startBlip("git", "n1", withImage("reg/img:v1"), withMount("repo", "/src", false))
	pod := git.Status.Pod
	e.run(e.blip, ns, "git")
	m := mountOf(e.getBlip("git"), "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "git")

	// Promote to writable; the writer is pre-acquired before teardown.
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Mounts[0].Writable = true })
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "repo", Phase: podapi.DiskDetached},
	}})
	e.run(e.blip, ns, "git")
	m = mountOf(e.getBlip("git"), "repo")
	if m == nil || !m.Writable || m.Phase != v1.MountPending {
		t.Fatalf("promotion did not create a writable mount: %+v", m)
	}
	writerID := m.AttachmentID

	// The writable attachment fails; the user reverts to read-only.
	e.observe(pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: writerID, State: "repo", Phase: podapi.DiskFailed, Message: "nvme timeout"},
	}})
	e.run(e.blip, ns, "git")
	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Mounts[0].Writable = false })
	for range 3 {
		e.run(e.blip, ns, "git")
	}
	b := e.getBlip("git")
	m = mountOf(b, "repo")
	if m == nil || m.Writable || m.Path != "/src" {
		t.Fatalf("reverted mount %+v", m)
	}
	st := e.getState("repo")
	if st.Status.Writer != nil {
		t.Fatalf("failed promotion leaked writer %+v", st.Status.Writer)
	}
	if st.Status.Committed.ID != gen1 || st.Status.Pending != nil {
		t.Fatalf("reverted promotion advanced the state: %+v", st.Status)
	}
	for _, sr := range st.Status.Seals {
		if sr.AttachmentID == writerID {
			t.Fatalf("hidden seal for the failed promotion: %+v", sr)
		}
	}
}
