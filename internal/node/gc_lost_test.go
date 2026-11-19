package node

import (
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// TestFailedSaveCommitKeptWhileHeld covers a save the controller gave up on
// (its latest seal failed) while another node still reports the sealed commit.
// The node GC must keep that only durable copy; otherwise a brief heartbeat lag
// or a draining holder turns a recoverable save into data loss. The commit is
// released once no live node reports it, or once a later seal succeeds.
func TestFailedSaveCommitKeptWhileHeld(t *testing.T) {
	failed := v1alpha1.SealResult{AttachmentID: "save",
		Error: "pending generation 2 lost: no replica holds commit saved"}
	for _, tc := range []struct {
		name   string
		node   string
		commit string
		seals  []v1alpha1.SealResult
		keep   bool
	}{
		{name: "stale live holder", node: "n2", commit: "saved", seals: []v1alpha1.SealResult{failed}, keep: true},
		{name: "holder stopped reporting", node: "n2", commit: "other", seals: []v1alpha1.SealResult{failed}},
		{name: "holder node gone", node: "gone", commit: "saved", seals: []v1alpha1.SealResult{failed}},
		{name: "later seal succeeded", node: "n2", commit: "saved", seals: []v1alpha1.SealResult{failed, {AttachmentID: "next", CommitID: "c1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			s := state("s")
			s.Status.Committed = &v1alpha1.Commit{ID: "c0", Generation: 1}
			s.Status.Placements = []string{"n1"}
			s.Status.Nodes = []v1alpha1.NodeObservation{holding("n1", "c0"), holding(tc.node, tc.commit)}
			s.Status.Seals = tc.seals
			v.states = append(v.states, s)
			v.stateByUID = map[string]*v1alpha1.BlipState{"uid-s": s}
			v.volumes["saved"] = commit("saved", "uid-s")

			if got := v.keepCommit(v.volumes["saved"], nil); got != tc.keep {
				t.Fatalf("keepCommit(saved) = %v, want %v", got, tc.keep)
			}
		})
	}
}
