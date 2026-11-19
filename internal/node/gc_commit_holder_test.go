// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// TestGCKeepsCommittedCommitReportedByNode covers a generation the controller
// committed with an empty or incomplete placements list while its only copy is
// on a node that still reports holding it. GC must keep that copy: deleting it
// would lose the just-committed version. A node that does not report the
// committed commit, or reports it from an old incarnation, is still collected.
func TestGCKeepsCommittedCommitReportedByNode(t *testing.T) {
	for _, tc := range []struct {
		name         string
		placements   []string
		observations []v1alpha1.NodeObservation
		keep         bool
	}{
		{
			name:         "unplaced committed commit reported by node",
			observations: []v1alpha1.NodeObservation{holding(self, "saved")},
			keep:         true,
		},
		{
			name:         "listed placement",
			placements:   []string{self},
			observations: []v1alpha1.NodeObservation{holding(self, "saved")},
			keep:         true,
		},
		{
			name:         "commit reported only by another node",
			observations: []v1alpha1.NodeObservation{holding("n2", "saved")},
		},
		{
			name: "stale incarnation report",
			observations: []v1alpha1.NodeObservation{{
				Node: self, Incarnation: "old-inc", Commits: []string{"saved"},
			}},
		},
		{
			name: "node stopped reporting",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			s := state("s")
			s.Status.Committed = &v1alpha1.Commit{ID: "saved", Generation: 2}
			s.Status.Placements = tc.placements
			s.Status.Nodes = tc.observations
			v.states = append(v.states, s)
			v.volumes["saved"] = commit("saved", "uid-s")
			v.index()

			if got := v.keepCommit(v.volumes["saved"], nil); got != tc.keep {
				t.Fatalf("keepCommit(saved) = %v, want %v", got, tc.keep)
			}
		})
	}
}
