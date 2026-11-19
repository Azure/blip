// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestSaveDoesNotCommitWithEmptyPlacements covers a save whose sealing source
// was not usable when the save was reported, so it is absent from
// pending.replicas, while the only listed replica is bad. The state must never
// commit a generation with no placements: node GC keeps a committed commit
// only on a listed node, so an empty list would let it delete the only copy.
func TestSaveDoesNotCommitWithEmptyPlacements(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	const saved = "e621621621621621"
	since := metav1.NewTime(e.now)
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")

	// The source is healthy and holds the only copy, but it is not enrolled,
	// so it cannot be chosen as a replica.
	node := &corev1.Node{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, node))
	delete(node.Labels, v1.LabelEnrolled)
	e.must(e.c.Update(e.ctx, node))
	// The only listed replica is draining and never fetched the commit.
	e.setDrain("n2")

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("save did not commit: %+v", st.Status)
	}
	if !slices.Contains(st.Status.Placements, "n1") {
		t.Fatalf("committed generation %d without listing its only holder: placements=%v committed=%+v",
			st.Status.Committed.Generation, st.Status.Placements, st.Status.Committed)
	}

	// Repair cannot place the non-usable holder, but it must not drop the only
	// placement that still holds the commit either.
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if len(st.Status.Placements) == 0 || !slices.Contains(st.Status.Placements, "n1") {
		t.Fatalf("repair dropped the only holder: placements=%v message=%q", st.Status.Placements, st.Status.Message)
	}
}
