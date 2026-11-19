// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestSaveWaitsForStaleHolder covers a sealed save whose source node is gone
// while the only surviving holder has a brief heartbeat lag (< repairAfter).
// status.nodes still reports the commit, so the save must not be declared
// lost; once the node heartbeats again the commit completes.
func TestSaveWaitsForStaleHolder(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	committed := st.Status.Committed.ID
	const saved = "5151515151515151"
	since := metav1.NewTime(e.now)
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n2")
	e.removeNode("n1")
	e.now = e.now.Add(heartbeatTimeout + time.Second)

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending == nil {
		t.Fatalf("stale holder save was declared lost: %+v", st.Status)
	}
	if st.Status.Committed == nil || st.Status.Committed.ID != committed {
		t.Fatalf("stale holder changed the committed version: %+v", st.Status.Committed)
	}
	for _, sr := range st.Status.Seals {
		if sr.AttachmentID == "save" {
			t.Fatalf("stale holder save recorded a seal: %+v", sr)
		}
	}
	if strings.Contains(st.Status.Message, "lost") {
		t.Fatalf("stale holder save reported lost: %q", st.Status.Message)
	}

	// The holder heartbeats again before repairAfter: it becomes the source
	// and the save completes.
	e.heartbeat("n1")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("stale holder did not complete after recovery: %+v", st.Status)
	}
	if slices.Contains(st.Status.Placements, "n1") || !slices.Contains(st.Status.Placements, "n2") {
		t.Fatalf("placements after stale holder recovery: %v", st.Status.Placements)
	}
}

// TestSaveCommitsOnDrainingHolder covers a sealed save whose source node is
// gone and whose only surviving holder is healthy but draining. Draining
// forbids new placements, not completing an existing save, so the holder
// becomes the source and the commit completes instead of being failed.
func TestSaveCommitsOnDrainingHolder(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	const saved = "5252525252525252"
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"},
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n2")
	e.setDrain("n2")
	e.removeNode("n1")

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("draining holder did not complete the save: %+v", st.Status)
	}
	if !slices.Equal(st.Status.Placements, []string{"n2"}) {
		t.Fatalf("placements after draining holder save: %v", st.Status.Placements)
	}
}
