// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestLiveCopyReplansWhenSourceStartsSaving covers a source that starts
// stopping (or Saving) after the copy's live snapshot was planned. The copy
// must fall back to the source's committed version instead of freezing a
// guest that is shutting down.
func TestLiveCopyReplansWhenSourceStartsSaving(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*env, *v1.Blip)
	}{
		{
			name: "stopping",
			mutate: func(e *env, b *v1.Blip) {
				e.updateBlip(b.Name, func(b *v1.Blip) { b.Spec.Stop = true })
			},
		},
		{
			name: "saving",
			mutate: func(e *env, b *v1.Blip) {
				e.updateBlipStatus(b.Name, func(b *v1.Blip) { b.Status.Phase = v1.BlipSaving })
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := liveSource(t)
			e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo" })
			e.run(e.state, ns, "cp")
			first := e.getState("cp").Status.Pending
			if first == nil {
				t.Fatal("live copy not planned")
			}

			tt.mutate(e, e.getBlip("git"))
			e.run(e.state, ns, "cp")
			cp := e.getState("cp")
			if cp.Status.CopiedFrom != nil || cp.Status.Pending != nil || !strings.Contains(cp.Status.Message, "replanning") {
				t.Fatalf("copy kept a live plan for a saving source: %+v", cp.Status)
			}

			// Once the writer clears, the copy uses the committed version.
			e.setWriter("repo", nil)
			e.run(e.state, ns, "cp")
			cp = e.getState("cp")
			committed := e.getState("repo").Status.Committed.ID
			if cf := cp.Status.CopiedFrom; cf == nil || cf.AttachmentID != "" || cf.CommitID != committed || cp.Status.Pending == nil || cp.Status.Pending.CommitID == first.CommitID {
				t.Fatalf("copy did not fall back to the committed version: %+v", cp.Status)
			}
		})
	}
}
