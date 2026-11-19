// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// TestFailedCopyDoesNotPinSourceCommit covers a source deleted while a failed
// copy still names its commit in status.copiedFrom. The controller lets that
// copy release the source finalizer (copyBlocksDeletion), so node GC must not
// keep the source's only commit volume alive until the failed copy is deleted.
func TestFailedCopyDoesNotPinSourceCommit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		phase   string
		pending *v1alpha1.PendingCommit
		keep    bool
	}{
		{name: "live copy", phase: v1alpha1.StatePending, keep: true},
		{name: "saving copy", phase: v1alpha1.StateSaving, pending: &v1alpha1.PendingCommit{CommitID: "cp-commit"}, keep: true},
		{name: "failed copy", phase: v1alpha1.StateFailed},
		// A failed copy with a pending build can still commit if a replica
		// recovers, so its source stays pinned.
		{name: "failed copy with pending build", phase: v1alpha1.StateFailed, pending: &v1alpha1.PendingCommit{CommitID: "cp-commit"}, keep: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			v.statesGone["uid-src"] = true
			src := commit("src-commit", "uid-src")
			v.volumes[src.ID] = src
			cp := state("cp")
			cp.Status.Phase = tc.phase
			cp.Status.Pending = tc.pending
			cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-src", CommitID: src.ID}
			v.states = append(v.states, cp)
			v.index()

			if got := v.keepCommit(src, nil); got != tc.keep {
				t.Fatalf("keepCommit = %v, want %v", got, tc.keep)
			}
			if got := !hasDelete(compute(v), src.ID); got != tc.keep {
				t.Fatalf("compute kept the source commit = %v, want %v", got, tc.keep)
			}
		})
	}
}
