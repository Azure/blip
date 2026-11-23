// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/storage"
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

// TestCommitCacheRetention: unneeded commits stay as a local cache while the
// pool has free space, and are evicted least recently used first when it is
// under pressure.
func TestCommitCacheRetention(t *testing.T) {
	for _, tc := range []struct {
		name string
		free int64
		want []string
	}{
		{name: "room to spare", free: 3 << 30},
		{name: "under pressure", free: 0, want: []string{"old", "middle", "new"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			v.freeBytes, v.poolBytes = tc.free, 4<<30
			v.statesGone["gone"] = true
			for _, c := range []struct {
				id  string
				age time.Duration
			}{{"new", time.Hour}, {"middle", 2 * time.Hour}, {"old", 3 * time.Hour}} {
				vol := commit(c.id, "gone")
				vol.LastUsed = testNow.Add(-c.age)
				v.volumes[c.id] = vol
			}
			if got := compute(v).deletes; !slices.Equal(got, tc.want) {
				t.Fatalf("deletes = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCommitCacheKeepsNeededCommit: cache pressure never evicts a commit a
// state still needs.
func TestCommitCacheKeepsNeededCommit(t *testing.T) {
	v := newView()
	v.freeBytes, v.poolBytes = 0, 4<<30
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "needed", Generation: 2}
	s.Status.Placements = []string{self}
	v.states = append(v.states, s)
	v.volumes["needed"] = commit("needed", string(s.UID))
	if p := compute(v); hasDelete(p, "needed") {
		t.Fatalf("cache pressure evicted a needed commit: %+v", p)
	}
}

// TestReadOnlyWorkingVolumeIsAdopted: an unneeded read-only volume with a
// recorded mount becomes a cached commit, while a writable or still-hydrating
// volume is deleted as before.
func TestReadOnlyWorkingVolumeIsAdopted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*storage.Volume)
		adopt  bool
	}{
		{name: "read-only mount", adopt: true},
		{name: "writable", mutate: func(vol *storage.Volume) { vol.ReadOnly = false }},
		{name: "still hydrating", mutate: func(vol *storage.Volume) { vol.Hydrating = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			vol := storage.Volume{ID: "attach", Kind: storage.KindWorking, StateUID: "uid-img", ReadOnly: true}
			if tc.mutate != nil {
				tc.mutate(&vol)
			}
			b := blip("mounted")
			b.Status.Mounts = []v1alpha1.MountStatus{{AttachmentID: vol.ID, CommitID: "img-commit", StateUID: vol.StateUID}}
			v.volumes[vol.ID] = vol
			v.blips = append(v.blips, b)

			p := compute(v)
			want := []adopt{{attachmentID: vol.ID, commitID: "img-commit"}}
			if tc.adopt && !slices.Equal(p.adopts, want) {
				t.Fatalf("adopts = %+v, want %+v", p.adopts, want)
			}
			if !tc.adopt && len(p.adopts) != 0 {
				t.Fatalf("unexpected adopt: %+v", p.adopts)
			}
			if got := hasDelete(p, vol.ID); got == tc.adopt {
				t.Fatalf("delete of adopted volume = %v: %+v", got, p)
			}
		})
	}
}

// TestAdoptionFailureDeletesWorkingVolume: when the store cannot snapshot the
// volume, exec deletes it so the adoption never retries forever.
func TestAdoptionFailureDeletesWorkingVolume(t *testing.T) {
	st := newFakeStore()
	st.adoptErr = errors.New("unclean")
	st.add(storage.Volume{ID: "attach", Kind: storage.KindWorking, ReadOnly: true})
	a := &Agent{store: st}
	a.execute(context.Background(), newView(), &plan{adopts: []adopt{{attachmentID: "attach", commitID: "commit"}}})
	if len(st.adopts) != 1 || st.adopts[0] != (adopt{attachmentID: "attach", commitID: "commit"}) {
		t.Fatalf("adopt calls = %+v", st.adopts)
	}
	if !slices.Equal(st.deleted, []string{"attach"}) {
		t.Fatalf("deleted = %v, want [attach]", st.deleted)
	}
}
