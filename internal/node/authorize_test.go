package node

import (
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/peer"
)

// A copied commit needs the immutable spec and the source state to agree
// with CopiedFrom; status alone must not authorize a cross-owner export.
func TestAuthorizeCopySourceAgreement(t *testing.T) {
	src := state("src")
	src.Labels = map[string]string{ownerLabel: "alice"}
	src.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	dst := func() *v1alpha1.BlipState {
		s := state("dst")
		s.Labels = map[string]string{ownerLabel: "alice"}
		s.Spec.CopyFrom = "src"
		s.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-src", CommitID: "c1"}
		s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 1, Replicas: []string{"n2"}}
		return s
	}
	req := peer.ExportRequest{StateUID: "uid-src", CommitID: "c1"}
	if err := authorize([]*v1alpha1.BlipState{src, dst()}, nil, "n2", req); err != nil {
		t.Fatalf("matching copy denied: %v", err)
	}
	other := dst()
	other.Spec.CopyFrom = "elsewhere"
	if err := authorize([]*v1alpha1.BlipState{src, other}, nil, "n2", req); err == nil {
		t.Fatal("copy with mismatched spec.copyFrom allowed")
	}
	other = dst()
	other.Labels[ownerLabel] = "bob"
	if err := authorize([]*v1alpha1.BlipState{src, other}, nil, "n2", req); err == nil {
		t.Fatal("cross-owner copy allowed")
	}
}

func TestAuthorize(t *testing.T) {
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{"n1", "n2"}
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: "n1", Replicas: []string{"n1", "n3"}}
	ws := state("w")
	ws.Status.Writer = &v1alpha1.Writer{AttachmentID: "a1", Node: "n4", BaseCommit: "wc"}
	cp := state("copy")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-gone", CommitID: "src", Nodes: []string{"n2"}}
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "cc", Generation: 1, SourceNode: "n5", Replicas: []string{"n5"}}
	live := state("live")
	live.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-w", AttachmentID: "a1", Nodes: []string{"n4"}}
	live.Status.Pending = &v1alpha1.PendingCommit{CommitID: "lc", Generation: 1, SourceNode: "n4", Replicas: []string{"n4", "n9"}}
	ro := blip("ro")
	ro.Status.Node = "n6"
	ro.Status.Mounts = []v1alpha1.MountStatus{{State: "s", StateUID: "uid-s", CommitID: "old", Phase: v1alpha1.MountMounted}}
	rw := blip("rw")
	rw.Status.Node = "n7"
	rw.Status.Mounts = []v1alpha1.MountStatus{{State: "s", StateUID: "uid-s", CommitID: "c1", Writable: true}}
	done := blip("done")
	done.Status.Node = "n8"
	done.Status.Phase = v1alpha1.BlipSucceeded
	done.Status.Mounts = []v1alpha1.MountStatus{{State: "s", StateUID: "uid-s", CommitID: "old"}}

	states := []*v1alpha1.BlipState{s, ws, cp, live}
	blips := []*v1alpha1.Blip{ro, rw, done}
	cases := []struct {
		node, state, commit string
		ok                  bool
	}{
		{"n3", "uid-s", "c2", true},  // pending replica
		{"n2", "uid-s", "c2", false}, // placement, not pending replica
		{"n2", "uid-s", "c1", true},  // committed on placement
		{"n3", "uid-s", "c1", false}, // not a placement
		{"n4", "uid-w", "wc", true},  // writer base
		{"n1", "uid-w", "wc", false}, // writer runs elsewhere
		{"n5", "uid-gone", "src", true},
		{"n2", "uid-gone", "src", false},
		{"n6", "uid-s", "old", true},   // read-only mount pin
		{"n7", "uid-s", "old", false},  // writable mounts do not pin
		{"n8", "uid-s", "old", false},  // finished blip
		{"n6", "uid-w", "old", false},  // wrong state
		{"n9", "uid-live", "lc", true}, // live copy replica reads the new commit
		{"n9", "uid-w", "", false},     // a live copy names no source commit
	}
	for _, c := range cases {
		err := authorize(states, blips, c.node, peer.ExportRequest{StateUID: c.state, CommitID: c.commit})
		if (err == nil) != c.ok {
			t.Errorf("authorize(%s, %s/%s) = %v, want ok=%v", c.node, c.state, c.commit, err, c.ok)
		}
	}
}
