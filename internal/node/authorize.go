package node

import (
	"fmt"
	"slices"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/peer"
)

const ownerLabel = "blip.dev/owner"

// copyAllowed reports whether dst may copy from src. An unlabelled source is
// an administrator-created shared state that anyone may copy. A labelled
// source may only be copied by a state carrying the same owner label, so a
// non-VM writer cannot read another owner's data by creating an unlabelled
// destination that points at a labelled source.
func copyAllowed(dst, src *v1alpha1.BlipState) bool {
	so, do := src.Labels[ownerLabel], dst.Labels[ownerLabel]
	return so == "" || so == do
}

// authorize implements the export authorization rule: node may read commit C
// of state S if C is S's pending commit and node is a pending replica, C is
// S's committed commit and node is a placement, S's writer runs on node with
// base C, a non-finished Blip on node pins C in a read-only mount, or C is the
// copy source of a state whose pending replicas include node.
func authorize(states []*v1alpha1.BlipState, blips []*v1alpha1.Blip, node string, req peer.ExportRequest) error {
	byUID := map[string]*v1alpha1.BlipState{}
	for _, s := range states {
		byUID[string(s.UID)] = s
	}
	for _, s := range states {
		st := s.Status
		if string(s.UID) == req.StateUID {
			if st.Pending != nil && st.Pending.CommitID == req.CommitID && slices.Contains(st.Pending.Replicas, node) {
				return nil
			}
			if st.Committed != nil && st.Committed.ID == req.CommitID && slices.Contains(st.Placements, node) {
				return nil
			}
			if w := st.Writer; w != nil && w.Node == node && w.BaseCommit == req.CommitID {
				return nil
			}
		}
		if cf := st.CopiedFrom; cf != nil && cf.CommitID != "" && cf.StateUID == req.StateUID && cf.CommitID == req.CommitID &&
			st.Pending != nil && slices.Contains(st.Pending.Replicas, node) {
			// status is user-writable in principle, so corroborate the copy
			// with the immutable spec and the source's own status. Without
			// this a forged CopiedFrom could export another owner's commit.
			// A deleted source leaves nothing to check; its copied commit
			// must stay readable for the copy to finish.
			src := byUID[cf.StateUID]
			if src == nil || (s.Spec.CopyFrom == src.Name && copyAllowed(s, src) &&
				src.Status.Committed != nil && src.Status.Committed.ID == cf.CommitID) {
				return nil
			}
		}
	}
	for _, b := range blips {
		if blipFinished(b) || b.Status.Node != node {
			continue
		}
		for _, m := range b.Status.Mounts {
			if !m.Writable && m.StateUID == req.StateUID && m.CommitID == req.CommitID {
				return nil
			}
		}
	}
	return fmt.Errorf("node %s may not read commit %s of state %s", node, req.CommitID, req.StateUID)
}
