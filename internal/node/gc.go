package node

import (
	"slices"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/storage"
)

// planGC deletes volumes, device nodes, and pod directories nobody needs.
func planGC(v *view, p *plan, sealed map[string][]v1alpha1.SealResult) {
	reserved := clone(v.busy)
	for _, op := range p.operations() {
		for _, id := range append(slices.Clone(op.Reads), op.Writes...) {
			reserved[id] = true
		}
	}
	// A delete that failed after its phase was recorded is hidden from List,
	// so it never enters v.volumes. Retry it here until teardown succeeds.
	pending := map[string]bool{}
	for _, id := range sortedUnique(v.pending) {
		if reserved[id] {
			continue
		}
		pending[id] = true
		p.deletes = append(p.deletes, id)
	}
	owners := map[string][]string{} // an old and replacement pod can both have a device node
	for _, name := range sortedKeys(v.dirs) {
		dir := v.dirs[name]
		for id := range dir.devs {
			owners[id] = append(owners[id], name)
		}
	}
	for _, id := range sortedKeys(v.volumes) {
		if pending[id] {
			continue
		}
		vol := v.volumes[id]
		if reserved[id] {
			continue
		}
		switch vol.Kind {
		case storage.KindWorking:
			if v.workingUnneeded(vol, owners[id], p.needed) {
				p.deletes = append(p.deletes, id)
			}
		case storage.KindCommit:
			if !v.keepCommit(vol, sealed) {
				p.deletes = append(p.deletes, id)
			}
		case storage.KindImage:
			if v.idleImages[id] {
				p.deletes = append(p.deletes, id)
			}
		}
	}

	for _, name := range sortedKeys(v.dirs) {
		dir := v.dirs[name]
		for _, id := range sortedKeys(dir.devs) {
			if _, ok := v.volumes[id]; !ok && !reserved[id] && v.fenced(name, "", id) {
				p.rmDevs = append(p.rmDevs, devRef{pod: name, id: id})
			}
		}
		if v.pods[name] == nil && v.podsGone[name] && len(dir.devs) == 0 && !reserved[podDirectoryKey(name)] {
			p.rmDirs = append(p.rmDirs, name)
		}
	}
}

// workingUnneeded decides whether a working volume can be deleted. A durable
// volume that still holds the writer slot is kept until its seal produced a
// commit (or the controller released the slot). Everything else goes once
// its VM can no longer use it. A failed volume (remote clone lost in a
// restart) that no VM has seen is deleted so it can be recreated.
func (v *view) workingUnneeded(vol storage.Volume, ownerPods []string, needed map[string]bool) bool {
	if vol.Failed != "" && len(ownerPods) == 0 {
		return true // never handed to a VM; recreate it
	}
	if vol.StateUID != "" && !vol.ReadOnly {
		if s := v.stateByUID[vol.StateUID]; s != nil {
			if w := s.Status.Writer; w != nil && w.AttachmentID == vol.ID && w.Node == v.node {
				return v.holds(SealCommitID(vol.ID))
			}
		}
	}
	if len(ownerPods) != 0 {
		for _, pod := range ownerPods {
			if !v.fenced(pod, "", vol.ID) {
				return false
			}
		}
		return true
	}
	return !needed[vol.ID]
}

// keepCommit is the GC rule: a commit stays while it is the state's pending
// commit, its committed commit on a placement (or base for a pending
// replica), a not yet processed seal, a writer base, a read-only mount, a copy
// source still needed by a live copy, or pinned by an export lease. A commit
// of a state with no committed version, or of a state not confirmed deleted,
// is kept too, so a version newer than the committed one is never deleted.
func (v *view) keepCommit(c storage.Volume, sealed map[string][]v1alpha1.SealResult) bool {
	id := c.ID
	if v.pinned[id] {
		return true
	}
	for _, b := range v.blips {
		if v1alpha1.Finished(b) {
			continue
		}
		for _, m := range b.Status.Mounts {
			if m.CommitID == id {
				return true
			}
		}
	}
	for _, t := range v.states {
		// A failed copy cannot use its source, so it must not pin the
		// source's commit after the source is deleted. This matches the
		// controller, which lets a failed copy release the source
		// finalizer. A pending build can still commit, so it stays
		// pinned.
		if cf := t.Status.CopiedFrom; cf != nil && cf.CommitID == id && t.Status.Committed == nil &&
			!(t.Status.Phase == v1alpha1.StateFailed && t.Status.Pending == nil) {
			return true
		}
		if w := t.Status.Writer; w != nil && w.BaseCommit == id {
			return true
		}
	}
	s := v.stateByUID[c.StateUID]
	if s == nil {
		return !v.statesGone[c.StateUID]
	}
	st := s.Status
	if st.Pending != nil && st.Pending.CommitID == id {
		return true
	}
	if v.lostCommitHeld(s, id) {
		return true
	}
	for _, r := range sealed[c.StateUID] {
		if r.CommitID == id {
			return true
		}
	}
	if st.Committed == nil {
		return true
	}
	if st.Committed.ID == id {
		// A node that still reports the committed commit holds its only copy
		// when placements omitted it (for example it was not usable at
		// save-report time). Never delete that copy just because the
		// controller failed to list the holder.
		return slices.Contains(st.Placements, v.node) ||
			(st.Pending != nil && slices.Contains(st.Pending.Replicas, v.node)) ||
			v.reportsCommit(s, id)
	}
	return false
}

// reportsCommit reports whether this node's current incarnation still reports
// holding id for s.
func (v *view) reportsCommit(s *v1alpha1.BlipState, id string) bool {
	for _, o := range s.Status.Nodes {
		if o.Node != v.node || !slices.Contains(o.Commits, id) {
			continue
		}
		if bn := v.blipNodes[o.Node]; bn != nil && bn.Status.Incarnation == o.Incarnation {
			return true
		}
	}
	return false
}

// lostCommitHeld reports whether a live node still reports holding id while
// the state's latest seal failed and id is not the committed version. A save
// the controller gave up on can leave its only durable copy on a node that
// still reports it (for example after a brief heartbeat lag or while
// draining). Deleting that commit would turn a recoverable save into data
// loss. A later successful seal replaces the failure and lets normal GC drop
// the superseded commit.
func (v *view) lostCommitHeld(s *v1alpha1.BlipState, id string) bool {
	st := s.Status
	if st.Committed == nil || st.Committed.ID == id || len(st.Seals) == 0 {
		return false
	}
	if st.Seals[len(st.Seals)-1].Error == "" {
		return false
	}
	for _, o := range st.Nodes {
		if !slices.Contains(o.Commits, id) {
			continue
		}
		if bn := v.blipNodes[o.Node]; bn != nil && bn.Status.Incarnation == o.Incarnation {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
