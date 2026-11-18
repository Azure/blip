package node

import (
	"slices"
	"sort"

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
	ids := make([]string, 0, len(v.volumes))
	for id := range v.volumes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
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

	names := make([]string, 0, len(v.dirs))
	for name := range v.dirs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
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
// source in progress, or pinned by an export lease. A commit of a state with
// no committed version, or of a state not confirmed deleted, is kept too, so
// a version newer than the committed one is never deleted.
func (v *view) keepCommit(c storage.Volume, sealed map[string][]v1alpha1.SealResult) bool {
	id := c.ID
	if v.pinned[id] {
		return true
	}
	for _, b := range v.blips {
		if blipFinished(b) {
			continue
		}
		for _, m := range b.Status.Mounts {
			if m.CommitID == id {
				return true
			}
		}
	}
	for _, t := range v.states {
		if cf := t.Status.CopiedFrom; cf != nil && cf.CommitID == id && t.Status.Committed == nil {
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
	for _, r := range sealed[c.StateUID] {
		if r.CommitID == id {
			return true
		}
	}
	if st.Committed == nil {
		return true
	}
	if st.Committed.ID == id {
		return slices.Contains(st.Placements, v.node) ||
			(st.Pending != nil && slices.Contains(st.Pending.Replicas, v.node))
	}
	return false
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
