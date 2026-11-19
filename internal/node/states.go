package node

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// planSeals plans seals of this node's fenced writer attachments and returns
// the seal results to report, by state UID. A result is reported while the
// writer slot still names the attachment and the controller has not yet
// turned it into a pending or committed version.
func planSeals(v *view, p *plan) map[string][]v1alpha1.SealResult {
	out := map[string][]v1alpha1.SealResult{}
	for _, s := range v.states {
		w := s.Status.Writer
		if w == nil || w.Node != v.node || w.PodUID == "" || processed(s, w.AttachmentID) {
			continue
		}
		if !v.fenced(podKey(s.Namespace, w.PodName), w.PodUID, w.AttachmentID) || v.busy[w.AttachmentID] {
			continue
		}
		if r, ok := v.sealResult(w.AttachmentID); ok {
			out[string(s.UID)] = append(out[string(s.UID)], r)
			continue
		}
		p.seals = append(p.seals, seal{stateUID: string(s.UID), attachmentID: w.AttachmentID, commitID: SealCommitID(w.AttachmentID)})
	}
	return out
}

func processed(s *v1alpha1.BlipState, attachmentID string) bool {
	st := s.Status
	return (st.Pending != nil && st.Pending.AttachmentID == attachmentID) ||
		(st.Committed != nil && st.Committed.AttachmentID == attachmentID)
}

func (v *view) sealResult(attachmentID string) (v1alpha1.SealResult, bool) {
	c := SealCommitID(attachmentID)
	if vol, ok := v.volumes[c]; ok && vol.Kind == storage.KindCommit {
		return v1alpha1.SealResult{AttachmentID: attachmentID, CommitID: c, SizeBytes: vol.SizeBytes}, true
	}
	if e := v.sealErrs[attachmentID]; e != "" {
		return v1alpha1.SealResult{AttachmentID: attachmentID, Error: e}, true
	}
	vol, ok := v.volumes[attachmentID]
	if !ok {
		return v1alpha1.SealResult{AttachmentID: attachmentID, Error: "no working volume on this node"}, true
	}
	if vol.Failed != "" {
		return v1alpha1.SealResult{AttachmentID: attachmentID, Error: vol.Failed}, true
	}
	return v1alpha1.SealResult{}, false
}

// planStates plans image imports, initial builds, and commit fetches.
func planStates(v *view, p *plan) {
	refs := map[string]imageImport{}
	for _, r := range v.imageRefs() {
		if id, err := image.DigestOf(r.Ref); err == nil {
			refs[id] = imageImport{ref: r.Ref, secrets: r.Secrets}
		}
	}
	for _, id := range sortedKeys(refs) {
		if !v.busy[id] && (!v.hasImage(id) || v.configs[id] == nil) {
			p.imports = append(p.imports, refs[id])
		}
	}

	for _, s := range v.states {
		planDigests(v, p, string(s.UID))
		if v.busy[stateKey(string(s.UID))] {
			continue
		}
		if planBuild(v, p, s) {
			continue
		}
		if f := planFetch(v, p, s); f != nil {
			p.fetches = append(p.fetches, *f)
		}
	}
}

// planDigests computes the content digests of a state's commits built from
// an image ahead of the first save, which offers them as delta bases by
// digest (see view.imageBases).
func planDigests(v *view, p *plan, stateUID string) {
	for _, id := range v.imageBases(stateUID) {
		if v.volumes[id].Digest == "" && !v.busy[digestKey(id)] {
			p.digests = append(p.digests, id)
		}
	}
}

// planBuild plans the initial commit when this node builds it (see
// buildTarget). It reports whether s needs no fetch planning.
func planBuild(v *view, p *plan, s *v1alpha1.BlipState) bool {
	commitID := v.buildTarget(s)
	if commitID == "" || v.holds(commitID) {
		return false
	}
	if v.busy[commitID] {
		return true
	}
	req := storage.CreateCommit{StateUID: string(s.UID), CommitID: commitID, SizeBytes: s.Status.SizeBytes}
	switch {
	case s.Status.ImageDigest != "":
		id, err := image.DigestOf(s.Status.ImageDigest)
		if err != nil || !v.hasImage(id) {
			return true
		}
		req.FromImage = id
	case s.Status.CopiedFrom != nil && s.Status.CopiedFrom.AttachmentID != "":
		planLiveCopy(v, p, s, commitID)
		return true
	case s.Status.CopiedFrom != nil:
		cf := s.Status.CopiedFrom
		if !v.holds(cf.CommitID) {
			if src := v.copySource(cf); src != nil && !v.busy[cf.CommitID] {
				p.fetches = append(p.fetches, fetch{owner: string(s.UID), src: *src})
			}
			return true
		}
		req.FromCommit = cf.CommitID
	}
	p.builds = append(p.builds, build{req: req})
	return true
}

// planLiveCopy plans the snapshot of the copy source's running writer
// attachment into commitID. The VM using it must run on this node.
func planLiveCopy(v *view, p *plan, s *v1alpha1.BlipState, commitID string) {
	cf := s.Status.CopiedFrom
	if v.busy[cf.AttachmentID] || v.volumes[cf.AttachmentID].Hydrating {
		return
	}
	key := v.liveCopyPod(cf)
	if key == "" {
		// The writer is starting, stopping, unmounted, or gone. All of those
		// are transient: the controller either starts the VM, replans the
		// copy from the committed version, or times the pending build out.
		// Failing the state permanently here makes a fork that raced a save
		// unrecoverable.
		return
	}
	p.liveCopies = append(p.liveCopies, liveCopy{pod: key, stateUID: string(s.UID), attachmentID: cf.AttachmentID, commitID: commitID})
}

// liveCopyPod returns the key of the running VM pod on this node that holds
// the copy source's writer slot for cf.AttachmentID with the disk mounted,
// or "".
func (v *view) liveCopyPod(cf *v1alpha1.CopySource) string {
	id := cf.AttachmentID
	src := v.stateByUID[cf.StateUID]
	if src == nil {
		return ""
	}
	w := src.Status.Writer
	if w == nil || w.AttachmentID != id || w.Node != v.node || w.PodUID == "" {
		return ""
	}
	if vol, ok := v.volumes[id]; !ok || vol.Kind != storage.KindWorking || vol.Failed != "" {
		return ""
	}
	key := podKey(src.Namespace, w.PodName)
	pod, dir := v.pods[key], v.dirs[key]
	if pod == nil || string(pod.UID) != w.PodUID || dir == nil || dir.desired == nil || dir.desired.Stop ||
		dir.observed == nil || dir.observed.Phase != podapi.PhaseRunning || v.fenced(key, w.PodUID, id) {
		return ""
	}
	if c := dir.desired.Claim; c != nil && c.Root.ID == id {
		return key
	}
	for _, m := range dir.observed.Mounts {
		if m.ID == id && m.Phase == podapi.DiskMounted {
			return key
		}
	}
	return ""
}

// buildTarget returns the initial commit of s this node must build, or "".
// The pending source builds it. Each node converts images itself, so the
// initial version of an image state is not fetched: every pending replica,
// and later every placement while it is still the committed version, builds
// its own. A replica of a copy also builds locally when it already holds the
// committed version being copied, which is the usual case after replication.
// A save replicating to this node is fetched first.
func (v *view) buildTarget(s *v1alpha1.BlipState) string {
	st := s.Status
	pd, c := st.Pending, st.Committed
	switch {
	case pd != nil && pd.AttachmentID == "" &&
		(pd.SourceNode == v.node ||
			(fromImage(s, pd.Generation, pd.AttachmentID) || v.copyBase(s, pd.Generation)) &&
				slices.Contains(pd.Replicas, v.node)):
		return pd.CommitID
	case pd != nil && slices.Contains(pd.Replicas, v.node) && !v.holds(pd.CommitID):
		return ""
	case c != nil && fromImage(s, c.Generation, c.AttachmentID) && slices.Contains(st.Placements, v.node):
		return c.ID
	}
	return ""
}

// fromImage reports whether a version of s is its initial version built from
// an image.
func fromImage(s *v1alpha1.BlipState, generation int64, attachmentID string) bool {
	return s.Status.ImageDigest != "" && generation == 1 && attachmentID == ""
}

// copyBase reports whether this node can build the initial version of a copy
// from the committed version it was copied from. Live copies must snapshot on
// the source node, so they are excluded.
func (v *view) copyBase(s *v1alpha1.BlipState, generation int64) bool {
	cf := s.Status.CopiedFrom
	if generation != 1 || cf == nil || cf.AttachmentID != "" || cf.CommitID == "" {
		return false
	}
	vol, ok := v.volumes[cf.CommitID]
	return ok && vol.Kind == storage.KindCommit && vol.StateUID == cf.StateUID
}

func (v *view) copySource(cf *v1alpha1.CopySource) *source {
	if src := v.holder(v.stateByUID[cf.StateUID], cf.CommitID, ""); src != nil {
		src.purpose = "copy"
		return src
	}
	// The source state may be gone. Fall back to the nodes captured when the
	// copy was resolved, validating each BlipNode that still exists so a
	// re-created node with a new incarnation is not trusted.
	for _, n := range sortedUnique(cf.Nodes) {
		if n == v.node {
			continue
		}
		if v.healthyNode(n, v.observedIncarnation(cf.StateUID, n)) == nil {
			continue
		}
		return &source{node: n, purpose: "copy", stateUID: cf.StateUID,
			commitID: cf.CommitID, bases: v.bases(cf.StateUID), imageBases: v.imageBases(cf.StateUID)}
	}
	return nil
}

// observedIncarnation returns the incarnation a node reported for a state, or
// "" if there is no observation (for example because the state is gone).
func (v *view) observedIncarnation(stateUID, node string) string {
	s := v.stateByUID[stateUID]
	if s == nil {
		return ""
	}
	for _, e := range s.Status.Nodes {
		if e.Node == node {
			return e.Incarnation
		}
	}
	return ""
}

// planFetch returns the fetch this node should run for s: the pending commit
// when this node is a pending replica that does not hold it, else the
// committed commit when this node is a placement that lacks it (repair). A
// pending source that lost the commit fetches it from another healthy holder
// like any other replica; only holding the commit locally skips the fetch.
func planFetch(v *view, p *plan, s *v1alpha1.BlipState) *fetch {
	st := s.Status
	var src *source
	var want string
	if pd := st.Pending; pd != nil && slices.Contains(pd.Replicas, v.node) && !v.holds(pd.CommitID) {
		want = pd.CommitID
		src = v.holder(s, pd.CommitID, pd.SourceNode)
		if src == nil && pd.Generation > 1 {
			// A draining source that already sealed the commit is still a
			// valid source for the save it produced: it may not take new
			// placements, but it can serve the disk it holds. Otherwise a
			// drain during a save would wedge every replica on "no healthy
			// holder". Generation 1 is different: there the source must
			// still build and publish the commit.
			src = v.servingSource(s, pd.CommitID, pd.SourceNode)
		}
	} else if c := st.Committed; c != nil && slices.Contains(st.Placements, v.node) && !v.holds(c.ID) {
		want = c.ID
		src = v.servingHolder(s, c.ID)
	}
	if want == "" {
		return nil
	}
	if src == nil {
		if pd := st.Pending; pd != nil && pd.CommitID == want && pd.Generation == 1 &&
			v.healthyNode(pd.SourceNode, "") != nil {
			// The source may not have published the initial commit yet.
			// Waiting for it is not a preparation failure; the state
			// stays pending until the source reports the commit or an
			// error.
			return nil
		}
		msg := fmt.Sprintf("no healthy holder of commit %s", want)
		if pd := st.Pending; pd != nil && pd.CommitID == want && pd.SourceNode != "" {
			msg = fmt.Sprintf("no healthy holder of commit %s (source node %s)", want, pd.SourceNode)
		}
		p.errs[string(s.UID)] = msg
		return nil
	}
	if v.busy[src.commitID] {
		return nil
	}
	src.purpose = "replica"
	return &fetch{owner: string(s.UID), src: *src}
}

// planEntries computes this node's status.nodes entry for every state and
// keeps the ones that differ from what the cluster shows.
func planEntries(v *view, p *plan, sealed map[string][]v1alpha1.SealResult) {
	for _, s := range v.states {
		uid := string(s.UID)
		stateErr := v.stateErrs[uid]
		if stateErr == "" {
			stateErr = p.errs[uid]
		}
		obs := v1alpha1.NodeObservation{
			Node:        v.node,
			Incarnation: v.incarnation,
			Commits:     v.held(uid),
			Sealed:      sealed[uid],
			Error:       stateErr,
		}
		if id, err := image.DigestOf(s.Status.ImageDigest); err == nil && obs.Error == "" && !v.hasImage(id) && v.buildTarget(s) != "" {
			obs.Error = v.stateErrs[imageKey(id)]
		}
		if t := v.progress[uid]; t != nil {
			t := *t
			obs.Fetching = &t
		}
		var cur *v1alpha1.NodeObservation
		for i := range s.Status.Nodes {
			if s.Status.Nodes[i].Node == v.node {
				cur = &s.Status.Nodes[i]
			}
		}
		empty := len(obs.Commits) == 0 && len(obs.Sealed) == 0 && obs.Fetching == nil && obs.Error == ""
		switch {
		case empty && cur == nil:
		case empty:
			p.entries = append(p.entries, entry{namespace: s.Namespace, name: s.Name})
		case cur == nil || !sameJSON(*cur, obs):
			p.entries = append(p.entries, entry{namespace: s.Namespace, name: s.Name, obs: &obs})
		}
	}
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
