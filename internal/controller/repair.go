package controller

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// repairNode runs one pass of orphan cleanup, replica repair and scrub for a
// storage node (design 7.8).
func (c *Controller) repairNode(ctx context.Context, node string) {
	info := c.nodes.Info(node)
	if !info.Connected || info.Caps == nil || !info.Caps.Storage {
		return
	}
	log := c.log.WithValues("node", node)
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		log.Error(err, "repair: storage config")
		return
	}
	opID := "ls-" + node + "-" + randID()
	res, err := c.nodes.Call(ctx, node, opID, c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_ListState{ListState: &nodepb.ListState{}}})
	c.nodes.Forget(opID)
	if err != nil || !ok(res) || res.GetState() == nil {
		log.Info("repair: list state failed", "err", err, "result", resultErr(res))
		return
	}
	st := res.GetState()
	if cap := st.GetCapacity().GetStorage(); cap != nil {
		metricPoolUsage.WithLabelValues(node, "data").Set(cap.DataPercent)
		metricPoolUsage.WithLabelValues(node, "metadata").Set(cap.MetadataPercent)
		if cap.MaxLvs > 0 {
			metricPoolUsage.WithLabelValues(node, "lvs").Set(float64(cap.LvCount) * 100 / float64(cap.MaxLvs))
		}
	}
	g := cfg.GroupOf(node)

	var vols v1.BlipVolList
	if err := c.List(ctx, &vols); err != nil {
		return
	}
	byUID := map[string]*v1.BlipVol{}
	expected := map[string]snapRef{}
	var group []snapRef // Ready and Pending snapshots in this node's group
	for i := range vols.Items {
		v := &vols.Items[i]
		byUID[string(v.UID)] = v
		for j := range v.Status.Snapshots {
			sn := &v.Status.Snapshots[j]
			ref := snapRef{v, sn}
			expected[sn.ContentID] = ref
			if g != nil && sn.StorageGroup == g.Name {
				group = append(group, ref)
			}
		}
	}

	now := timeNow()
	have := map[string]*nodepb.ContentInfo{}
	orphans := 0
	for _, ci := range st.Contents {
		id := ci.ContentId
		have[id] = ci
		// Every snapshot has an entry before any content is made for it,
		// so in-flight receives and clones are never orphans. Content of
		// a snapshot whose sequence was not allocated yet (a cache behind
		// the capture) is not either.
		age := now.Sub(c.firstSeen(node, id, ci))
		ref, exp := expected[id]
		if !exp {
			if uid, seq, okID := api.ParseSnapshotContentID(id); okID {
				if v := byUID[uid]; v != nil && seq > v.Status.LastSequence {
					continue
				}
			}
		}
		del := false
		switch {
		case !exp:
			orphans++
			del = age > c.opts.OrphanAge && !c.saveActive(id)
		case ci.Sealed || ref.snap.State == v1.SnapshotPending:
		case ref.snap.State == v1.SnapshotReady || ref.snap.State == v1.SnapshotFailed:
			// An unsealed copy of a Ready snapshot is rebuilt by repair; a
			// Failed snapshot's partial receive is garbage.
			del = age > c.opts.OrphanAge
		}
		if del {
			log.Info("deleting orphan content", "content", id, "sealed", ci.Sealed, "age", age.Round(time.Second))
			op := "orphan-" + node + "-" + randID()
			if r, err := c.nodes.Call(ctx, node, op, c.opts.CommandTimeout, deleteContentCmd(id)); err == nil && ok(r) {
				delete(have, id)
			}
			c.nodes.Forget(op)
		}
	}
	metricOrphans.WithLabelValues(node).Set(float64(orphans))
	if g == nil {
		return
	}

	// Rebuild missing sealed content oldest first, so sharing is preserved.
	sortSnapRefs(group)
	missing := 0
	for _, ref := range group {
		v, sn := ref.vol, ref.snap
		if sn.State != v1.SnapshotReady || v.DeletionTimestamp != nil {
			continue
		}
		if ci := have[sn.ContentID]; ci != nil && ci.Sealed {
			continue
		}
		missing++
		if ctx.Err() != nil {
			return
		}
		if c.repairContent(ctx, node, g, ref, have, group) {
			have[sn.ContentID] = &nodepb.ContentInfo{ContentId: sn.ContentID, Sealed: true}
			missing--
		}
	}
	metricReplicaMissing.Set(float64(missing))

	// Record replica state for this node.
	for _, ref := range group {
		if ref.snap.State != v1.SnapshotReady || ref.vol.DeletionTimestamp != nil {
			continue
		}
		state := v1.ReplicaMissing
		if ci := have[ref.snap.ContentID]; ci != nil && ci.Sealed {
			state = v1.ReplicaSealed
		}
		c.setReplica(ctx, ref, node, state)
	}

	// One node per group runs the scrub.
	if members := c.connectedMembers(g); len(members) > 0 && members[0] == node {
		c.scrubDue(ctx, g, group)
	}
}

// snapRef is one snapshot entry of a BlipVol.
type snapRef struct {
	vol  *v1.BlipVol
	snap *v1.VolSnapshot
}

// sortSnapRefs orders snapshots by BlipVol creation, then sequence.
func sortSnapRefs(refs []snapRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.vol != b.vol {
			if !a.vol.CreationTimestamp.Equal(&b.vol.CreationTimestamp) {
				return a.vol.CreationTimestamp.Before(&b.vol.CreationTimestamp)
			}
			if a.vol.Name != b.vol.Name {
				return a.vol.Name < b.vol.Name
			}
		}
		return a.snap.Sequence < b.snap.Sequence
	})
}

func (c *Controller) firstSeen(node, id string, ci *nodepb.ContentInfo) time.Time {
	if ci.Created != nil && ci.Created.IsValid() {
		return ci.Created.AsTime()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := "seen/" + node + "/" + id
	t, ok := c.scrubbed[k]
	if !ok {
		t = timeNow()
		c.scrubbed[k] = t
	}
	return t
}

// setReplica updates one replica entry of a snapshot.
func (c *Controller) setReplica(ctx context.Context, ref snapRef, node string, state v1.ReplicaState) {
	if cur := ref.snap; cur != nil {
		for _, r := range cur.Replicas {
			if r.Node == node && r.State == state {
				return
			}
		}
	}
	seq := ref.snap.Sequence
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: ref.vol.Namespace, Name: ref.vol.Name}, string(ref.vol.UID), func(v *v1.BlipVol) (bool, error) {
		s := v.Snapshot(seq)
		if s == nil || s.State != v1.SnapshotReady {
			return false, nil
		}
		return setReplicaState(s, node, state), nil
	})
	if err != nil && err != errGone {
		c.log.Info("update replica state", "blipvol", ref.vol.Name, "sequence", seq, "err", err)
	}
}

// repairContent rebuilds a snapshot's content on target from a healthy
// replica. The base is the snapshot's own base, else the newest older
// snapshot of the same BlipVol, else of the same root, in the group, held
// sealed by both nodes; else the whole content is copied.
func (c *Controller) repairContent(ctx context.Context, target string, g *api.StorageGroup, ref snapRef, have map[string]*nodepb.ContentInfo, group []snapRef) bool {
	v, sn := ref.vol, ref.snap
	id := sn.ContentID
	log := c.log.WithValues("node", target, "content", id, "blipvol", v.Name, "sequence", sn.Sequence)
	var src string
	var srcInfo NodeInfo
	for _, n := range c.connectedMembers(g) {
		if n == target {
			continue
		}
		info := c.nodes.Info(n)
		if ci := info.Contents[id]; ci != nil && ci.Sealed {
			src, srcInfo = n, info
			break
		}
	}
	if src == "" {
		log.Info("repair: no healthy source replica")
		return false
	}
	usable := func(base string) bool {
		t, s := have[base], srcInfo.Contents[base]
		return base != "" && base != id && t != nil && t.Sealed && s != nil && s.Sealed
	}
	base := ""
	if usable(sn.Base) {
		base = sn.Base
	} else {
		// Another snapshot of the same BlipVol, else of the same root.
		var sameVol, sameRoot string
		for _, o := range group {
			if o.snap == sn || o.snap.State != v1.SnapshotReady || !usable(o.snap.ContentID) {
				continue
			}
			if o.vol.UID == v.UID {
				if o.snap.Sequence < sn.Sequence || sameVol == "" {
					sameVol = o.snap.ContentID
				}
			} else if o.vol.Status.RootContentID == v.Status.RootContentID {
				sameRoot = o.snap.ContentID
			}
		}
		base = sameVol
		if base == "" {
			base = sameRoot
		}
	}
	pre := "r-" + id + "-" + target + "-" + randID() + "."
	defer c.nodes.Forget(pre)
	to := c.opts.CommandTimeout
	fail := func(step string, r *nodepb.CommandResult, err error) bool {
		log.Info("repair failed", "step", step, "err", err, "result", resultErr(r))
		metricRepairs.WithLabelValues("failed").Inc()
		_, _ = c.nodes.Call(ctx, target, pre+"cleanup", to, deleteContentCmd(id))
		return false
	}
	var first *nodepb.Command
	if base != "" {
		first = &nodepb.Command{Op: &nodepb.Command_Clone{Clone: &nodepb.Clone{ContentId: id, ParentContentId: base, Blipvol: volRef(v), Mode: nodepb.CloneMode_CLONE_MODE_SNAPSHOT}}}
	} else {
		first = &nodepb.Command{Op: &nodepb.Command_CreateContent{CreateContent: &nodepb.CreateContent{ContentId: id, SizeBytes: sizeBytes(v), Kind: nodepb.ContentKind_CONTENT_KIND_REPAIR, Blipvol: volRef(v)}}}
	}
	log.Info("repairing replica", "source", src, "base", base)
	c.setReplica(ctx, ref, target, v1.ReplicaRepair)
	if r, err := c.nodes.Call(ctx, target, pre+"prepare", to, first); err != nil || !ok(r) {
		return fail("prepare", r, err)
	}
	r, err := c.nodes.Call(ctx, target, pre+"export", to, c.exportCmd(id, nodepb.ExportMode_EXPORT_MODE_READ_WRITE, src, "", false))
	if err != nil || !ok(r) || r.GetExport().GetPath() == nil {
		return fail("export", r, err)
	}
	path := r.GetExport().GetPath()
	r, err = c.nodes.Call(ctx, src, pre+"copy", c.opts.ImportTimeout, &nodepb.Command{Op: &nodepb.Command_Repair{Repair: &nodepb.Repair{ContentId: id, BaseContentId: base, Target: path}}})
	_, _ = c.nodes.Call(ctx, target, pre+"unexport", to, unexportCmd(id, ""))
	if err != nil || !ok(r) {
		return fail("copy", r, err)
	}
	if r, err := c.nodes.Call(ctx, target, pre+"seal", to, sealCmd(id, volRef(v))); err != nil || !ok(r) {
		return fail("seal", r, err)
	}
	metricRepairs.WithLabelValues("ok").Inc()
	return true
}

// scrubDue scrubs at most one snapshot of the group whose scrub is due.
func (c *Controller) scrubDue(ctx context.Context, g *api.StorageGroup, refs []snapRef) {
	now := timeNow()
	for _, ref := range refs {
		if ref.snap.State != v1.SnapshotReady || ref.vol.DeletionTimestamp != nil {
			continue
		}
		id := ref.snap.ContentID
		c.mu.Lock()
		last, seen := c.scrubbed[id]
		if !seen {
			// Spread first scrubs over the interval.
			last = now.Add(-time.Duration(rand.Int64N(int64(c.opts.ScrubInterval) + 1)))
			c.scrubbed[id] = last
		}
		due := now.Sub(last) >= c.opts.ScrubInterval
		if due {
			c.scrubbed[id] = now
		}
		c.mu.Unlock()
		if due {
			if err := c.Scrub(ctx, g, ref); err != nil {
				c.log.Info("scrub", "blipvol", ref.vol.Name, "sequence", ref.snap.Sequence, "err", err)
			}
			return
		}
	}
}

// Scrub compares the content of one snapshot on all replicas, repairs a
// minority from the majority, and marks the snapshot Failed when no two
// replicas agree.
func (c *Controller) Scrub(ctx context.Context, g *api.StorageGroup, ref snapRef) error {
	v := ref.vol
	id := ref.snap.ContentID
	var reps []string
	chunk := int64(api.DefaultChunkBytes)
	for _, n := range c.connectedMembers(g) {
		info := c.nodes.Info(n)
		if ci := info.Contents[id]; ci != nil && ci.Sealed {
			reps = append(reps, n)
			if info.Caps != nil && info.Caps.ChunkSizeBytes > 0 {
				chunk = info.Caps.ChunkSizeBytes
			}
		}
	}
	if len(reps) < 2 {
		return fmt.Errorf("%d sealed replicas reachable", len(reps))
	}
	total := (sizeBytes(v) + chunk - 1) / chunk
	pre := "scrub-" + id + "-" + randID() + "."
	defer c.nodes.Forget(pre)
	type rng struct{ start, count int64 }
	work := []rng{{0, total}}
	leaf := map[int64]map[string][]byte{} // bad chunk -> node -> hash
	n := 0
	for len(work) > 0 {
		w := work[len(work)-1]
		work = work[:len(work)-1]
		bph := max(1, (w.count+63)/64)
		hashes := map[string][][]byte{}
		for _, s := range reps {
			n++
			r, err := c.nodes.Call(ctx, s, fmt.Sprintf("%s%s.%d", pre, s, n), c.opts.ImportTimeout, &nodepb.Command{Op: &nodepb.Command_Scrub{Scrub: &nodepb.Scrub{
				ContentId: id, StartChunk: w.start, ChunkCount: w.count, BlocksPerHash: bph,
			}}})
			if err != nil {
				return err
			}
			if !ok(r) {
				return fmt.Errorf("scrub on %s: %s", s, resultErr(r))
			}
			hashes[s] = r.GetScrub().GetHashes()
		}
		count := int64(len(hashes[reps[0]]))
		for i := int64(0); i < count; i++ {
			same := true
			for _, s := range reps[1:] {
				if i >= int64(len(hashes[s])) || !bytes.Equal(hashes[s][i], hashes[reps[0]][i]) {
					same = false
				}
			}
			if same {
				continue
			}
			start := w.start + i*bph
			cnt := min(bph, w.start+w.count-start)
			if bph == 1 {
				m := map[string][]byte{}
				for _, s := range reps {
					if i < int64(len(hashes[s])) {
						m[s] = hashes[s][i]
					}
				}
				leaf[start] = m
			} else {
				work = append(work, rng{start, cnt})
			}
		}
	}
	if len(leaf) == 0 {
		return nil
	}
	metricScrubMismatch.Add(float64(len(leaf)))
	extents := map[string]map[string][]*nodepb.Extent{} // target -> source -> extents
	for ch, m := range leaf {
		maj, src := majority(m)
		if maj == nil {
			c.log.Info("scrub: no majority, marking snapshot Failed", "blipvol", v.Name, "chunk", ch)
			return c.markScrubFailed(ctx, ref, fmt.Sprintf("replicas disagree at chunk %d", ch))
		}
		for s, h := range m {
			if !bytes.Equal(h, maj) {
				if extents[s] == nil {
					extents[s] = map[string][]*nodepb.Extent{}
				}
				extents[s][src] = append(extents[s][src], &nodepb.Extent{OffsetBytes: ch * chunk, LengthBytes: chunk})
			}
		}
	}
	to := c.opts.CommandTimeout
	for t, bySrc := range extents {
		for s, ex := range bySrc {
			c.log.Info("scrub: repairing minority replica", "blipvol", v.Name, "target", t, "source", s, "chunks", len(ex))
			c.setReplica(ctx, ref, t, v1.ReplicaMismatch)
			r, err := c.nodes.Call(ctx, t, pre+"exp."+t, to, c.exportCmd(id, nodepb.ExportMode_EXPORT_MODE_READ_WRITE, s, "", true))
			if err != nil || !ok(r) || r.GetExport().GetPath() == nil {
				metricRepairs.WithLabelValues("failed").Inc()
				continue
			}
			r, err = c.nodes.Call(ctx, s, pre+"fix."+t, c.opts.ImportTimeout, &nodepb.Command{Op: &nodepb.Command_Repair{Repair: &nodepb.Repair{ContentId: id, Extents: ex, Target: r.GetExport().GetPath()}}})
			_, _ = c.nodes.Call(ctx, t, pre+"unexp."+t, to, unexportCmd(id, ""))
			if err != nil || !ok(r) {
				metricRepairs.WithLabelValues("failed").Inc()
				continue
			}
			metricRepairs.WithLabelValues("ok").Inc()
			c.setReplica(ctx, ref, t, v1.ReplicaSealed)
		}
	}
	return nil
}

// majority returns the hash held by at least 2 replicas, and one node holding it.
func majority(m map[string][]byte) ([]byte, string) {
	for s, h := range m {
		n := 0
		for _, h2 := range m {
			if bytes.Equal(h, h2) {
				n++
			}
		}
		if n >= 2 {
			return h, s
		}
	}
	return nil, ""
}

// markScrubFailed marks a snapshot Failed; the current snapshot moves to
// the newest Ready one left (the BlipVol is Failed if none is).
func (c *Controller) markScrubFailed(ctx context.Context, ref snapRef, msg string) error {
	seq := ref.snap.Sequence
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: ref.vol.Namespace, Name: ref.vol.Name}, string(ref.vol.UID), func(v *v1.BlipVol) (bool, error) {
		if !setSnapFailed(v, seq, "ScrubMismatch: "+msg, true) {
			return false, nil
		}
		if v.Status.Phase == v1.BlipVolFailed {
			setCond(&v.Status.Conditions, v.Generation, api.CondReady, false, api.ReasonScrubMismatch, msg)
			setCond(&v.Status.Conditions, v.Generation, api.CondFailed, true, api.ReasonScrubMismatch, msg)
		}
		return true, nil
	})
	if err == errGone {
		return nil
	}
	return err
}
