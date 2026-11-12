package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// Derive: a BlipVol D with spec.parent {name: S, snapshot?} is a clone of
// one snapshot of S.
//
//   - With parent.snapshot, that snapshot (it must exist and be Ready).
//   - Otherwise the first Ready snapshot of S captured after D was
//     created, whatever triggered it; while S is claimed by a running Blip
//     D waits (WaitingForCapture, or SourceUnreachable when S's node is
//     unreachable) and S's Blip captures at once (capture.go, captureDue).
//     If S is not claimed, S's newest Ready snapshot.
//
// status.origin {namespace, name, uid} is written as soon as S is found
// (the index on status.origin.uid lets S's Blip see waiting derives);
// snapshot and contentID once one is chosen, which pins it against
// compaction of S. Before that, a Clone hold naming the snapshot is put on
// S (checked against a fresh copy of S), so it cannot be compacted in
// between; the hold is dropped when the clone is done. The clone is an
// O(1) thin snapshot in S's group, or a full copy to the least full group
// when S's group is at --placement-threshold. It becomes D's sequence 1.

// derive drives a BlipVol with spec.parent to its sequence 1.
func (c *Controller) derive(ctx context.Context, bv *v1.BlipVol, cfg *api.StorageConfig) (reconcile.Result, error) {
	st := &bv.Status
	key := parentKey(bv)
	var p v1.BlipVol
	err := c.Get(ctx, key, &p)
	if apierrors.IsNotFound(err) || (err == nil && st.Origin != nil && st.Origin.UID != "" && string(p.UID) != st.Origin.UID) {
		if bv.Snapshot(1) != nil {
			return c.volFail(ctx, bv, api.ReasonParentDeleted, "the parent was deleted during the clone")
		}
		return volWait(bv, api.ReasonParentNotFound, fmt.Sprintf("parent %s not found", key), 10*time.Second)
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if st.Origin == nil || st.Origin.UID == "" {
		st.Origin = &v1.OriginStatus{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)}
	}
	s1 := bv.Snapshot(1)
	if s1 == nil {
		seq, wait, reason, msg := c.chooseParentSnapshot(bv, &p)
		if seq == 0 {
			if !wait {
				return c.volFail(ctx, bv, reason, msg)
			}
			return volWait(bv, reason, msg, 10*time.Second)
		}
		ps := p.Snapshot(seq)
		if err := c.addHold(ctx, p.Namespace, v1.ObjectRef{Name: p.Name, UID: string(p.UID)}, v1.HoldClone, volHolder(bv),
			"clone "+bv.Namespace+"/"+bv.Name, seq); err != nil {
			if rf, ok := err.(*refusal); ok {
				return volWait(bv, api.ReasonParentNotReady, rf.msg, 5*time.Second)
			}
			if err == errGone {
				return volWait(bv, api.ReasonParentNotFound, fmt.Sprintf("parent %s not found", key), 10*time.Second)
			}
			return reconcile.Result{}, err
		}
		id := api.SnapshotContentID(string(bv.UID), 1)
		g, base, root := cfg.Group(ps.StorageGroup), ps.ContentID, p.Status.RootContentID
		if g == nil || c.groupFullness(g) >= c.opts.PlacementThreshold {
			exclude := ""
			if g != nil {
				exclude = g.Name
			}
			if g = c.leastFullGroup(cfg, exclude); g == nil {
				return volWait(bv, api.ReasonStorageFull, "no storage group has room for a full copy", 30*time.Second)
			}
			base, root = "", id
		}
		st.Origin = &v1.OriginStatus{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID), Snapshot: seq, ContentID: ps.ContentID}
		st.Size = p.Status.Size
		st.RootContentID = root
		st.Snapshots = append(st.Snapshots, v1.VolSnapshot{Sequence: 1, ContentID: id, Reason: v1.SnapshotInitial, State: v1.SnapshotPending, StorageGroup: g.Name, Base: base})
		st.LastSequence = 1
		st.Phase = v1.BlipVolImporting
		setCond(&st.Conditions, bv.Generation, api.CondReady, false, api.ReasonImporting, fmt.Sprintf("cloning snapshot %d of %s", seq, key))
		setCond(&st.Conditions, bv.Generation, api.CondFailed, false, api.ReasonImporting, "")
		return reconcile.Result{Requeue: true}, nil
	}
	o := st.Origin
	ps := p.Snapshot(o.Snapshot)
	if ps == nil || ps.State != v1.SnapshotReady {
		return c.volFail(ctx, bv, api.ReasonSnapshotNotFound, fmt.Sprintf("snapshot %d of %s is gone", o.Snapshot, key))
	}
	// The parent keeps the snapshot until the clone is done.
	if !hasHold(&p, v1.HoldClone, string(bv.UID)) {
		if err := c.addHold(ctx, p.Namespace, v1.ObjectRef{Name: p.Name, UID: string(p.UID)}, v1.HoldClone, volHolder(bv),
			"clone "+bv.Namespace+"/"+bv.Name, o.Snapshot); err != nil {
			if rf, ok := err.(*refusal); ok {
				return volWait(bv, api.ReasonParentNotReady, rf.msg, 5*time.Second)
			}
			return reconcile.Result{}, err
		}
	}
	g := cfg.Group(s1.StorageGroup)
	if g == nil {
		return volWait(bv, "GroupMissing", fmt.Sprintf("storage group %q is not configured", s1.StorageGroup), 30*time.Second)
	}
	if ps.StorageGroup == s1.StorageGroup {
		return c.snapshotClone(ctx, bv, s1, ps)
	}
	return c.copyClone(ctx, bv, s1, ps, g)
}

// chooseParentSnapshot picks the parent snapshot to clone. With seq 0 the
// BlipVol waits (wait) or fails, with the reason and message.
func (c *Controller) chooseParentSnapshot(bv, p *v1.BlipVol) (seq int64, wait bool, reason, msg string) {
	if want := bv.Spec.Parent.Snapshot; want != nil {
		s := p.Snapshot(*want)
		switch {
		case s == nil && *want > p.Status.LastSequence:
			return 0, true, api.ReasonSnapshotNotYetTaken, fmt.Sprintf("snapshot %d of %s/%s does not exist yet", *want, p.Namespace, p.Name)
		case s == nil:
			return 0, false, api.ReasonSnapshotNotFound, fmt.Sprintf("snapshot %d of %s/%s was deleted", *want, p.Namespace, p.Name)
		case s.State == v1.SnapshotPending:
			return 0, true, api.ReasonParentNotReady, fmt.Sprintf("snapshot %d of %s/%s is not Ready yet", *want, p.Namespace, p.Name)
		case s.State == v1.SnapshotFailed:
			return 0, false, api.ReasonSnapshotNotFound, fmt.Sprintf("snapshot %d of %s/%s failed", *want, p.Namespace, p.Name)
		}
		return s.Sequence, false, "", ""
	}
	if p.DeletionTimestamp != nil {
		return 0, true, api.ReasonParentNotReady, fmt.Sprintf("parent %s/%s is being deleted", p.Namespace, p.Name)
	}
	// The first snapshot captured after this BlipVol was created. Both
	// times are compared in whole seconds (capture times are stored
	// truncated), so a snapshot captured in the same second as the
	// creation does not count: it may predate it. captureDue waits for
	// the next second before capturing for a derive.
	var first *v1.VolSnapshot
	for i := range p.Status.Snapshots {
		s := &p.Status.Snapshots[i]
		if s.State == v1.SnapshotReady && s.CaptureTime != nil && s.CaptureTime.Unix() > bv.CreationTimestamp.Unix() && (first == nil || s.Sequence < first.Sequence) {
			first = s
		}
	}
	if first != nil {
		return first.Sequence, false, "", ""
	}
	cl := p.Status.Claim
	if cl == nil {
		if nr := p.NewestReady(); nr != nil {
			return nr.Sequence, false, "", ""
		}
		if p.Status.Phase == v1.BlipVolFailed {
			return 0, false, "ParentFailed", fmt.Sprintf("parent %s/%s failed", p.Namespace, p.Name)
		}
		return 0, true, api.ReasonParentNotReady, fmt.Sprintf("parent %s/%s is not ready", p.Namespace, p.Name)
	}
	if cl.Node != "" && !c.nodes.Connected(cl.Node) {
		return 0, true, api.ReasonSourceUnreachable, fmt.Sprintf("parent %s/%s is attached to blip %s on node %s, which is unreachable; set spec.parent.snapshot to use an older snapshot", p.Namespace, p.Name, cl.BlipName, cl.Node)
	}
	return 0, true, api.ReasonWaitingForCapture, fmt.Sprintf("parent %s/%s is attached to blip %s; waiting for a snapshot", p.Namespace, p.Name, cl.BlipName)
}

// snapshotClone is the O(1) clone in the parent snapshot's group.
func (c *Controller) snapshotClone(ctx context.Context, bv *v1.BlipVol, s1, ps *v1.VolSnapshot) (reconcile.Result, error) {
	reps := c.snapReplicas(ps)
	if len(reps) < 2 {
		return volWait(bv, api.ReasonImporting, fmt.Sprintf("%d replicas of the parent snapshot reachable, need 2", len(reps)), 10*time.Second)
	}
	own, pre := volOwner(bv), volOpPrefix(bv)
	var good []string
	pending := false
	for _, s := range reps {
		res := c.nodes.Do(s, pre+"clone."+s, own, c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_Clone{Clone: &nodepb.Clone{
			ContentId: s1.ContentID, ParentContentId: ps.ContentID, Blipvol: volRef(bv), Mode: nodepb.CloneMode_CLONE_MODE_SNAPSHOT,
		}}})
		if res == nil {
			pending = true
		} else if ok(res) {
			good = append(good, s)
		}
	}
	if pending {
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}
	sealed, pending := c.sealAll(bv, s1.ContentID, good)
	if pending {
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if len(sealed) < 2 {
		return c.volFail(ctx, bv, api.ReasonCloneFailed, fmt.Sprintf("cloned on %d replicas, need 2", len(sealed)))
	}
	return c.volReady(ctx, bv, s1, sealed)
}

// copyClone copies the parent snapshot into another group (design 7.10).
func (c *Controller) copyClone(ctx context.Context, bv *v1.BlipVol, s1, ps *v1.VolSnapshot, g *api.StorageGroup) (reconcile.Result, error) {
	reps := c.snapReplicas(ps)
	members := c.connectedMembers(g)
	if len(reps) == 0 || len(members) < 2 {
		return volWait(bv, api.ReasonImporting, "waiting for parent replicas and target group members", 10*time.Second)
	}
	src := reps[0]
	own, pre, to, id := volOwner(bv), volOpPrefix(bv), c.opts.CommandTimeout, s1.ContentID
	waitRes := reconcile.Result{RequeueAfter: 10 * time.Second}
	var targets []*nodepb.Path
	pending := false
	for _, s := range members {
		res := c.nodes.Do(s, pre+"create."+s, own, to, &nodepb.Command{Op: &nodepb.Command_CreateContent{CreateContent: &nodepb.CreateContent{
			ContentId: id, SizeBytes: sizeBytes(bv), Kind: nodepb.ContentKind_CONTENT_KIND_CLONE, Blipvol: volRef(bv),
		}}})
		if res == nil {
			pending = true
			continue
		}
		if !ok(res) {
			continue
		}
		res = c.nodes.Do(s, pre+"exp."+s, own, to, c.exportCmd(id, nodepb.ExportMode_EXPORT_MODE_READ_WRITE, src, "", false))
		if res == nil {
			pending = true
		} else if ok(res) && res.GetExport().GetPath() != nil {
			targets = append(targets, res.GetExport().GetPath())
		}
	}
	if pending {
		return waitRes, nil
	}
	if len(targets) < 2 {
		return c.volFail(ctx, bv, api.ReasonCloneFailed, fmt.Sprintf("%d copy targets, need 2", len(targets)))
	}
	res := c.nodes.Do(src, pre+"copy."+src, own, c.opts.ImportTimeout, &nodepb.Command{Op: &nodepb.Command_Clone{Clone: &nodepb.Clone{
		ContentId: id, ParentContentId: ps.ContentID, Blipvol: volRef(bv), Mode: nodepb.CloneMode_CLONE_MODE_COPY, Targets: targets,
	}}})
	if res == nil {
		return waitRes, nil
	}
	if !ok(res) {
		return c.volFail(ctx, bv, api.ReasonCloneFailed, resultErr(res))
	}
	var good []string
	for _, t := range res.GetCopy().GetTargets() {
		if t.Ok {
			good = append(good, t.Node)
		}
	}
	for _, s := range members {
		if c.nodes.Do(s, pre+"unexp."+s, own, to, unexportCmd(id, "")) == nil {
			pending = true
		}
	}
	if pending {
		return waitRes, nil
	}
	sealed, pending := c.sealAll(bv, id, good)
	if pending {
		return waitRes, nil
	}
	if len(sealed) < 2 {
		return c.volFail(ctx, bv, api.ReasonCloneFailed, fmt.Sprintf("copied to %d replicas, need 2", len(sealed)))
	}
	return c.volReady(ctx, bv, s1, sealed)
}
