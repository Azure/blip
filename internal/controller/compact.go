package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// Compaction keeps the snapshot history of a BlipVol bounded: the newest
// snapshotPolicy.limit Ready snapshots are kept, older Ready snapshots and
// Failed snapshots older than the newest Ready one are deleted. Of the
// Failed snapshots newer than every Ready one, the newest limit are kept,
// so a volume whose captures keep failing does not grow without bound.
// Never deleted: the newest Ready snapshot, Pending snapshots, Held ones
// (the claim's snapshot and baseline, the base of a Pending snapshot, the
// snapshot of a Clone hold) and Pinned ones (the origin snapshot of any
// existing BlipVol derived from this one). Ready snapshots kept beyond the limit
// set RetentionLimitExceeded with reason Pinned or Held.
//
// A snapshot is deleted by removing its entry first (on a fresh copy, so a
// hold or claim taken meanwhile is seen) and then its content on every
// member of its group; content left behind (a node away) is an orphan and
// removed by the orphan scan.

// Protection reasons of a snapshot.
const (
	protectNone   = ""
	protectHeld   = api.ReasonHeld
	protectPinned = api.ReasonPinned
)

// compactSnap is a snapshot as seen by the compaction planner.
type compactSnap struct {
	Seq     int64
	State   v1.SnapshotState
	Protect string // protectNone, protectHeld or protectPinned
}

// compactPlan returns the sequences to delete, sorted, and, when more
// Ready snapshots than limit are kept, why (Pinned wins over Held).
func compactPlan(snaps []compactSnap, limit int32) (del []int64, exceeded string) {
	ss := append([]compactSnap(nil), snaps...)
	sort.Slice(ss, func(i, j int) bool { return ss[i].Seq > ss[j].Seq })
	var newestReady int64
	for _, s := range ss {
		if s.State == v1.SnapshotReady {
			newestReady = s.Seq
			break
		}
	}
	ready, failedNew := int32(0), int32(0)
	for _, s := range ss {
		switch s.State {
		case v1.SnapshotReady:
			ready++
			if ready <= limit {
				continue
			}
			if s.Protect != protectNone {
				if s.Protect == protectPinned || exceeded == "" {
					exceeded = s.Protect
				}
				continue
			}
		case v1.SnapshotFailed:
			if s.Seq > newestReady {
				failedNew++
				if failedNew <= limit {
					continue
				}
			}
			if s.Protect != protectNone {
				continue
			}
		default:
			continue
		}
		del = append(del, s.Seq)
	}
	sort.Slice(del, func(i, j int) bool { return del[i] < del[j] })
	return del, exceeded
}

// protection returns why each protected snapshot of v must be kept. pins
// are the origin snapshots of BlipVols derived from v.
func protection(v *v1.BlipVol, pins map[int64]bool) map[int64]string {
	p := map[int64]string{}
	for seq := range pins {
		p[seq] = protectPinned
	}
	held := func(seq int64) {
		if seq != 0 && p[seq] == protectNone {
			p[seq] = protectHeld
		}
	}
	if cl := v.Status.Claim; cl != nil {
		held(cl.Snapshot)
		held(cl.Baseline)
	}
	for _, h := range v.Status.Holds {
		held(h.Snapshot)
	}
	for _, s := range v.Status.Snapshots {
		if s.State == v1.SnapshotPending && s.Base != "" {
			if b := snapByContent(v, s.Base); b != nil {
				held(b.Sequence)
			}
		}
	}
	return p
}

// originPins returns the snapshots of v that BlipVols derived from it
// were cloned from, or will be: the explicit spec.parent.snapshot of a
// derived BlipVol still provisioning is pinned too. It reads the cache and
// must run after a live read of v that found the cache caught up with it
// (see compact).
func (c *Controller) originPins(ctx context.Context, v *v1.BlipVol) (map[int64]bool, error) {
	var l v1.BlipVolList
	if err := c.List(ctx, &l, client.MatchingFields{idxOriginUID: string(v.UID)}); err != nil {
		return nil, err
	}
	pins := map[int64]bool{}
	for _, d := range l.Items {
		if o := d.Status.Origin; o != nil && o.UID == string(v.UID) && o.Snapshot != 0 && d.Status.Phase != v1.BlipVolFailed {
			pins[o.Snapshot] = true
		}
	}
	var pl v1.BlipVolList
	key := types.NamespacedName{Namespace: v.Namespace, Name: v.Name}.String()
	if err := c.List(ctx, &pl, client.MatchingFields{idxParent: key}); err != nil {
		return nil, err
	}
	for _, d := range pl.Items {
		p := d.Spec.Parent
		if p == nil || p.Snapshot == nil || d.DeletionTimestamp != nil || d.Status.Phase == v1.BlipVolReady || d.Status.Phase == v1.BlipVolFailed {
			continue
		}
		if o := d.Status.Origin; o != nil && o.UID != "" && o.UID != string(v.UID) {
			continue // derived from an earlier BlipVol of the same name
		}
		pins[*p.Snapshot] = true
	}
	return pins, nil
}

// abandonedCaptures returns the Pending captures of v whose writer no
// longer holds the claim (claim released, taken over or cleared): they
// will never finish.
func abandonedCaptures(v *v1.BlipVol) []int64 {
	var out []int64
	for i := range v.Status.Snapshots {
		s := &v.Status.Snapshots[i]
		if s.State == v1.SnapshotPending && s.Writer != nil && !writerOwnsClaim(v, s) {
			out = append(out, s.Sequence)
		}
	}
	return out
}

// errCacheBehind aborts a compaction whose cache is older than the live
// copy of the BlipVol.
var errCacheBehind = fmt.Errorf("cache behind")

// compact applies compaction to a BlipVol. Pins are computed inside the
// status update, after the live read, from a cache that has caught up with
// that read: the cache of BlipVols is fed by one watch in resourceVersion
// order, so it then also holds every BlipVol write made before, in
// particular status.origin.snapshot of a derived BlipVol whose Clone hold
// the live read no longer shows (the hold is dropped only after the
// origin is written).
func (c *Controller) compact(ctx context.Context, bv *v1.BlipVol) (reconcile.Result, error) {
	plan := func(v *v1.BlipVol, pins map[int64]bool) ([]int64, string) {
		prot := protection(v, pins)
		in := make([]compactSnap, 0, len(v.Status.Snapshots))
		for _, s := range v.Status.Snapshots {
			in = append(in, compactSnap{Seq: s.Sequence, State: s.State, Protect: prot[s.Sequence]})
		}
		return compactPlan(in, v.SnapshotLimit())
	}
	condOK := func(v *v1.BlipVol, exceeded string) bool {
		cd := findCond(v.Status.Conditions, api.CondRetentionLimitExceeded)
		if exceeded == "" {
			return cd == nil || cd.Status != "True"
		}
		return cd != nil && cd.Status == "True" && cd.Reason == exceeded
	}
	idle := func() bool {
		pins, err := c.originPins(ctx, bv)
		if err != nil {
			return false
		}
		del, exceeded := plan(bv, pins)
		return len(del) == 0 && condOK(bv, exceeded) && len(abandonedCaptures(bv)) == 0
	}
	if idle() {
		return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
	}
	var removed []v1.VolSnapshot
	key := types.NamespacedName{Namespace: bv.Namespace, Name: bv.Name}
	_, err := c.updateVolStatus(ctx, key, string(bv.UID), func(v *v1.BlipVol) (bool, error) {
		removed = nil
		if v.DeletionTimestamp != nil {
			return false, nil
		}
		var cached v1.BlipVol
		if err := c.Get(ctx, key, &cached); err != nil {
			return false, err
		}
		if cached.ResourceVersion != v.ResourceVersion {
			return false, errCacheBehind
		}
		pins, err := c.originPins(ctx, v)
		if err != nil {
			return false, err
		}
		changed := false
		for _, seq := range abandonedCaptures(v) {
			changed = setSnapFailed(v, seq, "the writer no longer holds the claim", false) || changed
		}
		del, exceeded := plan(v, pins)
		if len(del) > 0 {
			gone := map[int64]bool{}
			for _, d := range del {
				gone[d] = true
			}
			var keep []v1.VolSnapshot
			for _, s := range v.Status.Snapshots {
				if gone[s.Sequence] {
					removed = append(removed, s)
				} else {
					keep = append(keep, s)
				}
			}
			v.Status.Snapshots = keep
			syncCurrent(v)
			changed = true
		}
		if !condOK(v, exceeded) {
			if exceeded == "" {
				setCond(&v.Status.Conditions, v.Generation, api.CondRetentionLimitExceeded, false, api.ReasonWithinLimit, "")
			} else {
				n := 0
				for _, s := range v.Status.Snapshots {
					if s.State == v1.SnapshotReady {
						n++
					}
				}
				setCond(&v.Status.Conditions, v.Generation, api.CondRetentionLimitExceeded, true, exceeded,
					fmt.Sprintf("%d Ready snapshots are kept, the limit is %d", n, v.SnapshotLimit()))
			}
			changed = true
		}
		return changed, nil
	})
	if err == errGone {
		return reconcile.Result{}, nil
	}
	if err == errCacheBehind {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if len(removed) > 0 {
		c.deleteSnapContent(ctx, bv, removed)
	}
	return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
}

// deleteSnapContent deletes the content of removed snapshot entries on the
// connected members of their groups (best effort: the orphan scan removes
// what is left).
func (c *Controller) deleteSnapContent(ctx context.Context, bv *v1.BlipVol, removed []v1.VolSnapshot) {
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		return
	}
	ids := map[string][]string{}
	for _, s := range removed {
		c.saveDone(s.ContentID)
		c.log.Info("compaction deleted snapshot", "blipvol", bv.Namespace+"/"+bv.Name, "sequence", s.Sequence, "state", s.State)
		metricSnapshots.WithLabelValues(snapKind(s.Reason), "deleted").Inc()
		if g := cfg.Group(s.StorageGroup); g != nil {
			for _, n := range g.Nodes {
				ids[n] = append(ids[n], s.ContentID)
			}
		}
	}
	for _, n := range sortedKeys(ids) {
		if c.nodes.Connected(n) {
			c.nodes.Send(n, deleteContentCmd(ids[n]...))
		}
	}
}
