package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// Per-attachment capture loop: one capture per attachment at a time, no
// consistency across volumes. The algorithm (triggers, steps, base and
// group choice, ownership) is in docs/design.md section 7.9; the save is in
// save.go (section 7.8).

// localSeq is the local snapshot sequence on the compute node of snapshot
// seq of the BlipVol of an attachment. Local sequences must be unique in
// the allocation (CaptureLocal records them per allocation) and increase
// per attachment; BlipVol sequences are per BlipVol, so the slot disk of
// the attachment (unique among the live attachments of the allocation) is
// folded in.
func localSeq(vs *v1.BlipVolumeStatus, seq int64) int64 {
	var disk int64
	if vs.SlotDisk != nil {
		disk = int64(*vs.SlotDisk)
	}
	return seq*localSeqStride + disk
}

// localSeqStride bounds the slot disks per slot.
const localSeqStride = 1024

// interval returns the scaled snapshot interval of a BlipVol (0: none).
func (c *Controller) interval(v *v1.BlipVol) time.Duration {
	iv := v.SnapshotInterval()
	if iv <= 0 {
		return 0
	}
	d := time.Duration(float64(iv) / c.opts.SnapshotIntervalScale)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// captureLoop drives interval and derive captures of every attached volume.
func (c *Controller) captureLoop(ctx context.Context, r *blipRun) error {
	b := r.b
	a := b.Status.Allocation
	if !c.nodes.Connected(a.Node) {
		return nil
	}
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		if vs.State != v1.VolumeAttached || vs.BlipVolRef == nil {
			continue
		}
		v, err := c.inputVol(ctx, b, vs)
		if err != nil {
			return err
		}
		if v == nil || !ownClaim(v, string(b.UID), vs.AttachmentID, vs.Generation) {
			continue
		}
		if s := pendingCapture(v, vs.AttachmentID); s != nil {
			if iv := c.interval(v); iv > 0 && s.CaptureTime != nil && !r.now.Before(s.CaptureTime.Add(iv)) {
				setCond(&b.Status.Conditions, b.Generation, api.CondSnapshotsBehind, true, api.ReasonCaptureSkipped,
					fmt.Sprintf("volume %s: snapshot %d is still being saved; an interval was skipped", vs.Name, s.Sequence))
			}
			st, msg := c.driveCapture(ctx, r, vs, v, s, nil)
			c.noteCapture(r, vs, s.Sequence, st, msg)
			continue
		}
		if !c.dropLocals(ctx, r, vs, v) {
			continue
		}
		reason, wait, err := c.captureDue(ctx, r, vs, v)
		if err != nil {
			return err
		}
		if reason == "" {
			if wait > 0 {
				r.after(wait)
			}
			continue
		}
		if _, err := c.startCapture(ctx, r, vs, v, reason); err != nil {
			if rf, ok := err.(*refusal); ok {
				setCond(&b.Status.Conditions, b.Generation, api.CondSnapshotsBehind, true, rf.reason, fmt.Sprintf("volume %s: %s", vs.Name, rf.msg))
				r.after(10 * time.Second)
				continue
			}
			return err
		}
		r.after(100 * time.Millisecond)
	}
	return nil
}

// noteCapture records the outcome of an interval or derive capture in
// SnapshotsBehind.
func (c *Controller) noteCapture(r *blipRun, vs *v1.BlipVolumeStatus, seq int64, st saveResult, msg string) {
	b := r.b
	switch st {
	case saveReady:
		setCond(&b.Status.Conditions, b.Generation, api.CondSnapshotsBehind, false, "Saved", fmt.Sprintf("volume %s: snapshot %d saved", vs.Name, seq))
	case saveFailed, saveGone:
		setCond(&b.Status.Conditions, b.Generation, api.CondSnapshotsBehind, true, "CaptureFailed", fmt.Sprintf("volume %s: snapshot %d failed: %s", vs.Name, seq, msg))
	}
}

// waitingDerives returns the BlipVols deriving from v that wait for a live
// capture: status.origin names v, no snapshot is chosen yet, no explicit
// spec.parent.snapshot, and the derive reported that it waits for a
// capture (WaitingForCapture, or SourceUnreachable while v's node is
// away).
func (c *Controller) waitingDerives(ctx context.Context, v *v1.BlipVol) ([]v1.BlipVol, error) {
	var l v1.BlipVolList
	if err := c.List(ctx, &l, client.MatchingFields{idxOriginUID: string(v.UID)}); err != nil {
		return nil, err
	}
	var out []v1.BlipVol
	for _, d := range l.Items {
		o := d.Status.Origin
		if o == nil || o.Snapshot != 0 || d.DeletionTimestamp != nil || d.Status.Phase == v1.BlipVolReady || d.Status.Phase == v1.BlipVolFailed {
			continue
		}
		if d.Spec.Parent == nil || d.Spec.Parent.Snapshot != nil {
			continue
		}
		if r := condReason(d.Status.Conditions, api.CondReady); r != api.ReasonWaitingForCapture && r != api.ReasonSourceUnreachable {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// capturedAfter reports whether v has a Ready or Pending snapshot captured
// after t (at second resolution, as stored).
func capturedAfter(v *v1.BlipVol, t metav1.Time) bool {
	for _, s := range v.Status.Snapshots {
		if s.State != v1.SnapshotFailed && s.CaptureTime != nil && s.CaptureTime.Unix() > t.Unix() {
			return true
		}
	}
	return false
}

// captureDue says whether an attachment needs a capture now, and why
// (Derive wins over Interval), or how long until the next one.
func (c *Controller) captureDue(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, v *v1.BlipVol) (v1.SnapshotReason, time.Duration, error) {
	ds, err := c.waitingDerives(ctx, v)
	if err != nil {
		return "", 0, err
	}
	var wait time.Duration
	for _, d := range ds {
		if capturedAfter(v, d.CreationTimestamp) {
			continue
		}
		// Capture times are stored in seconds: a capture in the second
		// the derive was created would not count as after it.
		if r.now.Unix() > d.CreationTimestamp.Unix() {
			return v1.SnapshotDerive, 0, nil
		}
		wait = time.Second
	}
	if iv := c.interval(v); iv > 0 {
		next := nextInterval(v, vs.AttachmentID, iv)
		if !r.now.Before(next) {
			return v1.SnapshotInterval, 0, nil
		}
		if d := next.Sub(r.now); wait == 0 || d < wait {
			wait = d
		}
	}
	return "", wait, nil
}

// nextInterval is when the attachment's next interval capture is due: an
// interval after its newest Ready or Pending capture (or after the claim
// was taken). A Failed capture newer than that is retried
// min(interval, 1m) after it: sooner than a full interval when the last
// good capture is recent, and never right away when it is older than an
// interval (that would retry a failing capture in a tight loop). Repeated
// failures are retried at that pace.
func nextInterval(v *v1.BlipVol, attachmentID string, iv time.Duration) time.Time {
	var last time.Time
	if cl := v.Status.Claim; cl != nil && cl.Since != nil {
		last = cl.Since.Time
	}
	if t := lastCaptureBy(v, attachmentID, false); t != nil && t.After(last) {
		last = t.Time
	}
	if f := lastCaptureBy(v, attachmentID, true); f != nil && f.After(last) {
		return f.Add(min(iv, time.Minute))
	}
	return last.Add(iv)
}

// startCapture appends a Pending snapshot written by the attachment and
// returns it; an existing Pending capture of the attachment is returned
// instead. A lost claim or no room for the snapshot is a *refusal.
func (c *Controller) startCapture(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, v *v1.BlipVol, reason v1.SnapshotReason) (*v1.VolSnapshot, error) {
	b := r.b
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		return nil, err
	}
	var out v1.VolSnapshot
	_, err = c.updateVolStatus(ctx, types.NamespacedName{Namespace: v.Namespace, Name: v.Name}, string(v.UID), func(x *v1.BlipVol) (bool, error) {
		if !ownClaim(x, string(b.UID), vs.AttachmentID, vs.Generation) {
			return false, &refusal{"ClaimLost", fmt.Sprintf("blipvol %s is no longer claimed by the attachment", x.Name)}
		}
		if p := pendingCapture(x, vs.AttachmentID); p != nil {
			out = *p
			return false, nil
		}
		cl := x.Status.Claim
		base := x.Snapshot(cl.Baseline)
		if base == nil || base.State != v1.SnapshotReady || base.Writer == nil || base.Writer.AttachmentID != vs.AttachmentID {
			base = x.Snapshot(cl.Snapshot)
		}
		if base == nil {
			return false, &refusal{api.ReasonSnapshotNotFound, fmt.Sprintf("snapshot %d of blipvol %s is gone", cl.Snapshot, x.Name)}
		}
		g, baseID := cfg.Group(base.StorageGroup), base.ContentID
		if g == nil || c.groupFullness(g) >= c.opts.StorageFullThreshold {
			exclude := ""
			if g != nil {
				exclude = g.Name
			}
			if g = c.leastFullGroup(cfg, exclude); g == nil {
				return false, &refusal{api.ReasonStorageFull, "no storage group has room for the snapshot"}
			}
			baseID = ""
		}
		seq := x.Status.LastSequence + 1
		now := metav1.NewTime(r.now.Truncate(time.Second))
		out = v1.VolSnapshot{Sequence: seq, ContentID: api.SnapshotContentID(string(x.UID), seq), Reason: reason, State: v1.SnapshotPending,
			CaptureTime: &now, StorageGroup: g.Name, Base: baseID,
			Writer: &v1.Writer{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: vs.AttachmentID, Generation: vs.Generation}}
		x.Status.Snapshots = append(x.Status.Snapshots, out)
		x.Status.LastSequence = seq
		return true, nil
	})
	if err == errGone {
		return nil, &refusal{"ClaimLost", fmt.Sprintf("blipvol %s is gone", v.Name)}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// driveCapture takes the local snapshot of a Pending entry and transfers
// it. saveGone means the attachment or its overlay is gone on the node;
// the entry is then Failed.
func (c *Controller) driveCapture(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, v *v1.BlipVol, s *v1.VolSnapshot, result *v1.RunResult) (saveResult, string) {
	switch s.State {
	case v1.SnapshotReady:
		return saveReady, ""
	case v1.SnapshotFailed:
		return saveFailed, s.Message
	}
	a := r.b.Status.Allocation
	if !c.nodes.Connected(a.Node) {
		r.after(5 * time.Second)
		return savePending, fmt.Sprintf("node %s is not connected", a.Node)
	}
	key := fmt.Sprintf("cap/%s/%d", vs.AttachmentID, s.Sequence)
	n, due := c.retryState(key)
	if !due {
		r.after(time.Second)
		return savePending, ""
	}
	res := c.nodes.Do(a.Node, opN(fmt.Sprintf("cap-%s-%d", v.UID, s.Sequence), n), r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_CaptureLocal{CaptureLocal: &nodepb.CaptureLocal{
		AllocationId: a.ID, Seq: localSeq(vs, s.Sequence), Attachments: []*nodepb.AttachmentRef{{AttachmentId: vs.AttachmentID, Generation: vs.Generation}},
	}}})
	if res == nil {
		return savePending, ""
	}
	if !ok(res) {
		msg := "capture: " + resultErr(res)
		if res.Code == nodepb.ErrorCode_ERROR_CODE_NOT_FOUND || res.Code == nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION {
			// The overlay is gone (node rebooted) or no longer ours.
			c.retryClearKey(key)
			if err := c.markSnapFailed(ctx, v, s.Sequence, msg); err != nil {
				return savePending, err.Error()
			}
			return saveGone, msg
		}
		if n+1 >= c.opts.TransferAttempts {
			c.retryClearKey(key)
			if err := c.markSnapFailed(ctx, v, s.Sequence, msg); err != nil {
				return savePending, err.Error()
			}
			return saveFailed, msg
		}
		d := backoff(n, 2*time.Second, time.Minute)
		c.retryLater(key, d)
		r.after(d)
		return savePending, msg
	}
	st, msg := c.transfer(ctx, r, v, s, vs, result)
	if st == saveGone {
		if err := c.markSnapFailed(ctx, v, s.Sequence, msg); err != nil {
			return savePending, err.Error()
		}
	}
	if st != savePending {
		c.retryClearKey(key)
	}
	return st, msg
}

// dropLocals drops the local snapshots of the attachment that are no
// longer needed: every settled snapshot it wrote except the baseline. It
// reports whether none is left to drop (a new capture needs the room: the
// node keeps a small number per attachment).
func (c *Controller) dropLocals(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, v *v1.BlipVol) bool {
	a := r.b.Status.Allocation
	cl := v.Status.Claim
	if cl == nil || !c.nodes.Connected(a.Node) {
		return false
	}
	done := true
	for _, s := range v.Status.Snapshots {
		if s.Writer == nil || s.Writer.AttachmentID != vs.AttachmentID || s.State == v1.SnapshotPending || s.Sequence == cl.Baseline {
			continue
		}
		c.mu.Lock()
		dropped := c.dropped[vs.AttachmentID][s.Sequence]
		c.mu.Unlock()
		if dropped {
			continue
		}
		key := fmt.Sprintf("drop/%s/%d", vs.AttachmentID, s.Sequence)
		n, due := c.retryState(key)
		if !due {
			done = false
			continue
		}
		res := c.nodes.Do(a.Node, opN(fmt.Sprintf("%sdrop.%d", attachPrefix(a, vs), s.Sequence), n), r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_DropLocalSnapshot{DropLocalSnapshot: &nodepb.DropLocalSnapshot{
			AllocationId: a.ID, AttachmentId: vs.AttachmentID, Generation: vs.Generation, Seq: localSeq(vs, s.Sequence),
		}}})
		if res == nil {
			done = false
			continue
		}
		if retryDrop(res) {
			// A kept local snapshot would exhaust the local budget and
			// block every later capture.
			c.log.Info("drop local snapshot failed, retrying", "allocation", a.ID, "attachment", vs.AttachmentID, "seq", s.Sequence, "err", resultErr(res))
			c.retryLater(key, 5*time.Second)
			r.after(5 * time.Second)
			done = false
			continue
		}
		// Not sent again in later passes (until the attachment is
		// forgotten, e.g. on a controller restart).
		c.retryClearKey(key)
		c.mu.Lock()
		if c.dropped[vs.AttachmentID] == nil {
			c.dropped[vs.AttachmentID] = map[int64]bool{}
		}
		c.dropped[vs.AttachmentID][s.Sequence] = true
		c.mu.Unlock()
	}
	return done
}

// retryDrop reports whether a DropLocalSnapshot result is a failure worth
// retrying. Unknown attachments and allocations succeed on the node; a
// stale generation or a finished allocation means the snapshot is not
// ours to drop (any more).
func retryDrop(res *nodepb.CommandResult) bool {
	if ok(res) || res.Status == nodepb.ResultStatus_RESULT_STATUS_REJECTED {
		return false
	}
	return res.Code != nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION && res.Code != nodepb.ErrorCode_ERROR_CODE_NOT_FOUND
}

// capturing reports whether an attachment has a capture in flight (as the
// cached BlipVol shows).
func (c *Controller) capturing(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) bool {
	v, err := c.inputVol(ctx, b, vs)
	if err != nil {
		return true
	}
	return v != nil && pendingCapture(v, vs.AttachmentID) != nil
}

func findCond(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}
