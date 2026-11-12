package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// releaseReason maps the workload result to the shutdown snapshot reason.
func releaseReason(b *v1.Blip) v1.ReleaseReason {
	switch {
	case rescheduling(b) && !isFailed(b) && b.Status.Allocation != nil:
		return v1.ReleaseReschedule
	case isTrue(b.Status.Conditions, api.CondComplete):
		return v1.ReleaseCompleted
	case condReason(b.Status.Conditions, api.CondFailed) == api.ReasonTTLExceeded:
		return v1.ReleaseDeadlineExceeded
	case b.DeletionTimestamp != nil || condReason(b.Status.Conditions, api.CondFailed) == api.ReasonCancelled:
		return v1.ReleaseDeleted
	}
	return v1.ReleaseFailed
}

func ssSettled(ss *v1.ShutdownSnapshot) bool {
	if ss == nil {
		return true
	}
	switch ss.State {
	case v1.ShutdownSnapshotReady, v1.ShutdownSnapshotSkipped, v1.ShutdownSnapshotUnavailable, v1.ShutdownSnapshotFailed:
		return true
	}
	return false
}

// snapReason is the snapshot reason of a shutdown snapshot.
func snapReason(r v1.ReleaseReason) v1.SnapshotReason {
	if r == v1.ReleaseReschedule {
		return v1.SnapshotReschedule
	}
	return v1.SnapshotShutdown
}

// release is the single path for every terminal outcome (success, failure,
// deadline, cancel, deletion, node loss, reschedule): stop the VM, save
// the shutdown snapshots, release attachments and claims, release the
// allocation. It reports whether everything is done; the Blip is Finished
// (or waits for its next attempt) only then.
func (c *Controller) release(ctx context.Context, r *blipRun) (bool, error) {
	b := r.b
	a := b.Status.Allocation
	b.Status.Phase = v1.BlipSaving
	if !c.nodes.Connected(a.Node) {
		if gone, why := c.nodeGone(ctx, a.Node); gone {
			return c.abandon(ctx, r, why)
		}
		if rescheduling(b) && !isFailed(b) {
			return c.salvageWait(ctx, r)
		}
		msg := fmt.Sprintf("node %s is unreachable and not fenced (taint %s)", a.Node, api.TaintOutOfService)
		setCond(&b.Status.Conditions, b.Generation, api.CondFinished, false, api.ReasonNodeUnreachable, msg)
		r.after(5 * time.Second)
		return false, nil
	}
	if condReason(b.Status.Conditions, api.CondFinished) == api.ReasonNodeUnreachable {
		setCond(&b.Status.Conditions, b.Generation, api.CondFinished, false, api.ReasonReleasing, "")
	}
	if cd := findCond(b.Status.Conditions, api.CondRescheduling); cd != nil && cd.Reason == api.ReasonNodeUnreachable && rescheduling(b) {
		reason := api.ReasonNodeLost
		if lf := b.Status.LastFailure; lf != nil {
			reason = lf.Reason
		}
		setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, true, reason, fmt.Sprintf("node %s returned; saving the volumes", a.Node))
	}
	rt := c.nodes.Alloc(a.ID)
	recordRuntime(b, rt)
	// 1. Stop the VM: press the power button (Kill graceful), then kill it
	// once the graceful timeout passed. A guest that exited by itself
	// (Exited) needs nothing.
	if rt.Exit == nil && rt.Assigned {
		// The graceful timeout counts from the first stop request; after
		// a restart the guest gets the rest of it.
		graceful, budget := true, c.opts.GracefulTimeout
		if t := b.Status.StopRequestedTime; t != nil {
			budget -= r.now.Sub(t.Time)
			if budget <= 0 {
				graceful, budget = false, 0
			}
		} else {
			now := metav1.NewTime(r.now)
			b.Status.StopRequestedTime = &now
		}
		reason := condReason(b.Status.Conditions, api.CondFailed)
		if isTrue(b.Status.Conditions, api.CondComplete) {
			reason = api.ReasonSucceeded
		} else if lf := b.Status.LastFailure; lf != nil && rescheduling(b) && !isFailed(b) {
			reason = lf.Reason
		}
		// Nodes cache results by operation ID: a retry needs a new one.
		kn, due := c.retryState("kill/" + a.ID)
		if !due {
			r.after(time.Second)
			return false, nil
		}
		res := c.nodes.Do(a.Node, opN(a.ID+".kill", kn), r.owner(), c.opts.CommandTimeout+c.opts.GracefulTimeout, &nodepb.Command{Op: &nodepb.Command_Kill{Kill: &nodepb.Kill{
			AllocationId: a.ID, Reason: reason, Graceful: graceful, GracefulTimeout: durationpb.New(budget),
		}}})
		if res == nil {
			return false, nil
		}
		if !ok(res) && res.Status != nodepb.ResultStatus_RESULT_STATUS_REJECTED && res.Code != nodepb.ErrorCode_ERROR_CODE_NOT_FOUND {
			c.log.Info("kill failed, retrying", "allocation", a.ID, "err", resultErr(res))
			c.retryLater("kill/"+a.ID, 2*time.Second)
			r.after(2 * time.Second)
			return false, nil
		}
	}
	// 2. Shutdown snapshots, attachments and claims.
	all := true
	reason := releaseReason(b)
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		if !c.releaseOnStop(ctx, r, vs, reason) {
			all = false
		}
	}
	if !all {
		return false, nil
	}
	// 3. Release the allocation and the slot.
	res := c.nodes.Do(a.Node, a.ID+".release", r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_Release{Release: &nodepb.Release{AllocationId: a.ID}}})
	if res == nil {
		return false, nil
	}
	if !ok(res) && res.Status != nodepb.ResultStatus_RESULT_STATUS_REJECTED {
		c.log.Info("release failed; the node drops it on reconnect", "allocation", a.ID, "err", resultErr(res))
	}
	c.deletePod(ctx, b.Namespace, a.PodName, types.UID(a.PodUID))
	c.retryClear("kill/" + a.ID)
	return true, nil
}

// salvageWait handles the release of a failed attempt whose node is
// unreachable and not known to be gone: wait up to
// spec.reschedule.salvageTimeout from the end of the attempt for the node
// to return with the overlays; then, with nodeLoss Abandon, abandon them
// and reschedule from the newest Ready snapshots, or, with Fence, wait for
// the node to return or be fenced.
func (c *Controller) salvageWait(ctx context.Context, r *blipRun) (bool, error) {
	b := r.b
	a := b.Status.Allocation
	p := b.Spec.Reschedule
	end := r.now
	if lf := b.Status.LastFailure; lf != nil {
		end = lf.Time.Time
	}
	limit := end.Add(p.SalvageTimeoutOrDefault())
	if r.now.Before(limit) {
		setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, true, api.ReasonNodeUnreachable,
			fmt.Sprintf("node %s is unreachable; waiting until %s for it to return to save the volumes", a.Node, limit.UTC().Format(time.RFC3339)))
		r.after(min(5*time.Second, limit.Sub(r.now)))
		return false, nil
	}
	if p != nil && p.NodeLoss == v1.NodeLossAbandon {
		return c.abandon(ctx, r, fmt.Sprintf("node %s did not return within the salvage timeout; the writes since the last snapshot are abandoned", a.Node))
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, false, api.ReasonNodeUnreachable,
		fmt.Sprintf("node %s is unreachable and not fenced (taint %s); waiting for it to return or be fenced", a.Node, api.TaintOutOfService))
	r.after(5 * time.Second)
	return false, nil
}

// releaseOnStop releases one attachment after the VM stopped.
func (c *Controller) releaseOnStop(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, reason v1.ReleaseReason) bool {
	switch vs.State {
	case v1.VolumeReleased, v1.VolumeFailed:
		return true
	case v1.VolumeReserving:
		if vs.Generation > 0 {
			if err := c.releaseClaim(ctx, r.b, vs); err != nil {
				vs.Message = err.Error()
				return false
			}
		}
		vs.State, vs.ShutdownSnapshot = v1.VolumeReleased, nil
		return true
	case v1.VolumeAttaching:
		if c.nodes.Pending(attachPrefix(r.b.Status.Allocation, vs)) {
			return false
		}
		// Never attached: nothing was written, nothing to save.
		vs.ShutdownSnapshot = nil
	}
	return c.releaseVolume(ctx, r, vs, reason)
}

// releaseVolume saves the shutdown snapshot (unless skipped), then
// releases the attachment on the node, unexports the origin and gives back
// the hold and the claim. The VM must be stopped or the volume detached.
func (c *Controller) releaseVolume(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, reason v1.ReleaseReason) bool {
	b := r.b
	a := b.Status.Allocation
	if ss := vs.ShutdownSnapshot; ss != nil && !ssSettled(ss) {
		if vs.State != v1.VolumeCapturing && vs.State != v1.VolumePublishing {
			vs.State = v1.VolumeCapturing
		}
		if !c.shutdownSnapshot(ctx, r, vs, reason) {
			return false
		}
	}
	pre := attachPrefix(a, vs)
	if c.nodes.Connected(a.Node) {
		key := "relatt/" + vs.AttachmentID
		n, due := c.retryState(key)
		if !due {
			r.after(time.Second)
			return false
		}
		res := c.nodes.Do(a.Node, opN(pre+"relatt", n), r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_ReleaseAttachment{ReleaseAttachment: &nodepb.ReleaseAttachment{
			AllocationId: a.ID, AttachmentId: vs.AttachmentID, Generation: vs.Generation,
		}}})
		if res == nil {
			return false
		}
		if !ok(res) && res.Code != nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION && res.Code != nodepb.ErrorCode_ERROR_CODE_NOT_FOUND {
			vs.Message = "release attachment: " + resultErr(res)
			c.retryLater(key, 5*time.Second)
			r.after(5 * time.Second)
			return false
		}
	} else if gone, _ := c.nodeGone(ctx, a.Node); !gone {
		return false
	}
	if in, err := c.inputVol(ctx, b, vs); err == nil && in != nil {
		pending := false
		if s := in.Snapshot(vs.Snapshot); s != nil {
			for _, rep := range s.Replicas {
				if !c.nodes.Connected(rep.Node) {
					continue
				}
				if c.nodes.Do(rep.Node, pre+"unexp."+rep.Node, r.owner(), c.opts.CommandTimeout, unexportCmd(s.ContentID, api.HostNQN(a.Node))) == nil {
					pending = true
				}
			}
		}
		if pending {
			return false
		}
	}
	if err := c.releaseClaim(ctx, b, vs); err != nil {
		vs.Message = err.Error()
		return false
	}
	if strings.HasPrefix(vs.Message, api.ReasonAttachFailed) {
		vs.State = v1.VolumeFailed
	} else {
		vs.State, vs.Message = v1.VolumeReleased, ""
	}
	c.retryClear(vs.AttachmentID)
	return true
}

// shutdownSnapshot finishes a capture in flight, then takes and saves the
// final snapshot of an attachment. It reports whether the shutdown
// snapshot settled.
func (c *Controller) shutdownSnapshot(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, reason v1.ReleaseReason) bool {
	b := r.b
	ss := vs.ShutdownSnapshot
	if ss.Reason == "" {
		ss.Reason = reason
	}
	if ss.State == "" {
		ss.State = v1.ShutdownSnapshotPending
	}
	v, err := c.inputVol(ctx, b, vs)
	if err != nil {
		return false
	}
	if v == nil {
		ss.State, ss.Message = v1.ShutdownSnapshotFailed, "the blipvol is gone"
		return true
	}
	if !ownClaim(v, string(b.UID), vs.AttachmentID, vs.Generation) {
		ss.State, ss.Message = v1.ShutdownSnapshotUnavailable, "the attachment no longer holds the claim"
		return true
	}
	if p := pendingCapture(v, vs.AttachmentID); p != nil && p.Sequence != ss.Sequence {
		if ss.Sequence == 0 && p.Reason == snapReason(ss.Reason) {
			// Appended by an earlier pass whose status write was lost.
			ss.Sequence = p.Sequence
		} else {
			// An interval or derive capture finishes first.
			st, msg := c.driveCapture(ctx, r, vs, v, p, nil)
			switch st {
			case savePending:
				return false
			case saveGone:
				ss.State, ss.Message = v1.ShutdownSnapshotUnavailable, msg
				metricSnapshots.WithLabelValues(snapKind(snapReason(ss.Reason)), "unavailable").Inc()
				return true
			}
			r.after(100 * time.Millisecond)
			return false
		}
	}
	if ss.Sequence == 0 {
		if ss.Reason != v1.ReleaseReschedule && v.SkipShutdown() {
			ss.State, ss.Message = v1.ShutdownSnapshotSkipped, "snapshotPolicy.skipShutdown is set; writes since the newest snapshot are discarded"
			return true
		}
		if !c.dropLocals(ctx, r, vs, v) {
			return false
		}
		s, err := c.startCapture(ctx, r, vs, v, snapReason(ss.Reason))
		if err != nil {
			if rf, ok := err.(*refusal); ok {
				ss.State, ss.Message = v1.ShutdownSnapshotFailed, rf.msg
				return true
			}
			vs.Message = err.Error()
			r.after(2 * time.Second)
			return false
		}
		ss.Sequence = s.Sequence
		r.after(100 * time.Millisecond)
		return false
	}
	s := v.Snapshot(ss.Sequence)
	if s == nil {
		if ss.Sequence > v.Status.LastSequence {
			r.after(100 * time.Millisecond) // the cache is behind
			return false
		}
		ss.State, ss.Message = v1.ShutdownSnapshotFailed, fmt.Sprintf("snapshot %d was deleted", ss.Sequence)
		return true
	}
	var result *v1.RunResult
	if ss.Reason != v1.ReleaseDetach && ss.Reason != v1.ReleaseReschedule {
		result = runResult(b)
	}
	st, msg := c.driveCapture(ctx, r, vs, v, s, result)
	switch st {
	case saveReady:
		ss.State, ss.Message = v1.ShutdownSnapshotReady, ""
		vs.State = v1.VolumePublishing
		return true
	case saveFailed:
		ss.State, ss.Message = v1.ShutdownSnapshotFailed, msg
		return true
	case saveGone:
		ss.State, ss.Message = v1.ShutdownSnapshotUnavailable, msg
		metricSnapshots.WithLabelValues(snapKind(s.Reason), "unavailable").Inc()
		return true
	}
	if msg != "" {
		ss.Message = msg
	}
	return false
}

// runResult is the result of the run, recorded on its shutdown snapshots.
func runResult(b *v1.Blip) *v1.RunResult {
	var exit int32
	if b.Status.LastExitCode != nil {
		exit = *b.Status.LastExitCode
	}
	return &v1.RunResult{ExitCode: exit, RestartCount: b.Status.RestartCount}
}

// abandon gives up every attachment of the allocation without the node:
// shutdown snapshots not saved become Unavailable, captures in flight
// fail, holds and claims are released (the next claim has a higher
// generation, which the node honors when it returns), and the slot pod is
// deleted. The node is told to release the allocation when it returns.
func (c *Controller) abandon(ctx context.Context, r *blipRun, why string) (bool, error) {
	b := r.b
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		if vs.State == v1.VolumeReleased || vs.State == v1.VolumeFailed {
			continue
		}
		if vs.State == v1.VolumeReserving || vs.State == v1.VolumeAttaching {
			vs.ShutdownSnapshot = nil
		}
		if ss := vs.ShutdownSnapshot; ss != nil && !ssSettled(ss) {
			if ss.Reason == "" {
				ss.Reason = releaseReason(b)
			}
			ss.State, ss.Message = v1.ShutdownSnapshotUnavailable, why
			metricSnapshots.WithLabelValues(snapKind(snapReason(ss.Reason)), "unavailable").Inc()
		}
		if vs.Generation > 0 {
			c.unexportAttached(ctx, b, vs)
			if err := c.releaseClaim(ctx, b, vs); err != nil {
				return false, err
			}
		}
		vs.State = v1.VolumeReleased
	}
	a := b.Status.Allocation
	c.log.Info("abandoning allocation", "blip", r.key, "allocation", a.ID, "node", a.Node, "why", why)
	c.deletePod(ctx, b.Namespace, a.PodName, types.UID(a.PodUID))
	return true, nil
}

// unexportAttached tells the connected replicas of the snapshot an
// abandoned attachment started from to stop exporting it to the node
// (best effort, not waited for).
func (c *Controller) unexportAttached(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) {
	a := b.Status.Allocation
	if a == nil || vs.BlipVolRef == nil {
		return
	}
	in, err := c.inputVol(ctx, b, vs)
	if err != nil || in == nil {
		return
	}
	s := in.Snapshot(vs.Snapshot)
	if s == nil {
		return
	}
	for _, rep := range s.Replicas {
		if c.nodes.Connected(rep.Node) {
			c.nodes.Send(rep.Node, unexportCmd(s.ContentID, api.HostNQN(a.Node)))
		}
	}
}

// nodeGone reports whether a node is known to be gone: it has the
// out-of-service taint, or its Node object does not exist.
func (c *Controller) nodeGone(ctx context.Context, node string) (bool, string) {
	if node == "" {
		return false, ""
	}
	var n corev1.Node
	err := c.Get(ctx, types.NamespacedName{Name: node}, &n)
	if apierrors.IsNotFound(err) {
		return true, fmt.Sprintf("node %s no longer exists", node)
	}
	if err != nil {
		return false, ""
	}
	for _, t := range n.Spec.Taints {
		if t.Key == api.TaintOutOfService {
			return true, fmt.Sprintf("node %s was fenced", node)
		}
	}
	return false, ""
}

// fenced reports whether the node is fenced (out-of-service taint) or its
// Node object is gone.
func (c *Controller) fenced(ctx context.Context, node string) bool {
	gone, _ := c.nodeGone(ctx, node)
	return gone
}

// retry state for operations retried with new operation IDs.
type retryEntry struct {
	n         int
	notBefore time.Time
}

// retryState returns the attempt number of key and whether it is due.
func (c *Controller) retryState(key string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.retry[key]
	if e == nil {
		return 0, true
	}
	return e.n, !timeNow().Before(e.notBefore)
}

// retryLater moves key to its next attempt after d.
func (c *Controller) retryLater(key string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.retry[key]
	if e == nil {
		e = &retryEntry{}
		c.retry[key] = e
	}
	e.n++
	e.notBefore = timeNow().Add(d)
}

// retryClearKey drops the retry state of one key.
func (c *Controller) retryClearKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.retry, key)
}

// retryClear drops retry state of keys containing id, and the dropped
// local snapshots of attachment id.
func (c *Controller) retryClear(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.dropped, id)
	for k := range c.retry {
		if strings.Contains(k, id) {
			delete(c.retry, k)
		}
	}
}

// opN is the operation ID of attempt n of op: op itself for the first
// attempt (so IDs of commands that succeed first time stay stable), then
// op.rN. Nodes cache results by operation ID, so a retry after a failure
// needs a new one.
func opN(op string, n int) string {
	if n == 0 {
		return op
	}
	return fmt.Sprintf("%s.r%d", op, n)
}
