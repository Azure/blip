package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// Rescheduling (spec.reschedule): a retryable failure of an allocated
// Blip does not set Failed. Instead Rescheduling=True is set and the
// allocation is released like any other run, except that every attached
// volume always gets a shutdown snapshot with reason Reschedule (even with
// skipShutdown: the next attempt continues the same run). When the release
// is done the allocation is cleared and the Blip waits Pending until
// status.nextScheduleTime; the next attempt attaches each BlipVol's newest
// Ready snapshot. startTime and deadline are kept: maxTTLSeconds covers
// all attempts.
//
// A node that is unreachable when the attempt ends gets
// spec.reschedule.salvageTimeout to return (release.go, salvageWait).

// rescheduling reports whether the current allocation is released for a
// reschedule (also while the release waits for an unreachable node with
// Rescheduling=False/NodeUnreachable), or the Blip waits for its next
// attempt.
func rescheduling(b *v1.Blip) bool {
	cd := findCond(b.Status.Conditions, api.CondRescheduling)
	if cd == nil {
		return false
	}
	return cd.Status == metav1.ConditionTrue || (cd.Reason == api.ReasonNodeUnreachable && b.Status.Allocation != nil)
}

// retryableReason reports whether a failure with the reason may succeed in
// a new VM. Deadline, cancel and bad inputs never will.
func retryableReason(reason string) bool {
	switch reason {
	case api.ReasonError, api.ReasonNodeLost, api.ReasonSlotLost, api.ReasonHypervisorExited,
		api.ReasonStartFailed, api.ReasonAttachFailed, api.ReasonGuestPanic, api.ReasonInitExited, api.ReasonBootFailed:
		return true
	}
	return false
}

// rescheduleBackoff is the wait before reschedule n (1 based):
// initial * 2^(n-1), at most max.
func rescheduleBackoff(p *v1.ReschedulePolicy, n int32) time.Duration {
	initial, maxB := time.Duration(p.InitialBackoffSeconds)*time.Second, time.Duration(p.MaxBackoffSeconds)*time.Second
	if initial <= 0 {
		initial = 10 * time.Second
	}
	if maxB <= 0 {
		maxB = 300 * time.Second
	}
	return backoff(int(max(n-1, 0)), initial, max(maxB, initial))
}

// endAttempt ends the run of the current allocation with a failure: a
// reschedule when the policy allows it, otherwise Failed.
func (c *Controller) endAttempt(r *blipRun, reason, msg string) {
	b := r.b
	p := b.Spec.Reschedule
	if p == nil || !retryableReason(reason) || r.deleted() {
		setFailed(b, reason, msg)
		return
	}
	if p.Limit != nil && b.Status.RescheduleCount >= *p.Limit {
		setFailed(b, reason, fmt.Sprintf("%s (reschedule limit %d reached)", msg, *p.Limit))
		return
	}
	wait := rescheduleBackoff(p, b.Status.RescheduleCount+1)
	if d := b.Status.Deadline; d != nil && !r.now.Add(wait).Before(d.Time) {
		setFailed(b, reason, fmt.Sprintf("%s (the deadline is before the next attempt)", msg))
		return
	}
	now := metav1.NewTime(r.now)
	b.Status.LastFailure = &v1.AttemptFailure{Reason: reason, Message: firstLine(msg), Time: now}
	setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, true, reason, firstLine(msg))
	b.Status.Phase = v1.BlipSaving
	// Every attached volume saves its overlay for the next attempt.
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		if vs.State != v1.VolumeAttached {
			continue
		}
		if vs.ShutdownSnapshot == nil || vs.ShutdownSnapshot.State == "" {
			vs.ShutdownSnapshot = &v1.ShutdownSnapshot{Reason: v1.ReleaseReschedule}
		}
	}
	c.log.Info("rescheduling", "blip", r.key, "reason", reason, "message", msg, "count", b.Status.RescheduleCount+1)
}

// finishReschedule runs after the release of a rescheduled attempt: it
// resets the volume entries for the next attempt (which attaches each
// BlipVol's newest Ready snapshot), records where an attempt resumes from
// an older snapshot than where this one stopped, and returns the Blip to
// Pending until the backoff ends.
func (c *Controller) finishReschedule(ctx context.Context, r *blipRun) (reconcile.Result, error) {
	b := r.b
	a := b.Status.Allocation
	end := r.now
	if lf := b.Status.LastFailure; lf != nil {
		end = lf.Time.Time
	}
	var vols []v1.BlipVolumeStatus
	var lost []string
	for i := range b.Status.Volumes {
		vs := b.Status.Volumes[i]
		if specVol(b, vs.Name) == nil {
			continue
		}
		nvs := v1.BlipVolumeStatus{Name: vs.Name, BlipVolRef: vs.BlipVolRef}
		if ss := vs.ShutdownSnapshot; ss != nil && ss.Reason == v1.ReleaseReschedule && ss.State != v1.ShutdownSnapshotReady {
			v, err := c.inputVol(ctx, b, &vs)
			if err != nil {
				return reconcile.Result{}, err
			}
			if v != nil {
				if cur := v.NewestReady(); cur != nil {
					nvs.ResumedFrom = &v1.ResumedFrom{Sequence: cur.Sequence, CaptureTime: cur.CaptureTime}
					window := "unknown"
					if cur.CaptureTime != nil {
						window = end.Sub(cur.CaptureTime.Time).Round(time.Second).String()
					}
					lost = append(lost, fmt.Sprintf("%s resumes from snapshot %d (%s of writes lost: %s)", vs.Name, cur.Sequence, window, ss.State))
				}
			}
			nvs.Message = fmt.Sprintf("the overlay was not saved (%s: %s)", ss.State, ss.Message)
		}
		vols = append(vols, nvs)
	}
	c.forgetBlip(ctx, b)
	c.schedMu.Lock()
	for pod, as := range c.assumed {
		if as.allocID == a.ID {
			delete(c.assumed, pod)
		}
	}
	c.schedMu.Unlock()
	b.Status.Volumes = vols
	b.Status.Allocation = nil
	b.Status.PodIP = ""
	b.Status.StopRequestedTime = nil
	b.Status.RescheduleCount++
	next := metav1.NewTime(r.now.Add(rescheduleBackoff(b.Spec.Reschedule, b.Status.RescheduleCount)))
	b.Status.NextScheduleTime = &next
	b.Status.Phase = v1.BlipPending
	msg := ""
	if lf := b.Status.LastFailure; lf != nil {
		msg = fmt.Sprintf("attempt %d ended (%s: %s)", b.Status.RescheduleCount, lf.Reason, lf.Message)
	}
	reason := api.ReasonRescheduleBackoff
	if len(lost) > 0 {
		reason = api.ReasonResumedFromOlderSnapshot
		msg = firstLine(msg + "; " + strings.Join(lost, "; "))
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, true, reason, msg)
	setCond(&b.Status.Conditions, b.Generation, api.CondScheduled, false, api.ReasonRescheduleBackoff, "next attempt at "+next.UTC().Format(time.RFC3339))
	setCond(&b.Status.Conditions, b.Generation, api.CondStarted, false, api.ReasonRescheduled, "")
	if condReason(b.Status.Conditions, api.CondVolumesReady) != "" {
		setCond(&b.Status.Conditions, b.Generation, api.CondVolumesReady, false, api.ReasonRescheduled, "")
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondFinished, false, api.ReasonRescheduled, "")
	metricReschedules.Inc()
	return reconcile.Result{RequeueAfter: next.Sub(r.now)}, nil
}

// noteResumed corrects the resumedFrom of a volume once its claim names
// the snapshot the attempt actually starts from (finishReschedule recorded
// the newest Ready snapshot it saw, which may have changed since).
func (c *Controller) noteResumed(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) {
	rf := vs.ResumedFrom
	if rf == nil || vs.Snapshot == 0 || rf.Sequence == vs.Snapshot {
		return
	}
	rf.Sequence, rf.CaptureTime = vs.Snapshot, nil
	if v, err := c.inputVol(ctx, b, vs); err == nil && v != nil {
		if s := v.Snapshot(vs.Snapshot); s != nil {
			rf.CaptureTime = s.CaptureTime
		}
	}
}

// resumedLost describes the volumes whose current attempt resumed from an
// older snapshot than where the previous attempt stopped, using the
// snapshots actually claimed. It is empty when no writes were lost.
func resumedLost(b *v1.Blip) string {
	var lost []string
	for _, vs := range b.Status.Volumes {
		rf := vs.ResumedFrom
		if rf == nil {
			continue
		}
		window := "unknown"
		if lf := b.Status.LastFailure; lf != nil && rf.CaptureTime != nil {
			window = lf.Time.Sub(rf.CaptureTime.Time).Round(time.Second).String()
		}
		lost = append(lost, fmt.Sprintf("%s resumed from snapshot %d (%s of writes lost)", vs.Name, rf.Sequence, window))
	}
	return strings.Join(lost, "; ")
}

// rescheduleWait keeps a rescheduled Blip Pending until its backoff ends,
// and fails it once the deadline passed. It reports whether schedule must
// stop here.
func (c *Controller) rescheduleWait(r *blipRun) (reconcile.Result, bool) {
	b := r.b
	if d := b.Status.Deadline; d != nil && !r.now.Before(d.Time) {
		setFailed(b, api.ReasonTTLExceeded, "the deadline passed before the next attempt")
		return reconcile.Result{Requeue: true}, true
	}
	n := b.Status.NextScheduleTime
	if n == nil || !r.now.Before(n.Time) {
		return reconcile.Result{}, false
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondScheduled, false, api.ReasonRescheduleBackoff, "next attempt at "+n.UTC().Format(time.RFC3339))
	b.Status.Phase = v1.BlipPending
	wait := n.Sub(r.now)
	if d := b.Status.Deadline; d != nil {
		wait = min(wait, d.Sub(r.now)+time.Second)
	}
	return reconcile.Result{RequeueAfter: wait}, true
}

// attemptStart is when the current attempt claimed its slot.
func attemptStart(b *v1.Blip) *metav1.Time {
	for _, cd := range b.Status.Conditions {
		if cd.Type == api.CondScheduled && cd.Status == metav1.ConditionTrue && !cd.LastTransitionTime.IsZero() && b.Status.RescheduleCount > 0 {
			t := cd.LastTransitionTime
			return &t
		}
	}
	return b.Status.StartTime
}
