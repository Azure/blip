package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// Save of one local snapshot of an attachment into a snapshot entry of
// its BlipVol (docs/design.md section 7.8).

type saveResult int

const (
	savePending saveResult = iota
	saveReady
	saveFailed
	saveGone // the local snapshot or attachment is gone on the compute node
)

// saveState is the in-memory state of a save, by destination content.
// After a controller restart a save starts a new attempt.
type saveState struct {
	attempt   string
	tries     int
	notBefore time.Time
	start     time.Time
	counted   bool
}

func (c *Controller) save(content string) *saveState {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.saves[content]
	if x == nil {
		x = &saveState{attempt: randID(), start: timeNow()}
		c.saves[content] = x
	}
	return x
}

func (c *Controller) saveDone(content string) {
	c.mu.Lock()
	delete(c.saves, content)
	c.mu.Unlock()
}

// saveActive reports whether a save into content is in progress here.
func (c *Controller) saveActive(content string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.saves[content]
	return ok
}

// transfer drives the save of the local snapshot of attachment vs
// with the sequence of entry s into the content of s (group and base are
// fixed in the entry when it is appended). result is recorded on the
// entry when it becomes Ready.
func (c *Controller) transfer(ctx context.Context, r *blipRun, v *v1.BlipVol, s *v1.VolSnapshot, vs *v1.BlipVolumeStatus, result *v1.RunResult) (saveResult, string) {
	a := r.b.Status.Allocation
	switch s.State {
	case v1.SnapshotReady:
		return saveReady, ""
	case v1.SnapshotFailed:
		return saveFailed, s.Message
	}
	content := s.ContentID
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		return savePending, err.Error()
	}
	g := cfg.Group(s.StorageGroup)
	if g == nil {
		return savePending, fmt.Sprintf("storage group %q is not configured", s.StorageGroup)
	}
	members := c.connectedMembers(g)
	var sealed []string
	for _, m := range members {
		if ci := c.nodes.Info(m).Contents[content]; ci != nil && ci.Sealed {
			sealed = append(sealed, m)
		}
	}
	if len(sealed) >= 2 {
		return c.snapshotReady(ctx, r, v, s, vs, sealed, result)
	}
	x := c.save(content)
	if x.tries >= c.opts.TransferAttempts || timeNow().Sub(x.start) > c.opts.SaveTimeout {
		msg := fmt.Sprintf("save failed after %d attempts", x.tries)
		if err := c.markSnapFailed(ctx, v, s.Sequence, msg); err != nil {
			return savePending, err.Error()
		}
		return saveFailed, msg
	}
	if d := x.notBefore.Sub(timeNow()); d > 0 {
		r.after(d)
		return savePending, ""
	}
	if len(members) < 2 {
		r.after(5 * time.Second)
		return savePending, fmt.Sprintf("%d members of %s connected, need 2", len(members), g.Name)
	}
	full := s.Base == ""
	// The local base is the attachment's own earlier snapshot (its
	// baseline, kept on the compute node); 0 is the attached origin.
	var bseq int64
	if b := snapByContent(v, s.Base); b != nil && b.Writer != nil && b.Writer.AttachmentID == vs.AttachmentID {
		bseq = localSeq(vs, b.Sequence)
	}
	own, to := r.owner(), c.opts.CommandTimeout
	pre := "t-" + content + "-" + x.attempt + "."
	written := map[string]bool{}
	for _, m := range sealed {
		written[m] = true
	}
	var targets []*nodepb.Path
	var prepared []string
	pending := false
	for _, m := range members {
		if written[m] {
			continue
		}
		res := c.nodes.Do(m, pre+"prep."+m, own, to, &nodepb.Command{Op: &nodepb.Command_PrepareReceive{PrepareReceive: &nodepb.PrepareReceive{
			ContentId: content, BaseContentId: s.Base, SizeBytes: sizeBytes(v), Owner: volRef(v), Generation: vs.Generation,
			AllocationId: a.ID, AttachmentId: vs.AttachmentID,
		}}})
		if res == nil {
			pending = true
			continue
		}
		if !ok(res) || !res.GetPrepareReceive().GetOk() {
			c.log.Info("prepare receive failed", "node", m, "content", content, "err", resultErr(res))
			continue
		}
		res = c.nodes.Do(m, pre+"exp."+m, own, to, c.exportCmd(content, nodepb.ExportMode_EXPORT_MODE_READ_WRITE, a.Node, "", false))
		if res == nil {
			pending = true
			continue
		}
		prepared = append(prepared, m)
		if !ok(res) || res.GetExport().GetPath() == nil {
			c.log.Info("export for snapshot write failed", "node", m, "content", content, "err", resultErr(res))
			continue
		}
		targets = append(targets, res.GetExport().GetPath())
	}
	if pending {
		return savePending, ""
	}
	if len(targets)+len(written) < 2 {
		return c.failAttempt(ctx, r, x, pre, members, content, fmt.Sprintf("%d targets prepared, need 2", len(targets)+len(written)))
	}
	if len(targets) > 0 {
		res := c.nodes.Do(a.Node, pre+"write", own, c.opts.SaveTimeout, &nodepb.Command{Op: &nodepb.Command_WriteSnapshot{WriteSnapshot: &nodepb.WriteSnapshot{
			AllocationId: a.ID, AttachmentId: vs.AttachmentID, Generation: vs.Generation, Seq: localSeq(vs, s.Sequence), BaseSeq: bseq, Full: full,
			ContentId: content, Targets: targets,
		}}})
		if res == nil {
			return savePending, ""
		}
		wr := res.GetWriteSnapshot()
		for _, t := range wr.GetTargets() {
			if t.Ok {
				written[t.Node] = true
			}
		}
		if !x.counted && wr != nil {
			x.counted = true
			n := 0
			for _, t := range wr.Targets {
				if t.Ok {
					n++
				}
			}
			metricSnapshotWrittenBytes.Add(float64(wr.ChangedBytes) * float64(n))
		}
		if !ok(res) && (res.Code == nodepb.ErrorCode_ERROR_CODE_NOT_FOUND || res.Code == nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION) {
			c.cleanupContent(ctx, r, pre, members, content)
			c.saveDone(content)
			return saveGone, "write: " + resultErr(res)
		}
	}
	// The write is over: remove the read-write exports (Seal needs none).
	for _, m := range prepared {
		if c.nodes.Do(m, pre+"unexp."+m, own, to, unexportCmd(content, "")) == nil {
			pending = true
		}
	}
	if pending {
		return savePending, ""
	}
	if len(written) < 2 {
		return c.failAttempt(ctx, r, x, pre, members, content, fmt.Sprintf("%d targets written, need 2", len(written)))
	}
	var ok2 []string
	for _, m := range keys(written) {
		res := c.nodes.Do(m, pre+"seal."+m, own, to, sealCmd(content, volRef(v)))
		if res == nil {
			pending = true
		} else if ok(res) {
			ok2 = append(ok2, m)
		}
	}
	if pending {
		return savePending, ""
	}
	if len(ok2) < 2 {
		return c.failAttempt(ctx, r, x, pre, members, content, fmt.Sprintf("sealed on %d replicas, need 2", len(ok2)))
	}
	return c.snapshotReady(ctx, r, v, s, vs, ok2, result)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// failAttempt removes the partial content and schedules a new attempt.
func (c *Controller) failAttempt(ctx context.Context, r *blipRun, x *saveState, pre string, members []string, content, msg string) (saveResult, string) {
	if !c.cleanupContent(ctx, r, pre, members, content) {
		return savePending, msg
	}
	c.mu.Lock()
	x.tries++
	x.attempt = randID()
	x.counted = false
	x.notBefore = timeNow().Add(backoff(x.tries-1, time.Second, time.Minute))
	c.mu.Unlock()
	c.nodes.Forget(pre)
	c.log.Info("snapshot save attempt failed", "content", content, "attempt", x.tries, "err", msg)
	r.after(time.Second)
	return savePending, msg
}

// cleanupContent deletes content on the members; it reports whether done.
func (c *Controller) cleanupContent(ctx context.Context, r *blipRun, pre string, members []string, content string) bool {
	pending := false
	for _, m := range members {
		if c.nodes.Do(m, pre+"del."+m, r.owner(), c.opts.CommandTimeout, deleteContentCmd(content)) == nil {
			pending = true
		}
	}
	return !pending
}

// snapshotReady marks a captured snapshot Ready with its sealed replicas,
// makes it current and the baseline of the attachment. If the fresh copy
// shows the entry settled by another writer (Failed by a release, scrub or
// a retried failure) or gone, that outcome is returned instead.
func (c *Controller) snapshotReady(ctx context.Context, r *blipRun, v *v1.BlipVol, s *v1.VolSnapshot, vs *v1.BlipVolumeStatus, sealed []string, result *v1.RunResult) (saveResult, string) {
	seq := s.Sequence
	var fresh *v1.VolSnapshot
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: v.Namespace, Name: v.Name}, string(v.UID), func(x *v1.BlipVol) (bool, error) {
		fresh = nil
		e := x.Snapshot(seq)
		if e != nil {
			fresh = e.DeepCopy()
		}
		if e == nil || e.State != v1.SnapshotPending {
			return false, nil
		}
		e.State, e.Message = v1.SnapshotReady, ""
		e.Replicas = sealedList(sealed)
		if result != nil {
			e.Result = result.DeepCopy()
		}
		if cl := x.Status.Claim; ownClaim(x, string(r.b.UID), vs.AttachmentID, vs.Generation) && cl.Baseline < seq {
			cl.Baseline = seq
		}
		syncCurrent(x)
		fresh = e.DeepCopy()
		metricSnapshots.WithLabelValues(snapKind(e.Reason), "ready").Inc()
		if e.CaptureTime != nil {
			metricSnapshotLatency.WithLabelValues(snapKind(e.Reason)).Observe(timeNow().Sub(e.CaptureTime.Time).Seconds())
		}
		return true, nil
	})
	if err == errGone {
		return saveFailed, "the blipvol was deleted"
	}
	if err != nil {
		return savePending, err.Error()
	}
	c.saveDone(s.ContentID)
	switch {
	case fresh == nil:
		return saveFailed, fmt.Sprintf("snapshot %d was deleted", seq)
	case fresh.State == v1.SnapshotReady:
		return saveReady, ""
	case fresh.State == v1.SnapshotFailed:
		return saveFailed, fresh.Message
	}
	return savePending, ""
}

// markSnapFailed marks a Pending snapshot Failed.
func (c *Controller) markSnapFailed(ctx context.Context, v *v1.BlipVol, seq int64, msg string) error {
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: v.Namespace, Name: v.Name}, string(v.UID), func(x *v1.BlipVol) (bool, error) {
		return setSnapFailed(x, seq, msg, false), nil
	})
	if err == errGone {
		err = nil
	}
	c.saveDone(api.SnapshotContentID(string(v.UID), seq))
	return err
}
