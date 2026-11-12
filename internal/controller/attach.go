package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// Per-attachment state machine (status.volumes[].state):
//
//	Reserving -> Attaching -> Attached -> Detaching
//	          -> Capturing -> Publishing -> Released
//
// Attach failures go through Detaching (no snapshot) to Failed. A live
// detach waits while a capture of that volume is in flight.

func attachPrefix(a *v1.Allocation, vs *v1.BlipVolumeStatus) string {
	return a.ID + "." + vs.AttachmentID + "."
}

// reconcileAttachments diffs spec.volumes against status.volumes and drives
// each attachment. With initial set (before StartWorkload) only the initial
// volumes are attached; a failure is returned as a Blip failure reason.
func (c *Controller) reconcileAttachments(ctx context.Context, r *blipRun, initial bool) (string, string) {
	b := r.b
	// New attachments are acted on only after the status with their IDs
	// was written (a write from a stale copy fails), so nothing is ever
	// claimed or attached under an ID that is not recorded.
	fresh := map[string]bool{}
	if !initial {
		for _, sv := range b.Spec.Volumes {
			vs := volStatus(b, sv.Name)
			if vs != nil && vs.State != v1.VolumeReleased {
				continue
			}
			nvs := v1.BlipVolumeStatus{Name: sv.Name, AttachmentID: newID(), State: v1.VolumeReserving, DevicePath: api.GuestVolumePath(sv.Name)}
			if vs != nil {
				*vs = nvs
			} else {
				b.Status.Volumes = append(b.Status.Volumes, nvs)
			}
			fresh[sv.Name] = true
			r.after(100 * time.Millisecond)
		}
	}
	var drop []string
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		sv := specVol(b, vs.Name)
		if fresh[vs.Name] {
			continue
		}
		switch vs.State {
		case v1.VolumeReserving:
			if sv == nil {
				if vs.Generation > 0 {
					if err := c.releaseClaim(ctx, b, vs); err != nil {
						vs.Message = err.Error()
						continue
					}
				}
				drop = append(drop, vs.Name)
				continue
			}
			if reason, msg := c.reserve(ctx, r, vs, sv, initial); reason != "" {
				return reason, msg
			}
			if vs.State == v1.VolumeAttaching {
				if reason, msg := c.attach(ctx, r, vs, initial); reason != "" {
					return reason, msg
				}
			}
		case v1.VolumeAttaching:
			if reason, msg := c.attach(ctx, r, vs, initial); reason != "" {
				return reason, msg
			}
		case v1.VolumeAttached:
			if sv != nil {
				continue
			}
			if c.capturing(ctx, b, vs) {
				r.after(2 * time.Second)
				continue
			}
			vs.State = v1.VolumeDetaching
			c.detach(ctx, r, vs)
		case v1.VolumeDetaching:
			c.detach(ctx, r, vs)
		case v1.VolumeCapturing, v1.VolumePublishing:
			c.releaseVolume(ctx, r, vs, v1.ReleaseDetach)
		case v1.VolumeFailed:
			if sv == nil {
				drop = append(drop, vs.Name)
			}
		}
	}
	if len(drop) > 0 {
		b.Status.Volumes = slices.DeleteFunc(b.Status.Volumes, func(vs v1.BlipVolumeStatus) bool { return slices.Contains(drop, vs.Name) })
	}
	return "", ""
}

// freeDisk returns the lowest slot disk not used by a live attachment.
func freeDisk(b *v1.Blip, max int) (int32, bool) {
	used := map[int32]bool{}
	for _, vs := range b.Status.Volumes {
		if vs.SlotDisk != nil && vs.State != v1.VolumeReleased && vs.State != v1.VolumeFailed {
			used[*vs.SlotDisk] = true
		}
	}
	for d := int32(0); int(d) < max; d++ {
		if !used[d] {
			return d, true
		}
	}
	return 0, false
}

// reserve resolves and claims the BlipVol of a Reserving attachment and
// moves it to Attaching.
func (c *Controller) reserve(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, sv *v1.BlipVolume, initial bool) (string, string) {
	b := r.b
	if vs.BlipVolRef == nil || vs.Generation == 0 {
		var bv v1.BlipVol
		err := c.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: sv.BlipVolRef.Name}, &bv)
		switch {
		case apierrors.IsNotFound(err) || (err == nil && bv.DeletionTimestamp != nil):
			vs.Message = fmt.Sprintf("%s: blipvol %q not found", api.ReasonWaitingForBlipVol, sv.BlipVolRef.Name)
			r.after(10 * time.Second)
			return "", ""
		case err != nil:
			vs.Message = err.Error()
			return "", ""
		case bv.Status.Phase == v1.BlipVolFailed:
			if initial {
				return api.ReasonInputBlipVolFailed, fmt.Sprintf("blipvol %q failed", bv.Name)
			}
			vs.State, vs.Message = v1.VolumeFailed, fmt.Sprintf("%s: blipvol %q failed", api.ReasonInputBlipVolFailed, bv.Name)
			return "", ""
		case bv.Status.Phase != v1.BlipVolReady:
			vs.Message = fmt.Sprintf("%s: blipvol %q is not ready", api.ReasonWaitingForBlipVol, bv.Name)
			r.after(5 * time.Second)
			return "", ""
		}
		vs.BlipVolRef = &v1.ObjectRef{Name: bv.Name, UID: string(bv.UID)}
		vs.DevicePath = api.GuestVolumePath(vs.Name)
	}
	if vs.SlotDisk == nil {
		d, ok := freeDisk(b, c.nodes.Info(b.Status.Allocation.Node).DisksPerSlot())
		if !ok {
			vs.Message = fmt.Sprintf("%s: every disk of the slot is in use", api.ReasonTooManyVolumes)
			r.after(10 * time.Second)
			return "", ""
		}
		vs.SlotDisk = &d
	}
	// Takes the claim, or adopts it and records the allocation and node.
	gen, snap, err := c.claimVol(ctx, b, vs)
	if err != nil {
		if rf, ok := err.(*refusal); ok {
			if initial && vs.Generation > 0 {
				return api.ReasonAttachFailed, rf.msg
			}
			vs.Message = rf.Error()
			r.after(3 * time.Second)
			return "", ""
		}
		vs.Message = err.Error()
		r.after(2 * time.Second)
		return "", ""
	}
	vs.Generation, vs.Snapshot = gen, snap
	c.noteResumed(ctx, b, vs)
	// The shutdown snapshot is on by default; skipShutdown (mutable) is
	// read at release.
	vs.ShutdownSnapshot = &v1.ShutdownSnapshot{}
	vs.State, vs.Message = v1.VolumeAttaching, ""
	return "", ""
}

// attach exports the snapshot the attachment starts from read-only to the compute node and hot-plugs it.
func (c *Controller) attach(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus, initial bool) (string, string) {
	b := r.b
	a := b.Status.Allocation
	own, to, pre := r.owner(), c.opts.CommandTimeout, attachPrefix(a, vs)
	failed := func(msg string) (string, string) {
		if initial {
			return api.ReasonAttachFailed, fmt.Sprintf("volume %s: %s", vs.Name, msg)
		}
		vs.State, vs.Message, vs.ShutdownSnapshot = v1.VolumeDetaching, api.ReasonAttachFailed+": "+msg, nil
		return "", ""
	}
	in, err := c.inputVol(ctx, b, vs)
	if err != nil {
		return "", ""
	}
	if in == nil {
		return failed("the blipvol is gone")
	}
	snap := in.Snapshot(vs.Snapshot)
	if snap == nil || snap.State != v1.SnapshotReady {
		return failed(fmt.Sprintf("snapshot %d of the blipvol is gone", vs.Snapshot))
	}
	// Nodes cache failed results by operation ID: a retry after a
	// transient failure uses new IDs (<op>.rN) for the exports and the
	// attach.
	key := "attach/" + vs.AttachmentID
	n, due := c.retryState(key)
	if !due {
		r.after(time.Second)
		return "", ""
	}
	retry := func(msg string) (string, string) {
		if n+1 >= attachAttempts {
			return failed(fmt.Sprintf("%s (after %d attempts)", msg, n+1))
		}
		vs.Message = fmt.Sprintf("attach attempt %d failed: %s", n+1, msg)
		d := attachBackoff(n)
		c.retryLater(key, d)
		r.after(d)
		return "", ""
	}
	var paths []*nodepb.Path
	pending := false
	for _, s := range c.snapReplicas(snap) {
		res := c.nodes.Do(s, opN(pre+"exp."+s, n), own, to, c.exportCmd(snap.ContentID, nodepb.ExportMode_EXPORT_MODE_READ_ONLY, a.Node, a.ID, false))
		if res == nil {
			pending = true
		} else if ok(res) && res.GetExport().GetPath() != nil {
			paths = append(paths, res.GetExport().GetPath())
		}
	}
	if pending {
		return "", ""
	}
	if len(paths) == 0 {
		return retry("no replica of the blipvol could be exported")
	}
	res := c.nodes.Do(a.Node, opN(pre+"attach", n), own, to, &nodepb.Command{Op: &nodepb.Command_AttachVolume{AttachVolume: &nodepb.AttachVolume{
		AllocationId: a.ID, AttachmentId: vs.AttachmentID, Generation: vs.Generation, Uid: vs.BlipVolRef.UID, Name: vs.Name,
		ContentId: snap.ContentID, SizeBytes: sizeBytes(in), OriginPaths: paths, SlotDisk: *vs.SlotDisk, Blipvol: volRef(in),
	}}})
	if res == nil {
		return "", ""
	}
	if !ok(res) {
		if transientAttach(res) {
			return retry(resultErr(res))
		}
		return failed(resultErr(res))
	}
	if p := res.GetAttachVolume().GetGuestPath(); p != "" {
		vs.DevicePath = p
	}
	vs.State, vs.Message = v1.VolumeAttached, ""
	c.retryClearKey(key)
	return "", ""
}

// detachBackoff is the wait after failed DetachVolume attempt n: 5s
// doubling up to 5 minutes.
func detachBackoff(n int) time.Duration {
	return min(5*time.Second<<min(n, 10), 5*time.Minute)
}

// attachAttempts bounds the AttachVolume attempts (with their exports) of
// one attachment before it fails with AttachFailed.
const attachAttempts = 4

// attachBackoff is the wait after failed attempt n (0 based): 2s, 4s, 8s...
func attachBackoff(n int) time.Duration {
	return min(2*time.Second<<n, time.Minute)
}

// transientAttach reports whether a failed AttachVolume may succeed when
// retried: node-side failures (hot-plug, storage, timeouts). A
// rejection (stale or conflicting generation, slot disk in use, VM gone)
// or an unknown allocation never will.
func transientAttach(res *nodepb.CommandResult) bool {
	switch res.Status {
	case nodepb.ResultStatus_RESULT_STATUS_FAILED, nodepb.ResultStatus_RESULT_STATUS_DEADLINE_EXCEEDED:
	default:
		return false
	}
	switch res.Code {
	case nodepb.ErrorCode_ERROR_CODE_NOT_FOUND, nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION, nodepb.ErrorCode_ERROR_CODE_CONFLICT:
		return false
	}
	return true
}

// inputVol returns the BlipVol of an attachment, or nil if it is gone.
func (c *Controller) inputVol(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) (*v1.BlipVol, error) {
	if vs.BlipVolRef == nil {
		return nil, nil
	}
	var bv v1.BlipVol
	err := c.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: vs.BlipVolRef.Name}, &bv)
	if apierrors.IsNotFound(err) || (err == nil && string(bv.UID) != vs.BlipVolRef.UID) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &bv, nil
}

// detach unplugs a live attachment (forced: the guest is not asked).
func (c *Controller) detach(ctx context.Context, r *blipRun, vs *v1.BlipVolumeStatus) {
	b := r.b
	a := b.Status.Allocation
	key := "detach/" + vs.AttachmentID
	n, due := c.retryState(key)
	if !due {
		r.after(time.Second)
		return
	}
	res := c.nodes.Do(a.Node, fmt.Sprintf("%sdetach.%d", attachPrefix(a, vs), n), r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_DetachVolume{DetachVolume: &nodepb.DetachVolume{
		AllocationId: a.ID, AttachmentId: vs.AttachmentID, Generation: vs.Generation,
	}}})
	if res == nil {
		return
	}
	switch {
	case res.Code == nodepb.ErrorCode_ERROR_CODE_NOT_FOUND && !c.nodes.ReportsAlloc(a.Node, a.ID):
		// The node has no record of the allocation (rebooted, or
		// released it), so no VM of it holds the device: detached. The
		// release below finds no overlay (CaptureLocal NOT_FOUND).
		c.log.Info("detach: allocation unknown to the node, treating as detached", "allocation", a.ID, "attachment", vs.AttachmentID)
	case !ok(res):
		// NOT_FOUND while the node still reports the allocation is
		// inconsistent: refresh the node state (ListState, applied when
		// it returns) and retry with a growing backoff, so the next
		// attempt sees state and answer agree.
		vs.Message = "detach: " + resultErr(res)
		if res.Code == nodepb.ErrorCode_ERROR_CODE_NOT_FOUND {
			c.nodes.Do(a.Node, opN(attachPrefix(a, vs)+"detach-ls", n), r.owner(), c.opts.CommandTimeout, &nodepb.Command{Op: &nodepb.Command_ListState{ListState: &nodepb.ListState{}}})
		}
		d := detachBackoff(n)
		c.retryLater(key, d)
		r.after(d)
		return
	}
	if vs.ShutdownSnapshot != nil {
		vs.State = v1.VolumeCapturing
	}
	c.releaseVolume(ctx, r, vs, v1.ReleaseDetach)
}
