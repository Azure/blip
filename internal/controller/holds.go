package controller

import (
	"context"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// Claims and holds live in BlipVol status and are written with the live
// client and a resourceVersion precondition (status update), so a claim and
// the deletionTimestamp of the same BlipVol can never both win: whichever
// write comes second sees the other or fails with a conflict and re-reads.

// refusal is a claim or hold that cannot be taken now.
type refusal struct{ reason, msg string }

func (r *refusal) Error() string { return r.reason + ": " + r.msg }

func blipHolder(b *v1.Blip) v1.HolderRef {
	return v1.HolderRef{Kind: "Blip", Namespace: b.Namespace, Name: b.Name, UID: string(b.UID)}
}

func volHolder(bv *v1.BlipVol) v1.HolderRef {
	return v1.HolderRef{Kind: "BlipVol", Namespace: bv.Namespace, Name: bv.Name, UID: string(bv.UID)}
}

// errGone is returned when the BlipVol does not exist (or has another UID).
var errGone = fmt.Errorf("blipvol is gone")

// updateVolStatus applies f to a fresh copy of the BlipVol and writes the
// status if f reports a change, retrying on conflicts. uid, if set, must
// match.
func (c *Controller) updateVolStatus(ctx context.Context, key types.NamespacedName, uid string, f func(*v1.BlipVol) (bool, error)) (*v1.BlipVol, error) {
	for range 8 {
		var bv v1.BlipVol
		err := c.live.Get(ctx, key, &bv)
		if apierrors.IsNotFound(err) || (err == nil && uid != "" && string(bv.UID) != uid) {
			return nil, errGone
		}
		if err != nil {
			return nil, err
		}
		changed, err := f(&bv)
		if err != nil || !changed {
			return &bv, err
		}
		err = c.live.Status().Update(ctx, &bv)
		if apierrors.IsConflict(err) {
			continue
		}
		if apierrors.IsNotFound(err) {
			return nil, errGone
		}
		return &bv, err
	}
	return nil, fmt.Errorf("blipvol %s keeps changing", key)
}

func hasHold(bv *v1.BlipVol, kind v1.HoldKind, holderUID string) bool {
	return slices.ContainsFunc(bv.Status.Holds, func(h v1.Hold) bool { return h.Kind == kind && h.Holder.UID == holderUID })
}

func setHold(bv *v1.BlipVol, kind v1.HoldKind, h v1.HolderRef, msg string) bool {
	if hasHold(bv, kind, h.UID) {
		return false
	}
	now := metav1.NewTime(timeNow())
	bv.Status.Holds = append(bv.Status.Holds, v1.Hold{Kind: kind, Holder: h, Since: &now, Message: msg})
	return true
}

func removeHold(bv *v1.BlipVol, kind v1.HoldKind, holderUID string) bool {
	n := len(bv.Status.Holds)
	bv.Status.Holds = slices.DeleteFunc(bv.Status.Holds, func(h v1.Hold) bool { return h.Kind == kind && h.Holder.UID == holderUID })
	if len(bv.Status.Holds) == 0 {
		bv.Status.Holds = nil
	}
	return len(bv.Status.Holds) != n
}

// claimVol takes (or adopts) the exclusive claim of a BlipVol for an
// attachment of b and adds the Attachment hold. It returns the claim
// generation and the snapshot the attachment starts from (the BlipVol's
// current snapshot when the claim was taken). A claim held by another Blip
// or attachment, a BlipVol being deleted or not Ready is a *refusal.
func (c *Controller) claimVol(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) (int64, int64, error) {
	var gen, snap int64
	alloc, node := "", ""
	if a := b.Status.Allocation; a != nil {
		alloc, node = a.ID, a.Node
	}
	key := types.NamespacedName{Namespace: b.Namespace, Name: vs.BlipVolRef.Name}
	_, err := c.updateVolStatus(ctx, key, vs.BlipVolRef.UID, func(bv *v1.BlipVol) (bool, error) {
		changed := false
		if cl := bv.Status.Claim; cl != nil && cl.BlipUID == string(b.UID) && cl.AttachmentID != vs.AttachmentID && c.orphanClaim(ctx, b, cl.AttachmentID) {
			// Taken by this Blip under an attachment ID its status does not
			// record (a lost status write): take it over. Its captures
			// never finish.
			failCaptures(bv, cl.AttachmentID, "the claim was taken over by another attachment")
			bv.Status.Claim = nil
		}
		if cl := bv.Status.Claim; cl != nil {
			if cl.BlipUID != string(b.UID) || cl.AttachmentID != vs.AttachmentID {
				return false, &refusal{api.ReasonVolumeInUse, fmt.Sprintf("blipvol %s is attached to blip %s", bv.Name, cl.BlipName)}
			}
			gen, snap = cl.Generation, cl.Snapshot
			if alloc != "" && (cl.AllocationID != alloc || cl.Node != node) {
				cl.AllocationID, cl.Node = alloc, node
				changed = true
			}
		} else {
			if bv.DeletionTimestamp != nil {
				return false, &refusal{api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %s is being deleted", bv.Name)}
			}
			cur := bv.Snapshot(bv.Status.Current)
			if bv.Status.Phase != v1.BlipVolReady || cur == nil || cur.State != v1.SnapshotReady {
				return false, &refusal{api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %s is not ready", bv.Name)}
			}
			gen, snap = bv.Status.ClaimGeneration+1, cur.Sequence
			now := metav1.NewTime(timeNow())
			bv.Status.ClaimGeneration = gen
			bv.Status.Claim = &v1.Claim{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: vs.AttachmentID,
				AllocationID: alloc, Node: node, Generation: gen, Since: &now, Snapshot: snap}
			changed = true
		}
		if setHold(bv, v1.HoldAttachment, blipHolder(b), "attachment "+vs.Name) {
			changed = true
		}
		return changed, nil
	})
	if err == errGone {
		return 0, 0, &refusal{api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %s not found", vs.BlipVolRef.Name)}
	}
	return gen, snap, err
}

// orphanClaim reports whether the current Blip (read live) records no
// attachment with the ID. Such a claim was taken by a pass whose status
// write was lost; no node command was ever sent for it.
func (c *Controller) orphanClaim(ctx context.Context, b *v1.Blip, attachmentID string) bool {
	var cur v1.Blip
	if err := c.live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Name}, &cur); err != nil || cur.UID != b.UID {
		return false
	}
	for _, vs := range cur.Status.Volumes {
		if vs.AttachmentID == attachmentID {
			return false
		}
	}
	return true
}

// releaseClaim drops the claim of an attachment of b (if it still holds it)
// and its Attachment hold. A missing BlipVol counts as released.
func (c *Controller) releaseClaim(ctx context.Context, b *v1.Blip, vs *v1.BlipVolumeStatus) error {
	if vs.BlipVolRef == nil {
		return nil
	}
	key := types.NamespacedName{Namespace: b.Namespace, Name: vs.BlipVolRef.Name}
	_, err := c.updateVolStatus(ctx, key, vs.BlipVolRef.UID, func(bv *v1.BlipVol) (bool, error) {
		changed := false
		if cl := bv.Status.Claim; cl != nil && cl.BlipUID == string(b.UID) && cl.AttachmentID == vs.AttachmentID {
			bv.Status.Claim = nil
			changed = true
		}
		// A capture of the attachment that did not finish never will.
		changed = failCaptures(bv, vs.AttachmentID, "the attachment was released before the snapshot was saved") || changed
		// The Attachment hold goes with the last attachment of this Blip.
		if bv.Status.Claim == nil || bv.Status.Claim.BlipUID != string(b.UID) {
			changed = removeHold(bv, v1.HoldAttachment, string(b.UID)) || changed
		}
		return changed, nil
	})
	if err == errGone {
		return nil
	}
	return err
}

// addHold adds a hold. With snap set, the hold names that snapshot, which
// must exist and be Ready (checked on the fresh copy, so compaction cannot
// delete it in between); an existing hold of the holder is moved to it. It
// refuses BlipVols being deleted unless the holder already has a hold of
// another kind on it.
func (c *Controller) addHold(ctx context.Context, ns string, ref v1.ObjectRef, kind v1.HoldKind, h v1.HolderRef, msg string, snap int64) error {
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, ref.UID, func(bv *v1.BlipVol) (bool, error) {
		if snap != 0 {
			if s := bv.Snapshot(snap); s == nil || s.State != v1.SnapshotReady {
				return false, &refusal{api.ReasonSnapshotNotFound, fmt.Sprintf("snapshot %d of blipvol %s is not Ready", snap, bv.Name)}
			}
		}
		for i := range bv.Status.Holds {
			if x := &bv.Status.Holds[i]; x.Kind == kind && x.Holder.UID == h.UID {
				if x.Snapshot == snap {
					return false, nil
				}
				x.Snapshot = snap
				return true, nil
			}
		}
		if bv.DeletionTimestamp != nil && !slices.ContainsFunc(bv.Status.Holds, func(x v1.Hold) bool { return x.Holder.UID == h.UID }) {
			return false, &refusal{api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %s is being deleted", bv.Name)}
		}
		setHold(bv, kind, h, msg)
		bv.Status.Holds[len(bv.Status.Holds)-1].Snapshot = snap
		return true, nil
	})
	return err
}

// dropHold removes a hold; a missing BlipVol counts as done.
func (c *Controller) dropHold(ctx context.Context, ns string, ref v1.ObjectRef, kind v1.HoldKind, holderUID string) error {
	_, err := c.updateVolStatus(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, ref.UID, func(bv *v1.BlipVol) (bool, error) {
		return removeHold(bv, kind, holderUID), nil
	})
	if err == errGone {
		return nil
	}
	return err
}
