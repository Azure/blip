// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/mountpath"
	"github.com/Azure/blip/internal/podapi"
)

// validateMounts validates the complete root topology before changing any disk.
func validateMounts(root string, mounts []v1.Mount) string {
	seen := map[string]bool{}
	for _, m := range mounts {
		if m.State == "" || seen[m.State] {
			return "mount states must be nonempty and unique"
		}
		seen[m.State] = true
		if msg := mountError(root, mounts, m); msg != "" {
			return fmt.Sprintf("mount %s: %s", m.State, msg)
		}
	}
	return ""
}

func immutableStateMessage(name string) string {
	return fmt.Sprintf("state %q is an immutable image template; fork it before writing", name)
}

// Check the exact state object whose UID will be attached. An earlier profile
// validation may have observed a shared base that was since deleted/recreated.
func mountStateError(b *v1.Blip, st *v1.BlipState, writable bool) string {
	if writable && st.Spec.Image != "" {
		return immutableStateMessage(st.Name)
	}
	owner := b.Labels[v1.LabelOwner]
	if !readableBy(owner, st) && !(b.Labels[v1.LabelChatSession] != "" && chatStateOwnedBy(owner, st)) {
		return fmt.Sprintf("mount %q is not owned by %s or a shared read-only image template", st.Name, owner)
	}
	return ""
}

// readableBy reports whether owner may use st: it owns st, or st is a shared
// read-only image template.
func readableBy(owner string, st *v1.BlipState) bool {
	return owner == "" ||
		(v1.OwnedBy(st.Name, owner) && st.Labels[v1.LabelOwner] == owner) ||
		(st.Spec.Image != "" && st.Labels[v1.LabelOwner] == "")
}

// chatStateOwnedBy reports whether a chat state belongs to owner. Chat tree
// names are opaque rather than owner-prefixed, so a matching label is the
// ownership test. The caller must already be part of the same chat tree; this
// is intentionally narrower than readableBy so a normal Blip cannot mount a
// chat workspace by claiming its owner label.
func chatStateOwnedBy(owner string, st *v1.BlipState) bool {
	return owner != "" && st.Labels[v1.LabelChatSession] != "" && st.Labels[v1.LabelOwner] == owner
}

// rootIntent reads only the root profile. Auxiliary profiles never expand.
// Invalid edits leave a running Blip's current attachments intact.
func (r *BlipReconciler) rootIntent(ctx context.Context, b *v1.Blip) (*v1.BlipState, []v1.Mount, string, string, error) {
	root := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Spec.State}, root); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, ReasonStateNotFound, fmt.Sprintf("state %q not found", b.Spec.State), nil
		}
		return nil, nil, "", "", err
	}
	if root.DeletionTimestamp != nil {
		return root, nil, reasonStateDeleting, fmt.Sprintf("state %q is being deleted", root.Name), nil
	}
	if root.Spec.Image != "" {
		return root, nil, ReasonInvalidSpec, immutableStateMessage(root.Name), nil
	}
	if msg := mountStateError(b, root, true); msg != "" {
		return root, nil, ReasonInvalidSpec, msg, nil
	}
	if err := pruneTemporaryMounts(ctx, r.Client, r.Live, root); err != nil {
		return nil, nil, "", "", err
	}
	mounts := v1.DesiredMounts(root, b)
	if msg := validateMounts(root.Name, mounts); msg != "" {
		return root, nil, ReasonInvalidSpec, msg, nil
	}
	for _, m := range mounts {
		owner := b.Labels[v1.LabelOwner]
		if !m.Writable && owner == "" {
			continue
		}
		st := &v1.BlipState{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: m.State}, st); err != nil {
			if apierrors.IsNotFound(err) {
				// A missing state may be created again; check only the name
				// prefix, since there is no object to read a label from.
				if owner != "" && !v1.OwnedBy(m.State, owner) {
					return root, nil, ReasonInvalidSpec, fmt.Sprintf("mount %q is not owned by %s or a shared read-only image template", m.State, owner), nil
				}
				continue
			}
			return nil, nil, "", "", err
		}
		if msg := mountStateError(b, st, m.Writable); msg != "" {
			return root, nil, ReasonInvalidSpec, msg, nil
		}
	}
	return root, mounts, "", "", nil
}

// Only acknowledge a generation after its desired topology is mounted, and
// every removed writable attachment has finished saving.
func mountsReconciled(b *v1.Blip, mounts []v1.Mount) bool {
	if len(b.Status.Mounts) != len(mounts) || b.Status.Message != "" {
		return false
	}
	for _, desired := range mounts {
		if !slices.ContainsFunc(b.Status.Mounts, func(m v1.MountStatus) bool {
			return m.State == desired.State && m.Path == desired.Path && m.Writable == desired.Writable &&
				m.Phase == v1.MountMounted && !m.Switching && m.Message == ""
		}) {
			return false
		}
	}
	return true
}

// mountError validates one spec mount against the rest of the spec.
func mountError(root string, mounts []v1.Mount, m v1.Mount) string {
	if msg := pathError(m.Path); msg != "" {
		return msg
	}
	// A path the Linux guest cannot create would make the durable root
	// unstartable, so reject it with the same rules the CLI preflights.
	if err := mountpath.Validate(m.Path); err != nil && !mountpath.CollectMountPath(m.Path) {
		return err.Error()
	}
	if m.State == root {
		return "the root state cannot also be mounted"
	}
	for _, o := range mounts {
		if o.State != m.State && overlaps(o.Path, m.Path) {
			return fmt.Sprintf("path %s overlaps mount %s at %s", m.Path, o.State, o.Path)
		}
	}
	return ""
}

func pathError(p string) string {
	switch {
	case !strings.HasPrefix(p, "/"):
		return fmt.Sprintf("path %q is not absolute", p)
	case p == "/":
		return "path must not be /"
	case strings.Contains("/"+p+"/", "/../"):
		return fmt.Sprintf("path %q contains ..", p)
	case path.Clean(p) != p:
		return fmt.Sprintf("path %q is not clean", p)
	}
	return ""
}

func overlaps(a, b string) bool {
	// Resolve known image aliases so /bin/x and /usr/bin/x are one mount
	// identity here too, not only in the guest.
	return mountpath.Overlap(a, b)
}

// syncMounts moves status mounts through their phases from the runtime's
// observations and spec changes, and acquires newly added mounts.
func (r *BlipReconciler) syncMounts(ctx context.Context, b *v1.Blip, mounts []v1.Mount, pod *corev1.Pod, obs *podapi.Observed) error {
	disks := map[string]podapi.DiskStatus{}
	for _, d := range obs.Mounts {
		disks[d.ID] = d
	}
	spec := map[string]v1.Mount{}
	for _, m := range mounts {
		spec[m.State] = m
	}
	stop := stopping(b)

	var out []v1.MountStatus
	var saveErrs []string
	present := map[string]bool{}
	for _, m := range b.Status.Mounts {
		sm, inSpec := spec[m.State]
		pathSame := inSpec && sm.Path == m.Path
		same := pathSame && sm.Writable == m.Writable
		switchTo := pathSame && !same && !stop
		// A failed save stays visible even after its mount leaves the spec;
		// a mount that merely never attached is forgotten with it.
		saveFailure := strings.HasPrefix(m.Message, "save failed:")
		neverAttached := diskNeverAttached(obs, m.AttachmentID)
		// A writable mount only risks losing data if the guest could have
		// reached the disk: it belongs to the accepted claim, was last
		// observed attached, or is still desired by the topology. A dynamic
		// mount that never attached and whose desired entry was rolled back
		// has nothing to save; the never-attached release below drops it.
		// Failing it here would kill an otherwise unaffected command for a
		// save that cannot exist.
		inUse := m.InClaim || m.Phase == v1.MountMounted || same || !neverAttached
		if m.Writable && !stop && inUse {
			// attachment treats a deleting state as resolved so its
			// finalizers cannot deadlock with this Blip. Never let an
			// already-attached mount keep writing into it (and keep the
			// state's finalizer waiting) after it is deleted, whether by
			// its owner or directly.
			st, err := r.deletingState(ctx, b, m.State)
			if err != nil {
				return err
			}
			if st != nil {
				msg := discardedSave(st, b)
				m.Phase, m.Message = v1.MountFailed, "save failed: "+msg
				saveErrs = append(saveErrs, msg)
				out = append(out, m)
				present[m.State] = true
				continue
			}
		}
		if !pathSame && m.Switching {
			// Removing the mount or changing its path cancels a switch in
			// progress. A writable mount still goes through the normal
			// save path below.
			if !m.Writable {
				if err := r.releaseSwitchWriter(ctx, b, m.State); err != nil {
					return err
				}
			}
			m.Switching, m.Message = false, ""
		}
		d, seen := disks[m.AttachmentID]
		if (m.Phase == v1.MountPending || m.Phase == v1.MountFailed && !saveFailure) &&
			m.Writable && neverAttached && !same && !stop && !m.Switching {
			// The writable mount never attached (no disk, or only an
			// attaching/failed one) and is being removed or changed,
			// including a demotion and a failed attach that was rolled
			// back. There is no working volume to save: release the
			// writer and drop the entry instead of waiting for a seal
			// that cannot happen. A recorded save failure is handled
			// below and stays visible. The spec loop recreates the mount
			// if it is still wanted.
			if err := r.releaseUnattachedWriter(ctx, b, m.State, m.AttachmentID); err != nil {
				return err
			}
			continue
		}
		switch m.Phase {
		case v1.MountPending, v1.MountMounted:
			switch {
			case switchTo && !m.Switching:
				if m.Phase == v1.MountPending {
					// Wait until the current mount is actually up
					// before checking promotion preconditions or
					// tearing it down for a demotion.
					switch {
					case seen && d.Phase == podapi.DiskMounted:
						m.Phase = v1.MountMounted
					case seen && d.Phase == podapi.DiskFailed:
						m.Phase, m.Message = v1.MountFailed, d.Message
					}
					break
				}
				if sm.Writable {
					msg, err := r.preparePromote(ctx, b, sm, m)
					if err != nil {
						return err
					}
					if msg != "" {
						if strings.Contains(msg, "saving a new version") {
							// The version this mount would promote from
							// is briefly unavailable. Keep the mount
							// usable and retry on the next reconcile.
							m.Phase, m.Message = v1.MountMounted, "waiting to switch to writable: "+msg
							break
						}
						// Keep the old disk usable and retry accepted intent.
						// A busy writer can disappear without another spec edit.
						m.Phase, m.Message, m.Switching = v1.MountMounted, "cannot switch to writable: "+msg, false
						break
					}
				}
				m.Phase, m.Message, m.Switching = v1.MountUnmounting, "", true
			case !same && !stop && !m.Switching:
				m.Phase, m.Message = v1.MountUnmounting, ""
			case seen && d.Phase == podapi.DiskMounted:
				m.Phase = v1.MountMounted
				if same {
					m.Message, m.Switching = "", false
				}
			case seen && d.Phase == podapi.DiskFailed && m.Phase == v1.MountPending:
				m.Phase, m.Message = v1.MountFailed, d.Message
			}
		case v1.MountUnmounting:
			if m.Switching && !m.Writable && !switchTo {
				// A promotion was cancelled before the new writable
				// mount appeared; return the pre-acquired slot.
				if err := r.releaseSwitchWriter(ctx, b, m.State); err != nil {
					return err
				}
			}
			switch {
			case same && seen && (d.Phase == podapi.DiskMounted || d.Phase == podapi.DiskFailed):
				// The spec was reverted while the old mount was still up.
				m.Phase, m.Message, m.Switching = v1.MountMounted, "", false
			case !seen || d.Phase == podapi.DiskDetached:
				if m.Writable && (m.Switching || !same) {
					// A detached writable mount must be saved even if
					// the spec was changed back while it was going
					// away; its contents are no longer reachable
					// through the old disk.
					m.Phase, m.Message = v1.MountSaving, ""
				} else {
					// A read-only mount (or a cancelled switch) is
					// replaced by the spec loop below.
					continue
				}
			case d.Phase == podapi.DiskFailed:
				m.Message = d.Message
			case d.Phase == podapi.DiskUnmounting:
				// The retry succeeded; stop reporting the old busy error.
				m.Message = ""
			}
		}
		if m.Phase == v1.MountSaving || m.Phase == v1.MountFailed {
			switch {
			case m.Switching && m.Writable && m.Phase == v1.MountSaving:
				sr, found, err := r.sealResult(ctx, b.Namespace, m.State, m.AttachmentID)
				if err != nil {
					return err
				}
				if !found {
					break
				}
				if sr.CommitID == "" {
					m.Phase, m.Message = v1.MountFailed, "switch failed: "+sealError(sr)
					break
				}
				// Demote in place: the same path becomes read-only at
				// the version just saved. This does not wait for the
				// commit to replicate so the mount comes back sooner.
				// If the spec was changed back to writable while the
				// save was in flight, the next reconcile promotes the
				// read-only mount once the saved version lands.
				m.Writable, m.CommitID, m.AttachmentID = false, sr.CommitID, r.newID()
				m.Phase, m.Message, m.Switching = v1.MountPending, "", false
			case m.Switching && same:
				// The switch was cancelled before anything was torn
				// down. Recreate the mount in its current mode.
				if seen && d.Phase == podapi.DiskMounted {
					m.Phase, m.Message, m.Switching = v1.MountMounted, "", false
				} else if !m.Writable {
					continue
				}
				// A writable save that failed stays visible: recreating
				// it from the old committed version would hide the loss.
			case m.Switching:
				// A failed switch keeps its old mount or failure visible.
			default:
				done, msg := true, ""
				if m.Writable && m.AttachmentID != "" {
					var err error
					if done, msg, err = r.attachment(ctx, b.Namespace, m.State, m.AttachmentID); err != nil {
						return err
					}
				}
				switch {
				case !done:
				case msg != "":
					m.Phase, m.Message = v1.MountFailed, "save failed: "+msg
					saveFailure = true
					if !same {
						// The mount was removed from the spec, but the
						// failure must stay visible (and fail the Blip)
						// instead of disappearing with the entry.
						saveErrs = append(saveErrs, fmt.Sprintf("save of state %s failed: %s", m.State, msg))
					}
				case m.Phase == v1.MountSaving:
					continue
				}
			}
		}
		if m.Phase == v1.MountFailed && !same && !m.Switching && !saveFailure {
			// The mount never attached and is gone from the spec: drop it
			// so it no longer blocks unmounting or remounting the state.
			// A failed writable attach may already have its pod recorded
			// in the pre-acquired writer (promotion), so release that too.
			if m.Writable && m.AttachmentID != "" {
				if err := r.releaseUnattachedWriter(ctx, b, m.State, m.AttachmentID); err != nil {
					return err
				}
			}
			continue
		}
		out = append(out, m)
		// Keep an in-progress switch visible and a failed save visible after
		// its mount leaves the spec; a failed attach that was removed is
		// dropped above.
		if m.Phase != v1.MountFailed || same || m.Switching {
			present[m.State] = true
		}
	}

	var waits []string
	for _, sm := range mounts {
		if stop || present[sm.State] {
			continue
		}
		if busy := busyPath(out, sm); busy != "" {
			waits = append(waits, busy)
			continue
		}
		st, reason, msg, err := r.usableState(ctx, b.Namespace, sm.State)
		if err != nil {
			return err
		}
		if reason == ReasonStateFailed {
			out = append(out, v1.MountStatus{State: sm.State, Path: sm.Path, Writable: sm.Writable, Phase: v1.MountFailed, Message: msg})
			continue
		}
		if reason != "" {
			waits = append(waits, "mount "+sm.State+": "+msg)
			continue
		}
		if msg := mountStateError(b, st, sm.Writable); msg != "" {
			waits = append(waits, msg)
			continue
		}
		var id string
		if sm.Writable {
			ids, blocked, err := r.acquire(ctx, b, map[string]*v1.BlipState{sm.State: st}, []string{sm.State}, pod)
			if err != nil {
				return err
			}
			if blocked != "" {
				waits = append(waits, "mount "+sm.State+": "+blocked)
				continue
			}
			id = ids[sm.State]
		}
		// Mounts are a map keyed by state: a mount added again after an
		// earlier removed one failed replaces its kept failure entry.
		out = slices.DeleteFunc(out, func(old v1.MountStatus) bool { return old.State == sm.State })
		out = append(out, r.newMount(b, sm, st, id))
	}
	b.Status.Mounts = out
	if len(saveErrs) > 0 {
		// A save that failed while its mount was being removed is final:
		// keep the entry visible and fail the Blip now.
		r.finish(b, v1.BlipFailed, ReasonSaveFailed, strings.Join(saveErrs, "; "))
		return nil
	}
	if len(waits) > 0 && b.Status.Message == "" {
		b.Status.Message = strings.Join(waits, "; ")
	}
	return nil
}

// diskNeverAttached reports whether the node's last observation shows no
// attached disk for id: either no entry, or one that only reached Attaching or
// Failed. Such a mount was never writable on the VM, so there is nothing to
// save for it.
func diskNeverAttached(obs *podapi.Observed, id string) bool {
	for _, d := range obs.Mounts {
		if d.ID == id {
			return d.Phase == podapi.DiskAttaching || d.Phase == podapi.DiskFailed
		}
	}
	return true
}

// busyPath reports an active mount of another state that overlaps m.
func busyPath(mounts []v1.MountStatus, m v1.Mount) string {
	for _, o := range mounts {
		if o.State != m.State && o.Phase != v1.MountFailed && o.Phase != v1.MountSaving && overlaps(o.Path, m.Path) {
			return fmt.Sprintf("mount %s: waiting for %s to unmount from %s", m.State, o.State, o.Path)
		}
	}
	return ""
}
