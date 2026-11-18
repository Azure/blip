package controller

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// validateSpec checks the root and every mount of a Blip.
func validateSpec(b *v1.Blip) string {
	if (b.Spec.Image == "") == (b.Spec.State == "") {
		return "set exactly one of image and state"
	}
	for _, m := range b.Spec.Mounts {
		if msg := mountError(b, m); msg != "" {
			return fmt.Sprintf("mount %s: %s", m.State, msg)
		}
	}
	return ""
}

// mountError validates one spec mount against the rest of the spec.
func mountError(b *v1.Blip, m v1.Mount) string {
	if msg := pathError(m.Path); msg != "" {
		return msg
	}
	if m.State == b.Spec.State {
		return "the root state cannot also be mounted"
	}
	for _, o := range b.Spec.Mounts {
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
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// syncMounts moves status mounts through their phases from the runtime's
// observations and spec changes, and acquires newly added mounts.
func (r *BlipReconciler) syncMounts(ctx context.Context, b *v1.Blip, pod *corev1.Pod, obs *podapi.Observed) error {
	disks := map[string]podapi.DiskStatus{}
	for _, d := range obs.Mounts {
		disks[d.ID] = d
	}
	spec := map[string]v1.Mount{}
	for _, m := range b.Spec.Mounts {
		spec[m.State] = m
	}
	stop := stopping(b)

	var out []v1.MountStatus
	var saveErrs []string
	present := map[string]bool{}
	for _, m := range b.Status.Mounts {
		sm, inSpec := spec[m.State]
		same := inSpec && sm.Path == m.Path && sm.Writable == m.Writable
		d, seen := disks[m.AttachmentID]
		switch m.Phase {
		case v1.MountPending, v1.MountMounted:
			switch {
			case !same && !stop:
				m.Phase, m.Message = v1.MountUnmounting, ""
			case seen && d.Phase == podapi.DiskMounted:
				m.Phase, m.Message = v1.MountMounted, ""
			case seen && d.Phase == podapi.DiskFailed && m.Phase == v1.MountPending:
				m.Phase, m.Message = v1.MountFailed, d.Message
			}
		case v1.MountUnmounting:
			switch {
			case !seen || d.Phase == podapi.DiskDetached:
				if !m.Writable {
					continue
				}
				m.Phase, m.Message = v1.MountSaving, ""
			case d.Phase == podapi.DiskFailed:
				m.Message = d.Message
			}
		}
		if m.Phase == v1.MountSaving || m.Phase == v1.MountFailed {
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
		out = append(out, m)
		// A failed removed mount is kept for the CLI but must not stop
		// the same state from being mounted again.
		if m.Phase != v1.MountFailed || same {
			present[m.State] = true
		}
	}

	var waits []string
	for _, sm := range b.Spec.Mounts {
		if stop || present[sm.State] {
			continue
		}
		if msg := mountError(b, sm); msg != "" {
			out = append(out, v1.MountStatus{State: sm.State, Path: sm.Path, Writable: sm.Writable, Phase: v1.MountFailed, Message: msg})
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

// busyPath reports an active mount of another state that overlaps m.
func busyPath(mounts []v1.MountStatus, m v1.Mount) string {
	for _, o := range mounts {
		if o.State != m.State && o.Phase != v1.MountFailed && o.Phase != v1.MountSaving && overlaps(o.Path, m.Path) {
			return fmt.Sprintf("mount %s: waiting for %s to unmount from %s", m.State, o.State, o.Path)
		}
	}
	return ""
}
