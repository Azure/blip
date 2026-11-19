package cli

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/mountpath"
	"github.com/Azure/blip/internal/workspace"
)

// updateState applies a single atomic edit to the latest state, including any
// collect ownership bookkeeping, retrying on conflicts.
func (a *app) updateState(ctx context.Context, name string, change func(*v1alpha1.BlipState) error) (*v1alpha1.BlipState, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	var s *v1alpha1.BlipState
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if s, err = a.getState(ctx, name); err != nil {
			return err
		}
		if err := change(s); err != nil {
			return err
		}
		return c.Kube.Update(ctx, s)
	})
	return s, err
}

var errUnchanged = errors.New("unchanged")

// errStaleAttach makes an add retry outside the atomic edit, after waiting
// for the previous attachment to detach. See waitDetached.
var errStaleAttach = errors.New("stale attachment")

var switchBusyTimeout = 30 * time.Second

// editMountsWaitingStale edits root's mounts and retries when the edit asks to
// wait for a stale attachment. edit returns the attachment to wait for
// together with errStaleAttach; its stale return value is ignored otherwise.
func (a *app) editMountsWaitingStale(ctx context.Context, root, state string, edit func(*v1alpha1.BlipState) (stale string, err error)) (*v1alpha1.BlipState, error) {
	for {
		var stale string
		s, err := a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
			var err error
			stale, err = edit(s)
			return err
		})
		if !errors.Is(err, errStaleAttach) {
			return s, err
		}
		// The edit saw an old attachment that the controller could revive.
		// Wait outside the atomic edit, against the latest root writer.
		latest, err := a.getState(ctx, root)
		if err != nil {
			return nil, err
		}
		writer, err := a.rootWriter(ctx, latest)
		if err != nil {
			return nil, err
		}
		if err := a.waitDetached(ctx, writer, root, state, stale); err != nil {
			return nil, err
		}
	}
}

// rootWriter resolves only this root's current execution. A writer of an
// auxiliary mount, or a new Blip reusing an old writer's name, is not a match.
func (a *app) rootWriter(ctx context.Context, root *v1alpha1.BlipState) (*v1alpha1.Blip, error) {
	w := root.Status.Writer
	if w == nil || w.BlipUID == "" {
		return nil, nil
	}
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	b, err := get(ctx, c, w.BlipName, &v1alpha1.Blip{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if string(b.UID) != w.BlipUID || b.Spec.State != root.Name || v1alpha1.Finished(b) ||
		b.Spec.Stop || b.DeletionTimestamp != nil || b.Status.Phase == v1alpha1.BlipSaving {
		return nil, nil
	}
	return b, nil
}

// mountRequest is one desired mount addition, validated before anything is
// created or written.
type mountRequest struct {
	state    string
	path     string
	writable bool
}

// mountPathsOverlap reports whether either path contains the other after both
// are reduced to their canonical offline identity. It mirrors the controller's
// topology rule; a root with an overlapping set is rejected on every execution.
func mountPathsOverlap(a, b string) bool {
	return mountpath.Overlap(a, b)
}

// mountPathConflict checks mountPath against the other states already in the
// root's mount set. Same-state entries are handled by the caller so a mode
// change or an idempotent re-add stays valid.
func mountPathConflict(root string, mounts []v1alpha1.Mount, state, mountPath string) error {
	for _, other := range mounts {
		if other.State == state {
			continue
		}
		if mountpath.Resolve(other.Path) == mountpath.Resolve(mountPath) {
			return fmt.Errorf("root state %q already has state %q mounted at %s", root, other.State, other.Path)
		}
		if mountPathsOverlap(other.Path, mountPath) {
			return fmt.Errorf("mount %s: path %s overlaps mount %s at %s", state, mountPath, other.State, other.Path)
		}
	}
	return nil
}

// validateMountPlan validates the complete mount set the CLI is about to write,
// including earlier requests from the same invocation, before any state is
// created or the root is edited. removed holds the states this invocation will
// unmount before the adds, so their current entries do not participate in the
// final topology. allowMove permits an add for a state that is already mounted
// at another path to replace that path in the same command.
func validateMountPlan(root *v1alpha1.BlipState, requests []mountRequest, removed map[string]bool, allowMove bool) error {
	mounts := make([]v1alpha1.Mount, 0, len(root.Spec.Mounts))
	for _, m := range root.Spec.Mounts {
		if !removed[m.State] {
			mounts = append(mounts, m)
		}
	}
	for _, req := range requests {
		if err := mountpath.Validate(req.path); err != nil {
			return err
		}
		if req.state == root.Name {
			return errors.New("a root state cannot mount itself")
		}
		if m := findSpecMount(mounts, req.state); m != nil {
			if m.Path != req.path {
				if !allowMove {
					return fmt.Errorf("state %q is already mounted on root state %q at %s; unmount it first", req.state, root.Name, m.Path)
				}
				// The new path must be free before the old entry is
				// replaced, so check the remaining topology without it.
				for i := range mounts {
					if mounts[i].State == req.state {
						mounts = append(mounts[:i], mounts[i+1:]...)
						break
					}
				}
				if err := mountPathConflict(root.Name, mounts, req.state, req.path); err != nil {
					return err
				}
				mounts = append(mounts, v1alpha1.Mount{State: req.state, Path: req.path, Writable: req.writable})
				continue
			}
			m.Writable = req.writable
			continue
		}
		if err := mountPathConflict(root.Name, mounts, req.state, req.path); err != nil {
			return err
		}
		mounts = append(mounts, v1alpha1.Mount{State: req.state, Path: req.path, Writable: req.writable})
	}
	return nil
}

func (a *app) mountState(ctx context.Context, state, root, mountPath string, target *bool) error {
	return a.mountStatePlanned(ctx, state, root, mountPath, target, false)
}

// collectPath reports whether p is at or below collect's reserved mount root.
func collectPath(p string) bool {
	return p == collectMountRoot || strings.HasPrefix(p, collectMountRoot+"/")
}

// collectAdoption reports whether s still holds the temporary collect mount of
// state at mountPath. Adopting that entry as a durable mount is the only edit
// permitted below the reserved collect root.
func collectAdoption(s *v1alpha1.BlipState, state, mountPath string) bool {
	if !collectPath(mountPath) {
		return false
	}
	m := findSpecMount(s.Spec.Mounts, state)
	return m != nil && m.Path == mountPath && m.BlipUID != ""
}

// mountStatePlanned mounts state, optionally moving an existing mount to a new
// path when the same invocation also removes mounts. The move is validated
// against the final topology by validateMountPlan before this edit.
func (a *app) mountStatePlanned(ctx context.Context, state, root, mountPath string, target *bool, move bool) error {
	if !path.IsAbs(mountPath) || path.Clean(mountPath) != mountPath || mountPath == "/" {
		return fmt.Errorf("invalid path %q: must be a clean absolute path other than /", mountPath)
	}
	if err := mountpath.Validate(mountPath); err != nil {
		// Adopting a temporary collect mount edits its existing entry rather
		// than adding a user mount below the reserved collect root. The final
		// state is checked in the edit below, where the temporary entry is
		// visible.
		if !collectPath(mountPath) {
			return err
		}
	}
	if state == root {
		return errors.New("a root state cannot mount itself")
	}
	r, err := a.getState(ctx, root)
	if err != nil {
		return err
	}
	if r.DeletionTimestamp != nil {
		return fmt.Errorf("state %q is being deleted", a.short(root))
	}
	if r.Spec.Image != "" {
		return fmt.Errorf("state %q is an imported base and cannot be executed directly; use --from %s", a.short(root), a.short(root))
	}
	if msg := usableStateFailure(r); msg != "" {
		return fmt.Errorf("state %q failed: %s", a.short(root), msg)
	}
	source, err := a.getState(ctx, state)
	if err != nil {
		return err
	}
	if source.DeletionTimestamp != nil {
		// A terminating state can never be attached. Reject it before writing
		// desired intent, which would otherwise outlive this command and make
		// every later Blip on the root wait for a state that is gone.
		return fmt.Errorf("state %q is being deleted", a.short(state))
	}
	if msg := usableStateFailure(source); msg != "" {
		// A state that can never commit cannot be attached either. Writing
		// intent for it would poison the root until the mount is removed by
		// hand.
		return fmt.Errorf("state %q failed: %s", a.short(state), msg)
	}
	var want, demoting, added, moved bool
	var prevPath string
	var prevWritable bool
	var oldAttachment string
	s, err := a.editMountsWaitingStale(ctx, root, state, func(s *v1alpha1.BlipState) (string, error) {
		if s.DeletionTimestamp != nil {
			// The root started deleting while this command waited to
			// edit it. Do not add intent that can never run.
			return "", fmt.Errorf("state %q is being deleted", a.short(root))
		}
		// Re-read the source inside the edit: the preflight read can race
		// with a deletion, and intent for a gone state would make every
		// later execution wait for it.
		if gone, err := a.mountSourceChanged(ctx, source); err != nil {
			return "", err
		} else if gone != "" {
			return "", errors.New(gone)
		}
		want, demoting, added, moved = false, false, false, false
		prevPath, prevWritable = "", false
		oldAttachment = ""
		if err := mountpath.Validate(mountPath); err != nil && !collectAdoption(s, state, mountPath) {
			return "", err
		}
		m := findSpecMount(s.Spec.Mounts, state)
		if m != nil {
			if m.Path != mountPath {
				if !move {
					return "", fmt.Errorf("state %q is already mounted on root state %q at %s; unmount it first", state, root, m.Path)
				}
				// Replace the path in place. The controller unmounts the
				// old attachment and mounts the new path; waitMount below
				// waits for the status entry to move too.
				if err := mountPathConflict(root, s.Spec.Mounts, state, mountPath); err != nil {
					return "", err
				}
				moved = true
				prevPath, prevWritable = m.Path, m.Writable
				m.Path = mountPath
			}
			want = m.Writable
			// Adoption of a collect mount must finish its pending reattach.
			if u := mountUsers(s)[state]; m.BlipUID != "" && u.BlipUID == m.BlipUID && u.Path == m.Path {
				oldAttachment = u.PreviousAttachment
			}
		} else {
			// Re-check against the latest root: the CLI preflight can race
			// with another writer, and direct callers skip it.
			if err := mountPathConflict(root, s.Spec.Mounts, state, mountPath); err != nil {
				return "", err
			}
			writer, err := a.rootWriter(ctx, s)
			if err != nil {
				return "", err
			}
			// Re-adding a read-only mount while the old attachment is
			// still visible would let the controller revive it instead
			// of attaching a fresh one. Detach it first.
			oldAttachment = mountedAttachment(writer, state)
			if oldAttachment != "" && (target == nil || !*target) {
				return oldAttachment, errStaleAttach
			}
			s.Spec.Mounts = append(s.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath})
			m = &s.Spec.Mounts[len(s.Spec.Mounts)-1]
			added = true
		}
		if target != nil {
			want = *target
		}
		if want && source.Spec.Image != "" {
			return "", fmt.Errorf("state %q is an imported base; fork it before mounting writable", a.short(state))
		}
		demoting = m.Writable && !want
		m.Writable, m.BlipUID = want, ""
		// Explicit mounting adopts a temporary mount as durable intent.
		users := mountUsers(s)
		delete(users, state)
		return oldAttachment, setMountUsers(s, users)
	})
	if err != nil {
		return err
	}
	b, err := a.rootWriter(ctx, s)
	if err != nil {
		return err
	}
	if b == nil {
		fmt.Fprintf(a.env.Out, "state %s mounted on root state %s at %s (%s); applied on next execution\n", a.short(state), a.short(root), mountPath, modeName(want))
		return nil
	}
	var generation int64
	if demoting && source.Status.Committed != nil {
		generation = source.Status.Committed.Generation
	}
	if err := a.waitMount(ctx, b, state, mountPath, want, generation, oldAttachment); err != nil {
		var refused *mountRefused
		if errors.As(err, &refused) {
			// The controller declined the mode change and will keep the
			// mount as it is. Do not leave desired intent claiming a mode
			// that can never converge.
			if rerr := a.restoreMountMode(ctx, root, state, mountPath, want, refused.writable); rerr != nil {
				fmt.Fprintf(a.env.Err, "warning: could not restore desired mode of state %s: %v\n", a.short(state), rerr)
			}
		}
		var gone *mountStateGoneError
		var rejected *mountRejectedError
		if errors.As(err, &gone) || errors.As(err, &rejected) {
			switch {
			case added:
				// The state disappeared or the guest rejected the mount
				// point while this command waited. Remove only the desired
				// mount this command just added; a mount that was already in
				// the root belongs to someone else.
				if rerr := a.rollbackAddedMount(ctx, root, state, mountPath, want); rerr != nil {
					fmt.Fprintf(a.env.Err, "warning: could not remove desired mount of state %s from root state %s: %v\n", a.short(state), a.short(root), rerr)
					err = fmt.Errorf("%w; desired mount remains applied", err)
				} else {
					err = fmt.Errorf("%w; the desired mount was removed from root state %q", err, a.short(root))
				}
			case moved:
				// A move rewrote an existing mount's path. On a rejection
				// the old path must come back, or every later execution of
				// the root fails at the rejected mount point. If another
				// mount now occupies the old path, the rejected entry is
				// removed instead and the user must mount again.
				restored, blockedBy, rerr := a.restoreMovedMount(ctx, root, state, mountPath, want, prevPath, prevWritable)
				switch {
				case rerr != nil:
					fmt.Fprintf(a.env.Err, "warning: could not restore previous path of state %s on root state %s: %v\n", a.short(state), a.short(root), rerr)
					err = fmt.Errorf("%w; desired mount remains applied", err)
				case restored:
					err = fmt.Errorf("%w; the previous mount of state %s at %s was restored", err, a.short(state), prevPath)
				case blockedBy != "":
					err = fmt.Errorf("%w; the previous mount of state %s at %s could not be restored because %s; the rejected mount was removed from root state %q; mount %s again", err, a.short(state), prevPath, blockedBy, a.short(root), a.short(state))
				default:
					// A concurrent edit replaced the entry this command
					// wrote, so there is nothing to roll back.
					err = fmt.Errorf("%w; the mount of state %s was changed concurrently and was left as is", err, a.short(state))
				}
			default:
				// The mount was already in the root before this command, so
				// it stays as desired intent.
				err = fmt.Errorf("%w; desired mount remains applied", err)
			}
		}
		return err
	}
	fmt.Fprintf(a.env.Out, "state %s mounted on blip %s at %s (%s)\n", a.short(state), a.short(b.Name), mountPath, modeName(want))
	return nil
}

// mountedAttachment captures the attachment that may belong to an old mount
// before desired intent is re-added. Any status other than Pending can
// describe a mount that is still up: Unmounting is the dangerous one, because
// the controller revives it to Mounted if the spec returns while the runtime
// still reports the disk. Pending is a new acquisition and is never reused as
// an old attachment.
func mountedAttachment(b *v1alpha1.Blip, state string) string {
	if b == nil {
		return ""
	}
	if m := findMount(b.Status.Mounts, state); m != nil && m.Phase != v1alpha1.MountPending {
		return m.AttachmentID
	}
	return ""
}

// waitDetached waits until the writer no longer reports stale as the
// attachment of state. Re-adding a mount while that attachment is still
// visible makes the controller revive it instead of creating a fresh one, and
// a revived attachment keeps its ID even when the runtime detaches and
// re-attaches the disk, so waiting for a different ID afterwards would never
// finish. The wait is by specific attachment: another collector's fresh mount
// is not stale, and if desired intent reappears the caller reuses it.
func (a *app) waitDetached(ctx context.Context, writer *v1alpha1.Blip, rootName, state, stale string) error {
	if writer == nil || stale == "" {
		return nil
	}
	r := &reporter{a: a}
	defer r.stop()
	return a.waitBlip(ctx, writer.Name, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil || b.UID != writer.UID || v1alpha1.Finished(b) || b.Spec.Stop || b.DeletionTimestamp != nil {
			// Let the caller decide what an ended execution means.
			return true, nil
		}
		m := findMount(b.Status.Mounts, state)
		if m == nil || m.Phase == v1alpha1.MountPending || m.AttachmentID != stale {
			return true, nil
		}
		root, err := a.getState(ctx, rootName)
		if err != nil {
			return false, err
		}
		if findSpecMount(root.Spec.Mounts, state) != nil {
			// Somebody put the mount back; retrying now reuses it.
			return true, nil
		}
		r.say("waiting for %s to finish detaching on %s...", state, b.Name)
		return false, nil
	})
}

// mountStateGone reports the part of a top-level Blip status message that says
// the wanted state is terminating or no longer exists. The controller records
// these as waits because it only needs to observe them for the current
// execution, but a mount that is waiting for an attachment can never finish.
// Like mountBusy, only a segment that both names this state and reports a
// terminal lifecycle error matches, so unrelated waits for other mounts stay
// out of the way.
func mountStateGone(msg, state string) string {
	quoted := strconv.Quote(state)
	for _, part := range strings.Split(msg, "; ") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, quoted) {
			continue
		}
		if strings.Contains(part, "is being deleted") || strings.Contains(part, "not found") {
			return part
		}
	}
	return ""
}

// mountStateGoneError marks a wait that can never finish because the mount's
// source state is terminating or gone. mountState rolls back the desired mount
// it added for this command.
type mountStateGoneError struct{ msg string }

func (e *mountStateGoneError) Error() string { return e.msg }

// mountSourceGone reports why the mount's source state can no longer attach,
// reading the state directly. A stopped writer may not have published its
// status message yet, so the CLI cannot rely on the Blip alone when a source
// is deleted mid-wait. An empty result means the source is still usable.
func (a *app) mountSourceGone(ctx context.Context, state string) string {
	c, err := a.clients()
	if err != nil {
		return ""
	}
	var s v1alpha1.BlipState
	switch err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: state}, &s); {
	case apierrors.IsNotFound(err):
		return fmt.Sprintf("state %q not found", state)
	case err != nil:
		return ""
	case s.DeletionTimestamp != nil:
		return fmt.Sprintf("state %q is being deleted", state)
	}
	return ""
}

// mountSourceChanged reports why the mount's source state can no longer be
// attached, re-reading it inside the root edit. The preflight read can race
// with a deletion, and writing desired intent for a state that is gone would
// make every later execution wait for it. A state recreated under the same
// name is not the source this command validated either.
func (a *app) mountSourceChanged(ctx context.Context, source *v1alpha1.BlipState) (string, error) {
	c, err := a.clients()
	if err != nil {
		return "", err
	}
	var cur v1alpha1.BlipState
	switch err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: source.Name}, &cur); {
	case apierrors.IsNotFound(err):
		return fmt.Sprintf("state %q not found", a.short(source.Name)), nil
	case err != nil:
		return "", err
	case cur.DeletionTimestamp != nil:
		return fmt.Sprintf("state %q is being deleted", a.short(source.Name)), nil
	case source.UID != "" && cur.UID != source.UID:
		return fmt.Sprintf("state %q was replaced", a.short(source.Name)), nil
	}
	return "", nil
}

// mountRejectedError marks a mount the guest or controller refused for a
// permanent reason, such as an ancestor of the mount point being a symlink to
// a file, a regular file, or a reserved guest path. Retrying cannot help, so
// mountState rolls back the desired mount it added instead of leaving a root
// that can never start.
type mountRejectedError struct{ msg string }

func (e *mountRejectedError) Error() string { return e.msg }

// mountPointRejected reports a fixed guest error for a mount point it cannot
// create. These are terminal: the guest's own path and target checks produced
// them, so retrying with the same durable root cannot succeed. Attach and save
// failures (no space, device errors, busy mounts, transport timeouts) may still
// be worth keeping as desired intent, so they are excluded first.
func mountPointRejected(msg string) bool {
	for _, prefix := range []string{"save failed:", "save of state ", "switch failed:"} {
		if strings.HasPrefix(msg, prefix) {
			return false
		}
	}
	for _, transient := range []string{
		"processes are still using", "no space", "input/output", "i/o",
		"device or resource busy", "deadline", "timed out", "timeout",
		"connection", "transport",
	} {
		if strings.Contains(msg, transient) {
			return false
		}
	}
	for _, permanent := range []string{
		"is a symlink", "not a directory", "guest reserves", "overlaps",
		"mount path",
	} {
		if strings.Contains(msg, permanent) {
			return true
		}
	}
	return false
}

// mountSourceFailed reports the part of a mount status message that says the
// source state became Failed while the mount waited. Only the controller's
// fixed `state "NAME" failed:` segment matches, so unrelated mount and save
// failures keep their desired intent.
func mountSourceFailed(msg, state string) string {
	prefix := "state " + strconv.Quote(state) + " failed"
	for _, part := range strings.Split(msg, "; ") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, prefix) {
			return part
		}
	}
	return ""
}

// mountBusy reports the part of a top-level Blip status message that says the
// wanted state is already written by another Blip. The controller records a
// writable mount rejected for that reason on the Blip itself, not as a mount
// status entry, so a wait keyed on status.mounts would never finish. Only a
// segment that both names this state and reports the holder matches; unrelated
// waits and failures for other mounts stay out of the way.
func mountBusy(msg, state string) string {
	quoted := strconv.Quote(state)
	for _, part := range strings.Split(msg, "; ") {
		if strings.Contains(part, "is in use by blip") && strings.Contains(part, quoted) {
			return strings.TrimSpace(part)
		}
	}
	return ""
}

// mountRefused reports that the controller declined to change an existing
// mount's mode. The mount keeps its current mode, so the caller restores
// desired intent to match it.
type mountRefused struct {
	msg      string
	writable bool
}

func (e *mountRefused) Error() string { return e.msg }

// restoreMountMode reverts a refused mode change when desired intent still
// matches what this command wrote; a concurrent edit wins.
func (a *app) restoreMountMode(ctx context.Context, root, state, mountPath string, want, actual bool) error {
	_, err := a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
		m := findSpecMount(s.Spec.Mounts, state)
		if m == nil || m.Path != mountPath || m.Writable != want || m.BlipUID != "" {
			return errUnchanged
		}
		m.Writable = actual
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// restoreMovedMount reverts the path and mode of an existing mount after a
// rejected move. It only rewrites the exact entry this command wrote, so a
// concurrent edit wins. The previous path is restored only when it is still
// free: restoring over another mount would leave an overlapping set the
// controller rejects on every execution, so in that case the rejected entry is
// removed instead and blockedBy describes the occupant.
func (a *app) restoreMovedMount(ctx context.Context, root, state, mountPath string, want bool, prevPath string, prevWritable bool) (restored bool, blockedBy string, err error) {
	_, err = a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
		restored, blockedBy = false, ""
		m := findSpecMount(s.Spec.Mounts, state)
		if m == nil || m.Path != mountPath || m.Writable != want || m.BlipUID != "" {
			return errUnchanged
		}
		for _, other := range s.Spec.Mounts {
			if other.State == state {
				continue
			}
			if mountPathsOverlap(other.Path, prevPath) {
				blockedBy = fmt.Sprintf("state %s is mounted at %s", a.short(other.State), other.Path)
				// Neither the rejected path nor the old path is usable.
				// Remove this command's entry so the root can run again.
				users := mountUsers(s)
				delete(users, state)
				for i := range s.Spec.Mounts {
					if s.Spec.Mounts[i].State == state {
						s.Spec.Mounts = append(s.Spec.Mounts[:i], s.Spec.Mounts[i+1:]...)
						break
					}
				}
				return setMountUsers(s, users)
			}
		}
		m.Path, m.Writable = prevPath, prevWritable
		restored = true
		return nil
	})
	if errors.Is(err, errUnchanged) {
		err = nil
	}
	return restored, blockedBy, err
}

// rollbackAddedMount removes the desired mount this command just added after
// its source state disappeared. It removes only the exact entry this command
// wrote, so a concurrent edit or a pre-existing mount is left alone.
func (a *app) rollbackAddedMount(ctx context.Context, root, state, mountPath string, want bool) error {
	_, err := a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
		for i, m := range s.Spec.Mounts {
			if m.State != state {
				continue
			}
			if m.Path != mountPath || m.Writable != want || m.BlipUID != "" {
				return errUnchanged
			}
			users := mountUsers(s)
			delete(users, state)
			s.Spec.Mounts = append(s.Spec.Mounts[:i], s.Spec.Mounts[i+1:]...)
			return setMountUsers(s, users)
		}
		return errUnchanged
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// restoreRemovedMounts re-adds the mounts this invocation removed when a later
// add failed. A combined command that cannot be applied must not silently lose
// the original mounts. It returns the removed states it restored and the ones
// that could not be restored because their path is now occupied.
func (a *app) restoreRemovedMounts(ctx context.Context, root string, original []v1alpha1.Mount, removed map[string]bool) (restored, missing []string, err error) {
	if len(removed) == 0 {
		return nil, nil, nil
	}
	_, err = a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
		restored, missing = nil, nil
		for _, old := range original {
			if !removed[old.State] {
				continue
			}
			if findSpecMount(s.Spec.Mounts, old.State) != nil {
				// A move rollback or a concurrent edit already restored it.
				continue
			}
			blocked := false
			for _, cur := range s.Spec.Mounts {
				if mountPathsOverlap(cur.Path, old.Path) {
					blocked = true
					break
				}
			}
			if blocked {
				missing = append(missing, old.State)
				continue
			}
			s.Spec.Mounts = append(s.Spec.Mounts, old)
			restored = append(restored, old.State)
		}
		if len(restored) == 0 {
			return errUnchanged
		}
		return nil
	})
	if errors.Is(err, errUnchanged) {
		err = nil
	}
	return restored, missing, err
}

// restoreAfterFailedAdd reports a failed add together with the fate of the
// mounts the same invocation removed first. Either they are restored, or the
// error says they are gone and must be mounted again; it never leaves the user
// to infer a rollback that did not happen.
func (a *app) restoreAfterFailedAdd(ctx context.Context, root string, original []v1alpha1.Mount, removed map[string]bool, cause error) error {
	restored, missing, err := a.restoreRemovedMounts(ctx, root, original, removed)
	if err != nil {
		fmt.Fprintf(a.env.Err, "warning: could not restore mounts unmounted by this command: %v\n", err)
		return cause
	}
	if len(restored) > 0 {
		return fmt.Errorf("%w; the previously removed mount(s) %s were restored", cause, strings.Join(a.shortAll(restored), ", "))
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w; the mount(s) %s removed by this command could not be restored; mount them again", cause, strings.Join(a.shortAll(missing), ", "))
	}
	return cause
}

// shortAll maps state names through short for user-facing lists.
func (a *app) shortAll(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = a.short(name)
	}
	return out
}

// waitMount observes the runtime attachment without editing desired intent.
// oldAttachment identifies a previous mount that was still visible when the
// desired mount was re-added, and must not be accepted as the new attachment.
// The add path waits for that mount to detach first (see waitDetached); this
// check is a backstop against a revival that slips through.
func (a *app) waitMount(ctx context.Context, writer *v1alpha1.Blip, state, mountPath string, want bool, baseGeneration int64, oldAttachment string) error {
	r := &reporter{a: a}
	defer r.stop()
	start := time.Now()
	return a.waitBlip(ctx, writer.Name, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil || b.UID != writer.UID || b.Spec.State != writer.Spec.State {
			return false, fmt.Errorf("blip %q stopped before the mount completed; desired mount remains on root state %q", writer.Name, writer.Spec.State)
		}
		// A terminating or missing source never gets an attachment. The
		// controller reports it as a wait on the Blip, so waiting for a
		// status entry would poll forever and leave the root poisoned. A
		// deleted writable source also stops the Blip, so this must run
		// before the generic stop check to keep the rollback cause.
		if gone := mountStateGone(b.Status.Message, state); gone != "" {
			return false, &mountStateGoneError{msg: fmt.Sprintf("mount of state %q on blip %q failed: %s", state, b.Name, gone)}
		}
		if v1alpha1.Finished(b) || b.Spec.Stop || b.DeletionTimestamp != nil || b.Status.Phase == v1alpha1.BlipSaving {
			// The controller sets spec.stop before it publishes the reason.
			// A source deleted while this mount waited would therefore look
			// like a plain stop. Re-read the source so the deletion cause
			// still wins and the caller rolls back the intent it added.
			if gone := a.mountSourceGone(ctx, state); gone != "" {
				return false, &mountStateGoneError{msg: fmt.Sprintf("mount of state %q on blip %q failed: %s", state, b.Name, gone)}
			}
			return false, fmt.Errorf("blip %q stopped before the mount completed; desired mount remains on root state %q", writer.Name, writer.Spec.State)
		}
		root, err := a.getState(ctx, writer.Spec.State)
		if err != nil {
			return false, err
		}
		if w := root.Status.Writer; w == nil || w.BlipName != b.Name || w.BlipUID != string(b.UID) {
			return false, fmt.Errorf("blip %q no longer owns root state %q", b.Name, root.Name)
		}
		if m := findSpecMount(root.Spec.Mounts, state); m == nil || m.Path != mountPath || m.Writable != want ||
			(m.BlipUID != "" && m.BlipUID != string(writer.UID)) {
			return false, fmt.Errorf("mount of state %q changed concurrently", state)
		}
		m := findMount(b.Status.Mounts, state)
		if m == nil || m.Path != mountPath {
			// A writable mount can be rejected before any status entry
			// exists: the controller leaves the reason on the Blip. Report
			// that as final instead of waiting for an attachment that will
			// never appear.
			if m == nil && want {
				if busy := mountBusy(b.Status.Message, state); busy != "" {
					return false, fmt.Errorf("mount of state %q on blip %q failed: %s; desired mount remains applied", state, b.Name, busy)
				}
			}
			r.say("mounting %s on %s...", state, b.Name)
			return false, nil
		}
		if m.Phase == v1alpha1.MountFailed || m.Switching && m.Writable != want && m.Message != "" &&
			(!strings.Contains(m.Message, "busy") || time.Since(start) > switchBusyTimeout) {
			if strings.Contains(m.Message, "busy") {
				return false, fmt.Errorf("could not switch state %q on blip %q: processes are still using %s; desired mount remains applied", state, b.Name, mountPath)
			}
			msg := fmt.Sprintf("mount of state %q on blip %q failed: %s", state, b.Name, m.Message)
			if failed := mountSourceFailed(m.Message, state); failed != "" {
				// The source can never commit, so the mount can never
				// attach. Roll it back like a rejected mount point.
				return false, &mountRejectedError{msg: fmt.Sprintf("mount of state %q on blip %q failed: %s", state, b.Name, failed)}
			}
			if mountPointRejected(m.Message) {
				// mountState appends the accurate outcome after attempting
				// its rollback; claiming here that the mount remains applied
				// would contradict a successful removal.
				return false, &mountRejectedError{msg: msg}
			}
			msg += "; desired mount remains applied"
			return false, errors.New(msg)
		}
		if m.Phase == v1alpha1.MountMounted && !m.Switching && m.Writable != want && m.Message != "" &&
			!strings.HasPrefix(m.Message, "waiting to switch to writable") {
			// preparePromote refusals are reported on the still-mounted
			// entry with Switching=false: the old mount stays up and no
			// switch will start. Treat that as final instead of waiting
			// for a mode change that can never happen.
			return false, &mountRefused{
				msg:      fmt.Sprintf("mount of state %q on blip %q failed: %s; desired mount restored", state, b.Name, m.Message),
				writable: m.Writable,
			}
		}
		if m.Phase == v1alpha1.MountMounted && !m.Switching && m.Writable == want {
			// Read-only mounts get a fresh ID; writable mounts can reuse their
			// writer attachment. Wait until the stale read-only attach is gone.
			if !want && oldAttachment != "" && m.AttachmentID == oldAttachment {
				r.say("waiting for %s to finish detaching on %s...", state, b.Name)
				return false, nil
			}
			if baseGeneration > 0 {
				s, err := a.getState(ctx, state)
				if err != nil {
					return false, err
				}
				if s.Status.Committed == nil || s.Status.Committed.Generation <= baseGeneration {
					// A save from this mount comes back read-only at
					// the commit it produced, so its CommitID differs
					// from the state's committed version until that
					// version lands. A mount that is read-only at the
					// committed version has no save left to wait for:
					// a promotion cancelled by a concurrent command
					// (or one that never attached) leaves it there.
					if s.Status.Committed == nil || m.CommitID == "" || m.CommitID == s.Status.Committed.ID {
						return true, nil
					}
					r.say("saving new version of %s...", state)
					return false, nil
				}
			}
			return true, nil
		}
		r.say("mounting %s on %s: %s", state, b.Name, m.Message)
		return false, nil
	})
}

func modeName(write bool) string {
	if write {
		return "writable"
	}
	return "read-only"
}

func (a *app) unmountState(ctx context.Context, state, root string) error {
	c, err := a.clients()
	if err != nil {
		return err
	}
	var copies v1alpha1.BlipStateList
	if err := c.Kube.List(ctx, &copies, client.InNamespace(c.Namespace)); err != nil {
		return err
	}
	for i := range copies.Items {
		cp := &copies.Items[i]
		if cp.Spec.CopyFrom == state && cp.Status.Committed == nil && cp.DeletionTimestamp == nil && cp.Status.Phase != v1alpha1.StateFailed {
			return fmt.Errorf("state %q is being forked by %q; wait for the fork to finish before unmounting", state, a.short(cp.Name))
		}
	}
	inSpec := false
	s, err := a.updateState(ctx, root, func(s *v1alpha1.BlipState) error {
		inSpec = false
		users := mountUsers(s)
		for i, m := range s.Spec.Mounts {
			if m.State != state {
				continue
			}
			if u := users[state]; m.BlipUID != "" && u.BlipUID == m.BlipUID && u.Path == m.Path && u.Users > 0 {
				b, err := a.rootWriter(ctx, s)
				if err != nil {
					return err
				}
				if b != nil && string(b.UID) == m.BlipUID {
					return fmt.Errorf("state %q is in use by collect; wait for collect to finish before unmounting", state)
				}
			}
			inSpec = true
			s.Spec.Mounts = append(s.Spec.Mounts[:i], s.Spec.Mounts[i+1:]...)
			delete(users, state)
			return setMountUsers(s, users)
		}
		return errUnchanged
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return err
	}
	terminating := s != nil && s.DeletionTimestamp != nil
	b, err := a.rootWriter(ctx, s)
	if err != nil {
		return err
	}
	if !inSpec && (b == nil || findMount(b.Status.Mounts, state) == nil) {
		return fmt.Errorf("state %q is not mounted on root state %q", state, root)
	}
	if b == nil {
		if terminating {
			// The removal was recorded, but the root is being deleted and
			// will never execute again, so promising a later application
			// would be false.
			return fmt.Errorf("state %q is being deleted; the mount of state %q was removed but the root will not execute again", a.short(root), a.short(state))
		}
		fmt.Fprintf(a.env.Out, "state %s unmounted from root state %s; applied on next execution\n", a.short(state), a.short(root))
		return nil
	}
	before := findMount(b.Status.Mounts, state)
	r := &reporter{a: a}
	defer r.stop()
	start := time.Now()
	err = a.waitBlip(ctx, b.Name, func(current *v1alpha1.Blip) (bool, error) {
		if current == nil || current.UID != b.UID {
			return true, nil
		}
		latest, err := a.getState(ctx, root)
		if err != nil {
			return false, err
		}
		if findSpecMount(latest.Spec.Mounts, state) != nil {
			return false, fmt.Errorf("mount of state %q changed concurrently", state)
		}
		m := findMount(current.Status.Mounts, state)
		if m == nil {
			return true, nil
		}
		if v1alpha1.Finished(current) {
			// saving resolves every writable attachment before a Blip
			// finishes, so an entry that is still visible is not a live
			// mount. Report the removal instead of polling forever.
			if m.Phase == v1alpha1.MountFailed && m.Message != "" {
				return false, fmt.Errorf("could not unmount state %q from blip %q: %s; desired removal remains applied", state, b.Name, m.Message)
			}
			return true, nil
		}
		if current.Status.Phase == v1alpha1.BlipSaving {
			// The writer stopped and the removal has left desired intent;
			// the controller is now saving the last version. Wait for the
			// Blip to finish rather than for the status entry to disappear.
			r.say("saving %s on %s...", state, b.Name)
			return false, nil
		}
		if (m.Phase == v1alpha1.MountFailed || m.Phase == v1alpha1.MountUnmounting) && m.Message != "" &&
			(before == nil || before.Message != m.Message || time.Since(start) > 5*time.Second) {
			if strings.Contains(m.Message, "busy") {
				return false, fmt.Errorf("could not unmount state %q from blip %q: processes are still using %s; desired removal remains applied", state, b.Name, m.Path)
			}
			return false, fmt.Errorf("could not unmount state %q from blip %q: %s; desired removal remains applied", state, b.Name, m.Message)
		}
		if m.Phase == v1alpha1.MountSaving {
			r.say("saving %s...", state)
		} else {
			r.say("unmounting %s from %s...", state, b.Name)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	if terminating {
		return fmt.Errorf("state %q is being deleted; the mount of state %q was removed but the root will not execute again", a.short(root), a.short(state))
	}
	fmt.Fprintf(a.env.Out, "state %s unmounted from blip %s\n", a.short(state), a.short(b.Name))
	return nil
}

// mountTarget scopes state names; inside a guest the root defaults to self's
// root state rather than its execution name.
func (a *app) mountTarget(root *string) error {
	if *root != "" {
		if err := a.validateStateName(*root); err != nil {
			return err
		}
	}
	if err := a.scope(root); err != nil {
		return err
	}
	if *root == "" {
		if a.self == nil {
			return errors.New("--root is required outside a blip")
		}
		*root = a.self.Spec.State
		return a.validateName("state", *root)
	}
	return nil
}

type mountFlags struct {
	root     string
	remove   []string
	create   []string
	from     string
	size     string
	replicas int32
}

// newMount is a scoped --new request, parsed before any state exists so the
// whole command can be validated first.
type newMount struct {
	spec     string
	name     string
	path     string
	writable bool
}

func (a *app) mountCommand() *cobra.Command {
	f := &mountFlags{}
	cmd := &cobra.Command{
		Use:   "mount [STATE:PATH[:rw|ro]]... [flags]",
		Short: "Mount states, remove mounts, or create a state to mount",
		Long: `Mount a state into a root state, remove a mount, create a state to mount, or
list the root's mounts.

  blip mount STATE:PATH[:rw|ro]     mount STATE at PATH (read-only by default)
  blip mount --rm STATE             remove the mount and wait for its save
  blip mount --new NAME:PATH[:rw|ro] [--from SRC] [--size SIZE] [--replicas N]
                                    create a state and mount it (writable by
                                    default)
  blip mount                        list the root's mounts

Inside a blip the root defaults to its own root state, so a mount takes effect
in the running command. Outside one, --root names the state to edit.

A PATH may contain ':' (for example /a:b). A trailing :rw or :ro is a mode
only when the PATH before it contains no colon; input with both is ambiguous
and rejected. gather --collect cannot name a mounted path that contains ':'
(it splits SRC:DEST at the last colon), so mount anything you intend to
collect at a path without a colon.`,
		Example: `  blip mount repo:/work:rw
  blip mount --rm repo
  blip mount --new cache:/cache:rw --size 20Gi
  kubectl blip mount repo:/work --root home`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.mount(cmd.Context(), args, f, cmd.Flags().Changed("replicas"))
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.root, "root", "", "root state to edit (default: the current blip's root state)")
	fl.StringArrayVar(&f.remove, "rm", nil, "remove this state's mount (repeatable)")
	fl.StringArrayVar(&f.create, "new", nil, "create STATE and mount it at PATH as NAME:PATH[:rw|ro] (repeatable)")
	fl.StringVar(&f.from, "from", "", "for --new: copy an existing workspace or imported base")
	fl.StringVar(&f.size, "size", "", "for --new: filesystem size, e.g. 20Gi")
	fl.Int32Var(&f.replicas, "replicas", 0, "for --new: nodes holding each committed version, 1-3 (default 3)")
	return cmd
}

// parseMountSpec parses STATE:PATH[:rw|ro]. A nil mode leaves an existing
// mount's mode unchanged and makes a new mount read-only.
//
// A trailing :rw or :ro is a mode only when the path before it contains no
// colon, so a legal path containing ':' is not truncated. Input that both
// contains ':' in its path and ends in a mode suffix is ambiguous: it could be
// either, so it is rejected instead of silently choosing one.
func parseMountSpec(s string) (state, mountPath string, writable *bool, err error) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", "", nil, fmt.Errorf("invalid mount %q: want STATE:PATH[:rw|ro]", s)
	}
	state, rest := s[:i], s[i+1:]
	mountPath = rest
	var mode string
	switch {
	case strings.HasSuffix(rest, ":rw"):
		mode = "rw"
	case strings.HasSuffix(rest, ":ro"):
		mode = "ro"
	}
	if mode != "" {
		base := strings.TrimSuffix(rest, ":"+mode)
		if strings.Contains(base, ":") {
			return "", "", nil, fmt.Errorf("invalid mount %q: ambiguous path %q ends with :%s but also contains ':'", s, rest, mode)
		}
		mountPath = base
		want := mode == "rw"
		writable = &want
	}
	if !path.IsAbs(mountPath) || path.Clean(mountPath) != mountPath || mountPath == "/" {
		return "", "", nil, fmt.Errorf("invalid mount %q: PATH must be a clean absolute path other than /", s)
	}
	return state, mountPath, writable, nil
}

func (a *app) mount(ctx context.Context, args []string, f *mountFlags, replicasSet bool) error {
	if err := a.mountTarget(&f.root); err != nil {
		return err
	}
	if err := checkNewOnlyFlags(f, replicasSet); err != nil {
		return err
	}
	for _, arg := range f.remove {
		if err := a.validateStateName(arg); err != nil {
			return err
		}
	}
	if f.from != "" {
		if err := a.validateStateName(f.from); err != nil {
			return err
		}
	}
	if len(args) == 0 && len(f.remove) == 0 && len(f.create) == 0 {
		return a.listMounts(ctx, f.root)
	}
	news, err := a.prepareNewMounts(f, replicasSet)
	if err != nil {
		return err
	}
	requests := make([]mountRequest, 0, len(news)+len(args))
	created := map[string]bool{}
	for _, n := range news {
		requests = append(requests, mountRequest{state: n.name, path: n.path, writable: n.writable})
		created[n.name] = true
	}
	type addition struct {
		state    string
		path     string
		writable *bool
	}
	adds := make([]addition, 0, len(args))
	for _, arg := range args {
		state, mountPath, writable, err := parseMountSpec(arg)
		if err != nil {
			return err
		}
		name, err := a.mountSource(ctx, state, created)
		if err != nil {
			return err
		}
		want := false
		if writable != nil {
			want = *writable
		}
		requests = append(requests, mountRequest{state: name, path: mountPath, writable: want})
		adds = append(adds, addition{state: name, path: mountPath, writable: writable})
	}
	// Validate the complete topology before creating states or editing the
	// root, so a rejected command leaves neither a partial mount set nor an
	// orphan state behind.
	root, err := a.getState(ctx, f.root)
	if err != nil {
		return err
	}
	hasAdds := len(args) > 0 || len(f.create) > 0
	if root.DeletionTimestamp != nil && hasAdds {
		// A terminating root can never execute again. Reject before
		// creating a state or writing intent that no run can use. A
		// removal-only command stays legal so a reader can still detach
		// and release the state's finalizer.
		return fmt.Errorf("state %q is being deleted", a.short(f.root))
	}
	if hasAdds {
		// An imported base is a shared template; edits to its mounts would
		// be inherited by every later fork. Reject it as a mount target, as
		// run --state does. A removal-only command stays legal for cleanup.
		if root.Spec.Image != "" {
			return fmt.Errorf("state %q is an imported base and cannot be executed directly; use --from %s", a.short(f.root), a.short(f.root))
		}
		// A root that can never commit cannot run the mount either. Reject
		// it before any state is created or intent is written.
		if msg := usableStateFailure(root); msg != "" {
			return fmt.Errorf("state %q failed: %s", a.short(f.root), msg)
		}
	}
	original := append([]v1alpha1.Mount(nil), root.Spec.Mounts...)
	removed := make(map[string]bool, len(f.remove))
	removeOrder := make([]string, 0, len(f.remove))
	for _, arg := range f.remove {
		state, err := a.removalState(ctx, arg, root)
		if err != nil {
			return err
		}
		removed[state] = true
		removeOrder = append(removeOrder, state)
	}
	// Reject a --rm that is not mounted before applying any of the others:
	// a typo must not leave the root without the mounts named earlier.
	if err := a.preflightRemovals(ctx, f.root, removeOrder); err != nil {
		return err
	}
	// A move is only implicit when the invocation also frees mount paths;
	// a plain add at a second path still tells the user to unmount first.
	move := len(removed) > 0
	if err := validateMountPlan(root, requests, removed, move); err != nil {
		return err
	}
	// Removals run first so the final topology validated above is the one
	// the adds are applied to.
	for _, state := range f.remove {
		if err := a.unmountArg(ctx, state, f.root); err != nil {
			return err
		}
	}
	for _, n := range news {
		if err := a.newMountedState(ctx, n.spec, f, replicasSet); err != nil {
			return a.restoreAfterFailedAdd(ctx, f.root, original, removed, err)
		}
	}
	for _, add := range adds {
		if err := a.mountStatePlanned(ctx, add.state, f.root, add.path, add.writable, move); err != nil {
			return a.restoreAfterFailedAdd(ctx, f.root, original, removed, err)
		}
	}
	return nil
}

// checkNewOnlyFlags rejects state settings that have no state to apply to.
// Silently discarding them would report success for a size, replica count, or
// copy source that was never used.
func checkNewOnlyFlags(f *mountFlags, replicasSet bool) error {
	if len(f.create) > 0 {
		return nil
	}
	var used []string
	if f.from != "" {
		used = append(used, "--from")
	}
	if f.size != "" {
		used = append(used, "--size")
	}
	if replicasSet {
		used = append(used, "--replicas")
	}
	if len(used) == 0 {
		return nil
	}
	return fmt.Errorf("%s can only be used with --new", strings.Join(used, ", "))
}

// prepareNewMounts parses and scopes every --new request before any state is
// created. newMountedState validates each one again against the current root.
func (a *app) prepareNewMounts(f *mountFlags, replicasSet bool) ([]newMount, error) {
	if replicasSet && (f.replicas < 1 || f.replicas > 3) {
		return nil, errors.New("--replicas must be between 1 and 3")
	}
	news := make([]newMount, 0, len(f.create))
	for _, spec := range f.create {
		name, mountPath, mode, err := parseMountSpec(spec)
		if err != nil {
			return nil, err
		}
		writable := true
		if mode != nil {
			writable = *mode
		}
		if err := a.scope(&name); err != nil {
			return nil, err
		}
		if err := a.validateName("state", name); err != nil {
			return nil, err
		}
		news = append(news, newMount{spec: spec, name: name, path: mountPath, writable: writable})
	}
	return news, nil
}

// mountSource resolves an existing state named by a mount argument. A state
// created earlier in the same command has no object yet, so its planned name is
// accepted instead.
func (a *app) mountSource(ctx context.Context, name string, created map[string]bool) (string, error) {
	if full := a.full(name); created[full] {
		return full, nil
	}
	src, err := a.resolveState(ctx, name)
	if err != nil {
		return "", err
	}
	if msg := usableStateFailure(src); msg != "" {
		return "", fmt.Errorf("state %q failed: %s", a.short(src.Name), msg)
	}
	return src.Name, nil
}

// newMountedState creates a state and mounts it on the root. An empty state
// gets its first version from the state controller; --from copies a workspace
// or imported base into a new one.
func (a *app) newMountedState(ctx context.Context, spec string, f *mountFlags, replicasSet bool) error {
	name, mountPath, mode, err := parseMountSpec(spec)
	if err != nil {
		return err
	}
	writable := true
	if mode != nil {
		writable = *mode
	}
	if replicasSet && (f.replicas < 1 || f.replicas > 3) {
		return errors.New("--replicas must be between 1 and 3")
	}
	if err := a.scope(&name); err != nil {
		return err
	}
	if err := a.validateName("state", name); err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	// Validate the target before creating anything: a rejected mount must not
	// leave behind a committed state that the user has to delete by hand.
	root, err := a.getState(ctx, f.root)
	if err != nil {
		return err
	}
	if root.DeletionTimestamp != nil {
		return fmt.Errorf("state %q is being deleted", a.short(f.root))
	}
	if root.Spec.Image != "" {
		return fmt.Errorf("state %q is an imported base and cannot be executed directly; use --from %s", a.short(f.root), a.short(f.root))
	}
	if msg := usableStateFailure(root); msg != "" {
		return fmt.Errorf("state %q failed: %s", a.short(f.root), msg)
	}
	if err := validateMountPlan(root, []mountRequest{{state: name, path: mountPath, writable: writable}}, nil, false); err != nil {
		return err
	}
	st := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace}}
	if replicasSet {
		st.Spec.Replicas = f.replicas
	}
	if f.size != "" {
		size, err := parseSizeFlag(f.size)
		if err != nil {
			return err
		}
		st.Spec.Size = size
	}
	a.label(st)
	var built []*v1alpha1.BlipState
	if f.from != "" {
		src, err := a.resolveState(ctx, f.from)
		if err != nil {
			return err
		}
		created, err := workspace.Fork(ctx, c.Kube, src, st, nil)
		if err != nil {
			if apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("state %q already exists; choose another name", a.short(name))
			}
			return err
		}
		built = created
	} else if err := c.Kube.Create(ctx, st); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state %q already exists; choose another name", a.short(name))
		}
		return err
	} else {
		built = []*v1alpha1.BlipState{st}
	}
	if _, err := a.waitStateCommitted(ctx, name); err != nil {
		a.removeCreatedStates(ctx, built)
		return err
	}
	// The root may have started deleting while the new state committed. It
	// can never run this mount, so remove what this command created instead
	// of leaving an orphan behind.
	if root, err := a.getState(ctx, f.root); err != nil {
		a.removeCreatedStates(ctx, built)
		return err
	} else if root.DeletionTimestamp != nil {
		a.removeCreatedStates(ctx, built)
		return fmt.Errorf("state %q is being deleted", a.short(f.root))
	}
	if err := a.mountState(ctx, name, f.root, mountPath, &writable); err != nil {
		a.removeUnusedCreatedStates(ctx, f.root, name, mountPath, built)
		return err
	}
	return nil
}

// removeUnusedCreatedStates deletes the states a failed --new created, but
// only if they never became desired intent and the running writer has released
// them. Deleting a state that the writer still reports makes the controller
// finish the execution with a discarded save and fail it.
func (a *app) removeUnusedCreatedStates(ctx context.Context, root, state, mountPath string, built []*v1alpha1.BlipState) {
	// A mount that became desired intent before failing is referenced by the
	// root, so its state is not an orphan and must stay.
	if a.mountApplied(ctx, root, state, mountPath) {
		return
	}
	if !a.createdStateUnused(ctx, root, state) {
		fmt.Fprintf(a.env.Err, "warning: state %s created for the failed mount is still in use; leaving it in place\n", a.short(state))
		return
	}
	a.removeCreatedStates(ctx, built)
}

// createdStateUnused reports whether a state this command created may be
// deleted: no desired intent references it and the root's running writer no
// longer reports it. A state still visible as a writable mount, or still
// attached or pre-acquired, belongs to the live execution; deleting it makes
// the controller report a discarded save and fail the Blip. The check is
// repeated briefly because the controller drops a failed entry and releases
// its writer slot a moment after the mount's intent is rolled back.
func (a *app) createdStateUnused(ctx context.Context, root, state string) bool {
	c, err := a.clients()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		s, err := a.getState(ctx, root)
		if err != nil {
			return false
		}
		// Serialize against the current root intent: a concurrent command
		// may have put the mount back, in which case the state is in use.
		if findSpecMount(s.Spec.Mounts, state) != nil {
			return false
		}
		b, err := a.rootWriter(ctx, s)
		if err != nil {
			return false
		}
		var st v1alpha1.BlipState
		err = c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: state}, &st)
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil {
			return false
		}
		w := st.Status.Writer
		if w != nil && w.PodUID != "" {
			// Attached to a VM: never delete it.
			return false
		}
		if b == nil {
			return true
		}
		if m := findMount(b.Status.Mounts, state); m != nil {
			if m.InClaim || m.Phase == v1alpha1.MountMounted || m.Phase == v1alpha1.MountSaving ||
				m.Phase == v1alpha1.MountUnmounting {
				return false
			}
			// Pending or Failed: never attached. Wait for the controller to
			// drop the failed entry and release the pre-acquired writer.
		} else if w == nil || w.BlipUID != string(b.UID) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// mountApplied reports whether the root's desired topology already references
// the mount.
func (a *app) mountApplied(ctx context.Context, root, state, mountPath string) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	s, err := a.getState(ctx, root)
	if err != nil {
		return false
	}
	m := findSpecMount(s.Spec.Mounts, state)
	return m != nil && m.Path == mountPath
}

// removeCreatedStates best-effort deletes the states this command created when a
// --new mount never became desired intent. Fork also creates a copy state for
// every writable mount of the source, so removing only the root would leak those
// full workspace copies. Cleanup must not hide the original error.
func (a *app) removeCreatedStates(ctx context.Context, states []*v1alpha1.BlipState) {
	c, err := a.clients()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	// Delete the root first, then the copies: the root is created last, so the
	// reverse of creation order is the natural teardown order.
	for i := len(states) - 1; i >= 0; i-- {
		st := states[i]
		opts := &client.DeleteOptions{}
		if st.UID != "" {
			uid := st.UID
			opts.Preconditions = &metav1.Preconditions{UID: &uid}
		}
		_ = c.Kube.Delete(ctx, st, opts)
	}
}

func (a *app) listMounts(ctx context.Context, root string) error {
	s, err := a.getState(ctx, root)
	if err != nil {
		return err
	}
	b, err := a.rootWriter(ctx, s)
	if err != nil {
		return err
	}
	printed := 0
	for _, m := range s.Spec.Mounts {
		if m.BlipUID != "" {
			continue
		}
		printed++
		line := fmt.Sprintf("%s:%s (%s)", a.short(m.State), m.Path, modeName(m.Writable))
		if b != nil {
			if st := findMount(b.Status.Mounts, m.State); st != nil {
				line += " " + string(st.Phase)
			}
		}
		fmt.Fprintln(a.env.Out, line)
	}
	if printed == 0 {
		fmt.Fprintf(a.env.Out, "state %s has no mounts\n", a.short(root))
	}
	return nil
}

// preflightRemovals rejects a command whose --rm names a state that is not
// mounted, before any later removal or add has been applied. A temporary
// collect mount may only be visible in the running writer's status, where
// unmountState can still remove it.
func (a *app) preflightRemovals(ctx context.Context, root string, states []string) error {
	s, err := a.getState(ctx, root)
	if err != nil {
		return err
	}
	var b *v1alpha1.Blip
	for _, state := range states {
		if findSpecMount(s.Spec.Mounts, state) != nil {
			continue
		}
		if b, err = a.rootWriter(ctx, s); err != nil {
			return err
		}
		if b != nil && findMount(b.Status.Mounts, state) != nil {
			continue
		}
		return fmt.Errorf("state %q is not mounted on root state %q", state, root)
	}
	return nil
}

// removalState resolves a --rm argument to the state name used by the root's
// spec, accepting an owner-local name or the qualified name that is actually
// in it.
func (a *app) removalState(ctx context.Context, arg string, s *v1alpha1.BlipState) (string, error) {
	state := a.full(arg)
	if state != arg && findSpecMount(s.Spec.Mounts, state) == nil {
		if findSpecMount(s.Spec.Mounts, arg) != nil {
			state = arg
		} else {
			b, err := a.rootWriter(ctx, s)
			if err != nil {
				return "", err
			}
			if b != nil && findMount(b.Status.Mounts, state) == nil && findMount(b.Status.Mounts, arg) != nil {
				state = arg
			}
		}
	}
	return state, nil
}

// unmountArg removes a mount, accepting an owner-local name or the qualified
// name that is actually in the root's spec.
func (a *app) unmountArg(ctx context.Context, arg, root string) error {
	s, err := a.getState(ctx, root)
	if err != nil {
		return err
	}
	state, err := a.removalState(ctx, arg, s)
	if err != nil {
		return err
	}
	return a.unmountState(ctx, state, root)
}
