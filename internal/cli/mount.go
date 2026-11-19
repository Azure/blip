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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
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

func (a *app) mountState(ctx context.Context, state, root, mountPath string, target *bool) error {
	if !path.IsAbs(mountPath) || path.Clean(mountPath) != mountPath || mountPath == "/" {
		return fmt.Errorf("invalid path %q: must be a clean absolute path other than /", mountPath)
	}
	if state == root {
		return errors.New("a root state cannot mount itself")
	}
	source, err := a.getState(ctx, state)
	if err != nil {
		return err
	}
	var want, demoting bool
	var oldAttachment string
	s, err := a.editMountsWaitingStale(ctx, root, state, func(s *v1alpha1.BlipState) (string, error) {
		want, demoting = false, false
		oldAttachment = ""
		m := findSpecMount(s.Spec.Mounts, state)
		if m != nil {
			if m.Path != mountPath {
				return "", fmt.Errorf("state %q is already mounted on root state %q at %s; unmount it first", state, root, m.Path)
			}
			want = m.Writable
			// Adoption of a collect mount must finish its pending reattach.
			if u := mountUsers(s)[state]; m.BlipUID != "" && u.BlipUID == m.BlipUID && u.Path == m.Path {
				oldAttachment = u.PreviousAttachment
			}
		} else {
			for _, other := range s.Spec.Mounts {
				if other.Path == mountPath {
					return "", fmt.Errorf("root state %q already has state %q mounted at %s", root, other.State, mountPath)
				}
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
		if b == nil || b.UID != writer.UID || b.Spec.State != writer.Spec.State || v1alpha1.Finished(b) ||
			b.Spec.Stop || b.DeletionTimestamp != nil || b.Status.Phase == v1alpha1.BlipSaving {
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
			return false, fmt.Errorf("mount of state %q on blip %q failed: %s; desired mount remains applied", state, b.Name, m.Message)
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
	b, err := a.rootWriter(ctx, s)
	if err != nil {
		return err
	}
	if !inSpec && (b == nil || findMount(b.Status.Mounts, state) == nil) {
		return fmt.Errorf("state %q is not mounted on root state %q", state, root)
	}
	if b == nil {
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
	fmt.Fprintf(a.env.Out, "state %s unmounted from blip %s\n", a.short(state), a.short(b.Name))
	return nil
}

// mountTarget scopes state names; inside a guest the root defaults to self's
// root state rather than its execution name.
func (a *app) mountTarget(root *string) error {
	if err := a.scope(root); err != nil {
		return err
	}
	if *root == "" {
		if a.self == nil {
			return errors.New("--root is required outside a blip")
		}
		*root = a.self.Spec.State
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
in the running command. Outside one, --root names the state to edit.`,
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
func parseMountSpec(s string) (state, mountPath string, writable *bool, err error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 || parts[0] == "" {
		return "", "", nil, fmt.Errorf("invalid mount %q: want STATE:PATH[:rw|ro]", s)
	}
	state, mountPath = parts[0], parts[1]
	if !path.IsAbs(mountPath) || path.Clean(mountPath) != mountPath || mountPath == "/" {
		return "", "", nil, fmt.Errorf("invalid mount %q: PATH must be a clean absolute path other than /", s)
	}
	if len(parts) == 3 {
		want := false
		switch parts[2] {
		case "rw":
			want = true
		case "ro":
		default:
			return "", "", nil, fmt.Errorf("invalid mount %q: mode must be rw or ro", s)
		}
		writable = &want
	}
	return state, mountPath, writable, nil
}

func (a *app) mount(ctx context.Context, args []string, f *mountFlags, replicasSet bool) error {
	if err := a.mountTarget(&f.root); err != nil {
		return err
	}
	if len(args) == 0 && len(f.remove) == 0 && len(f.create) == 0 {
		return a.listMounts(ctx, f.root)
	}
	for _, spec := range f.create {
		if err := a.newMountedState(ctx, spec, f, replicasSet); err != nil {
			return err
		}
	}
	for _, arg := range args {
		state, mountPath, writable, err := parseMountSpec(arg)
		if err != nil {
			return err
		}
		source, err := a.resolveState(ctx, state)
		if err != nil {
			return err
		}
		if err := a.mountState(ctx, source.Name, f.root, mountPath, writable); err != nil {
			return err
		}
	}
	for _, state := range f.remove {
		if err := a.unmountArg(ctx, state, f.root); err != nil {
			return err
		}
	}
	return nil
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
	c, err := a.clients()
	if err != nil {
		return err
	}
	st := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace}}
	if replicasSet {
		st.Spec.Replicas = f.replicas
	}
	if f.size != "" {
		size, err := resource.ParseQuantity(f.size)
		if err != nil {
			return fmt.Errorf("invalid --size %q: %w", f.size, err)
		}
		if size.Sign() <= 0 {
			return fmt.Errorf("invalid --size %q: must be positive", f.size)
		}
		st.Spec.Size = &size
	}
	a.label(st)
	if f.from != "" {
		src, err := a.resolveState(ctx, f.from)
		if err != nil {
			return err
		}
		if err := workspace.Fork(ctx, c.Kube, src, st, nil); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("state %q already exists; choose another name", a.short(name))
			}
			return err
		}
	} else if err := c.Kube.Create(ctx, st); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state %q already exists; choose another name", a.short(name))
		}
		return err
	}
	if _, err := a.waitStateCommitted(ctx, name); err != nil {
		return err
	}
	return a.mountState(ctx, name, f.root, mountPath, &writable)
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

// unmountArg removes a mount, accepting an owner-local name or the qualified
// name that is actually in the root's spec.
func (a *app) unmountArg(ctx context.Context, arg, root string) error {
	s, err := a.getState(ctx, root)
	if err != nil {
		return err
	}
	state := a.full(arg)
	if state != arg && findSpecMount(s.Spec.Mounts, state) == nil {
		if findSpecMount(s.Spec.Mounts, arg) != nil {
			state = arg
		} else {
			b, err := a.rootWriter(ctx, s)
			if err != nil {
				return err
			}
			if b != nil && findMount(b.Status.Mounts, state) == nil && findMount(b.Status.Mounts, arg) != nil {
				state = arg
			}
		}
	}
	return a.unmountState(ctx, state, root)
}
