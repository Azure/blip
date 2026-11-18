package cli

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

func (a *app) getState(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	var s v1alpha1.BlipState
	if err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("state %q not found in namespace %q", name, c.Namespace)
		}
		return nil, err
	}
	return &s, nil
}

func findMount(list []v1alpha1.MountStatus, state string) *v1alpha1.MountStatus {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
}

// updateBlip applies change to the latest blip, retrying on conflicts.
func (a *app) updateBlip(ctx context.Context, name string, change func(*v1alpha1.Blip) error) (*v1alpha1.Blip, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	var b *v1alpha1.Blip
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if b, err = a.getBlip(ctx, name); err != nil {
			return err
		}
		if err := change(b); err != nil {
			return err
		}
		return c.Kube.Update(ctx, b)
	})
	return b, err
}

var errUnchanged = errors.New("unchanged")

// switchBusyTimeout is how long a mode switch waits for processes to stop
// using the old mount before it gives up and leaves the mount as it was.
var switchBusyTimeout = 30 * time.Second

func (a *app) mountState(ctx context.Context, state, blip, mountPath string, target *bool) error {
	if !path.IsAbs(mountPath) || path.Clean(mountPath) != mountPath || mountPath == "/" {
		return fmt.Errorf("invalid path %q: must be a clean absolute path other than /", mountPath)
	}
	s, err := a.getState(ctx, state)
	if err != nil {
		return err
	}
	if target != nil && *target {
		if w := s.Status.Writer; w != nil && w.BlipName != blip {
			return fmt.Errorf("state %q is busy: blip %q is writing to it", state, w.BlipName)
		}
	}
	if s.Status.Phase == v1alpha1.StateFailed {
		return fmt.Errorf("state %q failed: %s", state, s.Status.Message)
	}
	var previous, want bool
	var changed bool
	baseGeneration := int64(0)
	if s.Status.Committed != nil {
		baseGeneration = s.Status.Committed.Generation
	}
	_, err = a.updateBlip(ctx, blip, func(b *v1alpha1.Blip) error {
		if finished(b) || b.DeletionTimestamp != nil || b.Spec.Stop {
			return fmt.Errorf("blip %q is stopping or has finished", blip)
		}
		previous, want, changed = false, false, false
		for i := range b.Spec.Mounts {
			m := &b.Spec.Mounts[i]
			if m.State != state {
				continue
			}
			if m.Path != mountPath {
				return fmt.Errorf("state %q is already mounted on blip %q at %s; unmount it first", state, blip, m.Path)
			}
			previous, want = m.Writable, m.Writable
			if target == nil || *target == m.Writable {
				return errUnchanged
			}
			want = *target
			m.Writable = want
			changed = true
			return nil
		}
		for _, m := range b.Spec.Mounts {
			if m.Path == mountPath {
				return fmt.Errorf("blip %q already has state %q mounted at %s", blip, m.State, mountPath)
			}
		}
		if target != nil {
			want = *target
		}
		b.Spec.Mounts = append(b.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath, Writable: want})
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return err
	}
	r := &reporter{a: a}
	defer r.stop()
	start := time.Now()
	err = a.waitBlip(ctx, blip, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil {
			return false, fmt.Errorf("blip %q was deleted", blip)
		}
		if finished(b) || b.Status.Phase == v1alpha1.BlipSaving {
			return false, fmt.Errorf("blip %q stopped before the mount completed", blip)
		}
		m := findMount(b.Status.Mounts, state)
		if m == nil || m.Path != mountPath {
			r.say("mounting %s on %s...", state, blip)
			return false, nil
		}
		if m.Phase == v1alpha1.MountFailed {
			if changed {
				a.revertMount(ctx, blip, state, mountPath, previous)
			}
			if strings.Contains(m.Message, "busy") {
				return false, fmt.Errorf("could not switch state %q on blip %q: processes are still using %s (stop them, then run the command again)", state, blip, mountPath)
			}
			return false, fmt.Errorf("mount of state %q on blip %q failed: %s (unmount it, then mount again to retry)", state, blip, m.Message)
		}
		if m.Switching && m.Writable != want {
			if strings.HasPrefix(m.Message, "cannot switch") {
				if changed {
					a.revertMount(ctx, blip, state, mountPath, previous)
				}
				return false, fmt.Errorf("switch of state %q on blip %q failed: %s", state, blip, m.Message)
			}
			if m.Message != "" {
				r.say("switching %s on %s: %s", state, blip, m.Message)
			} else {
				r.say("switching %s on %s to %s...", state, blip, modeName(want))
			}
			if m.Message != "" && !strings.Contains(m.Message, "busy") {
				if changed {
					a.revertMount(ctx, blip, state, mountPath, previous)
				}
				return false, fmt.Errorf("switch of state %q on blip %q failed: %s", state, blip, m.Message)
			}
			if strings.Contains(m.Message, "busy") && time.Since(start) > switchBusyTimeout {
				if changed {
					a.revertMount(ctx, blip, state, mountPath, previous)
				}
				return false, fmt.Errorf("could not switch state %q on blip %q: processes are still using %s (stop them, then run the command again)", state, blip, mountPath)
			}
			return false, nil
		}
		if m.Phase == v1alpha1.MountMounted && m.Writable == want {
			if !want && changed {
				st, err := a.getState(ctx, state)
				if err != nil {
					return false, err
				}
				landed := st.Status.Committed != nil &&
					(baseGeneration == 0 || st.Status.Committed.Generation > baseGeneration)
				if m.CommitID != "" && st.Status.Committed != nil && st.Status.Committed.ID == m.CommitID {
					landed = true
				}
				if !landed {
					r.say("saving new version of %s...", state)
					return false, nil
				}
			}
			return true, nil
		}
		if m.Message != "" {
			r.say("mounting %s on %s: %s", state, blip, m.Message)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.env.Out, "state %s mounted on blip %s at %s (%s)\n", a.short(state), a.short(blip), mountPath, modeName(want))
	return nil
}

func modeName(write bool) string {
	if write {
		return "writable"
	}
	return "read-only"
}

// revertMount puts a mount back in the mode it had before a failed switch.
func (a *app) revertMount(ctx context.Context, blip, state, mountPath string, writable bool) {
	_, _ = a.updateBlip(ctx, blip, func(b *v1alpha1.Blip) error {
		for i := range b.Spec.Mounts {
			m := &b.Spec.Mounts[i]
			if m.State == state && m.Path == mountPath && m.Writable != writable {
				m.Writable = writable
				return nil
			}
		}
		return errUnchanged
	})
}

func (a *app) unmountState(ctx context.Context, state, blip string) error {
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
		if cp.Spec.CopyFrom == state && cp.Status.Committed == nil && cp.DeletionTimestamp == nil &&
			cp.Status.Phase != v1alpha1.StateFailed {
			return fmt.Errorf("state %q is being forked by %q; wait for the fork to finish before unmounting", state, a.short(cp.Name))
		}
	}
	if b, err := a.getBlip(ctx, blip); err == nil {
		if m := findMount(b.Status.Mounts, state); m != nil && m.Switching {
			r := &reporter{a: a}
			err := a.waitBlip(ctx, blip, func(b *v1alpha1.Blip) (bool, error) {
				m := findMount(b.Status.Mounts, state)
				if m == nil || !m.Switching || m.Phase == v1alpha1.MountFailed ||
					m.Phase == v1alpha1.MountMounted && m.Message != "" {
					return true, nil
				}
				r.say("waiting for %s to finish switching...", state)
				return false, nil
			})
			r.stop()
			if err != nil {
				return err
			}
		}
	}
	var before *v1alpha1.MountStatus
	inSpec := false
	b, err := a.updateBlip(ctx, blip, func(b *v1alpha1.Blip) error {
		before = findMount(b.Status.Mounts, state)
		inSpec = false
		var keep []v1alpha1.Mount
		for _, m := range b.Spec.Mounts {
			if m.State == state {
				inSpec = true
			} else {
				keep = append(keep, m)
			}
		}
		if !inSpec {
			return errUnchanged
		}
		b.Spec.Mounts = keep
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return err
	}
	if !inSpec && findMount(b.Status.Mounts, state) == nil {
		return fmt.Errorf("state %q is not mounted on blip %q", state, blip)
	}
	r := &reporter{a: a}
	defer r.stop()
	start := time.Now()
	err = a.waitBlip(ctx, blip, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil {
			return true, nil
		}
		m := findMount(b.Status.Mounts, state)
		if m == nil {
			return true, nil
		}
		// A failed unmount is retried every 2s; an error that was already
		// there gets a few retries before it is reported.
		if (m.Phase == v1alpha1.MountFailed || m.Phase == v1alpha1.MountUnmounting) && m.Message != "" &&
			(before == nil || before.Message != m.Message || time.Since(start) > 5*time.Second) {
			msg := m.Message
			if strings.Contains(msg, "busy") {
				msg = fmt.Sprintf("processes are still using %s (stop them, then run the command again)", m.Path)
			}
			return false, fmt.Errorf("could not unmount state %q from blip %q: %s", state, blip, msg)
		}
		if m.Phase == v1alpha1.MountSaving {
			r.say("saving %s...", state)
		} else {
			r.say("unmounting %s from %s...", state, blip)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.env.Out, "state %s unmounted from blip %s\n", a.short(state), a.short(blip))
	return nil
}

// mountTarget scopes the state and blip names; the blip defaults to the
// one the command runs in.
func (a *app) mountTarget(state, blip *string) error {
	if err := a.scope(state, blip); err != nil {
		return err
	}
	if *blip == "" {
		if a.self == nil {
			return errors.New("--blip is required outside a blip")
		}
		*blip = a.self.Name
	}
	return nil
}

func (a *app) mountCommand() *cobra.Command {
	var blip, mountPath string
	var write, readOnly bool
	cmd := &cobra.Command{
		Use:     "mount STATE [--blip NAME] --path PATH [--write|--read-only]",
		Short:   "Mount a state into a running blip",
		Example: "  kubectl blip mount repo --blip agent --path /work --write",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.mountTarget(&args[0], &blip); err != nil {
				return err
			}
			if write && readOnly {
				return errors.New("--write and --read-only cannot be used together")
			}
			var target *bool
			if cmd.Flags().Changed("write") {
				v := true
				target = &v
			} else if cmd.Flags().Changed("read-only") {
				v := false
				target = &v
			}
			return a.mountState(cmd.Context(), args[0], blip, mountPath, target)
		},
	}
	cmd.Flags().StringVar(&blip, "blip", "", "blip to mount into (default: the blip this runs in)")
	cmd.Flags().StringVar(&mountPath, "path", "", "absolute mount path in the blip (required)")
	cmd.Flags().BoolVar(&write, "write", false, "mount writable (takes the state's writer and saves on unmount)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "mount read-only (the default for a new mount)")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func (a *app) unmountCommand() *cobra.Command {
	var blip string
	cmd := &cobra.Command{
		Use:   "unmount STATE [--blip NAME]",
		Short: "Unmount a state from a blip and wait until it is saved",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.mountTarget(&args[0], &blip); err != nil {
				return err
			}
			return a.unmountState(cmd.Context(), args[0], blip)
		},
	}
	cmd.Flags().StringVar(&blip, "blip", "", "blip to unmount from (default: the blip this runs in)")
	return cmd
}
