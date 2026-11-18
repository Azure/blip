package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// waitFor calls check with the object (nil once it is gone) after every
// change until check returns true or an error. It watches instead of
// polling and re-establishes the watch when the server closes it.
func waitFor[T client.Object](ctx context.Context, c client.WithWatch, list client.ObjectList, key client.ObjectKey, newObj func() T, check func(T) (bool, error)) error {
	for {
		w, err := c.Watch(ctx, list, client.InNamespace(key.Namespace), client.MatchingFields{"metadata.name": key.Name})
		if err != nil {
			return err
		}
		done, err := waitOnce(ctx, c, w, key, newObj, check)
		w.Stop()
		if done || err != nil {
			return err
		}
	}
}

func waitOnce[T client.Object](ctx context.Context, c client.WithWatch, w watch.Interface, key client.ObjectKey, newObj func() T, check func(T) (bool, error)) (bool, error) {
	var zero T
	obj := newObj()
	err := c.Get(ctx, key, obj)
	switch {
	case apierrors.IsNotFound(err):
		obj = zero
	case err != nil:
		return false, err
	}
	if done, err := check(obj); done || err != nil {
		return true, err
	}
	// Checks may depend on time, so they also run periodically.
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-tick.C:
			if done, err := check(obj); done || err != nil {
				return true, err
			}
		case ev, ok := <-w.ResultChan():
			if !ok {
				return false, nil
			}
			switch ev.Type {
			case watch.Error:
				if status, ok := ev.Object.(*metav1.Status); ok && status.Code != 410 {
					return true, apierrors.FromObject(status)
				}
				return false, nil
			case watch.Added, watch.Modified, watch.Deleted:
				o, ok := ev.Object.(T)
				if !ok || o.GetName() != key.Name {
					continue
				}
				if ev.Type == watch.Deleted {
					o = zero
				}
				obj = o
				if done, err := check(o); done || err != nil {
					return true, err
				}
			}
		}
	}
}

func (a *app) waitBlip(ctx context.Context, name string, check func(*v1alpha1.Blip) (bool, error)) error {
	c, err := a.clients()
	if err != nil {
		return err
	}
	return waitFor(ctx, c.Kube, &v1alpha1.BlipList{}, client.ObjectKey{Namespace: c.Namespace, Name: name},
		func() *v1alpha1.Blip { return &v1alpha1.Blip{} }, check)
}

// reporter prints a progress line whenever it changes. It holds lines
// back for Env.ProgressDelay so fast operations print nothing; call stop
// when the wait ends.
type reporter struct {
	a       *app
	mu      sync.Mutex
	start   time.Time
	last    string
	pending string
	timer   *time.Timer
	stopped bool
}

func (r *reporter) say(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.start.IsZero() {
		r.start = time.Now()
	}
	if wait := r.a.env.ProgressDelay - time.Since(r.start); wait > 0 {
		r.pending = msg
		if r.timer == nil {
			r.timer = time.AfterFunc(wait, r.flush)
		}
		return
	}
	r.print(msg)
}

func (r *reporter) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != "" {
		r.print(r.pending)
	}
}

func (r *reporter) print(msg string) {
	r.pending = ""
	if r.stopped || msg == r.last {
		return
	}
	r.last = msg
	r.a.progress("%s", msg)
}

func (r *reporter) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.timer != nil {
		r.timer.Stop()
	}
}

func finished(b *v1alpha1.Blip) bool {
	return b.Status.Phase == v1alpha1.BlipSucceeded || b.Status.Phase == v1alpha1.BlipFailed
}

// waitRunning waits until the blip runs (returns its pod) or finishes
// (returns "").
func (a *app) waitRunning(ctx context.Context, name string) (*v1alpha1.Blip, error) {
	r := &reporter{a: a}
	defer r.stop()
	var got *v1alpha1.Blip
	err := a.waitBlip(ctx, name, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil {
			return false, fmt.Errorf("blip %q was deleted", name)
		}
		got = b
		switch {
		case b.Status.Phase == v1alpha1.BlipRunning && b.Status.Pod != "":
			return true, nil
		case b.Status.Phase == v1alpha1.BlipSaving || finished(b):
			return true, nil
		}
		if b.Status.Message != "" {
			r.say("waiting for blip %s: %s", name, b.Status.Message)
		}
		return false, nil
	})
	return got, err
}

// waitFinished waits until the blip is Succeeded or Failed (saves included).
func (a *app) waitFinished(ctx context.Context, name string, quiet bool) (*v1alpha1.Blip, error) {
	r := &reporter{a: a}
	defer r.stop()
	var got *v1alpha1.Blip
	err := a.waitBlip(ctx, name, func(b *v1alpha1.Blip) (bool, error) {
		if b == nil {
			return false, fmt.Errorf("blip %q not found", name)
		}
		got = b
		if finished(b) {
			return true, nil
		}
		if !quiet && b.Status.Phase == v1alpha1.BlipSaving {
			r.say("blip %s: saving", name)
		}
		return false, nil
	})
	return got, err
}

func (a *app) waitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "wait NAME...",
		Short: "Wait until blips finish (including saves); fails if any failed",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			failed := false
			for _, name := range args {
				if err := a.scope(&name); err != nil {
					return err
				}
				fin, err := a.waitFinished(cmd.Context(), name, true)
				if err != nil {
					return err
				}
				line := fmt.Sprintf("blip/%s %s", a.short(name), fin.Status.Phase)
				if fin.Status.ExitCode != nil {
					line += fmt.Sprintf(" (exit %d)", *fin.Status.ExitCode)
				}
				if fin.Status.Phase == v1alpha1.BlipFailed {
					failed = true
					if msg := fin.Status.Message; strings.Contains(msg, "\n") {
						line += ":\n    " + strings.ReplaceAll(msg, "\n", "\n    ")
					} else if msg != "" {
						line += ": " + msg
					}
				}
				fmt.Fprintln(a.env.Out, line)
			}
			if failed {
				return &ExitError{Code: 1}
			}
			return nil
		},
	}
}
