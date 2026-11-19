package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/wire"
)

type gatherFlags struct {
	selector string
	collect  []string
	any      bool
	wait     time.Duration
	follow   bool
	keep     bool
}

func (a *app) gatherCommand() *cobra.Command {
	f := &gatherFlags{}
	cmd := &cobra.Command{
		Use:   "gather [BLIP...] [flags]",
		Short: "Wait for blips, collect their results, and delete them",
		Long: `Wait for blips to finish, collect results from their workspaces, and delete
them.

Inside a blip, gather with no arguments targets the forks that blip started.
Select any other set with blip names or --selector.

With --collect, each operation is applied to every finished blip. Operations
are the same as the collect syntax, and {name} is replaced with the blip's
short name, so "git:/work/repo:{name}" gives each blip its own branch.

A blip whose command failed, or whose results could not be collected, is kept
for inspection; its TTL (1h for forks by default) still deletes it. Successful
blips are deleted with their workspaces.`,
		Example: `  blip run -- sh -c "make test"
  blip gather
  blip gather w1 w2 --collect "git:/work/repo:{name}"
  blip gather --collect "/home/dev/out:./artifacts/{name}"
  blip gather -l app=nightly --wait 10m`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.gather(cmd.Context(), args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.selector, "selector", "l", "", "label selector of blips to gather")
	fl.StringArrayVar(&f.collect, "collect", nil, "copy out of each blip: SRC:DEST or git:SRC:BRANCH ({name} is the blip's name; repeatable)")
	fl.BoolVar(&f.any, "any", false, "return as soon as one blip finishes")
	fl.DurationVar(&f.wait, "wait", 0, "give up waiting after this long (0 waits forever)")
	fl.BoolVarP(&f.follow, "follow", "f", false, "stream the output of blips while they run")
	fl.BoolVar(&f.keep, "keep", false, "keep the blips and their workspaces")
	return cmd
}

func (a *app) gather(ctx context.Context, names []string, f *gatherFlags) error {
	if f.wait < 0 {
		return fmt.Errorf("--wait must not be negative: %s", f.wait)
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	selector := f.selector
	if len(names) == 0 && selector == "" {
		if a.self == nil {
			return errors.New("gather needs blip names or --selector outside a blip")
		}
		selector = v1alpha1.LabelParent + "=" + a.short(a.self.Name)
	}
	if len(f.collect) > 0 && a.self == nil {
		return errors.New("--collect copies into the workspace of the blip this command runs in, so it only works inside one; gather with --keep and collect with kubectl elsewhere")
	}
	targets, err := a.gatherTargets(ctx, c, names, selector)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintln(a.env.Out, "no blips to gather")
		return nil
	}
	var followWG sync.WaitGroup
	followDone := map[string]chan struct{}{}
	var followCancel context.CancelFunc
	if f.follow {
		var fctx context.Context
		fctx, followCancel = context.WithCancel(ctx)
		defer followCancel()
		for _, b := range targets {
			ch := make(chan struct{})
			followDone[b.Name] = ch
			followWG.Add(1)
			go func(name string, ch chan struct{}) {
				defer followWG.Done()
				defer close(ch)
				a.follow(fctx, name)
			}(b.Name, ch)
		}
	}

	waitCtx := ctx
	if f.wait > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, f.wait)
		defer cancel()
	}
	done, errs := a.awaitTargets(waitCtx, f, targets)
	if f.follow {
		// Drain finished blips' replay before deleting them, then stop the
		// followers still attached to running blips.
		finished := make(map[string]bool, len(done))
		for _, b := range done {
			finished[b.Name] = true
		}
		for _, b := range targets {
			if !finished[b.Name] {
				continue
			}
			if ch, ok := followDone[b.Name]; ok {
				<-ch
			}
		}
		followCancel()
		followWG.Wait()
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Name < done[j].Name })
	for _, b := range done {
		if err := a.gatherOne(ctx, c, b, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// gatherTargets resolves the blips named on the command line and the ones that
// match selector, in a stable order.
func (a *app) gatherTargets(ctx context.Context, c *Clients, names []string, selector string) ([]*v1alpha1.Blip, error) {
	seen := map[string]bool{}
	var out []*v1alpha1.Blip
	add := func(b *v1alpha1.Blip) {
		if b == nil || seen[b.Name] {
			return
		}
		seen[b.Name] = true
		out = append(out, b)
	}
	for _, name := range names {
		if err := a.scope(&name); err != nil {
			return nil, err
		}
		b, err := a.getBlip(ctx, name)
		if err != nil {
			return nil, err
		}
		add(b)
	}
	if selector != "" {
		sel, err := labels.Parse(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid --selector %q: %w", selector, err)
		}
		var list v1alpha1.BlipList
		if err := c.Kube.List(ctx, &list, client.InNamespace(c.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
			return nil, err
		}
		for i := range list.Items {
			add(&list.Items[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// awaitTargets waits for the target blips to finish. It returns the ones that
// finished and an error for the ones that could not be observed or that were
// still running when the wait ended.
func (a *app) awaitTargets(ctx context.Context, f *gatherFlags, targets []*v1alpha1.Blip) ([]*v1alpha1.Blip, []error) {
	type outcome struct {
		name string
		b    *v1alpha1.Blip
		err  error
	}
	ch := make(chan outcome, len(targets))
	left := map[string]bool{}
	for _, b := range targets {
		left[b.Name] = true
		go func(name string) {
			fin, err := a.waitFinished(ctx, name, true)
			ch <- outcome{name: name, b: fin, err: err}
		}(b.Name)
	}
	var done []*v1alpha1.Blip
	var errs []error
	for len(left) > 0 {
		select {
		case <-ctx.Done():
			names := make([]string, 0, len(left))
			for name := range left {
				names = append(names, a.short(name))
			}
			sort.Strings(names)
			errs = append(errs, fmt.Errorf("still running: %s", strings.Join(names, ", ")))
			return done, errs
		case o := <-ch:
			delete(left, o.name)
			if o.err != nil {
				errs = append(errs, o.err)
			} else {
				done = append(done, o.b)
			}
			if f.any {
				return done, errs
			}
		}
	}
	return done, errs
}

// gatherOne reports one finished blip, collects its results when asked, and
// deletes it. A failed command or a failed collect keeps the blip.
func (a *app) gatherOne(ctx context.Context, c *Clients, b *v1alpha1.Blip, f *gatherFlags) error {
	line := fmt.Sprintf("blip/%s %s", a.short(b.Name), b.Status.Phase)
	if b.Status.ExitCode != nil {
		line += fmt.Sprintf(" (exit %d)", *b.Status.ExitCode)
	}
	if b.Status.Reason != "" && b.Status.Reason != "Completed" {
		line += fmt.Sprintf(" (%s)", b.Status.Reason)
	}
	if why := b.Annotations[v1alpha1.AnnotationStopReason]; why != "" {
		line += fmt.Sprintf(" [%s]", why)
	}
	if b.Status.StartTime != nil && b.Status.FinishTime != nil {
		line += " " + b.Status.FinishTime.Sub(b.Status.StartTime.Time).Round(time.Second).String()
	}
	fmt.Fprintln(a.env.Out, line)
	if b.Status.Report != nil {
		fmt.Fprintf(a.env.Out, "  report: %s\n", strings.ReplaceAll(b.Status.Report.Text, "\n", " "))
	}

	var errs []error
	retained := false
	if b.Status.Phase == v1alpha1.BlipFailed {
		errs = append(errs, fmt.Errorf("blip %s failed: %s", a.short(b.Name), describe(b)))
		retained = true
	}
	if len(f.collect) > 0 {
		ops := make([]string, len(f.collect))
		for i, op := range f.collect {
			ops[i] = strings.ReplaceAll(op, "{name}", a.short(b.Name))
		}
		if err := a.collect(ctx, b.Name, ops); err != nil {
			errs = append(errs, fmt.Errorf("collect from %s: %w", a.short(b.Name), err))
			retained = true
		}
	}
	if f.keep || retained {
		if retained && !f.keep {
			a.progress("blip %s kept for inspection; delete it with kubectl delete blip %s", a.short(b.Name), b.Name)
		}
		return errors.Join(errs...)
	}
	if err := c.Kube.Delete(ctx, b); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete blip %s: %w", a.short(b.Name), err))
	}
	return errors.Join(errs...)
}

// follow streams a blip's primary output until it exits, prefixing each line
// with the blip's short name. A blip that finished before the follower
// attached still replays its retained output while its VM pod exists.
// Followers never block the command; gather drains them before deleting.
func (a *app) follow(ctx context.Context, name string) {
	b, err := a.waitRunning(ctx, name)
	if err != nil {
		return
	}
	// The blip may have finished between the wait and the get below. A
	// finished primary session stays replayable as long as the pod exists.
	if b, err = a.getBlip(ctx, name); err != nil {
		return
	}
	short := a.short(name)
	pod := b.Status.Pod
	if pod == "" {
		if v1alpha1.Finished(b) {
			a.progress("%s: output is no longer available (the VM pod is gone)", short)
		}
		return
	}
	s, err := a.openRetrying(ctx, name, pod, wire.Open{Mode: wire.OpenAttach, Session: wire.PrimarySession, Follow: true}, true)
	if err != nil {
		if v1alpha1.Finished(b) && ctx.Err() == nil {
			a.progress("%s: output is no longer available: %v", short, err)
		}
		return
	}
	defer s.Close()
	out := &prefixWriter{out: a.env.Out, prefix: short + "|"}
	errw := &prefixWriter{out: a.env.Err, prefix: short + "|"}
	_, _ = s.Copy(out, errw, func(m string) { a.progress("%s: %s", short, m) })
	out.flush()
	errw.flush()
}

// prefixWriter turns arbitrary output chunks into whole prefixed lines. Each
// line is one Write to out, so concurrent followers do not interleave inside a
// line.
type prefixWriter struct {
	out    io.Writer
	prefix string
	buf    []byte
}

const prefixLineMax = 64 << 10

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > prefixLineMax {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *prefixWriter) emit(line []byte) {
	fmt.Fprintf(w.out, "%s %s\n", w.prefix, strings.TrimSuffix(string(line), "\r"))
}

func (w *prefixWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
}
