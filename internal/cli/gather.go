package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
short name, so "git:/work/repo:{name}" gives each blip its own branch. A git
operation fetches commits only; uncommitted and untracked changes are not
collected, and a warning is printed when a worktree has them. Two operations
that expand to the same destination are rejected instead of overwriting each
other; {name} keeps each blip's destination distinct.

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
	fl.StringArrayVar(&f.collect, "collect", nil, "copy out of each blip: SRC:DEST (split at the last ':') or git:SRC:BRANCH (commits only; {name} is the blip's name; repeatable)")
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
	if err := a.checkCollectDestinations(done, f.collect); err != nil {
		// Do not collect or delete anything: the user cannot tell whose data
		// would survive.
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	for _, b := range done {
		if err := a.gatherOne(ctx, c, b, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// checkCollectDestinations rejects a gather whose expanded operations would
// copy two blips to the same path. {name} makes each destination unique.
func (a *app) checkCollectDestinations(done []*v1alpha1.Blip, raw []string) error {
	if len(raw) == 0 {
		return nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	type use struct {
		blip, source string
	}
	seen := map[string]use{}
	for _, b := range done {
		ops := make([]string, len(raw))
		for i, op := range raw {
			ops[i] = strings.ReplaceAll(op, "{name}", a.short(b.Name))
		}
		parsed, err := parseCollectOps(ops, cwd)
		if err != nil {
			// The per-blip collect reports parse errors with its name.
			continue
		}
		for _, op := range parsed {
			if op.git {
				continue
			}
			dst, err := filepath.Abs(op.dest)
			if err != nil {
				dst = op.dest
			}
			dst = filepath.Clean(dst)
			if prev, ok := seen[dst]; ok {
				return fmt.Errorf("collect destination %s is the same for blip %s (%s) and blip %s (%s); add {name} or give each blip a distinct DEST", dst, prev.blip, prev.source, a.short(b.Name), op.source)
			}
			seen[dst] = use{blip: a.short(b.Name), source: op.source}
		}
	}
	return nil
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
			b := &list.Items[i]
			// The caller is often labelled like the blips it gathers, but it
			// cannot wait for or delete itself.
			if a.self != nil && b.Name == a.self.Name {
				continue
			}
			add(b)
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
			// The wait can expire before the watcher's first Get. A blip that
			// already finished is not "still waiting"; collect those and only
			// report the ones that really are unfinished.
			finished, waiting := a.stillWaiting(ctx, left)
			done = append(done, finished...)
			errs = append(errs, waiting...)
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

// stillWaiting splits the blips that were still outstanding when the wait
// ended into those that actually finished (they are returned so they can be
// reported and collected) and errors describing the rest, grouped by their
// current phase. Pending and Saving blips are not running, so the message says
// what they are actually doing.
func (a *app) stillWaiting(ctx context.Context, left map[string]bool) ([]*v1alpha1.Blip, []error) {
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	labels := []string{"still running", "still pending", "still saving", "not finished"}
	groups := map[string][]string{}
	var finished []*v1alpha1.Blip
	for name := range left {
		b, err := a.getBlip(qctx, name)
		if err == nil && v1alpha1.Finished(b) {
			finished = append(finished, b)
			continue
		}
		label := "not finished"
		if err == nil {
			switch b.Status.Phase {
			case v1alpha1.BlipRunning:
				label = "still running"
			case v1alpha1.BlipPending, "":
				label = "still pending"
			case v1alpha1.BlipSaving:
				label = "still saving"
			}
		}
		groups[label] = append(groups[label], a.short(name))
	}
	var errs []error
	for _, label := range labels {
		names := groups[label]
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		errs = append(errs, fmt.Errorf("%s: %s", label, strings.Join(names, ", ")))
	}
	return finished, errs
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
	ending := v1alpha1.Finished(b) || b.Status.Phase == v1alpha1.BlipSaving
	pod := b.Status.Pod
	if pod == "" {
		if ending {
			if !a.printRetained(ctx, name, short) {
				a.progress("%s: output is no longer available (the VM pod is gone)", short)
			}
		}
		return
	}
	s, err := a.openRetrying(ctx, name, pod, wire.Open{Mode: wire.OpenAttach, Session: wire.PrimarySession, Follow: true}, true)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if ending || a.blipEnding(ctx, name) {
			// The replay ring died with the VM. The guest still mirrored the
			// command to the serial console, which the pod keeps as its log.
			if a.replayLogs(ctx, pod, short) || a.printRetained(ctx, name, short) {
				return
			}
			a.progress("%s: output is no longer available: %v", short, err)
			return
		}
		a.progress("%s: could not follow output: %v", short, err)
		return
	}
	defer s.Close()
	out := &prefixWriter{out: a.env.Out, prefix: short + "|"}
	errw := &prefixWriter{out: a.env.Err, prefix: short + "|"}
	_, _ = s.Copy(out, errw, func(m string) { a.progress("%s: %s", short, m) })
	out.flush()
	errw.flush()
	if !out.wrote && !errw.wrote && (ending || a.blipEnding(ctx, name)) {
		if !a.replayLogs(ctx, pod, short) && !a.printRetained(ctx, name, short) {
			a.progress("%s: output is no longer available", short)
		}
	}
}

// blipEnding reports whether the blip is saving or finished now. A follower
// may attach while the command is running and learn only later that the
// session ended without delivering output.
func (a *app) blipEnding(ctx context.Context, name string) bool {
	b, err := a.getBlip(ctx, name)
	return err == nil && (v1alpha1.Finished(b) || b.Status.Phase == v1alpha1.BlipSaving)
}

// retainedOutputWait bounds how long gather waits for the controller to
// publish status.output after the VM pod is gone. The controller patches the
// output before deleting the pod, but the client's view can lag behind a fast
// completion, and a fixed short wait used to give up silently.
var retainedOutputWait = 15 * time.Second

// printRetained prints the command output the controller saved in Blip status
// before deleting the VM pod. The controller and a finishing Blip race the
// follower, so poll for the status write until retainedOutputWait expires. It
// returns whether it printed anything.
func (a *app) printRetained(ctx context.Context, name, short string) bool {
	c, err := a.clients()
	if err != nil {
		return false
	}
	deadline := time.Now().Add(retainedOutputWait)
	for {
		b := &v1alpha1.Blip{}
		err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, b)
		switch {
		case err == nil && b.Status.Output != "":
			w := &prefixWriter{out: a.env.Out, prefix: short + "|"}
			_, _ = w.Write([]byte(b.Status.Output))
			w.flush()
			return w.wrote
		case apierrors.IsNotFound(err):
			// The Blip is gone, so no later status write can arrive.
			return false
		case ctx.Err() != nil || !time.Now().Before(deadline):
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// replayLogs prints the command output preserved on the VM serial console.
// The guest prefixes mirrored output with "blip: ", which separates it from
// kernel and runtime boot messages. It returns whether it printed anything.
func (a *app) replayLogs(ctx context.Context, pod, short string) bool {
	c, err := a.clients()
	if err != nil || c.Logs == nil {
		return false
	}
	rc, err := c.Logs(ctx, pod)
	if err != nil {
		return false
	}
	defer rc.Close()
	w := &prefixWriter{out: a.env.Out, prefix: short + "|"}
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), "blip: "); ok {
			_, _ = w.Write([]byte(line + "\n"))
		}
	}
	w.flush()
	return w.wrote
}

// prefixWriter turns arbitrary output chunks into whole prefixed lines. Each
// line is one Write to out, so concurrent followers do not interleave inside a
// line.
type prefixWriter struct {
	out    io.Writer
	prefix string
	buf    []byte
	wrote  bool
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
	w.wrote = true
}

func (w *prefixWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
}
