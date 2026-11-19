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
	corev1 "k8s.io/api/core/v1"
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
Select any other set with blip names or --selector, not both.

With --collect, each operation is applied to every finished blip. Operations
are the same as the collect syntax, and {name} is replaced with the blip's
short name, so "git:/work/repo:{name}" gives each blip its own branch. A git
operation fetches commits only; uncommitted and untracked changes are not
collected, and a warning is printed when a worktree has them. Two operations
that expand to the same destination are rejected instead of overwriting each
other; {name} keeps each blip's destination distinct.
--collect only works inside a blip, because it copies into the caller's
workspace; use --keep and collect with kubectl elsewhere.

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
	fl.StringArrayVar(&f.collect, "collect", nil, "copy out of each blip: SRC:DEST (split at the last ':') or git:SRC:BRANCH (inside a blip only; commits only; {name} is the blip's name; repeatable)")
	fl.BoolVar(&f.any, "any", false, "return as soon as one blip finishes or cannot be observed")
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
	// labels.Parse treats whitespace as a selector that matches everything,
	// and an unset shell variable is easy to pass by accident.
	selector := strings.TrimSpace(f.selector)
	if len(names) > 0 && selector != "" {
		return errors.New("gather takes blip names or --selector, not both")
	}
	if len(names) == 0 && selector == "" {
		if a.self == nil {
			return errors.New("gather needs blip names or --selector outside a blip")
		}
		selector = v1alpha1.LabelParent + "=" + v1alpha1.ParentLabel(a.short(a.self.Name))
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
	waitCtx := ctx
	if f.wait > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, f.wait)
		defer cancel()
	}
	var followWG sync.WaitGroup
	followDone := map[string]chan struct{}{}
	var followCancel context.CancelFunc
	if f.follow {
		var fctx context.Context
		// Followers share the wait deadline, so an expired --wait also stops
		// their retained-output replay instead of delaying the drain.
		fctx, followCancel = context.WithCancel(waitCtx)
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
// copy two blips to the same path or into overlapping trees. {name} makes
// each destination unique.
//
// A destination is compared with symlinks in the existing part resolved, and
// a destination nested under another is treated as part of that tree. The
// sources are not mounted yet, so this check cannot tell a file source from a
// directory source; collect re-checks the effective writes against the
// mounted sources before copying anything.
func (a *app) checkCollectDestinations(done []*v1alpha1.Blip, raw []string) error {
	if len(raw) == 0 {
		return nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	type use struct {
		blip, source, dest string
	}
	var seen []use
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
			dst, err := resolvePath(op.dest)
			if err != nil {
				// A destination that cannot be resolved can still be
				// compared literally.
				if dst, err = filepath.Abs(op.dest); err != nil {
					dst = op.dest
				}
			}
			dst = filepath.Clean(dst)
			for _, prev := range seen {
				if prev.dest == dst {
					// Distinct basenames can share a destination. The
					// gather check runs before any state is mounted, so it
					// cannot tell whether a source is a directory; collect
					// re-checks the mounted sources in order and rejects a
					// directory merge that would overwrite a sibling.
					if filepath.Base(prev.source) != filepath.Base(op.source) {
						continue
					}
					return fmt.Errorf("collect destination %s is the same for blip %s (%s) and blip %s (%s); add {name} or give each blip a distinct DEST", dst, prev.blip, prev.source, a.short(b.Name), op.source)
				}
				// A directory destination covers everything below it: the
				// tree is merged into place, and a file source is stored at
				// DEST/basename(SRC).
				if underDir(prev.dest, dst) || underDir(dst, prev.dest) {
					return fmt.Errorf("collect destinations %s for blip %s (%s) and %s for blip %s (%s) overlap; add {name} or give each blip a distinct DEST", prev.dest, prev.blip, prev.source, dst, a.short(b.Name), op.source)
				}
			}
			seen = append(seen, use{blip: a.short(b.Name), source: op.source, dest: dst})
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
		// A Blip cannot wait for or delete itself, just as the selector
		// path below cannot target the caller.
		if a.self != nil && b.Name == a.self.Name {
			return nil, fmt.Errorf("cannot gather %s, the blip running this gather; name another blip or gather its forks with no arguments", a.short(b.Name))
		}
		add(b)
	}
	if selector != "" {
		sel, err := labels.Parse(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid --selector %q: %w", selector, err)
		}
		if sel.Empty() {
			return nil, fmt.Errorf("invalid --selector %q: it selects every blip", selector)
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
			// A Blip that finished before claiming a VM never ran a
			// command, so no status.output can ever arrive. Do not wait
			// out the retained-output poll for it.
			if b.Status.Output == "" && b.Status.StartTime == nil {
				return
			}
			if !a.printRetained(ctx, name, short) && !a.endedWithoutOutput(ctx, name) {
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
		// The replay ring died with the VM. The guest still mirrored the
		// command to the serial console, and the controller retains the tail
		// in status. Try both even when our cached view still says Running:
		// the pod can disappear between the wait and this attach.
		if a.replayLogs(ctx, pod, short) {
			return
		}
		ending = ending || a.blipEnding(ctx, name)
		// A finished, empty-output Blip whose pod is gone cannot publish
		// output later: the controller writes status.output before it deletes
		// the pod. Do not spend the retained-output grace on it.
		if ending && a.outputFinal(ctx, name, pod) {
			return
		}
		if a.printRetainedFor(ctx, name, short, 3*time.Second) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if ending {
			if !a.endedWithoutOutput(ctx, name) {
				a.progress("%s: output is no longer available: %v", short, err)
			}
			return
		}
		a.progress("%s: could not follow output: %v", short, err)
		return
	}
	defer s.Close()
	out := &prefixWriter{out: a.env.Out, prefix: short + "|"}
	errw := &prefixWriter{out: a.env.Err, prefix: short + "|"}
	_, copyErr := s.Copy(out, errw, func(m string) { a.progress("%s: %s", short, m) })
	out.flush()
	errw.flush()
	if copyErr != nil {
		// The live stream ended before the guest delivered TExited, so the
		// bytes above are only a prefix. A follower that stops reading while
		// the command finishes is cut off when the guest closes the finished
		// primary session at its delivery deadline; the controller's retained
		// status.output still has the tail. Do not warn when gather itself
		// stopped the follower (ctx is done), for example after --wait or --any.
		if ctx.Err() == nil {
			a.replayTruncatedOutput(ctx, name, short, pod, ending || a.blipEnding(ctx, name))
		}
		return
	}
	if !out.wrote && !errw.wrote && (ending || a.blipEnding(ctx, name)) {
		if !a.replayLogs(ctx, pod, short) && !a.printRetained(ctx, name, short) && !a.endedWithoutOutput(ctx, name) {
			a.progress("%s: output is no longer available", short)
		}
	}
}

// truncatedOutputWait bounds how long a follower waits for the controller to
// publish status.output after its live stream was cut off. The controller
// writes the output before it deletes the VM pod, so this only covers client
// staleness.
var truncatedOutputWait = 3 * time.Second

// replayTruncatedOutput reports that a followed stream ended before the
// command's exit status arrived and, when the blip is finishing, prints the
// output the controller retained in status. Line-oriented prefixing cannot
// resume mid-stream, so the retained print repeats any lines the follower
// already saw. A blip that is still running may have more output, but nothing
// available to print now, so the follower only warns.
func (a *app) replayTruncatedOutput(ctx context.Context, name, short, pod string, ended bool) {
	if !ended {
		a.progress("%s: output stream ended before the command exited; output above may be incomplete", short)
		return
	}
	if a.printRetainedFor(ctx, name, short, truncatedOutputWait) || a.replayLogs(ctx, pod, short) {
		a.progress("%s: output stream ended before the command exited; replayed the retained output (lines above may repeat)", short)
		return
	}
	a.progress("%s: output stream ended before the command exited; the rest of the output is no longer available", short)
}

// blipEnding reports whether the blip is saving or finished now. A follower
// may attach while the command is running and learn only later that the
// session ended without delivering output.
func (a *app) blipEnding(ctx context.Context, name string) bool {
	b, err := a.getBlip(ctx, name)
	return err == nil && (v1alpha1.Finished(b) || b.Status.Phase == v1alpha1.BlipSaving)
}

// endedWithoutOutput reports that the blip is finished and produced no
// output. Losing an empty stream is not a failure, so followers should not
// warn that output is unavailable.
func (a *app) endedWithoutOutput(ctx context.Context, name string) bool {
	b, err := a.getBlip(ctx, name)
	if err != nil {
		return false
	}
	return (v1alpha1.Finished(b) || b.Status.Phase == v1alpha1.BlipSaving) && b.Status.Output == ""
}

// outputFinal reports that a finished, empty-output blip can no longer
// publish retained output because the VM pod that would hold it is gone. The
// controller writes status.output before it deletes the pod, so this is safe
// even when the client's cached view lags. While the pod still exists the
// follower keeps polling: the controller may not have published the output
// yet.
func (a *app) outputFinal(ctx context.Context, name, pod string) bool {
	b, err := a.getBlip(ctx, name)
	if err != nil || b.Status.Pod != pod || b.Status.Output != "" ||
		!(v1alpha1.Finished(b) || b.Status.Phase == v1alpha1.BlipSaving) {
		return false
	}
	c, err := a.clients()
	if err != nil {
		return false
	}
	p := &corev1.Pod{}
	err = c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: pod}, p)
	return apierrors.IsNotFound(err) || (err == nil && p.DeletionTimestamp != nil)
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
	return a.printRetainedFor(ctx, name, short, retainedOutputWait)
}

// printRetainedFor is printRetained with a caller-selected grace period.
func (a *app) printRetainedFor(ctx context.Context, name, short string, wait time.Duration) bool {
	c, err := a.clients()
	if err != nil {
		return false
	}
	deadline := time.Now().Add(wait)
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
