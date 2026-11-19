// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

type gatherFlags struct {
	selector    string
	selectorSet bool
	collect     []string
	any         bool
	wait        time.Duration
	follow      bool
	keep        bool
}

func (a *app) gatherCommand() *cobra.Command {
	f := &gatherFlags{}
	cmd := &cobra.Command{
		Use:   "gather [BLIP...] [flags]",
		Short: "Wait for blips, collect their results, and delete them",
		Long: `Wait for blips to finish, collect results from their workspaces, and delete
them.

Inside a blip, gather with no arguments targets the forks that blip started.
Inside an owner-scoped blip, both the default set and --selector are limited
to that owner's blips. Select a set with blip names or --selector, not both.

With --collect, each operation is applied to every finished blip. Operations
are the same as the collect syntax, and {name} is replaced with the blip's
short name, so "git:/work/repo:{name}" gives each blip its own branch. A git
operation fetches commits only; uncommitted and untracked changes are not
collected, and a warning is printed when a worktree has them. Two operations
that expand to the same destination are rejected instead of overwriting each
other; {name} keeps each blip's destination distinct.
SRC and DEST must not contain ':'; the last ':' separates them. A mount whose
path contains ':' (which mount accepts) therefore cannot be collected
directly: mount the data at a colon-free path to collect it.
--collect only works inside a blip, because it copies into the caller's
workspace. Outside a blip, gather with --keep to keep the blip and its
workspace for later inspection.

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
			f.selectorSet = cmd.Flags().Changed("selector")
			return a.gather(cmd.Context(), args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.selector, "selector", "l", "", "label selector of blips to gather")
	fl.StringArrayVar(&f.collect, "collect", nil, "copy out of each blip: SRC:DEST (split at the last ':'; neither SRC nor DEST may contain ':') or git:SRC:BRANCH (inside a blip only; commits only; {name} is the blip's name; repeatable)")
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
	// Validate --collect before choosing the target set. A malformed or empty
	// operation must not look like a successful gather that found nothing to
	// do, and outside a blip the dedicated error must win over the missing
	// target error.
	if len(f.collect) > 0 {
		if a.self == nil {
			return errors.New("--collect copies into the workspace of the blip this command runs in, so it only works inside one; gather with --keep to keep the blip and its workspace")
		}
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if _, err := parseCollectOps(f.collect, cwd); err != nil {
			return err
		}
	}
	// labels.Parse treats whitespace as a selector that matches everything,
	// and an unset shell variable is easy to pass by accident. An explicitly
	// set but blank selector is a mistake in every path: outside a blip it
	// used to look like a missing target, and with names it used to be
	// silently ignored. Inside a blip the default is every fork of the
	// caller, which gather would delete, so it must not fall back to that.
	selector := strings.TrimSpace(f.selector)
	if f.selectorSet && selector == "" {
		return errors.New("--selector must not be empty")
	}
	if len(names) > 0 && selector != "" {
		return errors.New("gather takes blip names or --selector, not both")
	}
	defaultSelector := false
	if len(names) == 0 && selector == "" {
		if a.self == nil {
			return errors.New("gather needs blip names or --selector outside a blip")
		}
		selector = v1alpha1.LabelParent + "=" + v1alpha1.ParentLabel(a.short(a.self.Name))
		defaultSelector = true
	}
	var sel labels.Selector
	if selector != "" {
		// Parse the selector as the user wrote it, so an error never quotes
		// the internal owner term added below.
		sel, err = labels.Parse(selector)
		if err != nil {
			return fmt.Errorf("invalid --selector %q: %w", selector, err)
		}
		// A requirement such as "key!=value", "!key" or "key notin ()"
		// matches every object that does not carry the key. Unlabelled blips
		// are common, so such a selector selects every blip in the namespace
		// and gather would delete them. Check before adding the internal
		// owner term, which would otherwise make a negated selector look
		// constrained even though it still matches all of the owner's blips.
		if !defaultSelector && (sel.Empty() || sel.Matches(labels.Set{})) {
			return fmt.Errorf("invalid --selector %q: it selects every blip", selector)
		}
		// Inside an owner-scoped blip, every selector is intersected with the
		// caller's owner. An explicit selector is constrained rather than
		// rejected, so one that names another owner matches nothing and can
		// never list or delete that owner's blips.
		if a.owner != "" {
			req, err := labels.NewRequirement(v1alpha1.LabelOwner, selection.Equals, []string{a.owner})
			if err != nil {
				return err
			}
			sel = sel.Add(*req)
		}
	}
	targets, err := a.gatherTargets(ctx, c, names, sel)
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
	followDone := make([]chan struct{}, len(targets))
	var followCancel context.CancelFunc
	if f.follow {
		var fctx context.Context
		// Followers share the wait deadline, so an expired --wait also stops
		// their retained-trajectory read instead of delaying the drain.
		fctx, followCancel = context.WithCancel(waitCtx)
		defer followCancel()
		for i, b := range targets {
			ch := make(chan struct{})
			followDone[i] = ch
			go func(b *v1alpha1.Blip, ch chan struct{}) {
				defer close(ch)
				a.follow(fctx, b)
			}(b, ch)
		}
	}

	done, errs := a.awaitTargets(waitCtx, f, targets)
	if f.follow {
		// Drain finished blips' retained trajectory before deleting them,
		// then stop followers of blips that are still running.
		finished := make(map[string]bool, len(done))
		for _, b := range done {
			finished[b.Name] = true
		}
		for i, b := range targets {
			if !finished[b.Name] {
				continue
			}
			if !waitFollower(waitCtx, followDone[i]) {
				break
			}
		}
		followCancel()
		for _, ch := range followDone {
			if !waitFollower(waitCtx, ch) {
				break
			}
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Name < done[j].Name })
	needsMountCheck, err := a.checkCollectDestinations(done, f.collect)
	if err != nil {
		// Do not collect or delete anything: the user cannot tell whose data
		// would survive.
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	if needsMountCheck {
		if err := a.checkCollectMountedWrites(ctx, done, f.collect); err != nil {
			// The mounted sources revealed a cross-blip collision that the
			// pre-mount check could not see. Do not collect or delete
			// anything: an earlier blip would already be gone when the later
			// one is collected.
			errs = append(errs, err)
			return errors.Join(errs...)
		}
	}
	for _, b := range done {
		if err := a.gatherOne(ctx, c, b, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// waitFollower waits for one follower to finish. It reports false when ctx is
// done first. A replay write to a local consumer that stopped reading cannot
// be cancelled, so gather abandons the follower instead of blocking past
// --wait.
func waitFollower(ctx context.Context, ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		// A follower that finished at the same moment still counts.
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
}

// checkCollectDestinations rejects a gather whose expanded operations would
// copy two blips to the same path or into overlapping trees. {name} makes
// each destination unique.
//
// A destination is compared with symlinks in the existing part resolved, and
// a destination nested under another is treated as part of that tree. Git
// operations share the caller's repository, so a branch name is a destination
// too. The sources are not mounted yet, so this check cannot tell a file
// source from a directory source; collect re-checks the effective writes
// against the mounted sources before copying anything. Operations of the same
// blip are left to collect, which can compare their effective paths exactly.
//
// The returned bool reports that an existing directory destination was shared
// by different basenames. That is only safe when every source is a file, which
// this check cannot know, so gather also compares the mounted writes across
// all blips before collecting any of them.
func (a *app) checkCollectDestinations(done []*v1alpha1.Blip, raw []string) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	needsMountCheck := false
	cwd, err := os.Getwd()
	if err != nil {
		return false, err
	}
	type use struct {
		id, blip, source, dest, branch string
	}
	var seen, seenGit []use
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
		blipID, blip := b.Name, a.short(b.Name)
		for _, op := range parsed {
			if op.git {
				// Every git operation fetches into the caller's repository,
				// so a branch name is a destination shared by the whole
				// gather. A second fetch of the same branch fails after the
				// first blip has already been collected and deleted.
				for _, prev := range seenGit {
					if prev.branch == op.branch {
						return false, fmt.Errorf("collect destination branch %s is the same for blip %s (%s) and blip %s (%s); add {name} or give each blip a distinct BRANCH", op.branch, prev.blip, prev.source, blip, op.source)
					}
				}
				seenGit = append(seenGit, use{id: blipID, blip: blip, source: op.source, branch: op.branch})
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
				// collect applies all of one blip's operations together and
				// models each effective write after the sources are mounted,
				// so it accepts distinct file paths under one destination
				// and rejects a real collision before the first copy. Only
				// operations from different blips need this conservative
				// pre-mount comparison: an earlier blip has already been
				// collected and deleted when a later one is checked.
				if prev.id == blipID {
					continue
				}
				if prev.dest == dst {
					// A file copied onto an existing directory is stored
					// under its basename, so distinct basenames can share
					// it. A destination that does not exist yet is created
					// by the first operation: a file op makes DEST itself a
					// file and a later file op replaces it, whatever the
					// basenames, so only an existing directory is safe.
					// A directory source, however, merges its whole tree
					// into DEST. The sources are not mounted yet, so the
					// mounted preflight below must rule that out.
					if filepath.Base(prev.source) != filepath.Base(op.source) && isExistingDir(dst) {
						needsMountCheck = true
						continue
					}
					return false, fmt.Errorf("collect destination %s is the same for blip %s (%s) and blip %s (%s); add {name} or give each blip a distinct DEST", dst, prev.blip, prev.source, blip, op.source)
				}
				// A directory destination covers everything below it: the
				// tree is merged into place, and a file source is stored at
				// DEST/basename(SRC).
				if underDir(prev.dest, dst) || underDir(dst, prev.dest) {
					return false, fmt.Errorf("collect destinations %s for blip %s (%s) and %s for blip %s (%s) overlap; add {name} or give each blip a distinct DEST", prev.dest, prev.blip, prev.source, dst, blip, op.source)
				}
			}
			seen = append(seen, use{id: blipID, blip: blip, source: op.source, dest: dst})
		}
	}
	return needsMountCheck, nil
}

// checkCollectMountedWrites mounts every target read-only and runs one
// effective-write check over all of the blips' operations. The pre-mount
// destination check cannot tell whether a source is a file or a directory;
// this second, mounted check sees the real trees and rejects a directory merge
// that would overwrite another blip's child before any copy or delete.
func (a *app) checkCollectMountedWrites(ctx context.Context, done []*v1alpha1.Blip, raw []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	var all []collectOp
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
		root, err := a.getState(ctx, b.Spec.State)
		if err != nil {
			return fmt.Errorf("collect from %s: %w", a.short(b.Name), err)
		}
		for i := range parsed {
			parsed[i].state, parsed[i].rel = stateForPath(b, root, parsed[i].source)
		}
		all = append(all, parsed...)
	}
	var copies []collectOp
	for _, op := range all {
		if !op.git {
			copies = append(copies, op)
		}
	}
	mounts, cleanup, err := a.mountCollectOps(ctx, copies)
	if err != nil {
		return err
	}
	defer cleanup()
	return checkCollectWrites(all, mounts)
}

// isExistingDir reports whether path is already a directory. A destination
// that does not exist (or is a file) is created or replaced by the first
// operation that targets it.
func isExistingDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// gatherTargets resolves the blips named on the command line and the ones that
// match sel, in a stable order.
func (a *app) gatherTargets(ctx context.Context, c *Clients, names []string, sel labels.Selector) ([]*v1alpha1.Blip, error) {
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
		if err := a.validateName("blip", name); err != nil {
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
	if sel != nil {
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

// follow streams a blip's trajectory until it finishes. The aggregated stream
// API replays retained records, so a follower that attached late still sees the
// output after the VM pod is gone.
func (a *app) follow(ctx context.Context, b *v1alpha1.Blip) {
	if b.Spec.State == "" {
		return
	}
	short := a.short(b.Name)
	w := &recordWriter{out: a.env.Out, err: a.env.Err, label: short}
	target := streamTarget{namespace: b.Namespace, state: b.Spec.State, blip: b.Name}
	err := a.readStream(ctx, target, 0, true, w, func(ctx context.Context) bool {
		return a.blipDone(ctx, b.Name)
	})
	if err != nil && ctx.Err() == nil {
		a.progress("%s: could not follow output: %v", short, err)
	}
}

// blipDone reports that a followed blip is finished. Saving is not done: the
// root state still has to commit, and the committed trajectory is retained
// after the pod is gone.
func (a *app) blipDone(ctx context.Context, name string) bool {
	b, err := a.getBlip(ctx, name)
	return err == nil && v1alpha1.Finished(b)
}
