package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Azure/blip/api/v1alpha1"
)

// collectMountRoot is where collect mounts a worker's state in the calling
// blip.
var collectMountRoot = "/run/blip-collect"

// collectSelfRoot is the calling blip's own root filesystem. A state that is
// the caller's root is already in use by the caller, so it cannot be mounted;
// its contents are here instead.
var collectSelfRoot = "/"

func (a *app) collect(ctx context.Context, name string, raw []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("blip name is empty")
	}
	if strings.Contains(name, ":") {
		return fmt.Errorf("invalid blip %q: the first argument is a blip name; put paths in the operations that follow", name)
	}
	ops, err := parseCollectOps(raw, cwd)
	if err != nil {
		return err
	}
	// Interrupted collects still remove the mounts they added.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	if err := a.scope(&name); err != nil {
		return err
	}
	if a.self == nil {
		return errors.New("collect only works inside a blip")
	}
	if name == a.self.Name {
		return fmt.Errorf("cannot collect from %s, the blip running this collect; use a fork (blip run --fork)", a.short(name))
	}
	b, err := a.getBlip(ctx, name)
	if err != nil {
		return err
	}
	root, err := a.getState(ctx, b.Spec.State)
	if err != nil {
		return err
	}
	for i := range ops {
		state, rel := stateForPath(b, root, ops[i].source)
		ops[i].state, ops[i].rel = state, rel
	}

	// Mount each referenced state once, read-only.
	mounts := map[string]string{}
	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	for _, op := range ops {
		if _, ok := mounts[op.state]; ok {
			continue
		}
		mountPath, cleanup, err := a.collectMount(ctx, op.state)
		if err != nil {
			return err
		}
		mounts[op.state] = mountPath
		cleanups = append(cleanups, cleanup)
	}

	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			return err
		}
		src := filepath.Join(mounts[op.state], op.rel)
		if op.git {
			if err := checkGitSource(ctx, mounts[op.state], src, op.source, a.short(op.state)); err != nil {
				return err
			}
			warnGitWorktree(ctx, src, op.source, op.branch, a.env.Err)
			if err := fetchBranch(ctx, a.env.In, a.env.Out, a.env.Err, cwd, src, op.branch); err != nil {
				return fmt.Errorf("collect %s: %w", op.source, err)
			}
			continue
		}
		if err := checkParentInsideMount(mounts[op.state], src, op.source, a.short(op.state)); err != nil {
			return err
		}
		if err := copyPath(ctx, src, op.dest); err != nil {
			return fmt.Errorf("collect %s: %w", op.source, err)
		}
	}
	return nil
}

// collectOp is one copy instruction. The state and rel fields are filled in
// from the source blip once the command knows its mounts.
type collectOp struct {
	source string
	dest   string
	branch string
	git    bool
	state  string
	rel    string
}

func parseCollectOps(raw []string, cwd string) ([]collectOp, error) {
	ops := make([]collectOp, 0, len(raw))
	for _, s := range raw {
		op, err := parseCollectOp(s, cwd)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// parseCollectOp splits SRC:DEST at the last colon, or git:SRC:BRANCH for a
// git operation. A relative SRC is relative to cwd in both the caller and the
// source blip.
func parseCollectOp(s, cwd string) (collectOp, error) {
	if strings.HasPrefix(s, "git:") {
		rest := strings.TrimPrefix(s, "git:")
		i := strings.LastIndexByte(rest, ':')
		if i <= 0 || i == len(rest)-1 {
			return collectOp{}, fmt.Errorf("invalid operation %q: want git:SRC:BRANCH", s)
		}
		src, branch := rest[:i], rest[i+1:]
		if strings.ContainsAny(branch, ": \t\r\n") || strings.HasPrefix(branch, "-") {
			return collectOp{}, fmt.Errorf("invalid operation %q: invalid branch %q", s, branch)
		}
		src, err := collectSource(src, cwd)
		if err != nil {
			return collectOp{}, fmt.Errorf("invalid operation %q: %w", s, err)
		}
		return collectOp{source: src, branch: branch, git: true}, nil
	}
	// Split from the right so a source with a colon is not silently read as
	// SRC:DEST at the first colon. A colon left in SRC is still ambiguous:
	// either side could own it, so reject instead of copying the wrong paths.
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return collectOp{}, fmt.Errorf("invalid operation %q: want SRC:DEST or git:SRC:BRANCH", s)
	}
	src, dest := s[:i], s[i+1:]
	if strings.Contains(src, ":") {
		return collectOp{}, fmt.Errorf("invalid operation %q: ambiguous source %q contains ':' (the last ':' separates SRC from DEST)", s, src)
	}
	src, err := collectSource(src, cwd)
	if err != nil {
		return collectOp{}, fmt.Errorf("invalid operation %q: %w", s, err)
	}
	return collectOp{source: src, dest: filepath.Clean(dest)}, nil
}

func collectSource(src, cwd string) (string, error) {
	if !path.IsAbs(src) {
		src = filepath.Join(cwd, src)
	}
	src = path.Clean(src)
	if !path.IsAbs(src) {
		return "", fmt.Errorf("source %q is not absolute", src)
	}
	return src, nil
}

// stateForPath uses the source root's mounts, preferring an actual attachment
// when an edit has not reached the guest yet. The longest path wins.
func stateForPath(b *v1alpha1.Blip, root *v1alpha1.BlipState, dir string) (state, rel string) {
	best := -1
	actualStates, actualPaths := map[string]bool{}, map[string]bool{}
	consider := func(m v1alpha1.Mount) {
		if (dir == m.Path || strings.HasPrefix(dir, m.Path+"/")) && len(m.Path) > best {
			best, state, rel = len(m.Path), m.State, strings.TrimPrefix(dir, m.Path)
		}
	}
	for _, m := range b.Status.Mounts {
		if m.Phase == v1alpha1.MountMounted || m.Phase == v1alpha1.MountUnmounting || m.Phase == v1alpha1.MountSaving {
			actualStates[m.State], actualPaths[m.Path] = true, true
			consider(v1alpha1.Mount{State: m.State, Path: m.Path})
		}
	}
	for _, m := range v1alpha1.DesiredMounts(root, b) {
		if !actualStates[m.State] && !actualPaths[m.Path] {
			consider(m)
		}
	}
	if best < 0 {
		state, rel = b.Spec.State, dir
	}
	return state, rel
}
