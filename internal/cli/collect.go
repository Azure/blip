package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// collectMountRoot is where collect mounts a worker's state in the calling
// blip.
var collectMountRoot = "/run/blip-collect"

// collectSelfRoot is the calling blip's own root filesystem. A state that is
// the caller's root is already in use by the caller, so it cannot be mounted;
// its contents are here instead.
var collectSelfRoot = "/"

// collectCommand copies files out of a finished blip's state and fetches
// git commits into the repository in the caller's working directory.
func (a *app) collectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect BLIP OP...",
		Short: "Copy files and fetch commits from a blip's state",
		Long: `Collect files or git commits from a blip's state. A state collect attaches
is mounted read-only in the blip this command runs in.

Each OP is one of:
  SRC:DEST              copy a file or directory from SRC in BLIP to DEST here
  git:SRC:BRANCH        fetch BRANCH from the repository at SRC into the
                        repository in the current directory, as local BRANCH

SRC is an absolute path in BLIP, or a path relative to the current directory.
DEST is a path here; directories are copied recursively. A file copied to an
existing directory keeps its name. Existing files are overwritten.

If a referenced state is still being written, collect waits until it is
available. An existing mount of that state in the calling blip is reused; if
it is read-only and behind the latest version, unmount it first.`,
		Example: `  blip collect w1 /home/dev/out/report.pdf:./report.pdf
  blip collect w1 /home/dev/out:./artifacts
  blip collect w1 git:/home/dev/src:w1
  blip collect w1 git:/work/repo:w1 /home/dev/out:./artifacts`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.collect(cmd.Context(), args[0], args[1:])
		},
	}
	// Everything after the blip name is a copy operation, including paths
	// that start with "-".
	cmd.Flags().SetInterspersed(false)
	return cmd
}

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
	for i := range ops {
		state, rel := stateForPath(b, ops[i].source)
		if state == "" {
			return fmt.Errorf("%s is not on a state of blip %s (its root is an image)", ops[i].source, a.short(name))
		}
		ops[i].state, ops[i].rel = state, rel
	}

	// Mount each referenced state once, read-only.
	quiet := *a
	qenv := *a.env
	qenv.Out = io.Discard // progress stays on stderr
	quiet.env = &qenv
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
		mountPath, cleanup, err := quiet.collectMount(ctx, op.state)
		if err != nil {
			return err
		}
		mounts[op.state] = mountPath
		cleanups = append(cleanups, cleanup)
	}

	for _, op := range ops {
		src := filepath.Join(mounts[op.state], op.rel)
		if op.git {
			if err := a.checkGitSource(ctx, mounts[op.state], src, op.source, op.state); err != nil {
				return err
			}
			if err := a.fetchBranch(ctx, cwd, src, op.branch); err != nil {
				return err
			}
			continue
		}
		if err := a.checkParentInsideMount(mounts[op.state], src, op.source, op.state); err != nil {
			return err
		}
		if err := copyPath(src, op.dest); err != nil {
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

// parseCollectOp splits SRC:DEST or git:SRC:BRANCH. A relative SRC is
// relative to cwd in both the caller and the source blip.
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
	src, dest, ok := strings.Cut(s, ":")
	if !ok || src == "" || dest == "" {
		return collectOp{}, fmt.Errorf("invalid operation %q: want SRC:DEST or git:SRC:BRANCH", s)
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

// stateForPath returns the state of b that holds dir and dir's path inside
// it: the mount with the longest matching path, else the root state.
func stateForPath(b *v1alpha1.Blip, dir string) (state, rel string) {
	best := -1
	for _, m := range b.Spec.Mounts {
		if (dir == m.Path || strings.HasPrefix(dir, m.Path+"/")) && len(m.Path) > best {
			best, state, rel = len(m.Path), m.State, strings.TrimPrefix(dir, m.Path)
		}
	}
	if best < 0 {
		state, rel = b.Spec.State, dir
	}
	return state, rel
}

// collectMount mounts state read-only in the calling blip, or reuses a mount
// of it there, and returns the mount path. A state that is not mounted yet
// is waited for until no blip is writing it.
func (a *app) collectMount(ctx context.Context, state string) (string, func(), error) {
	if _, err := a.clients(); err != nil {
		return "", nil, err
	}
	if a.self == nil {
		return "", nil, errors.New("collect only works inside a blip")
	}
	self := a.self.Name
	b, err := a.getBlip(ctx, self)
	if err != nil {
		return "", nil, err
	}
	// The caller's root state is this blip's own root filesystem. The caller
	// holds its writer, so waiting for it to become ready would never return,
	// and it is already mounted at /.
	if state == b.Spec.State {
		return collectSelfRoot, func() {}, nil
	}
	// A writable mount means this blip holds the writer; waiting for the
	// state to become ready would never return. Its contents are current.
	if existing := findSpecMount(b.Spec.Mounts, state); existing == nil || !existing.Writable {
		if err := a.waitStateReady(ctx, state); err != nil {
			return "", nil, err
		}
		// Another collect may have mounted the state while we waited. A
		// read-only mount pins its version, so do not reuse a stale one.
		b, err = a.getBlip(ctx, self)
		if err != nil {
			return "", nil, err
		}
		if m := findSpecMount(b.Spec.Mounts, state); m != nil && !m.Writable {
			if err := a.checkMountCurrent(ctx, b, state, m.Path); err != nil {
				return "", nil, err
			}
		}
	}
	var mountPath string
	var writable, shared bool
	_, err = a.updateBlip(ctx, self, func(b *v1alpha1.Blip) error {
		if finished(b) || b.DeletionTimestamp != nil || b.Spec.Stop {
			return fmt.Errorf("blip %q is stopping or has finished", self)
		}
		users := mountUsers(b)
		if m := findSpecMount(b.Spec.Mounts, state); m != nil {
			mountPath, writable = m.Path, m.Writable
			if users[state] == 0 {
				// Mounted by the caller: use it and leave it.
				shared = false
				return errUnchanged
			}
		} else {
			mountPath, writable = path.Join(collectMountRoot, state), false
			b.Spec.Mounts = append(b.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath})
			users[state] = 0
		}
		shared = true
		users[state]++
		return setMountUsers(b, users)
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return "", nil, err
	}
	cleanup := func() {}
	if shared {
		cleanup = func() { a.releaseMount(context.WithoutCancel(ctx), self, state, mountPath) }
	}
	mode := writable
	if err := a.mountState(ctx, state, self, mountPath, &mode); err != nil {
		cleanup()
		return "", nil, err
	}
	return mountPath, cleanup, nil
}

// waitStateReady waits until the state has no writer and no commit in
// flight, so a fresh read-only mount sees the latest version.
func (a *app) waitStateReady(ctx context.Context, name string) error {
	c, err := a.clients()
	if err != nil {
		return err
	}
	r := &reporter{a: a}
	defer r.stop()
	return waitFor(ctx, c.Kube, &v1alpha1.BlipStateList{}, client.ObjectKey{Namespace: c.Namespace, Name: name},
		func() *v1alpha1.BlipState { return &v1alpha1.BlipState{} },
		func(s *v1alpha1.BlipState) (bool, error) {
			if s == nil {
				return false, fmt.Errorf("state %q not found", name)
			}
			switch s.Status.Phase {
			case v1alpha1.StateReady:
				return true, nil
			case v1alpha1.StateFailed:
				return false, fmt.Errorf("state %q failed: %s", name, s.Status.Message)
			}
			switch {
			case s.Status.Writer != nil:
				r.say("waiting for state %s: blip %s is writing", a.short(name), a.short(s.Status.Writer.BlipName))
			case s.Status.Pending != nil:
				r.say("waiting for state %s: saving generation %d", a.short(name), s.Status.Pending.Generation)
			case s.Status.Message != "":
				r.say("waiting for state %s: %s", a.short(name), s.Status.Message)
			default:
				r.say("waiting for state %s...", a.short(name))
			}
			return false, nil
		})
}

// checkMountCurrent rejects reusing a read-only mount that pins an older
// version than the state's latest commit.
func (a *app) checkMountCurrent(ctx context.Context, b *v1alpha1.Blip, state, mountPath string) error {
	m := findMount(b.Status.Mounts, state)
	if m == nil || m.Phase != v1alpha1.MountMounted {
		return nil
	}
	s, err := a.getState(ctx, state)
	if err != nil {
		return err
	}
	if s.Status.Committed != nil && m.CommitID != s.Status.Committed.ID {
		return fmt.Errorf("state %q is already mounted read-only on blip %q at %s at an older version; unmount it first", state, b.Name, mountPath)
	}
	return nil
}

// checkGitSource rejects a git source that leaves its state through a
// symlink or a .git redirect. git resolves both against the caller's root,
// not the mounted state, and would otherwise serve unrelated files.
func (a *app) checkGitSource(ctx context.Context, mountPath, src, display, state string) error {
	root, rerr := filepath.EvalSymlinks(mountPath)
	target, terr := filepath.EvalSymlinks(src)
	if rerr != nil || terr != nil {
		return nil
	}
	if !underDir(root, target) {
		return fmt.Errorf("%s escapes state %s through a symlink (resolves to %s)", display, a.short(state), target)
	}
	top, err := gitRepoRoot(ctx, src)
	if err != nil {
		return nil // git fetch will report the error
	}
	out, err := exec.CommandContext(ctx, "git", "-C", top,
		"-c", "safe.directory=*", "rev-parse", "--absolute-git-dir").Output()
	if err != nil {
		return nil
	}
	dir, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		return nil
	}
	if !underDir(root, dir) {
		return fmt.Errorf("%s uses a git directory outside state %s (resolves to %s)", display, a.short(state), dir)
	}
	return nil
}

// checkParentInsideMount rejects a file source whose parent directories leave
// the state through a symlink. The final component may be a symlink: copyEntry
// copies it as a link instead of following it.
func (a *app) checkParentInsideMount(mountPath, src, display, state string) error {
	if src == mountPath {
		return nil
	}
	root, rerr := filepath.EvalSymlinks(mountPath)
	dir, derr := filepath.EvalSymlinks(filepath.Dir(src))
	if rerr == nil && derr == nil && !underDir(root, dir) {
		return fmt.Errorf("%s escapes state %s through a symlink (resolves to %s)", display, a.short(state), dir)
	}
	return nil
}

// fetchBranch fetches branch from repo into the repository at cwd under the
// same local name.
func (a *app) fetchBranch(ctx context.Context, cwd, repo, branch string) error {
	// The caller's working directory may be a subdirectory of the
	// repository. Fetch from the repository root instead.
	if top, err := gitRepoRoot(ctx, repo); err == nil {
		repo = top
	}
	args := []string{
		"-C", cwd, "-c", "safe.directory=" + repo, "fetch", "--", repo, branch + ":" + branch,
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.env.In, a.env.Out, a.env.Err
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ExitError{Code: exit.ExitCode()}
		}
		return fmt.Errorf("git fetch: %w", err)
	}
	return nil
}

// gitRepoRoot returns the repository containing repo.
func gitRepoRoot(ctx context.Context, repo string) (string, error) {
	// Discovery may start below the repository root, so the ownership
	// check has to accept the mount rather than the path given.
	out, err := exec.CommandContext(ctx, "git", "-C", repo,
		"-c", "safe.directory=*", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	top := strings.TrimSpace(string(out))
	if top == "" {
		return "", errors.New("git rev-parse returned an empty top level")
	}
	return top, nil
}

// underDir reports whether p is root or below it, after both are resolved.
func underDir(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

// commonDir returns the deepest ancestor of a that also contains b.
func commonDir(a, b string) string {
	for !underDir(a, b) {
		parent := filepath.Dir(a)
		if parent == a {
			return a
		}
		a = parent
	}
	return a
}

// collectMountsAnnotation counts, per state, the collect commands using a
// mount they added to the blip they run in. The last one to finish removes
// it. A blip mounts a state at most once, so concurrent collects share it.
const collectMountsAnnotation = "blip.dev/collect-mounts"

func mountUsers(b *v1alpha1.Blip) map[string]int {
	users := map[string]int{}
	if v := b.Annotations[collectMountsAnnotation]; v != "" {
		_ = json.Unmarshal([]byte(v), &users)
	}
	return users
}

func setMountUsers(b *v1alpha1.Blip, users map[string]int) error {
	if len(users) == 0 {
		delete(b.Annotations, collectMountsAnnotation)
		return nil
	}
	v, err := json.Marshal(users)
	if err != nil {
		return err
	}
	if b.Annotations == nil {
		b.Annotations = map[string]string{}
	}
	b.Annotations[collectMountsAnnotation] = string(v)
	return nil
}

// releaseMount drops this collect's use of the mount of state at mountPath
// and removes the mount if no other collect uses it.
func (a *app) releaseMount(ctx context.Context, self, state, mountPath string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = a.updateBlip(ctx, self, func(b *v1alpha1.Blip) error {
		users := mountUsers(b)
		switch n := users[state]; {
		case n > 1:
			users[state] = n - 1
			return setMountUsers(b, users)
		case n == 1:
			delete(users, state)
			var keep []v1alpha1.Mount
			for _, m := range b.Spec.Mounts {
				if m.State != state || m.Path != mountPath {
					keep = append(keep, m)
				}
			}
			b.Spec.Mounts = keep
			return setMountUsers(b, users)
		default:
			// The annotation was lost (or another collect already cleaned
			// up). Removing the mount now could pull it from under a
			// concurrent collect, so leave it until the blip exits.
			return errUnchanged
		}
	})
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		inside, err := pathInside(src, dst)
		if err != nil {
			return err
		}
		if inside {
			return fmt.Errorf("cannot copy directory %s into itself at %s", src, dst)
		}
		if err := checkDestParents(dst); err != nil {
			return err
		}
		return copyTree(src, dst, info)
	}
	if di, err := os.Stat(dst); err == nil && di.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}
	same, err := sameFile(src, dst)
	if err != nil {
		return err
	}
	if same {
		return fmt.Errorf("source and destination are the same file: %s", src)
	}
	if err := checkDestParents(dst); err != nil {
		return err
	}
	return copyEntry(src, dst, info)
}

// sameFile reports whether src and dst are the same existing file, including
// a hard link. dst may be missing.
func sameFile(src, dst string) (bool, error) {
	si, err := os.Lstat(src)
	if err != nil {
		return false, err
	}
	di, err := os.Lstat(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return os.SameFile(si, di), nil
}

// pathInside reports whether p is dir or below it, with symlinks in the
// existing part of either path resolved.
func pathInside(dir, p string) (bool, error) {
	d, err := resolvePath(dir)
	if err != nil {
		return false, err
	}
	q, err := resolvePath(p)
	if err != nil {
		return false, err
	}
	return underDir(d, q), nil
}

// resolvePath makes p absolute and resolves symlinks in its longest existing
// prefix, so a destination that does not exist yet can be compared too.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cur, rest := abs, ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// checkDestParents rejects a destination whose existing parent directories
// traverse a symlink. Only the final component is replaced by copyEntry; a
// symlink above it could redirect writes outside the destination the user
// named, for example a link created by an earlier collect.
func checkDestParents(dst string) error {
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	// A relative destination is trusted up to its common ancestor with the
	// working directory, so "../out" keeps working. An absolute one is
	// checked from /.
	root := string(filepath.Separator)
	if !filepath.IsAbs(dst) {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		root = commonDir(cwd, abs)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	// The last component is the destination itself, which copyEntry replaces
	// rather than writes through.
	cur := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination %s has a symlink at %s; refusing to write through it", abs, cur)
		}
	}
	return nil
}

func copyTree(src, dst string, info os.FileInfo) error {
	if di, err := os.Lstat(dst); err == nil {
		if !di.IsDir() {
			return fmt.Errorf("cannot copy directory %s onto %s: not a directory", src, dst)
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		// Create the directory writable so its children can be written even
		// when the source directory is read-only. The source mode is applied
		// after the tree is populated.
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Mkdir(dst, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		ei, err := os.Lstat(s)
		if err != nil {
			return err
		}
		if ei.IsDir() {
			if err := copyTree(s, d, ei); err != nil {
				return err
			}
			continue
		}
		if err := copyEntry(s, d, ei); err != nil {
			return err
		}
	}
	if err := os.Chmod(dst, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

// copyEntry copies a regular file or a symlink. It never follows a source
// symlink, so a link in a state cannot make collect read outside its mount.
func copyEntry(src, dst string, info os.FileInfo) error {
	switch {
	case info.Mode().IsRegular():
		return copyFile(src, dst, info)
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Symlink(target, dst)
	default:
		return fmt.Errorf("cannot copy special file %s", src)
	}
}

func copyFile(src, dst string, info os.FileInfo) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Replace a symlink at dst rather than writing through it.
	if di, err := os.Lstat(dst); err == nil && di.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dst); err != nil {
			return err
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	if err := out.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return cerr
	}
	if err := os.Chmod(dst, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func findSpecMount(list []v1alpha1.Mount, state string) *v1alpha1.Mount {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
}
