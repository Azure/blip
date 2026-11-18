package cli

import (
	"context"
	"crypto/rand"
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
	"sync"
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
	root, err := a.getState(ctx, b.Spec.State)
	if err != nil {
		return err
	}
	for i := range ops {
		state, rel := stateForPath(b, root, ops[i].source)
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
		if err := ctx.Err(); err != nil {
			return err
		}
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
	for _, m := range root.Spec.Mounts {
		if !actualStates[m.State] && !actualPaths[m.Path] && (m.BlipUID == "" || m.BlipUID == string(b.UID)) {
			consider(m)
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
	b, err := a.getBlip(ctx, a.self.Name)
	if err != nil {
		return "", nil, err
	}
	if b.UID != a.self.UID || b.UID == "" {
		return "", nil, errors.New("the calling blip was replaced")
	}
	root, err := a.getState(ctx, b.Spec.State)
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
	if existing := findSpecMount(root.Spec.Mounts, state); existing == nil || !existing.Writable {
		if err := a.waitStateReady(ctx, state); err != nil {
			return "", nil, err
		}
	}
	var mountPath string
	var writable, shared bool
	var token string
	var oldAttachment string
	_, err = a.updateState(ctx, root.Name, func(s *v1alpha1.BlipState) error {
		if s.UID != root.UID {
			return errors.New("the calling blip's root state was replaced")
		}
		writer, err := a.rootWriter(ctx, s)
		if err != nil {
			return err
		}
		if writer == nil || writer.UID != b.UID {
			return fmt.Errorf("blip %q no longer owns root state %q", b.Name, root.Name)
		}
		users := mountUsers(s)
		shared = false
		oldAttachment = ""
		if m := findSpecMount(s.Spec.Mounts, state); m != nil {
			mountPath, writable = m.Path, m.Writable
			if m.BlipUID != "" && m.BlipUID != string(b.UID) {
				return fmt.Errorf("temporary mount of state %q belongs to an earlier execution; wait for cleanup", state)
			}
			u := users[state]
			tracked := m.BlipUID != "" && u.BlipUID == m.BlipUID && u.Path == m.Path && u.Token != "" && u.Users > 0
			if tracked {
				oldAttachment = u.PreviousAttachment
			}
			if !writable && (oldAttachment == "" || mountedAttachment(writer, state) != oldAttachment) {
				if err := a.checkMountCurrent(ctx, writer, state, mountPath); err != nil {
					return err
				}
			}
			if !tracked {
				// Durable user mounts, and temporary mounts whose bookkeeping
				// was lost, are left in place until their owner's lifetime ends.
				return errUnchanged
			}
		} else {
			mountPath, writable = path.Join(collectMountRoot, state), false
			for _, m := range s.Spec.Mounts {
				if m.Path == mountPath {
					return fmt.Errorf("collect path %s is already used by state %q", mountPath, m.State)
				}
			}
			s.Spec.Mounts = append(s.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath, BlipUID: string(b.UID)})
			users[state] = collectMountUse{BlipUID: string(b.UID), Path: mountPath, Token: rand.Text(), PreviousAttachment: mountedAttachment(writer, state)}
		}
		shared = true
		u := users[state]
		u.Users++
		users[state], token = u, u.Token
		oldAttachment = u.PreviousAttachment
		return setMountUsers(s, users)
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return "", nil, err
	}
	cleanup := func() {}
	if shared {
		cleanup = sync.OnceFunc(func() { a.releaseMount(context.WithoutCancel(ctx), root, state, token) })
	}
	if err := a.waitMount(ctx, b, state, mountPath, writable, 0, oldAttachment); err != nil {
		cleanup()
		return "", nil, err
	}
	if !writable {
		current, err := a.getBlip(ctx, b.Name)
		if err == nil {
			err = a.checkMountCurrent(ctx, current, state, mountPath)
		}
		if err != nil {
			cleanup()
			return "", nil, err
		}
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
				if s.Status.Writer == nil && s.Status.Pending == nil {
					return true, nil
				}
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
	if m == nil || m.Path != mountPath || m.Writable || m.Phase != v1alpha1.MountMounted {
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
	// Resolve the git directory even when git itself refuses to start, so a
	// redirect is checked instead of skipped.
	dir := gitDir(ctx, target, root)
	if dir == "" {
		return nil // git fetch will report the error
	}
	dir, err := resolvePath(dir)
	if err != nil {
		return nil
	}
	if !underDir(root, dir) {
		return fmt.Errorf("%s uses a git directory outside state %s (resolves to %s)", display, a.short(state), dir)
	}
	return a.checkGitMetadata(root, dir, display, state)
}

// gitDir returns the git directory of the repository at src. Git is asked
// first; if it cannot run (for example because a redirect leaves the mounted
// state), the .git directory or file is followed by hand up to root.
func gitDir(ctx context.Context, src, root string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", src,
		"-c", "safe.directory=*", "rev-parse", "--absolute-git-dir").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	for dir := src; underDir(root, dir); dir = filepath.Dir(dir) {
		dotgit := filepath.Join(dir, ".git")
		info, err := os.Stat(dotgit)
		if err == nil && info.IsDir() {
			return dotgit
		}
		if err == nil && info.Mode().IsRegular() {
			b, err := os.ReadFile(dotgit)
			if err != nil {
				return ""
			}
			line := firstLine(b)
			if !strings.HasPrefix(line, "gitdir:") {
				return ""
			}
			p := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			return p
		}
		if dir == root {
			break
		}
	}
	return ""
}

// checkGitMetadata rejects commondir and alternates files that let the state
// make git read objects from outside its mount. Both may be relative, and
// alternates lists one path per line.
func (a *app) checkGitMetadata(root, gitDir, display, state string) error {
	common := gitDir
	if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		entry := firstLine(b)
		if entry != "" {
			dir, err := resolveGitPath(gitDir, entry)
			if err != nil {
				return fmt.Errorf("cannot resolve the git common directory %q of %s: %w", entry, display, err)
			}
			if !underDir(root, dir) {
				return fmt.Errorf("%s uses a git common directory outside state %s (resolves to %s)", display, a.short(state), dir)
			}
			common = dir
		}
	}
	objects := filepath.Join(common, "objects")
	b, err := os.ReadFile(filepath.Join(objects, "info", "alternates"))
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		dir, err := resolveGitPath(objects, entry)
		if err != nil {
			return fmt.Errorf("cannot resolve the git alternates entry %q of %s: %w", entry, display, err)
		}
		if !underDir(root, dir) {
			return fmt.Errorf("%s uses git alternates outside state %s (%s resolves to %s)", display, a.short(state), entry, dir)
		}
	}
	return nil
}

// resolveGitPath resolves a git metadata entry against base. It resolves
// symlinks in the existing part of the path, like resolvePath.
func resolveGitPath(base, entry string) (string, error) {
	if !filepath.IsAbs(entry) {
		entry = filepath.Join(base, entry)
	}
	return resolvePath(entry)
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
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

// collectMountsAnnotation lives on the caller's root state so refcounts and
// mount edits are atomic. Lifetime and token provenance prevent stale cleanup
// from removing a durable mount or a new use of the same path.
const collectMountsAnnotation = "blip.dev/collect-mounts"

type collectMountUse struct {
	BlipUID string `json:"blipUID"`
	Path    string `json:"path"`
	Token   string `json:"token"`
	Users   int    `json:"users"`
	// Concurrent collectors must wait for the same fresh attachment when
	// an old Mounted status remained after the previous mount was removed.
	PreviousAttachment string `json:"previousAttachment,omitempty"`
}

func mountUsers(s *v1alpha1.BlipState) map[string]collectMountUse {
	users := map[string]collectMountUse{}
	if v := s.Annotations[collectMountsAnnotation]; v != "" {
		if err := json.Unmarshal([]byte(v), &users); err != nil || users == nil {
			return map[string]collectMountUse{}
		}
	}
	return users
}

func setMountUsers(s *v1alpha1.BlipState, users map[string]collectMountUse) error {
	if len(users) == 0 {
		delete(s.Annotations, collectMountsAnnotation)
		return nil
	}
	v, err := json.Marshal(users)
	if err != nil {
		return err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[collectMountsAnnotation] = string(v)
	return nil
}

// releaseMount only releases the exact temporary mount this collect acquired.
func (a *app) releaseMount(ctx context.Context, root *v1alpha1.BlipState, state, token string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = a.updateState(ctx, root.Name, func(s *v1alpha1.BlipState) error {
		users := mountUsers(s)
		u := users[state]
		m := findSpecMount(s.Spec.Mounts, state)
		if s.UID != root.UID || u.Token != token || u.Users < 1 || m == nil ||
			m.BlipUID == "" || m.BlipUID != u.BlipUID || m.Path != u.Path {
			return errUnchanged
		}
		if u.Users > 1 {
			u.Users--
			users[state] = u
		} else {
			delete(users, state)
			var keep []v1alpha1.Mount
			for _, m := range s.Spec.Mounts {
				if m.State != state {
					keep = append(keep, m)
				}
			}
			s.Spec.Mounts = keep
		}
		return setMountUsers(s, users)
	})
}

func copyPath(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		return copyTree(ctx, src, dst, info)
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
	return copyEntry(ctx, src, dst, info)
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

func copyTree(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	created := false
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
		if err := os.Mkdir(dst, 0o700); err != nil {
			if !os.IsExist(err) {
				return err
			}
		} else {
			created = true
		}
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		ei, err := os.Lstat(s)
		if err != nil {
			return err
		}
		if ei.IsDir() {
			if err := copyTree(ctx, s, d, ei); err != nil {
				return err
			}
			continue
		}
		if err := copyEntry(ctx, s, d, ei); err != nil {
			return err
		}
	}
	// An existing destination directory belongs to the caller: keep its
	// mode and mtime. Only a directory created here takes the source's.
	if !created {
		return nil
	}
	if err := os.Chmod(dst, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

// copyEntry copies a regular file or a symlink. It never follows a source
// symlink, so a link in a state cannot make collect read outside its mount.
func copyEntry(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch {
	case info.Mode().IsRegular():
		return copyFile(ctx, src, dst, info)
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

func copyFile(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	_, cerr := io.Copy(out, ctxReader{ctx: ctx, r: in})
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

// ctxReader stops a copy when its context is canceled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func findSpecMount(list []v1alpha1.Mount, state string) *v1alpha1.Mount {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
}
