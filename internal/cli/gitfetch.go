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

	"github.com/Azure/blip/api/v1alpha1"
)

// gitMountRoot is where git-fetch mounts a worker's state in the calling
// blip.
var gitMountRoot = "/run/blip-git"

// gitFetchCommand fetches commits from a finished blip's state into the
// repository in the caller's working directory.
func (a *app) gitFetchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git-fetch BLIP[:PATH] [REFSPEC...]",
		Short: "Fetch commits from a finished blip",
		Long: `Fetch commits from a finished blip's state into the repository in the
current directory. PATH defaults to the current directory, so a worker forked
from here can usually be fetched by name. Use BLIP:PATH to fetch from another
directory, including a mount of an image-rooted blip.`,
		Example: `  cd ~/src && blip git-fetch w1 w1:w1
  blip git-fetch w1:/home/dev/src w1:w1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.gitFetch(cmd.Context(), args[0], args[1:])
		},
	}
	// Everything after the source belongs to git, not to blip.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func (a *app) gitFetch(ctx context.Context, source string, refspecs []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	name, dir, err := parseGitSource(source, cwd)
	if err != nil {
		return err
	}
	// Interrupted fetches still remove the mount they added.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	// Mount progress must not mix with git's output.
	quiet := *a
	qenv := *a.env
	qenv.Out, qenv.Err = io.Discard, io.Discard
	quiet.env = &qenv
	repo, cleanup, err := quiet.gitCheckout(ctx, name, dir)
	if err != nil {
		return err
	}
	defer cleanup()

	// The caller's working directory may be a subdirectory of the
	// repository. Fetch from the repository root instead.
	if top, err := gitTopLevel(ctx, repo); err == nil {
		repo = top
	}

	args := append([]string{
		"-C", cwd, "-c", "safe.directory=" + repo, "fetch", "--", repo,
	}, refspecs...)
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

// parseGitSource splits BLIP[:PATH]. Without a path it returns cwd. An
// explicit path is absolute in the blip's filesystem.
func parseGitSource(source, cwd string) (name, dir string, err error) {
	name, p, ok := strings.Cut(source, ":")
	if !ok {
		if name == "" {
			return "", "", errors.New("empty source")
		}
		return name, cwd, nil
	}
	if name == "" {
		return "", "", fmt.Errorf("invalid source %q: want BLIP[:PATH]", source)
	}
	if p == "" {
		return "", "", fmt.Errorf("invalid source %q: path is empty; omit \":\" to use the current directory", source)
	}
	return name, path.Clean("/" + p), nil
}

// gitTopLevel returns the repository containing repo.
func gitTopLevel(ctx context.Context, repo string) (string, error) {
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

// gitStateFor returns the state of b that holds dir and dir's path inside
// it: the mount with the longest matching path, else the root state.
func gitStateFor(b *v1alpha1.Blip, dir string) (state, rel string) {
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

// gitCheckout mounts the state holding dir in blip name read-only into the
// calling blip, or reuses a mount of it there, and returns the directory
// there. cleanup removes a mount the fetch added once nothing uses it.
func (a *app) gitCheckout(ctx context.Context, name, dir string) (string, func(), error) {
	if err := a.scope(&name); err != nil {
		return "", nil, err
	}
	if a.self == nil {
		return "", nil, errors.New("git-fetch only works inside a blip")
	}
	if name == a.self.Name {
		return "", nil, fmt.Errorf("cannot fetch from %s, the blip running this fetch; use a fork (blip run --fork)", a.short(name))
	}
	b, err := a.getBlip(ctx, name)
	if err != nil {
		return "", nil, err
	}
	state, rel := gitStateFor(b, dir)
	if state == "" {
		return "", nil, fmt.Errorf("%s is not on a state of blip %s (its root is an image)", dir, a.short(name))
	}
	s, err := a.getState(ctx, state)
	if err != nil {
		return "", nil, err
	}
	if s.Status.Writer != nil {
		short := a.short(name)
		return "", nil, fmt.Errorf("%s is still running; wait for it to finish (blip wait %s)", short, short)
	}
	self := a.self.Name
	var mountPath string
	var writable, shared bool
	_, err = a.updateBlip(ctx, self, func(b *v1alpha1.Blip) error {
		if finished(b) || b.DeletionTimestamp != nil || b.Spec.Stop {
			return fmt.Errorf("blip %q is stopping or has finished", self)
		}
		users := gitMountUsers(b)
		if m := findSpecMount(b.Spec.Mounts, state); m != nil {
			mountPath, writable = m.Path, m.Writable
			if users[state] == 0 {
				// Mounted by the caller: use it and leave it.
				shared = false
				return errUnchanged
			}
		} else {
			mountPath, writable = path.Join(gitMountRoot, state), false
			b.Spec.Mounts = append(b.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath})
			users[state] = 0
		}
		shared = true
		users[state]++
		return setGitMountUsers(b, users)
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return "", nil, err
	}
	cleanup := func() {}
	if shared {
		cleanup = func() { a.gitRelease(context.WithoutCancel(ctx), self, state, mountPath) }
	}
	mode := writable
	if err := a.mountState(ctx, state, self, mountPath, &mode); err != nil {
		cleanup()
		return "", nil, err
	}
	repo := filepath.Join(mountPath, rel)
	// git resolves an absolute symlink against the caller's root, not the
	// mounted state, which would silently serve unrelated files. Relative
	// symlinks stay inside the state and are fine.
	root, rerr := filepath.EvalSymlinks(mountPath)
	target, terr := filepath.EvalSymlinks(repo)
	if rerr == nil && terr == nil && !underDir(root, target) {
		cleanup()
		return "", nil, fmt.Errorf("%s escapes state %s through a symlink (resolves to %s)", dir, a.short(state), target)
	}
	return repo, cleanup, nil
}

// underDir reports whether p is root or below it, after both are resolved.
func underDir(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

// gitMountsAnnotation counts, per state, the git-fetch commands using a
// mount they added to the blip they run in. The last one to finish removes
// it. A blip mounts a state at most once, so concurrent fetches share it.
const gitMountsAnnotation = "blip.dev/git-mounts"

func gitMountUsers(b *v1alpha1.Blip) map[string]int {
	users := map[string]int{}
	if v := b.Annotations[gitMountsAnnotation]; v != "" {
		_ = json.Unmarshal([]byte(v), &users)
	}
	return users
}

func setGitMountUsers(b *v1alpha1.Blip, users map[string]int) error {
	if len(users) == 0 {
		delete(b.Annotations, gitMountsAnnotation)
		return nil
	}
	v, err := json.Marshal(users)
	if err != nil {
		return err
	}
	if b.Annotations == nil {
		b.Annotations = map[string]string{}
	}
	b.Annotations[gitMountsAnnotation] = string(v)
	return nil
}

// gitRelease drops this fetch's use of the mount of state at mountPath and
// removes the mount if no other fetch uses it.
func (a *app) gitRelease(ctx context.Context, self, state, mountPath string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = a.updateBlip(ctx, self, func(b *v1alpha1.Blip) error {
		users := gitMountUsers(b)
		switch n := users[state]; {
		case n > 1:
			users[state] = n - 1
			return setGitMountUsers(b, users)
		case n == 1:
			delete(users, state)
			var keep []v1alpha1.Mount
			for _, m := range b.Spec.Mounts {
				if m.State != state || m.Path != mountPath {
					keep = append(keep, m)
				}
			}
			b.Spec.Mounts = keep
			return setGitMountUsers(b, users)
		default:
			// The annotation was lost (or another fetch already cleaned
			// up). Removing the mount now could pull it from under a
			// concurrent fetch, so leave it until the blip exits.
			return errUnchanged
		}
	})
}

func findSpecMount(list []v1alpha1.Mount, state string) *v1alpha1.Mount {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
}
