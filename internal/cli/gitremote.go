package cli

import (
	"bufio"
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

	"github.com/Azure/blip/api/v1alpha1"
)

// gitMountRoot is where the git remote helper mounts a worker's state in
// the calling blip.
var gitMountRoot = "/run/blip-git"

// GitRemoteMain runs kubectl-blip as git-remote-blip, a git remote helper
// for URLs blip::NAME/PATH: it serves the repository at PATH in blip NAME,
// read-only, from inside another blip. git calls it with the remote name
// and the URL without the "blip::" prefix.
func GitRemoteMain(ctx context.Context, env *Env, args []string) int {
	if err := gitRemote(ctx, env, args); err != nil {
		fmt.Fprintf(env.Err, "blip: %v\n", err)
		return 1
	}
	return 0
}

func gitRemote(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: git-remote-blip REMOTE [blip::]NAME/PATH")
	}
	name, dir, err := parseGitURL(args[len(args)-1])
	if err != nil {
		return err
	}
	// Interrupted fetches still remove the mount they added.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	// Mount progress must not reach git's protocol stream.
	quiet := *env
	quiet.Out = io.Discard
	a := &app{env: &quiet}
	in := bufio.NewReader(env.In)
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch line = strings.TrimSuffix(line, "\n"); line {
		case "":
			return nil
		case "capabilities":
			fmt.Fprint(env.Out, "connect\n\n")
		case "connect git-upload-pack":
			repo, cleanup, err := a.gitCheckout(ctx, name, dir)
			if err != nil {
				return err
			}
			defer cleanup()
			fmt.Fprint(env.Out, "\n")
			cmd := exec.CommandContext(ctx, "git", "-c", "safe.directory="+repo, "upload-pack", repo)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = in, env.Out, env.Err
			return cmd.Run()
		case "connect git-receive-pack":
			return errors.New("push is not supported (read-only)")
		default:
			return fmt.Errorf("unsupported git remote helper command %q", line)
		}
	}
}

// parseGitURL splits [blip::]NAME/ABS/PATH.
func parseGitURL(url string) (name, dir string, err error) {
	url = strings.TrimPrefix(strings.TrimPrefix(url, "blip::"), "blip://")
	name, rest, ok := strings.Cut(url, "/")
	if !ok || name == "" {
		return "", "", fmt.Errorf("invalid URL %q: want blip::NAME/PATH", url)
	}
	return name, path.Clean("/" + rest), nil
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
// there. cleanup removes a mount the helpers added once none uses it.
func (a *app) gitCheckout(ctx context.Context, name, dir string) (string, func(), error) {
	if err := a.scope(&name); err != nil {
		return "", nil, err
	}
	if a.self == nil {
		return "", nil, errors.New("blip:: remotes only work inside a blip")
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
	if err := a.mountState(ctx, state, self, mountPath, writable); err != nil {
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

// gitMountsAnnotation counts, per state, the git remote helpers using a
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

// gitRelease drops this helper's use of the mount of state at mountPath and
// removes the mount if no other helper uses it.
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
			// The annotation was lost (or another helper already cleaned
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

// IsGitRemoteHelper reports whether argv0 runs kubectl-blip as git's remote
// helper.
func IsGitRemoteHelper(argv0 string) bool {
	return filepath.Base(argv0) == "git-remote-blip"
}
