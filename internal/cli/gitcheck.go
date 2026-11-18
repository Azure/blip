package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// checkGitSource rejects a git source that leaves its state through a
// symlink or a .git redirect. git resolves both against the caller's root,
// not the mounted state, and would otherwise serve unrelated files. display
// names the source and state names the state for messages.
func checkGitSource(ctx context.Context, mountPath, src, display, stateName string) error {
	root, rerr := filepath.EvalSymlinks(mountPath)
	target, terr := filepath.EvalSymlinks(src)
	if rerr != nil || terr != nil {
		return nil
	}
	if !underDir(root, target) {
		return fmt.Errorf("%s escapes state %s through a symlink (resolves to %s)", display, stateName, target)
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
		return fmt.Errorf("%s uses a git directory outside state %s (resolves to %s)", display, stateName, dir)
	}
	return checkGitMetadata(root, dir, display, stateName)
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
func checkGitMetadata(root, gitDir, display, stateName string) error {
	common := gitDir
	if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		entry := firstLine(b)
		if entry != "" {
			dir, err := resolveGitPath(gitDir, entry)
			if err != nil {
				return fmt.Errorf("cannot resolve the git common directory %q of %s: %w", entry, display, err)
			}
			if !underDir(root, dir) {
				return fmt.Errorf("%s uses a git common directory outside state %s (resolves to %s)", display, stateName, dir)
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
			return fmt.Errorf("%s uses git alternates outside state %s (%s resolves to %s)", display, stateName, entry, dir)
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
func checkParentInsideMount(mountPath, src, display, stateName string) error {
	if src == mountPath {
		return nil
	}
	root, rerr := filepath.EvalSymlinks(mountPath)
	dir, derr := filepath.EvalSymlinks(filepath.Dir(src))
	if rerr == nil && derr == nil && !underDir(root, dir) {
		return fmt.Errorf("%s escapes state %s through a symlink (resolves to %s)", display, stateName, dir)
	}
	return nil
}

// fetchBranch fetches branch from repo into the repository at cwd under the
// same local name.
func fetchBranch(ctx context.Context, in io.Reader, out, errOut io.Writer, cwd, repo, branch string) error {
	// The caller's working directory may be a subdirectory of the
	// repository. Fetch from the repository root instead.
	if top, err := gitRepoRoot(ctx, repo); err == nil {
		repo = top
	}
	args := []string{
		"-C", cwd, "-c", "safe.directory=" + repo, "fetch", "--", repo, branch + ":" + branch,
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
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
