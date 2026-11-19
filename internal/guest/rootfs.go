package guest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/mountpath"
)

// checkMountPath validates a user mount path against the documented rules.
// existing are the paths of current auxiliary mounts.
func checkMountPath(p string, existing []string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("mount path %q is not absolute", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return fmt.Errorf("mount path %q contains ..", p)
		}
	}
	p = filepath.Clean(p)
	if p == "/" {
		return errors.New("mount path must not be /")
	}
	if err := mountpath.ValidateLength(p); err != nil {
		return err
	}
	for _, e := range existing {
		if overlaps(p, e) {
			return fmt.Errorf("mount path %s overlaps %s", p, e)
		}
	}
	for _, e := range mountpath.Reserved {
		if overlaps(p, e) && !mountpath.CollectMountPath(p) {
			return fmt.Errorf("mount path %s overlaps %s", p, e)
		}
	}
	return nil
}

func overlaps(a, b string) bool {
	// Known image aliases are resolved lexically here and by mountpath.
	// Image-specific aliases are handled by checkMountTarget, which compares
	// the directories the guest actually opened.
	return mountpath.Overlap(a, b)
}

// checkMountTarget rejects a resolved mount target that equals or contains an
// existing resolved target. Written paths can differ through an image symlink
// (/bin/x and /usr/bin/x, /var/spool/mail/x and /var/mail/x) while naming one
// guest directory; mounting both would stack filesystems at one point and make
// path-based unmount remove the wrong attachment. root is the guest root, used
// only to show the resolved guest path in the error.
func checkMountTarget(root, p, target string, existing []*mount) error {
	for _, e := range existing {
		if overlaps(target, e.target) {
			return fmt.Errorf("mount path %s resolves to %s, which overlaps mount %s at %s",
				p, guestPath(root, target), e.id, e.path)
		}
	}
	return nil
}

// guestPath turns a path inside root back into the guest-visible path for an
// error message. It falls back to the original path if it is not below root.
func guestPath(root, p string) string {
	rel, err := filepath.Rel(filepath.Clean(root), p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return p
	}
	return "/" + filepath.ToSlash(rel)
}

// mountPointInRoot creates the directory a user mount will attach to and
// returns an O_PATH descriptor for it with the directory's resolved path.
// Unlike the guest's own directories, user mount points follow symlinks inside
// the root as Linux mount does, so image aliases such as
// /usr/share/doc/gcc-13 work. Symlinks to files, escapes, and reserved targets
// are still rejected.
func mountPointInRoot(root, p string) (int, string, error) {
	fd, err := mkdirInRoot(root, p, true)
	if err != nil {
		return -1, "", err
	}
	if err := validateMountTarget(root, p); err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	target, err := fdPath(fd)
	if err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	return fd, target, nil
}

// validateMountTarget reports why the directory p resolves to inside root
// cannot receive a user mount. Symlinks are allowed when their target is a
// directory inside the root, as Linux mount itself follows them, but the
// resolved directory must not be the root or one the guest reserves.
func validateMountTarget(root, p string) error {
	resolved, err := resolveInRoot(root, p)
	if err != nil {
		return fmt.Errorf("resolve mount path %s: %w", p, err)
	}
	if resolved == "/" {
		return fmt.Errorf("mount path %s resolves to /", p)
	}
	for _, r := range mountpath.Reserved {
		if overlaps(resolved, r) && !mountpath.CollectMountPath(resolved) {
			return fmt.Errorf("mount path %s resolves to %s, which the guest reserves", p, resolved)
		}
	}
	return nil
}

func openat2(dirfd int, path string, flags uint64, mode uint64, resolve uint64) (int, error) {
	for {
		fd, err := unix.Openat2(dirfd, path, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Mode: mode, Resolve: resolve})
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return fd, err
	}
}

// mkdirInRoot creates directory p (absolute, inside root) and its parents and
// returns an O_PATH descriptor for it. With follow, symlinks are resolved as
// if root were "/"; without, any symlink component is an error. Magic links
// are never followed, so a symlink inside the root cannot escape it.
func mkdirInRoot(root, p string, follow bool) (int, error) {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootfd)
	resolve := uint64(unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS)
	if !follow {
		resolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS
	}
	parts := strings.Split(strings.Trim(filepath.Clean(p), "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return unix.Dup(rootfd)
	}
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		fd, err := openat2(rootfd, prefix, unix.O_PATH|unix.O_DIRECTORY, 0, resolve)
		if err == unix.ENOENT {
			parent := "."
			if i > 0 {
				parent = strings.Join(parts[:i], "/")
			}
			pfd, perr := openat2(rootfd, parent, unix.O_PATH|unix.O_DIRECTORY, 0, resolve)
			if perr != nil {
				return -1, fmt.Errorf("open %s: %w", "/"+parent, perr)
			}
			merr := unix.Mkdirat(pfd, parts[i], 0o755)
			unix.Close(pfd)
			if merr != nil && merr != unix.EEXIST {
				return -1, fmt.Errorf("mkdir /%s: %w", prefix, merr)
			}
			fd, err = openat2(rootfd, prefix, unix.O_PATH|unix.O_DIRECTORY, 0, resolve)
		}
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR || err == unix.EXDEV {
				return -1, fmt.Errorf("/%s is a symlink or not a directory", prefix)
			}
			return -1, fmt.Errorf("open /%s: %w", prefix, err)
		}
		if i == len(parts)-1 {
			return fd, nil
		}
		unix.Close(fd)
	}
	return -1, errors.New("unreachable")
}

// openFileInRoot opens (creating if missing) regular file p inside root,
// resolving symlinks as if root were "/". It opens read-only, which is enough
// to bind-mount the file even when the image made it read-only.
func openFileInRoot(root, p string) (int, error) {
	return openFileInRootFlags(root, p, unix.O_RDONLY|unix.O_CREAT)
}

// openFileInRootWritable is openFileInRoot for a file the guest will rewrite.
func openFileInRootWritable(root, p string) (int, error) {
	return openFileInRootFlags(root, p, unix.O_RDWR|unix.O_CREAT)
}

func openFileInRootFlags(root, p string, flags uint64) (int, error) {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootfd)
	return openat2(rootfd, strings.TrimPrefix(p, "/"), flags, 0o644, unix.RESOLVE_IN_ROOT)
}

// statInRoot stats p inside root, resolving symlinks as if root were "/".
func statInRoot(root, p string) (os.FileInfo, error) {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootfd)
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		rel = "." // openat2 rejects an empty path
	}
	fd, err := openat2(rootfd, rel, unix.O_PATH, 0, unix.RESOLVE_IN_ROOT)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	return f.Stat()
}

// resolveInRoot returns dir as a canonical path inside root, resolving
// symlinks and ".." exactly as the child's chdir will after chroot. A lexical
// walk sees only the path components as written, so it can miss an
// unsearchable directory that a symlink points through.
func resolveInRoot(root, dir string) (string, error) {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(rootfd)
	rootPath, err := fdPath(rootfd)
	if err != nil {
		return "", err
	}
	rel := strings.TrimPrefix(dir, "/")
	if rel == "" {
		rel = "." // openat2 rejects an empty path
	}
	fd, err := openat2(rootfd, rel, unix.O_PATH|unix.O_DIRECTORY, 0, unix.RESOLVE_IN_ROOT)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	p, err := fdPath(fd)
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(rootPath, p)
	if err != nil || r == ".." || strings.HasPrefix(r, "../") {
		// RESOLVE_IN_ROOT clamps a path to the root, so this cannot happen
		// unless the root itself was renamed or removed.
		return "", errors.New("workdir resolved outside the root")
	}
	if r == "." {
		return "/", nil
	}
	return "/" + filepath.ToSlash(r), nil
}

// fdPath returns the real path of an open descriptor.
func fdPath(fd int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
}
