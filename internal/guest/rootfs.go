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
		if overlaps(p, e) {
			return fmt.Errorf("mount path %s overlaps %s", p, e)
		}
	}
	return nil
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
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
// if root were "/"; without, any symlink component is an error.
func mkdirInRoot(root, p string, follow bool) (int, error) {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootfd)
	resolve := uint64(unix.RESOLVE_IN_ROOT)
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
