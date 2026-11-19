package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

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
		unlock, err := lockDestination(dst)
		if err != nil {
			return err
		}
		defer unlock()
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
	unlock, err := lockDestination(dst)
	if err != nil {
		return err
	}
	defer unlock()
	return copyEntry(ctx, src, dst, info)
}

// lockDestination takes a non-blocking exclusive lock keyed by the resolved
// destination, so two gathers writing the same path fail loudly instead of
// racing to overwrite each other.
func lockDestination(dst string) (func(), error) {
	key, err := resolvePath(dst)
	if err != nil {
		key, err = filepath.Abs(dst)
		if err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256([]byte(key))
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("blip-collect-locks-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(sum[:])), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("destination %s is already being collected by another gather; wait for it to finish or use a distinct destination", dst)
		}
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			// Not every filesystem supports flock. Collection still works;
			// atomic replacement avoids mixed output.
			return func() {}, nil
		}
		return nil, fmt.Errorf("lock destination %s: %w", dst, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
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

const collectTempPattern = ".blip-tmp-*"

// removeTree deletes a staging tree even when it contains directories copied
// with read-only modes, which would otherwise stop RemoveAll from descending.
// It only ever runs on trees this process created or moved aside.
func removeTree(path string) error {
	makeTreeWritable(path)
	return os.RemoveAll(path)
}

func makeTreeWritable(path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return
	}
	_ = os.Chmod(path, info.Mode().Perm()|0o700)
	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}
	for _, e := range entries {
		makeTreeWritable(filepath.Join(path, e.Name()))
	}
}

// copyTree builds the tree in a temporary directory and only then moves it
// into place. A failed or interrupted copy therefore leaves an existing
// destination as it was; a new destination appears only when it is complete.
func copyTree(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	exists := false
	if di, err := os.Lstat(dst); err == nil {
		if !di.IsDir() {
			return fmt.Errorf("cannot copy directory %s onto %s: not a directory", src, dst)
		}
		exists = true
	} else if !os.IsNotExist(err) {
		return err
	}
	// Reject type conflicts before copying anything, so a merge cannot fail
	// halfway through after replacing other children.
	if exists {
		if err := checkMergeTypes(src, dst); err != nil {
			return err
		}
	}
	// Work with the resolved path so a destination such as "." or ".." has a
	// staging directory outside itself: filepath.Dir(".") is ".", which would
	// make the snapshot walk the staging tree it is still creating.
	absDst, err := resolvePath(dst)
	if err != nil {
		return err
	}
	if !exists {
		parent := filepath.Dir(absDst)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		staging, err := os.MkdirTemp(parent, collectTempPattern)
		if err != nil {
			return err
		}
		defer removeTree(staging)
		if err := copyTreeInto(ctx, src, staging, info); err != nil {
			return err
		}
		return os.Rename(staging, absDst)
	}
	staging, atomic, err := stageTree(ctx, src, absDst, info)
	if err != nil {
		return err
	}
	defer removeTree(staging)
	// Swapping the destination itself is not safe when it contains the
	// process's working directory: the old tree is removed after the swap,
	// leaving the caller in a deleted directory.
	if atomic && !cwdInside(absDst) {
		err := mergeTree(ctx, staging, absDst)
		if err == nil {
			return nil
		}
		if !swapUnsupported(err) {
			return err
		}
		// A mountpoint cannot be renamed even when its parent is writable
		// and on the same filesystem. Only merge in place if the failed
		// swap left the destination where it was.
		if _, statErr := os.Lstat(absDst); statErr != nil {
			return err
		}
	}
	return mergeInPlace(ctx, staging, absDst)
}

// stageTree copies src into a temporary directory used to merge into dst,
// which must exist and be a directory. It prefers a directory beside dst so
// mergeTree can swap the result atomically. When the parent is not writable or
// is on another filesystem (a mount root, for example), staging happens inside
// dst, on the filesystem the merge writes to.
func stageTree(ctx context.Context, src, dst string, info os.FileInfo) (string, bool, error) {
	parent := filepath.Dir(dst)
	if parent != dst && copyStageDevice(parent, dst) {
		if staging, err := os.MkdirTemp(parent, collectTempPattern); err == nil {
			if err := copyTreeInto(ctx, src, staging, info); err != nil {
				removeTree(staging)
				return "", false, err
			}
			return staging, true, nil
		}
	}
	staging, err := os.MkdirTemp(dst, collectTempPattern)
	if err != nil {
		return "", false, err
	}
	if err := copyTreeInto(ctx, src, staging, info); err != nil {
		removeTree(staging)
		return "", false, err
	}
	return staging, false, nil
}

// copyStageDevice reports whether two paths are on the same filesystem. It is
// a variable so tests can simulate a mount boundary.
var copyStageDevice = sameDevice

func sameDevice(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	as, ok := ai.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	bs, ok := bi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return as.Dev == bs.Dev
}

// cwdInside reports whether the process's working directory is dst or below
// it, so renaming dst would move the working directory out from under us.
func cwdInside(dst string) bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	return cwd == dst || underDir(dst, cwd)
}

// swapUnsupported reports whether an atomic swap failed because the
// destination cannot be renamed in its parent, which is normal for a
// mountpoint or a boundary between filesystems.
func swapUnsupported(err error) bool {
	return errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EBUSY)
}

// copyTreeInto copies a source tree into an empty, writable directory. The
// destination takes the source's mode and mtime; callers that merge into an
// existing directory preserve that directory's own metadata instead.
func copyTreeInto(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
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
			if err := os.Mkdir(d, 0o700); err != nil {
				return err
			}
			if err := copyTreeInto(ctx, s, d, ei); err != nil {
				return err
			}
			continue
		}
		if err := copyEntry(ctx, s, d, ei); err != nil {
			return err
		}
	}
	if err := os.Chmod(dst, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

// checkMergeTypes rejects a merge whose existing destination has a directory
// where the source has another kind of entry, or the reverse.
func checkMergeTypes(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		si, err := os.Lstat(s)
		if err != nil {
			return err
		}
		di, err := os.Lstat(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if si.IsDir() {
			if !di.IsDir() {
				return fmt.Errorf("cannot copy directory %s onto %s: not a directory", s, d)
			}
			if err := checkMergeTypes(s, d); err != nil {
				return err
			}
			continue
		}
		if di.IsDir() {
			return fmt.Errorf("cannot copy file %s onto directory %s", s, d)
		}
	}
	return nil
}

// mergeTree merges a complete staged tree into an existing destination without
// touching the destination until the merge is complete: it snapshots the
// existing tree into a sibling staging directory, overlays the staged entries
// there, and swaps the result into place. A failed merge therefore leaves the
// destination as it was. Directory metadata of directories the caller already
// had is preserved by the snapshot.
func mergeTree(ctx context.Context, staged, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(dst)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("cannot merge into %s: not a directory", dst)
	}
	parent := filepath.Dir(dst)
	merged, err := os.MkdirTemp(parent, collectTempPattern)
	if err != nil {
		return err
	}
	defer removeTree(merged)
	if err := copyTreeInto(ctx, dst, merged, info); err != nil {
		return err
	}
	if err := overlayTree(ctx, staged, merged); err != nil {
		return err
	}
	// Keep the old tree under a temporary name until the new one is in place,
	// and restore it if the swap fails.
	backup, err := os.MkdirTemp(parent, collectTempPattern)
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	if err := os.Rename(dst, backup); err != nil {
		return err
	}
	if err := os.Rename(merged, dst); err != nil {
		_ = os.Rename(backup, dst)
		return err
	}
	return removeTree(backup)
}

// overlayTree moves a complete staged tree into a staging copy of the
// destination. A directory present in both is merged; any other existing
// entry at the same name is replaced.
func overlayTree(ctx context.Context, staged, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		s := filepath.Join(staged, e.Name())
		d := filepath.Join(dst, e.Name())
		si, err := os.Lstat(s)
		if err != nil {
			return err
		}
		di, err := os.Lstat(d)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if si.IsDir() && err == nil && di.IsDir() {
			if err := overlayTree(ctx, s, d); err != nil {
				return err
			}
			continue
		}
		if err == nil {
			if err := removeTree(d); err != nil {
				return err
			}
		}
		if err := os.Rename(s, d); err != nil {
			return err
		}
	}
	return nil
}

// mergeInPlace merges a complete staged tree into an existing destination
// without renaming the destination itself. It is used when the destination is
// a mountpoint or lives at a filesystem boundary, where the atomic swap in
// mergeTree cannot work. Files are replaced by a rename when staging is on the
// destination's filesystem, so a partially written file is never visible.
// Unlike mergeTree, a failure can leave earlier children merged.
func mergeInPlace(ctx context.Context, staged, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		s := filepath.Join(staged, e.Name())
		d := filepath.Join(dst, e.Name())
		si, err := os.Lstat(s)
		if err != nil {
			return err
		}
		di, derr := os.Lstat(d)
		if derr != nil && !os.IsNotExist(derr) {
			return derr
		}
		if si.IsDir() {
			if derr == nil && di.IsDir() {
				if err := mergeInPlace(ctx, s, d); err != nil {
					return err
				}
				continue
			}
			if derr == nil {
				if err := removeTree(d); err != nil {
					return err
				}
			}
			if err := os.Rename(s, d); err == nil {
				continue
			} else if !swapUnsupported(err) {
				return err
			}
			// Staging is on another filesystem: create the directory and
			// merge its children across the boundary.
			if err := os.Mkdir(d, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
			if err := mergeInPlace(ctx, s, d); err != nil {
				return err
			}
			if err := os.Remove(s); err != nil {
				return err
			}
			if err := os.Chmod(d, si.Mode().Perm()); err != nil {
				return err
			}
			if err := os.Chtimes(d, si.ModTime(), si.ModTime()); err != nil {
				return err
			}
			continue
		}
		if derr == nil && di.IsDir() {
			if err := removeTree(d); err != nil {
				return err
			}
		}
		if err := os.Rename(s, d); err == nil {
			continue
		} else if !swapUnsupported(err) {
			return err
		}
		if err := copyEntry(ctx, s, d, si); err != nil {
			return err
		}
	}
	return nil
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
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Write beside the destination and rename into place. A symlink at dst is
	// replaced by the rename, not written through.
	out, err := os.CreateTemp(dir, collectTempPattern)
	if err != nil {
		return err
	}
	tmp := out.Name()
	done := false
	defer func() {
		if !done {
			out.Close()
			os.Remove(tmp)
		}
	}()
	cerr := copyFileData(ctx, in, out, info.Size())
	if cerr == nil {
		cerr = out.Sync()
	}
	if err := out.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return cerr
	}
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chtimes(tmp, info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	done = true
	return nil
}

// copyFileData copies size bytes while leaving holes as holes. Filesystems
// without SEEK_DATA/SEEK_HOLE fall back to a plain copy.
func copyFileData(ctx context.Context, in, out *os.File, size int64) error {
	ok, err := copySparse(ctx, in, out, size)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := out.Truncate(0); err != nil {
		return err
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(out, ctxReader{ctx: ctx, r: in})
	return err
}

// copySparse copies only the data extents reported by SEEK_DATA/SEEK_HOLE and
// ends with a truncate so the apparent size matches even when the tail is a
// hole. It reports false if the filesystem does not support hole seeking.
func copySparse(ctx context.Context, in, out *os.File, size int64) (bool, error) {
	offset := int64(0)
	for offset < size {
		data, err := in.Seek(offset, unix.SEEK_DATA)
		if err != nil {
			if errors.Is(err, unix.ENXIO) {
				break // no data at or after offset: the rest is a hole
			}
			if unsupportedSeek(err) {
				return false, nil
			}
			return false, err
		}
		if data < offset {
			data = offset
		}
		if data >= size {
			break
		}
		hole, err := in.Seek(data, unix.SEEK_HOLE)
		if err != nil {
			if errors.Is(err, unix.ENXIO) {
				hole = size
			} else if unsupportedSeek(err) {
				return false, nil
			} else {
				return false, err
			}
		}
		if hole > size {
			hole = size
		}
		if hole <= data {
			hole = size // do not loop or lose data on strange answers
		}
		if _, err := in.Seek(data, io.SeekStart); err != nil {
			return false, err
		}
		if _, err := out.Seek(data, io.SeekStart); err != nil {
			return false, err
		}
		if _, err := io.CopyN(out, ctxReader{ctx: ctx, r: in}, hole-data); err != nil {
			return false, err
		}
		offset = hole
	}
	if err := out.Truncate(size); err != nil {
		return false, err
	}
	return true, nil
}

func unsupportedSeek(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
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
