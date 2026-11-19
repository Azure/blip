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
	"sort"
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
		modes, err := copyTreeInto(ctx, src, staging, info)
		if err != nil {
			return err
		}
		// The staging root is renamed within its own parent, which does not
		// need write permission on it, so the new destination can appear
		// complete, modes included, in one step.
		if err := applyDirModes(staging, "", modes); err != nil {
			return err
		}
		return os.Rename(staging, absDst)
	}
	staging, _, modes, err := stageTree(ctx, src, absDst, info)
	if err != nil {
		return err
	}
	defer removeTree(staging)
	// Merge entry by entry into the existing destination. The destination
	// directory is never renamed or copied, so it keeps its inode and all
	// untouched entries keep their inode, mode, and hard links.
	return mergeTree(ctx, staging, absDst, modes)
}

// stageTree copies src into a temporary directory used to merge into dst,
// which must exist and be a directory. It prefers a directory beside dst so
// mergeTree can swap the result atomically. When the parent is not writable or
// is on another filesystem (a mount root, for example), staging happens inside
// dst, on the filesystem the merge writes to.
func stageTree(ctx context.Context, src, dst string, info os.FileInfo) (string, bool, []dirMode, error) {
	parent := filepath.Dir(dst)
	if parent != dst && copyStageDevice(parent, dst) {
		if staging, err := os.MkdirTemp(parent, collectTempPattern); err == nil {
			modes, err := copyTreeInto(ctx, src, staging, info)
			if err != nil {
				removeTree(staging)
				return "", false, nil, err
			}
			return staging, true, modes, nil
		}
	}
	staging, err := os.MkdirTemp(dst, collectTempPattern)
	if err != nil {
		return "", false, nil, err
	}
	modes, err := copyTreeInto(ctx, src, staging, info)
	if err != nil {
		removeTree(staging)
		return "", false, nil, err
	}
	return staging, false, modes, nil
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

// dirMode records the source mode a staged directory takes once it is in its
// final place. Staged directories are created writable and only then handed
// their final mode: renaming a directory needs write permission on the
// directory itself when it moves to a different parent, and a merge also has
// to rename entries out of a staged directory.
type dirMode struct {
	rel  string // path relative to the staging root ("" is the root)
	mode os.FileMode
}

// copyTreeInto copies a source tree into an empty, writable directory. The
// destination takes the source's modes and mtime; callers that merge into an
// existing directory preserve that directory's own metadata instead. It
// returns the directory modes still to apply, which the caller does after the
// tree, or part of it, has been moved into place.
func copyTreeInto(ctx context.Context, src, dst string, info os.FileInfo) ([]dirMode, error) {
	return copyTreeIntoAt(ctx, src, dst, info, "")
}

func copyTreeIntoAt(ctx context.Context, src, dst string, info os.FileInfo, rel string) ([]dirMode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return nil, err
	}
	var modes []dirMode
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		ei, err := os.Lstat(s)
		if err != nil {
			return nil, err
		}
		if ei.IsDir() {
			// Stay writable until the merge has moved this directory (and
			// everything under it) somewhere else.
			if err := os.Mkdir(d, 0o700); err != nil {
				return nil, err
			}
			sub, err := copyTreeIntoAt(ctx, s, d, ei, filepath.Join(rel, e.Name()))
			if err != nil {
				return nil, err
			}
			modes = append(modes, sub...)
			continue
		}
		if err := copyEntry(ctx, s, d, ei); err != nil {
			return nil, err
		}
	}
	if err := os.Chtimes(dst, info.ModTime(), info.ModTime()); err != nil {
		return nil, err
	}
	return append(modes, dirMode{rel: rel, mode: info.Mode()}), nil
}

// applyDirModes sets the source mode on the staged directories at and below
// rel, once they are in their final place. Children are handled before their
// parents: a directory may stop being searchable as soon as it gets its mode.
func applyDirModes(root, rel string, modes []dirMode) error {
	var pending []dirMode
	for _, m := range modes {
		if underDir(rel, m.rel) {
			pending = append(pending, m)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return strings.Count(pending[i].rel, string(filepath.Separator)) >
			strings.Count(pending[j].rel, string(filepath.Separator))
	})
	for _, m := range pending {
		if err := os.Chmod(filepath.Join(root, m.rel), m.mode); err != nil {
			return err
		}
	}
	return nil
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

// mergeOp is one entry a merge changed: a path it created or replaced, and for
// a replaced path the hidden sibling name holding the previous entry.
type mergeOp struct {
	path   string
	backup string
}

// mergeJournal records the changes an in-place merge made so that a failure can
// undo them in reverse order. Replaced entries are moved aside with a rename,
// so rolling back restores their inode, mode, ownership, and hard links.
type mergeJournal struct {
	ops []mergeOp
}

func (j *mergeJournal) add(path, backup string) {
	j.ops = append(j.ops, mergeOp{path: path, backup: backup})
}

// rollback removes anything the merge created and moves every replaced entry
// back to its original name.
func (j *mergeJournal) rollback() error {
	var errs []error
	for i := len(j.ops) - 1; i >= 0; i-- {
		op := j.ops[i]
		if err := removeTree(op.path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
			continue
		}
		if op.backup == "" {
			continue
		}
		if err := os.Rename(op.backup, op.path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// commit discards the backups of entries the merge replaced. The destination is
// already complete at this point, so a backup that cannot be removed is left
// behind rather than turning a successful merge into a reported failure.
func (j *mergeJournal) commit() {
	for _, op := range j.ops {
		if op.backup != "" {
			_ = removeTree(op.backup)
		}
	}
}

// writeGuard remembers a destination directory's mode so the merge can make it
// writable and then put it back exactly as it was.
type writeGuard struct {
	path string
	mode os.FileMode
}

// makeMergeDirsWritable grants owner write and search on every existing
// destination directory the merge writes into, and returns the modes to
// restore. A destination an earlier collect created takes the source root's
// mode, which can be read-only, and a read-only directory still has to receive
// renamed entries or have a child moved aside.
func makeMergeDirsWritable(staged, dst string) ([]writeGuard, error) {
	var guards []writeGuard
	var walk func(staged, dst string) error
	walk = func(staged, dst string) error {
		di, err := os.Lstat(dst)
		if err != nil {
			return err
		}
		if di.Mode().Perm()&0o300 != 0o300 {
			if err := os.Chmod(dst, di.Mode()|0o300); err != nil {
				return err
			}
			guards = append(guards, writeGuard{path: dst, mode: di.Mode()})
		}
		entries, err := os.ReadDir(staged)
		if err != nil {
			return err
		}
		for _, e := range entries {
			s := filepath.Join(staged, e.Name())
			si, err := os.Lstat(s)
			if err != nil {
				return err
			}
			if !si.IsDir() {
				continue
			}
			d := filepath.Join(dst, e.Name())
			di, err := os.Lstat(d)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
			if !di.IsDir() {
				// mergeInto reports the type conflict.
				continue
			}
			if err := walk(s, d); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(staged, dst); err != nil {
		_ = restoreDirModes(guards)
		return nil, err
	}
	return guards, nil
}

// restoreDirModes puts guarded directories back, children before parents so a
// parent that becomes unsearchable does not block its children.
func restoreDirModes(guards []writeGuard) error {
	var errs []error
	for i := len(guards) - 1; i >= 0; i-- {
		if err := os.Chmod(guards[i].path, guards[i].mode); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// mergeEntryHook, when non-nil, runs before a merge moves each entry. Tests use
// it to fail a merge after earlier entries were already placed, since a
// read-only destination directory no longer makes the merge fail.
var mergeEntryHook func(staged, dst string) error

// treeMerger carries the merge destination root and the directory modes that
// are applied as each staged subtree is moved into place.
type treeMerger struct {
	root    string
	journal *mergeJournal
	modes   []dirMode
}

// mergeTree merges a complete staged tree into an existing destination in
// place. Only entries the source provides are written: a new name is moved into
// place, while an existing name is moved to a hidden sibling first and restored
// if a later entry fails. Untouched destination entries are never copied or
// rewritten, so they keep their inode, mode, ownership, and hard links, and the
// merge needs space for the source and replaced entries rather than the whole
// destination.
func mergeTree(ctx context.Context, staged, dst string, modes []dirMode) (err error) {
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
	guards, err := makeMergeDirsWritable(staged, dst)
	if err != nil {
		return err
	}
	defer func() {
		if rerr := restoreDirModes(guards); rerr != nil && err == nil {
			err = rerr
		}
	}()
	m := &treeMerger{root: dst, journal: &mergeJournal{}, modes: modes}
	if err := m.mergeInto(ctx, staged, dst, ""); err != nil {
		if rerr := m.journal.rollback(); rerr != nil {
			return fmt.Errorf("%w (restoring destination: %v)", err, rerr)
		}
		return err
	}
	m.journal.commit()
	return nil
}

// mergeInto moves the entries of a staged directory into the matching existing
// destination directory, recursing where both have a directory.
func (m *treeMerger) mergeInto(ctx context.Context, staged, dst, rel string) error {
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
		if mergeEntryHook != nil {
			if err := mergeEntryHook(s, d); err != nil {
				return err
			}
		}
		si, err := os.Lstat(s)
		if err != nil {
			return err
		}
		di, err := os.Lstat(d)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		exists := err == nil
		if si.IsDir() {
			if !exists {
				// Nothing to merge with: move the whole staged subtree and
				// only then give its directories their source modes.
				if err := os.Rename(s, d); err != nil {
					return err
				}
				m.journal.add(d, "")
				if err := applyDirModes(m.root, filepath.Join(rel, e.Name()), m.modes); err != nil {
					return err
				}
				continue
			}
			if !di.IsDir() {
				return fmt.Errorf("cannot copy directory %s onto %s: not a directory", s, d)
			}
			// Keep the destination directory and its metadata.
			if err := m.mergeInto(ctx, s, d, filepath.Join(rel, e.Name())); err != nil {
				return err
			}
			continue
		}
		if !exists {
			if err := os.Rename(s, d); err != nil {
				return err
			}
			m.journal.add(d, "")
			continue
		}
		// Move the old entry aside without copying it, then put the staged
		// entry at the original name. The journal restores the old one if the
		// rename or a later entry fails.
		backup, err := moveAside(d)
		if err != nil {
			return err
		}
		m.journal.add(d, backup)
		if err := os.Rename(s, d); err != nil {
			return err
		}
	}
	return nil
}

// moveAside renames path to a fresh hidden name in the same directory, which
// keeps the old entry's inode and links intact and stays on one filesystem.
func moveAside(path string) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), collectTempPattern)
	if err != nil {
		return "", err
	}
	backup := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(backup)
		return "", err
	}
	if err := os.Rename(path, backup); err != nil {
		_ = os.Remove(backup)
		return "", err
	}
	return backup, nil
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

// copyFileHook, when non-nil, runs before copyFile reads src. Tests use it to
// observe, or fail, the file copies a merge performs.
var copyFileHook func(src, dst string) error

// makeParentDirs creates dir and any missing parents, returning the
// directories this call created, shallowest first. A failed copy can then
// remove exactly those, and only while they are still empty; a pre-existing
// directory is never returned.
func makeParentDirs(dir string, perm os.FileMode) ([]string, error) {
	var missing []string
	for p := dir; ; {
		if _, err := os.Lstat(p); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		missing = append(missing, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	created := make([]string, 0, len(missing))
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], perm); err != nil {
			if os.IsExist(err) {
				continue
			}
			removeEmptyDirs(created)
			return nil, err
		}
		created = append(created, missing[i])
	}
	return created, nil
}

// removeEmptyDirs removes directories this call created, deepest first. A
// directory that is no longer empty is left alone.
func removeEmptyDirs(dirs []string) {
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
}

func copyFile(ctx context.Context, src, dst string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if copyFileHook != nil {
		if err := copyFileHook(src, dst); err != nil {
			return err
		}
	}
	dir := filepath.Dir(dst)
	created, err := makeParentDirs(dir, 0o755)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			removeEmptyDirs(created)
		}
	}()
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
	// Reproduce the permission bits and the setuid, setgid, and sticky bits.
	// os.Chmod ignores the non-mode type bits that may also be set.
	if err := os.Chmod(tmp, info.Mode()); err != nil {
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
