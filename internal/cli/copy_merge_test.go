package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// lstat returns the Unix metadata for a path, including its inode and link
// count, so tests can prove a merge did not recreate an entry.
func lstat(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return st
}

func modeBits(st unix.Stat_t) uint32 {
	return st.Mode & 0o7777
}

// A directory merge that fails while placing a later child must leave the
// whole existing destination as it was, not a mix of old and new entries.
func TestCopyTreeMergeLeavesDestinationOnFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.MkdirAll(filepath.Join(src, "zsub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "zsub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "aaa"), []byte("NEW-AAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "zsub", "new"), []byte("NEW-SUB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "aaa"), []byte("OLD-AAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "zsub", "old"), []byte("OLD-SUB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dst, "zsub"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dst, "zsub"), 0o755) })

	// ReadDir sorts names, so aaa is merged before zsub/new is moved.
	mergeEntryHook = func(_, d string) error {
		if d == filepath.Join(dst, "zsub", "new") {
			return unix.EACCES
		}
		return nil
	}
	t.Cleanup(func() { mergeEntryHook = nil })
	err := copyPath(context.Background(), src, dst)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a permission error", err)
	}
	if got := readFile(t, filepath.Join(dst, "aaa")); got != "OLD-AAA\n" {
		t.Fatalf("aaa = %q after a failed merge", got)
	}
	if got := readFile(t, filepath.Join(dst, "zsub", "old")); got != "OLD-SUB\n" {
		t.Fatalf("zsub/old = %q after a failed merge", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "zsub", "new")); !os.IsNotExist(err) {
		t.Fatalf("zsub/new exists after a failed merge: %v", err)
	}
	assertNoTempFiles(t, base)
}

// Merging a small source into an existing destination must not copy the
// destination first: the old implementation snapshotted the whole destination,
// which fails with ENOSPC when it is nearly full. The hook makes any attempt to
// copy an existing destination entry fail as a full filesystem would.
func TestCopyTreeMergeDoesNotCopyExistingDestination(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	// A dense file larger than the source, like the nearly-full destination in
	// the bug report.
	fill := make([]byte, 1<<20)
	for i := range fill {
		fill[i] = byte(i)
	}
	if err := os.WriteFile(filepath.Join(dst, "fill"), fill, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "x"), []byte("hello-small\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := lstat(t, filepath.Join(dst, "fill"))

	var copied []string
	copyFileHook = func(s, d string) error {
		copied = append(copied, s)
		if strings.HasPrefix(s, dst+string(filepath.Separator)) {
			return unix.ENOSPC
		}
		return nil
	}
	t.Cleanup(func() { copyFileHook = nil })

	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if len(copied) != 1 || copied[0] != filepath.Join(src, "x") {
		t.Fatalf("copied %v, want only the source file", copied)
	}
	if got := readFile(t, filepath.Join(dst, "x")); got != "hello-small\n" {
		t.Fatalf("x = %q", got)
	}
	after := lstat(t, filepath.Join(dst, "fill"))
	if after.Ino != before.Ino || modeBits(after) != modeBits(before) {
		t.Fatalf("untouched destination file was rebuilt: inode %d -> %d, mode %o -> %o",
			before.Ino, after.Ino, modeBits(before), modeBits(after))
	}
	if got := readFile(t, filepath.Join(dst, "fill")); len(got) != len(fill) {
		t.Fatalf("fill length = %d, want %d", len(got), len(fill))
	}
	assertNoTempFiles(t, base)
}

// A merge must leave every destination entry the source does not replace
// exactly as it was, including special mode bits, hard links, and the top-level
// directory's inode.
func TestCopyTreeMergePreservesUntouchedDestinationMetadata(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.MkdirAll(filepath.Join(dst, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep"), []byte("KEEP\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dst, "keep"), filepath.Join(dst, "keep-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "sub", "nested"), []byte("NESTED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dst, "keep"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dst, "sub"), 0o775|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "x"), []byte("NEW\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeDst := lstat(t, dst)
	beforeKeep := lstat(t, filepath.Join(dst, "keep"))
	beforeLink := lstat(t, filepath.Join(dst, "keep-link"))
	beforeSub := lstat(t, filepath.Join(dst, "sub"))
	if modeBits(beforeDst) != 0o2775 || modeBits(beforeKeep) != 0o4755 || modeBits(beforeSub) != 0o3775 {
		t.Skipf("filesystem did not keep special mode bits: dir %o keep %o sub %o",
			modeBits(beforeDst), modeBits(beforeKeep), modeBits(beforeSub))
	}
	if beforeKeep.Ino != beforeLink.Ino || beforeKeep.Nlink != 2 {
		t.Fatalf("test setup did not create a hard link: %+v %+v", beforeKeep, beforeLink)
	}

	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatalf("merge failed: %v", err)
	}

	if got := readFile(t, filepath.Join(dst, "x")); got != "NEW\n" {
		t.Fatalf("x = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "keep")); got != "KEEP\n" {
		t.Fatalf("keep = %q after merge", got)
	}
	afterDst := lstat(t, dst)
	if afterDst.Ino != beforeDst.Ino || modeBits(afterDst) != modeBits(beforeDst) {
		t.Fatalf("destination directory changed: inode %d -> %d, mode %o -> %o",
			beforeDst.Ino, afterDst.Ino, modeBits(beforeDst), modeBits(afterDst))
	}
	afterKeep := lstat(t, filepath.Join(dst, "keep"))
	afterLink := lstat(t, filepath.Join(dst, "keep-link"))
	if afterKeep.Ino != beforeKeep.Ino || afterKeep.Nlink != 2 || modeBits(afterKeep) != 0o4755 {
		t.Fatalf("keep changed: before %+v after %+v", beforeKeep, afterKeep)
	}
	if afterLink.Ino != beforeKeep.Ino || afterLink.Nlink != 2 || modeBits(afterLink) != 0o4755 {
		t.Fatalf("keep-link changed: before %+v after %+v", beforeLink, afterLink)
	}
	afterSub := lstat(t, filepath.Join(dst, "sub"))
	if afterSub.Ino != beforeSub.Ino || modeBits(afterSub) != 0o3775 {
		t.Fatalf("sub changed: before %+v after %+v", beforeSub, afterSub)
	}
	if got := readFile(t, filepath.Join(dst, "sub", "nested")); got != "NESTED\n" {
		t.Fatalf("sub/nested = %q after merge", got)
	}
	assertNoTempFiles(t, base)
}

// A merge that fails after replacing one entry and creating another must restore
// the replaced entry's content, mode, and inode, and remove the created one.
func TestCopyTreeMergeFailureRestoresDestinationExactly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.MkdirAll(filepath.Join(src, "zsub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "zsub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "aaa"), []byte("NEW-AAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "bbb"), []byte("NEW-BBB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "zsub", "new"), []byte("NEW-SUB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "aaa"), []byte("OLD-AAA\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "zsub", "old"), []byte("OLD-SUB\n"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dst, "zsub"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dst, "zsub"), 0o755) })
	beforeDst := lstat(t, dst)
	beforeAAA := lstat(t, filepath.Join(dst, "aaa"))
	beforeSub := lstat(t, filepath.Join(dst, "zsub"))
	beforeOld := lstat(t, filepath.Join(dst, "zsub", "old"))

	// ReadDir sorts names, so aaa is replaced and bbb created before the
	// hook fails zsub/new. The read-only destination directory at the merge
	// boundary must not itself make the merge fail.
	mergeEntryHook = func(_, d string) error {
		if d == filepath.Join(dst, "zsub", "new") {
			return unix.EACCES
		}
		return nil
	}
	t.Cleanup(func() { mergeEntryHook = nil })
	err := copyPath(context.Background(), src, dst)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a permission error", err)
	}

	if got := readFile(t, filepath.Join(dst, "aaa")); got != "OLD-AAA\n" {
		t.Fatalf("aaa = %q after a failed merge", got)
	}
	afterAAA := lstat(t, filepath.Join(dst, "aaa"))
	if afterAAA.Ino != beforeAAA.Ino || modeBits(afterAAA) != 0o640 {
		t.Fatalf("aaa not restored: before %+v after %+v", beforeAAA, afterAAA)
	}
	if _, err := os.Lstat(filepath.Join(dst, "bbb")); !os.IsNotExist(err) {
		t.Fatalf("bbb exists after a failed merge: %v", err)
	}
	if got := readFile(t, filepath.Join(dst, "zsub", "old")); got != "OLD-SUB\n" {
		t.Fatalf("zsub/old = %q after a failed merge", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "zsub", "new")); !os.IsNotExist(err) {
		t.Fatalf("zsub/new exists after a failed merge: %v", err)
	}
	afterSub := lstat(t, filepath.Join(dst, "zsub"))
	if afterSub.Ino != beforeSub.Ino || modeBits(afterSub) != 0o555 {
		t.Fatalf("zsub not restored: before %+v after %+v", beforeSub, afterSub)
	}
	afterOld := lstat(t, filepath.Join(dst, "zsub", "old"))
	if afterOld.Ino != beforeOld.Ino || modeBits(afterOld) != 0o604 {
		t.Fatalf("zsub/old not restored: before %+v after %+v", beforeOld, afterOld)
	}
	afterDst := lstat(t, dst)
	if afterDst.Ino != beforeDst.Ino || modeBits(afterDst) != 0o2750 {
		t.Fatalf("destination directory changed: before %+v after %+v", beforeDst, afterDst)
	}
	assertNoTempFiles(t, base)
}

// A destination that is a filesystem boundary cannot be swapped atomically,
// so the merge must stage and write inside the destination itself.
func TestCopyTreeMergesAcrossSimulatedMountBoundary(t *testing.T) {
	old := copyStageDevice
	copyStageDevice = func(string, string) bool { return false }
	t.Cleanup(func() { copyStageDevice = old })

	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "new.txt"), []byte("NEW\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "child.txt"), []byte("CHILD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("KEEP\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dst, "new.txt")); got != "NEW\n" {
		t.Fatalf("new.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "sub", "child.txt")); got != "CHILD\n" {
		t.Fatalf("sub/child.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "keep.txt")); got != "KEEP\n" {
		t.Fatalf("keep.txt = %q", got)
	}
	assertNoTempFiles(t, dst)
	assertNoTempFiles(t, base)
}

// A mount root's parent is often not writable. Staging must fall back to the
// destination's own filesystem instead of failing to create a directory in
// the parent.
func TestCopyTreeStagesInsideWhenParentUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	holder := filepath.Join(base, "holder")
	dst := filepath.Join(holder, "dst")
	for _, d := range []string{src, dst} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "new.txt"), []byte("NEW\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("KEEP\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(holder, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(holder, 0o755) })

	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dst, "new.txt")); got != "NEW\n" {
		t.Fatalf("new.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "keep.txt")); got != "KEEP\n" {
		t.Fatalf("keep.txt = %q", got)
	}
	assertNoTempFiles(t, dst)
	assertNoTempFiles(t, base)
}
