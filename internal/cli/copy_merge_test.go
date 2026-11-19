package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	// ReadDir sorts names, so aaa is merged before zsub/new fails.
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
