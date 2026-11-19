package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A file copy that fails after creating the destination's parent directories
// must remove the ones it created, and only if they are still empty.
func TestCopyFileCleansCreatedParentsOnFailure(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("failed copy", func(t *testing.T) {
		base := t.TempDir()
		dst := filepath.Join(base, "fresh", "a", "b", "file")
		err := copyFile(context.Background(), filepath.Join(base, "missing"), dst, info)
		if err == nil {
			t.Fatal("copy of a missing source succeeded")
		}
		if _, err := os.Stat(filepath.Join(base, "fresh")); !os.IsNotExist(err) {
			t.Fatalf("created parent directories were left behind: %v", err)
		}
		assertNoTempFiles(t, base)
	})
	t.Run("interrupted copy", func(t *testing.T) {
		base := t.TempDir()
		src := filepath.Join(base, "src")
		if err := os.WriteFile(src, []byte("data\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		copyFileHook = func(string, string) error {
			cancel() // cancel after the parents exist, mid-copy
			return nil
		}
		t.Cleanup(func() { copyFileHook = nil })
		dst := filepath.Join(base, "fresh", "a", "b", "file")
		if err := copyFile(ctx, src, dst, info); err == nil {
			t.Fatal("interrupted copy succeeded")
		}
		if _, err := os.Stat(filepath.Join(base, "fresh")); !os.IsNotExist(err) {
			t.Fatalf("created parent directories were left behind: %v", err)
		}
		assertNoTempFiles(t, base)
	})
	t.Run("pre-existing parents are kept", func(t *testing.T) {
		base := t.TempDir()
		keep := filepath.Join(base, "keep")
		if err := os.Mkdir(keep, 0o755); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(keep, "new", "file")
		err := copyFile(context.Background(), filepath.Join(base, "missing"), dst, info)
		if err == nil {
			t.Fatal("copy of a missing source succeeded")
		}
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("pre-existing parent was removed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(keep, "new")); !os.IsNotExist(err) {
			t.Fatalf("created parent directory was left behind: %v", err)
		}
	})
	t.Run("successful copy keeps new parents", func(t *testing.T) {
		base := t.TempDir()
		src := filepath.Join(base, "src")
		if err := os.WriteFile(src, []byte("data\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(base, "fresh", "a", "file")
		if err := copyFile(context.Background(), src, dst, srcInfo); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, dst); got != "data\n" {
			t.Fatalf("content = %q", got)
		}
	})
}
