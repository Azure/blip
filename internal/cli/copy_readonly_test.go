// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// rcTree builds an empty source tree and registers cleanup so t.TempDir can
// delete it even after the test makes parts of it read-only. Callers fill the
// tree and chmod its root last.
func rcTree(t *testing.T, base string) string {
	t.Helper()
	src := filepath.Join(base, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTreeWritable(base) })
	return src
}

// Collecting a directory whose root or a child is read-only must merge into an
// existing destination: the staged directories stay writable through the merge
// and only take their source mode once they are in place.
func TestCopyTreeMergeReadOnlySourceIntoExistingDestination(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	for _, tc := range []struct {
		name     string
		rootMode os.FileMode
		roDirs   []string
		// nested puts a directory of the same name in the destination, so the
		// read-only child sits at a merge boundary instead of being moved whole.
		nested bool
	}{
		{name: "read-only child", rootMode: 0o755, roDirs: []string{"rodir"}},
		{name: "read-only root", rootMode: 0o555},
		{name: "read-only child at merge boundary", rootMode: 0o755, roDirs: []string{"parent/rodir"}, nested: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			src := rcTree(t, base)
			dst := filepath.Join(base, "dst")
			if err := os.MkdirAll(filepath.Join(dst, "keepdir"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("KEEP\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("TOP\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if len(tc.roDirs) > 0 {
				rodir := filepath.Join(src, tc.roDirs[0])
				if err := os.MkdirAll(rodir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rodir, "f.txt"), []byte("RO\n"), 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rodir, 0o555); err != nil {
					t.Fatal(err)
				}
			}
			if tc.nested {
				if err := os.MkdirAll(filepath.Join(dst, "parent"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(src, tc.rootMode); err != nil {
				t.Fatal(err)
			}
			roPath := dst
			if len(tc.roDirs) > 0 {
				roPath = filepath.Join(dst, filepath.FromSlash(tc.roDirs[0]))
			}

			if err := copyPath(context.Background(), src, dst); err != nil {
				t.Fatalf("merge failed: %v", err)
			}
			if got := readFile(t, filepath.Join(dst, "keep.txt")); got != "KEEP\n" {
				t.Fatalf("keep.txt = %q", got)
			}
			if got := readFile(t, filepath.Join(dst, "top.txt")); got != "TOP\n" {
				t.Fatalf("top.txt = %q", got)
			}
			if len(tc.roDirs) > 0 {
				if got := readFile(t, filepath.Join(roPath, "f.txt")); got != "RO\n" {
					t.Fatalf("rodir/f.txt = %q", got)
				}
				if info, err := os.Stat(roPath); err != nil || info.Mode().Perm() != 0o555 {
					t.Fatalf("read-only directory mode = %v %v, want 555", info, err)
				}
			}
			// An existing destination keeps its own mode even when the source
			// root is read-only.
			if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o755 {
				t.Fatalf("destination mode = %v %v, want 755", info, err)
			}
			assertNoTempFiles(t, base)
		})
	}
}

// A collect into a destination an earlier collect created must work even though
// the destination root took the source's read-only mode.
func TestCopyTreeRepeatedCollectIntoReadOnlyDestination(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	base := t.TempDir()
	src := rcTree(t, base)
	if err := os.Mkdir(filepath.Join(src, "rodir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "rodir", "f.txt"), []byte("F\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "rodir"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o555); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(base, "dst")

	for i := 1; i <= 2; i++ {
		if err := copyPath(context.Background(), src, dst); err != nil {
			t.Fatalf("collect %d failed: %v", i, err)
		}
		for name, want := range map[string]string{"a.txt": "A\n", "rodir/f.txt": "F\n"} {
			if got := readFile(t, filepath.Join(dst, filepath.FromSlash(name))); got != want {
				t.Fatalf("collect %d: %s = %q", i, name, got)
			}
		}
		for _, p := range []string{dst, filepath.Join(dst, "rodir")} {
			if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o555 {
				t.Fatalf("collect %d: %s mode = %v %v, want 555", i, p, info, err)
			}
		}
		assertNoTempFiles(t, base)
	}
}
