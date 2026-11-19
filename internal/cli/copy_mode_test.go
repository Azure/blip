// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Collect keeps the source's setuid, setgid, and sticky bits along with the
// permission bits.
func TestCopyTreePreservesSpecialModeBits(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	for _, d := range []string{"setgid", "sticky"} {
		if err := os.MkdirAll(filepath.Join(src, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(src, "setgid"), 0o775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "sticky"), 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"suid.txt": 0o755 | os.ModeSetuid,
		"sgid.txt": 0o755 | os.ModeSetgid,
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(name+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(src, name), mode); err != nil {
			t.Fatal(err)
		}
	}
	// Some filesystems silently drop these bits; skip rather than fail.
	for p, want := range map[string]uint32{
		filepath.Join(src, "setgid"):   0o2775,
		filepath.Join(src, "sticky"):   0o1777,
		filepath.Join(src, "suid.txt"): 0o4755,
		filepath.Join(src, "sgid.txt"): 0o2755,
	} {
		if got := modeBits(lstat(t, p)); got != want {
			t.Skipf("filesystem did not keep special bits on %s: %o, want %o", p, got, want)
		}
	}

	dst := filepath.Join(base, "dst")
	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]uint32{
		"setgid":   0o2775,
		"sticky":   0o1777,
		"suid.txt": 0o4755,
		"sgid.txt": 0o2755,
	} {
		if got := modeBits(lstat(t, filepath.Join(dst, rel))); got != want {
			t.Errorf("%s mode = %o, want %o", rel, got, want)
		}
	}
}
