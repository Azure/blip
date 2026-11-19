package guest

import (
	"os"
	"path/filepath"
	"testing"
)

// testRoot creates a minimal root filesystem with an /etc/passwd that knows
// only root, plus a regular file for workdir-not-a-directory checks.
func testRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/group"), []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "not-a-dir"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func testGuest(t *testing.T) *Guest {
	t.Helper()
	return &Guest{
		root:     testRoot(t),
		cgroupFD: -1,
		reaper:   newReaper(),
		mounts:   map[string]*mount{},
		frozen:   map[string]*frozenFS{},
		stdio:    newStdio(),
	}
}
