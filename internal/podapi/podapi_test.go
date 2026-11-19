// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package podapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DesiredFile)
	if err := WriteJSON(path, Desired{Claim: &Claim{Env: []string{"TOKEN=secret"}}}); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, FileMode)

	// A document left by an older release is replaced, not merely rewritten
	// in place, so its mode is tightened on upgrade.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, Desired{Stop: true}); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, FileMode)
}

func TestWriteJSONNoGroupOrOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), ObservedFile)
	if err := WriteJSON(path, Observed{Phase: PhaseWarm}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("%s mode %#o is readable by group or other", path, perm)
	}
}

func TestEnsurePodDirCreatesRootOnly(t *testing.T) {
	pods := filepath.Join(t.TempDir(), "pods")
	dir := filepath.Join(pods, "ns", "pod")
	if err := EnsurePodDir(dir); err != nil {
		t.Fatal(err)
	}
	assertMode(t, pods, DirMode) // MkdirAll creates missing intermediates root-only
	assertMode(t, filepath.Join(pods, "ns"), DirMode)
	assertMode(t, dir, DirMode)
}

func TestEnsurePodDirTightensExisting(t *testing.T) {
	pods := filepath.Join(t.TempDir(), "pods")
	nsDir := filepath.Join(pods, "ns")
	dir := filepath.Join(nsDir, "pod")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Simulate a directory created by an older release or by kubelet with a
	// wider mode, including a setgid bit that must not survive.
	if err := os.Chmod(nsDir, 0o2755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := EnsurePodDir(dir); err != nil {
		t.Fatal(err)
	}
	assertMode(t, nsDir, DirMode)
	assertMode(t, dir, DirMode)
}

func TestEnsureDirDoesNotTouchParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "pod")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	assertMode(t, dir, DirMode)
	// The runtime's pod directory lives below /run, which is not a pod
	// namespace directory and must keep its mode.
	assertMode(t, parent, 0o755)
}

func TestTightenDirRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := tightenDir(link); err == nil {
		t.Fatal("tightened a symlink")
	}
	assertMode(t, target, 0o755)
}

func TestEnsureSocketDirIsProxyWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ns", "pod")
	if err := EnsurePodDir(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock")
	// Kubelet's hostPath DirectoryOrCreate starts root-only.
	if err := os.Mkdir(sock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSocketDir(dir); err != nil {
		t.Fatal(err)
	}
	assertMode(t, sock, 0o777)
	assertMode(t, dir, DirMode)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode %#o, want %#o", path, got, want)
	}
}
