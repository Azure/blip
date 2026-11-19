package cli

import (
	"path/filepath"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// A directory op into a destination that does not exist yet creates that
// directory, so a later file op sharing the destination is stored under its
// basename. The gather check must not assume the destination is not a
// directory just because it does not exist before the first copy.
func TestGatherAllowsDirectoryThenFileIntoNewSharedDestination(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/sparse/sp", "SP\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/sparse/tailhole", "TAIL\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/repo/one.txt", "ONE\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)

	code, _, errOut := h.run("", "gather", "w1",
		"--collect", "/home/dev/sparse:./newdir",
		"--collect", "/home/dev/repo/one.txt:./newdir")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, filepath.Join(dir, "newdir/sp")); got != "SP\n" {
		t.Fatalf("sp = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "newdir/tailhole")); got != "TAIL\n" {
		t.Fatalf("tailhole = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "newdir/one.txt")); got != "ONE\n" {
		t.Fatalf("one.txt = %q", got)
	}
	if !h.gone("alice.w1") {
		t.Fatal("blip kept")
	}
}
