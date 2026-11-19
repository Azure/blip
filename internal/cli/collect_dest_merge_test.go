package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// A directory source spreads over everything below its destination, so a file
// op sharing that destination can land on a child of the tree. The gather check
// cannot see the mounted source types; collect must reject the pair before
// copying instead of silently overwriting one child.
func TestGatherRejectsDirectoryMergeIntoSharedExistingDestination(t *testing.T) {
	for _, dirFirst := range []bool{true, false} {
		name := "file-first"
		if dirFirst {
			name = "dir-first"
		}
		t.Run(name, func(t *testing.T) {
			root := withCollectMountRoot(t)
			worker := ownedBlip("alice.w1", "alice.w1")
			worker.Status.Phase = v1alpha1.BlipSucceeded
			h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
			h.self = "alice.box"
			writeCollectFile(t, root, "alice.w1", "/home/dev/tree/marker", "TREE\n", 0o644)
			writeCollectFile(t, root, "alice.w1", "/home/dev/tree/keep", "KEEP\n", 0o644)
			writeCollectFile(t, root, "alice.w1", "/home/dev/other/marker", "FILE\n", 0o644)

			dir := t.TempDir()
			t.Chdir(dir)
			if err := os.Mkdir("out", 0o755); err != nil {
				t.Fatal(err)
			}
			ops := []string{
				"--collect", "/home/dev/tree:./out",
				"--collect", "/home/dev/other/marker:./out",
			}
			if !dirFirst {
				ops = []string{
					"--collect", "/home/dev/other/marker:./out",
					"--collect", "/home/dev/tree:./out",
				}
			}
			args := append([]string{"gather", "w1"}, ops...)
			code, _, errOut := h.run("", args...)
			if code != 1 {
				t.Fatalf("code %d, want 1: %s", code, errOut)
			}
			mustContain(t, errOut, "destination", "out/marker")
			if _, err := os.Stat(filepath.Join(dir, "out/marker")); !os.IsNotExist(err) {
				t.Fatalf("a colliding destination was written: %v", err)
			}
			if h.gone("alice.w1") {
				t.Fatal("blip deleted despite the collision")
			}
		})
	}
}
