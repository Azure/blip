// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

// Two directory sources with different basenames expand onto the same existing
// destination as one tree. Before the states are mounted a directory source
// looks like a file source, so the gather check alone cannot reject the pair.
// gather must check the mounted sources across every blip and reject a merge
// that would overwrite another blip's child, before collecting or deleting
// either blip.
func TestGatherRejectsCrossBlipDirectoryMergeIntoExistingDest(t *testing.T) {
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/w1/result.txt", "ONE\n", 0o644)
	writeCollectFile(t, root, "alice.w2", "/home/dev/w2/result.txt", "TWO\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1", "w2", "--collect", "/home/dev/{name}:./out")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "/home/dev/w1", "/home/dev/w2")
	if _, err := os.Stat(filepath.Join(dir, "out/result.txt")); !os.IsNotExist(err) {
		t.Fatalf("a colliding destination was written: %v", err)
	}
	if h.gone("alice.w1") || h.gone("alice.w2") {
		t.Fatal("blips deleted despite the collision")
	}
}

// A directory merge that only adds children to a shared existing destination
// does not overwrite the other blip's data, so the mounted check must still
// allow the two trees to merge as a union.
func TestGatherAllowsCrossBlipDisjointDirectoryMergeIntoExistingDest(t *testing.T) {
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/w1/one.txt", "ONE\n", 0o644)
	writeCollectFile(t, root, "alice.w2", "/home/dev/w2/two.txt", "TWO\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1", "w2", "--collect", "/home/dev/{name}:./out")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, filepath.Join(dir, "out/one.txt")); got != "ONE\n" {
		t.Fatalf("one.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "out/two.txt")); got != "TWO\n" {
		t.Fatalf("two.txt = %q", got)
	}
	if !h.gone("alice.w1") || !h.gone("alice.w2") {
		t.Fatal("blips kept")
	}
}
