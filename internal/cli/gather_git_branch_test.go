package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

// A caller cannot fetch into a branch that one of its worktrees has checked
// out: git refuses, and its raw exit status does not tell the user what to do.
// collect must explain the conflict before fetching and leave the caller repo
// untouched.
func TestGatherGitCollectCheckedOutBranchIsActionable(t *testing.T) {
	requireGit(t)
	withCollectMountRoot(t)

	callerRepo := filepath.Join(t.TempDir(), "caller")
	gitInit(t, callerRepo)
	gitRun(t, callerRepo, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-q", "--allow-empty", "-m", "base")
	src := filepath.Join(collectMountRoot, "alice.w1", "home/dev/src")
	gitInit(t, src)
	gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-q", "--allow-empty", "-m", "src")

	h := newHarness(t, gitObjects()...)
	h.self = "alice.box"
	t.Chdir(callerRepo)

	code, _, errOut := h.run("", "gather", "w1", "--collect", "git:/home/dev/src:main")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "checked out", "main", "switch")
	if strings.Contains(errOut, "exit status 128") {
		t.Fatalf("reported a raw git exit status: %s", errOut)
	}
	if got := gitRun(t, callerRepo, "rev-parse", "--abbrev-ref", "HEAD"); got != "main" {
		t.Fatalf("caller branch = %q, want main", got)
	}
	if got := gitRun(t, callerRepo, "status", "--porcelain"); got != "" {
		t.Fatalf("caller worktree changed: %q", got)
	}
	if h.gone("alice.w1") {
		t.Fatal("blip deleted after a failed collect")
	}
}

// Every git operation fetches into the caller's same repository, so two blips
// collecting onto one branch would make the second fetch fail after the first
// blip was already collected and deleted. The branch is a destination, and a
// duplicate must be rejected before anything is fetched or deleted.
func TestGatherRejectsDuplicateGitDestinations(t *testing.T) {
	requireGit(t)
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	for _, state := range []string{"alice.w1", "alice.w2"} {
		src := filepath.Join(root, state, "home/dev/repo")
		gitInit(t, src)
		gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t",
			"checkout", "-q", "-b", "shared")
		if err := os.WriteFile(filepath.Join(src, state+".txt"), []byte(state+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t", "add", ".")
		gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t",
			"commit", "-q", "-m", state)
	}

	callerRepo := filepath.Join(t.TempDir(), "caller")
	gitInit(t, callerRepo)
	gitRun(t, callerRepo, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-q", "--allow-empty", "-m", "base")
	t.Chdir(callerRepo)

	code, _, errOut := h.run("", "gather", "w1", "w2",
		"--collect", "git:/home/dev/repo:shared")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "shared", "w1", "w2")
	if _, err := os.Stat(filepath.Join(callerRepo, ".git/refs/heads/shared")); !os.IsNotExist(err) {
		t.Fatalf("branch fetched despite the collision: %v", err)
	}
	if h.gone("alice.w1") || h.gone("alice.w2") {
		t.Fatal("blips were deleted despite the collision")
	}
}
