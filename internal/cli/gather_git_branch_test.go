package cli

import (
	"path/filepath"
	"strings"
	"testing"
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
