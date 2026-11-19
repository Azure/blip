package blipchat

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func requireInspectGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func runInspectGit(t *testing.T, dir string, argv []string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v: %s", argv, err, out)
	}
}

func writeMarkerScript(t *testing.T, dir, name, marker string) string {
	t.Helper()
	script := filepath.Join(dir, name)
	body := "#!/bin/sh\necho hit >> " + marker + "\n"
	if name == "textconv.sh" {
		body += "cat \"$1\"\n"
	}
	body += "exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// readOnly approves git status, but core.fsmonitor makes it execute a
// repository-configured program. The inspect invocation must disable that
// config without rejecting the command.
func TestInspectGitDisablesFsmonitor(t *testing.T) {
	requireInspectGit(t)
	dir := t.TempDir()
	runInspectGit(t, dir, []string{"git", "init", "-q", "."})
	runInspectGit(t, dir, []string{"git", "config", "user.email", "a@b"})
	runInspectGit(t, dir, []string{"git", "config", "user.name", "a"})
	marker := filepath.Join(dir, "fsmon-hits")
	script := writeMarkerScript(t, dir, "fsmon.sh", marker)
	runInspectGit(t, dir, []string{"git", "config", "core.fsmonitor", script})

	argv := []string{"git", "status"}
	if err := readOnly(argv); err != nil {
		t.Fatalf("readOnly rejected git status: %v", err)
	}
	// Prove the repository config is dangerous before checking the fix.
	runInspectGit(t, dir, argv)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fsmonitor did not run: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	runInspectGit(t, dir, hardenGitArgs(argv))
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("inspect git status executed fsmonitor: %v", err)
	}
}

// Plain git diff and git log -p run diff.<driver>.textconv filters named by
// .gitattributes. The inspect invocation must disable them.
func TestInspectGitDisablesTextconv(t *testing.T) {
	requireInspectGit(t)
	dir := t.TempDir()
	runInspectGit(t, dir, []string{"git", "init", "-q", "."})
	runInspectGit(t, dir, []string{"git", "config", "user.email", "a@b"})
	runInspectGit(t, dir, []string{"git", "config", "user.name", "a"})
	marker := filepath.Join(dir, "textconv-hits")
	script := writeMarkerScript(t, dir, "textconv.sh", marker)
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.bin diff=mybin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "config", "diff.mybin.textconv", script})
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "add", ".gitattributes", "a.bin"})
	runInspectGit(t, dir, []string{"git", "commit", "-qm", "one"})
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, argv := range [][]string{{"git", "diff"}, {"git", "log", "-p"}} {
		if err := readOnly(argv); err != nil {
			t.Fatalf("readOnly rejected %v: %v", argv, err)
		}
		runInspectGit(t, dir, argv)
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("textconv did not run for %v: %v", argv, err)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		runInspectGit(t, dir, hardenGitArgs(argv))
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Errorf("inspect %v executed the textconv filter: %v", argv, err)
		}
	}
}

func TestHardenGitArgsOnlyChangesGitSubcommands(t *testing.T) {
	for _, argv := range [][]string{
		{"ls", "-la"},
		{"git"},
	} {
		if got := hardenGitArgs(argv); !reflect.DeepEqual(got, argv) {
			t.Errorf("hardenGitArgs(%v) = %v, want unchanged", argv, got)
		}
	}
	got := hardenGitArgs([]string{"git", "status", "--short"})
	want := []string{"git", "-c", "core.fsmonitor=false", "status", "--short"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hardenGitArgs(status) = %v, want %v", got, want)
	}
	got = hardenGitArgs([]string{"git", "diff", "--", "a.bin"})
	want = []string{"git", "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "--", "a.bin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hardenGitArgs(diff) = %v, want %v", got, want)
	}
}
