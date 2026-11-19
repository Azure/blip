package blipchat

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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
	want := []string{"git",
		"-c", "core.fsmonitor=false",
		"-c", "diff.external=",
		"-c", "gpg.program=/bin/false",
		"-c", "log.showSignature=false",
		"status", "--short"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hardenGitArgs(status) = %v, want %v", got, want)
	}
	got = hardenGitArgs([]string{"git", "diff", "--", "a.bin"})
	want = []string{"git",
		"-c", "core.fsmonitor=false",
		"-c", "diff.external=",
		"-c", "gpg.program=/bin/false",
		"-c", "log.showSignature=false",
		"diff", "--no-ext-diff", "--no-textconv", "--", "a.bin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hardenGitArgs(diff) = %v, want %v", got, want)
	}
}

func TestReadOnlyGitRejectsProgramOptions(t *testing.T) {
	for _, argv := range [][]string{
		{"git", "log", "--remerge-diff"},
		{"git", "show", "--remerge-diff"},
		{"git", "log", "--diff-merges=remerge"},
		{"git", "log", "--diff-merges", "remerge"},
		{"git", "log", "--diff-merges=r"},
		{"git", "log", "--diff-merges", "r"},
		{"git", "log", "--show-signature"},
		{"git", "show", "--show-signature"},
		{"git", "log", "--format=%H %G?"},
		{"git", "log", "--pretty=%GG"},
		{"git", "show", "--format", "%GS"},
		{"git", "log", "--gpg-sign"},
		{"git", "branch", "--format=%(signature)"},
	} {
		if err := readOnly(argv); err == nil {
			t.Errorf("readOnly(%v) = nil, want rejection", argv)
		}
	}
}

func TestReadOnlyGitAllowsSafeInspectionOptions(t *testing.T) {
	for _, argv := range [][]string{
		{"git", "log", "-1", "--oneline"},
		{"git", "log", "-S", "needle", "--oneline"}, // pickaxe, not signing
		{"git", "log", "--diff-merges=first-parent", "-1"},
		{"git", "log", "--no-show-signature", "-1"},
		{"git", "log", "--format=%H %s", "-1"},
		{"git", "show", "--stat"},
	} {
		if err := readOnly(argv); err != nil {
			t.Errorf("readOnly(%v) = %v, want allowed", argv, err)
		}
	}
}

func inspectGit(t *testing.T, dir string, argv []string) error {
	t.Helper()
	if err := readOnly(argv); err != nil {
		return err
	}
	runInspectGit(t, dir, hardenGitArgs(argv))
	return nil
}

// A repository can configure merge.<driver>.driver and gpg.program, and can
// set log.showSignature. The read-only allowlist must reject every option that
// asks git to run those programs, and the hardened argv must keep an allowed
// command (git log with log.showSignature=true) from running gpg.
func TestInspectGitCannotRunRepoPrograms(t *testing.T) {
	requireInspectGit(t)
	for _, tc := range []struct {
		name string
		repo func(t *testing.T) (string, string)
		argv [][]string
	}{
		{name: "merge driver", repo: setupMergeDriverRepo, argv: [][]string{
			{"git", "log", "--remerge-diff", "--oneline", "-1"},
			{"git", "show", "--remerge-diff", "--oneline", "-1"},
			{"git", "log", "--diff-merges=remerge", "--oneline", "-1"},
			{"git", "log", "--diff-merges", "remerge", "--oneline", "-1"},
		}},
		{name: "gpg", repo: setupGPGRepo, argv: [][]string{
			{"git", "log", "--show-signature", "--oneline", "-1"},
			{"git", "show", "--show-signature", "--oneline", "-1"},
			{"git", "log", "--format=%H %G?", "-1"},
			{"git", "show", "--pretty=%GG", "-1"},
			{"git", "log", "--oneline", "-1"}, // log.showSignature=true in config
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, marker := tc.repo(t)
			for _, argv := range tc.argv {
				t.Run(strings.Join(argv, " "), func(t *testing.T) {
					// Prove the repository config is malicious.
					runInspectGit(t, dir, argv)
					if _, err := os.Stat(marker); err != nil {
						t.Fatalf("test setup: %v did not run the configured program", argv)
					}
					if err := os.Remove(marker); err != nil {
						t.Fatal(err)
					}
					// The allowed command (git log -1 with log.showSignature)
					// must be neutralized by the hardened config.
					if err := inspectGit(t, dir, argv); err == nil {
						if _, err := os.Stat(marker); !os.IsNotExist(err) {
							t.Errorf("inspect %v ran a repository-configured program", argv)
						}
					}
				})
			}
		})
	}
}

func setupMergeDriverRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	runInspectGit(t, dir, []string{"git", "init", "-q", "."})
	runInspectGit(t, dir, []string{"git", "config", "user.email", "a@b"})
	runInspectGit(t, dir, []string{"git", "config", "user.name", "a"})
	marker := filepath.Join(dir, "marker")
	script := writeMarkerScript(t, dir, "driver.sh", marker)
	runInspectGit(t, dir, []string{"git", "config", "merge.evil.driver", script})
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt merge=evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "add", "."})
	runInspectGit(t, dir, []string{"git", "commit", "-qm", "base"})
	runInspectGit(t, dir, []string{"git", "checkout", "-qb", "side"})
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("side\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "commit", "-qam", "side"})
	runInspectGit(t, dir, []string{"git", "checkout", "-q", "master"})
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "commit", "-qam", "main"})
	// The merge driver may fail or appear to resolve the conflict. Force a
	// merge commit with two parents either way.
	merge := exec.Command("git", "merge", "side", "-m", "merge")
	merge.Dir = dir
	if err := merge.Run(); err != nil {
		add := exec.Command("git", "add", "-A")
		add.Dir = dir
		_ = add.Run()
		commit := exec.Command("git", "commit", "-qm", "merge")
		commit.Dir = dir
		_ = commit.Run()
	}
	runInspectGitOutput(t, dir, []string{"git", "rev-parse", "HEAD^2"})
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return dir, marker
}

func setupGPGRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	runInspectGit(t, dir, []string{"git", "init", "-q", "."})
	runInspectGit(t, dir, []string{"git", "config", "user.email", "a@b"})
	runInspectGit(t, dir, []string{"git", "config", "user.name", "a"})
	marker := filepath.Join(dir, "gpgmarker")
	script := writeMarkerScript(t, dir, "fakegpg.sh", marker)
	runInspectGit(t, dir, []string{"git", "config", "gpg.program", script})
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInspectGit(t, dir, []string{"git", "add", "f"})
	runInspectGit(t, dir, []string{"git", "commit", "-qm", "base"})
	tree := runInspectGitOutput(t, dir, []string{"git", "write-tree"})
	spec := "tree " + tree + "\n" +
		"author A <a@b> 1234567890 +0000\n" +
		"committer A <a@b> 1234567890 +0000\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n fake\n -----END PGP SIGNATURE-----\n\nsigned commit\n"
	commit := runInspectGitInput(t, dir, []string{"git", "hash-object", "-t", "commit", "-w", "--stdin"}, spec)
	runInspectGit(t, dir, []string{"git", "update-ref", "refs/heads/master", commit})
	runInspectGit(t, dir, []string{"git", "config", "log.showSignature", "true"})
	return dir, marker
}

func runInspectGitOutput(t *testing.T, dir string, argv []string) string {
	t.Helper()
	return runInspectGitInput(t, dir, argv, "")
}

func runInspectGitInput(t *testing.T, dir string, argv []string, input string) string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v: %v", argv, err)
	}
	return strings.TrimSpace(string(out))
}
