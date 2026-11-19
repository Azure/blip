package guest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// lookPath must match execvp: a relative PATH entry is relative to the
// command's working directory, an empty entry means that directory, and a
// candidate that exists but cannot be executed is permission denied (126)
// rather than command not found (127).
func TestLookPathMatchesExecvp(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("home/dev/bin/hello", "#!/bin/sh\necho HELLO\n", 0o755)
	write("home/dev/tool", "#!/bin/sh\n", 0o755)
	write("relbin/foo", "#!/bin/sh\necho FOO\n", 0o644)
	write("usr/bin/hello", "#!/bin/sh\n", 0o755)

	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}
	acct := &account{uid: st.Uid, gid: st.Gid, groups: []uint32{st.Gid}}

	p, err := lookPath(root, "/home/dev", "hello", []string{"PATH=bin:/usr/bin"}, acct)
	if err != nil || p != "/home/dev/bin/hello" {
		t.Fatalf("relative PATH entry: %q, %v; want /home/dev/bin/hello", p, err)
	}
	p, err = lookPath(root, "/home/dev", "tool", []string{"PATH=:/usr/bin"}, acct)
	if err != nil || p != "/home/dev/tool" {
		t.Fatalf("empty PATH entry: %q, %v; want /home/dev/tool", p, err)
	}
	p, err = lookPath(root, "/tmp", "hello", []string{"PATH=/usr/bin"}, acct)
	if err != nil || p != "/usr/bin/hello" {
		t.Fatalf("absolute PATH entry: %q, %v; want /usr/bin/hello", p, err)
	}

	_, err = lookPath(root, "/tmp", "foo", []string{"PATH=/relbin"}, acct)
	if startExitCode(err) != 126 || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("non-executable candidate: %v, code %d; want 126 permission denied", err, startExitCode(err))
	}
	_, err = lookPath(root, "/tmp", "noseuch", []string{"PATH=/relbin"}, acct)
	if startExitCode(err) != 127 || !strings.Contains(err.Error(), "command not found") {
		t.Fatalf("missing command: %v, code %d; want 127 command not found", err, startExitCode(err))
	}
}
