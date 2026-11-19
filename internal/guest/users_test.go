// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
	// An entirely empty PATH is a single empty component (the working
	// directory), exactly like execvp's PATH="" handling.
	p, err = lookPath(root, "/home/dev", "tool", []string{"PATH="}, acct)
	if err != nil || p != "/home/dev/tool" {
		t.Fatalf("empty PATH: %q, %v; want /home/dev/tool", p, err)
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

// execve("") is ENOENT, so an empty command name is not found (127), not the
// directory candidate's permission denied (126). PATH must not change that.
func TestLookPathEmptyNameIsNotFound(t *testing.T) {
	root := testRoot(t)
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}
	acct := &account{uid: st.Uid, gid: st.Gid, groups: []uint32{st.Gid}}
	for _, env := range [][]string{nil, {"PATH="}, {"PATH=:/usr/bin"}} {
		// /home exists and is a directory, so the old directory-candidate
		// path would report 126.
		_, err := lookPath(root, "/home", "", env, acct)
		if startExitCode(err) != 127 || !strings.Contains(err.Error(), "command not found") {
			t.Fatalf("env %v: %v, code %d; want 127 command not found", env, err, startExitCode(err))
		}
	}
}

// A numeric user is matched by value, not by its spelling: 01000 is uid 1000
// and must get the same name, gid, groups and home as 1000. Out-of-range IDs
// are rejected before they reach the kernel.
func TestLookupAccountNumericNormalization(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/group"),
		[]byte("root:x:0:\nalice:x:1000:\nwheel:x:10:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	want, err := lookupAccount(root, "1000")
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"01000", "0001000"} {
		got, err := lookupAccount(root, spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if got.name != want.name || got.uid != want.uid || got.gid != want.gid ||
			got.home != want.home || len(got.groups) != len(want.groups) {
			t.Fatalf("%s: %+v, want %+v", spec, got, want)
		}
	}
	got, err := lookupAccount(root, "01000:01000")
	if err != nil || got.gid != 1000 || got.uid != 1000 {
		t.Fatalf("01000:01000 = %+v, %v", got, err)
	}

	for _, spec := range []string{"4294967295", "99999999999", "1000:4294967295", "1000:99999999999"} {
		if _, err := lookupAccount(root, spec); err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("%s: error = %v, want out of range", spec, err)
		}
	}
}

// accountDatabase writes a passwd and group file whose entries are clearly
// distinguishable from the synthetic root fallback. The returned passwd makes
// "escapee" look like a real account.
func accountDatabase(t *testing.T, dir string) (passwd, group string) {
	t.Helper()
	passwd = filepath.Join(dir, "passwd")
	group = filepath.Join(dir, "group")
	if err := os.WriteFile(passwd,
		[]byte("root:x:0:0:outside:/outside-root:/bin/outside\nescapee:x:4242:4242::/outside-home:/bin/outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group,
		[]byte("root:x:0:\nescapee:x:4242:escapee\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return passwd, group
}

// assertOutsideDatabaseNotUsed checks that root resolved to the synthetic
// fallback entry and that the outside database's account is not visible.
func assertOutsideDatabaseNotUsed(t *testing.T, root string) {
	t.Helper()
	a, err := lookupAccount(root, "")
	if err != nil {
		t.Fatalf("root lookup: %v", err)
	}
	if a.name != "root" || a.uid != 0 || a.gid != 0 || a.home != "/root" || a.shell != "/bin/sh" {
		t.Fatalf("root resolved through the outside database: %+v", a)
	}
	if _, err := lookupAccount(root, "escapee"); err == nil ||
		!strings.Contains(err.Error(), "not found in /etc/passwd") {
		t.Fatalf("outside passwd entry visible: %v", err)
	}
	// The numeric uid must not pick up the outside entry's name/gid/home.
	a, err = lookupAccount(root, "4242")
	if err != nil {
		t.Fatalf("numeric lookup: %v", err)
	}
	if a.name != "" || a.gid != 0 || a.home != "/" {
		t.Fatalf("numeric uid resolved through the outside database: %+v", a)
	}
}

// /etc/passwd and /etc/group are workload-controlled and are opened by the
// guest init, so a symlink there must be resolved inside the workload root
// (as every other guest path is) and never in the init's namespace. The old
// plain os.Open followed an absolute link out of the root and read the host
// database.
func TestLookupAccountSymlinksStayInRoot(t *testing.T) {
	outside := t.TempDir()
	outsidePasswd, outsideGroup := accountDatabase(t, outside)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePasswd, filepath.Join(root, "etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideGroup, filepath.Join(root, "etc/group")); err != nil {
		t.Fatal(err)
	}
	// The absolute target does not exist inside the root, so the database is
	// empty and root falls back to its synthetic entry.
	assertOutsideDatabaseNotUsed(t, root)

	// An absolute link that loops back to itself inside the root fails with a
	// read error instead of silently becoming an empty database.
	loopRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(loopRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(loopRoot, "etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupAccount(loopRoot, "root"); err == nil ||
		!strings.Contains(err.Error(), "read /etc/passwd") {
		t.Fatalf("self-referential passwd symlink: %v, want a read error", err)
	}
}

// Magic links such as /proc/self/root and /proc/1/root are absolute links that
// old plain opens followed into the guest init's namespace. RESOLVE_IN_ROOT
// rewrites the target to a path inside the workload root and
// RESOLVE_NO_MAGICLINKS forbids following it there, so the outside file is
// never read.
func TestLookupAccountMagicLinkSymlinksStayInRoot(t *testing.T) {
	outside := t.TempDir()
	outsidePasswd, _ := accountDatabase(t, outside)

	targets := []string{
		"/proc/1/root/init",
		"/proc/self/root" + outsidePasswd,
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"passwd", "group"} {
				if err := os.Symlink(target, filepath.Join(root, "etc", p)); err != nil {
					t.Fatal(err)
				}
			}
			// Reading may fail (ELOOP for a magic link inside the root) or the
			// path may not exist inside the root (ENOENT, an empty database).
			// Either way the outside file must not supply an identity.
			a, err := lookupAccount(root, "")
			if err == nil {
				if a.name != "root" || a.home != "/root" || a.shell != "/bin/sh" {
					t.Fatalf("root resolved through %s: %+v", target, a)
				}
				if _, err := lookupAccount(root, "escapee"); err == nil {
					t.Fatalf("outside passwd entry visible through %s", target)
				}
			} else if !strings.Contains(err.Error(), "/etc/passwd") {
				t.Fatalf("unexpected error for %s: %v", target, err)
			}
		})
	}

	// Regular files in the workload root still parse normally.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/group"),
		[]byte("root:x:0:\nalice:x:1000:\nwheel:x:10:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := lookupAccount(root, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if a.uid != 1000 || a.gid != 1000 || a.home != "/home/alice" || a.shell != "/bin/zsh" || len(a.groups) != 2 {
		t.Fatalf("normal lookup: %+v", a)
	}
}

// A failure to read the account database must be reported as such, not as a
// missing user. Descriptor exhaustion used to surface as "user ... not found
// in /etc/passwd" even though the lookup never read the file.
func TestLookupAccountReportsFileErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "etc"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := lookupAccount(root, "root")
	if err == nil {
		t.Fatal("lookupAccount ignored an unreadable /etc/passwd")
	}
	if !strings.Contains(err.Error(), "read /etc/passwd") {
		t.Fatalf("lookupAccount error = %v, want a read error for /etc/passwd", err)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Fatalf("read failure was reported as a missing user: %v", err)
	}
}
