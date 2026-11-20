// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestWorkdirInRoot(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/tmp", "/tmp"},
		// Paths are not cleaned: the kernel resolves ".." after following
		// symlinks, which is not the same as collapsing the string.
		{"/tmp/", "/tmp/"},
		{"/tmp/../etc", "/tmp/../etc"},
		{"/tmp/link/../other", "/tmp/link/../other"},
		// A relative workdir is anchored at the root; ".." is clamped there
		// by the chroot, not by the string.
		{"tmp", "/tmp"},
		{"tmp/", "/tmp/"},
		{"./tmp", "/./tmp"},
		{"a/../tmp", "/a/../tmp"},
		{"../etc", "/../etc"},
		{"../../../etc", "/../../../etc"},
		{"..", "/.."},
	} {
		if got := workdirInRoot(tc.dir); got != tc.want {
			t.Errorf("workdirInRoot(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}

// ".." after a symlink must be resolved by the kernel. Lexical cleaning sent
// /tmp/devlink/../other to /tmp/other instead of the symlink target's parent.
func TestWorkdirResolvesDotDotAfterSymlink(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"home/dev", "home/other", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/home/dev", filepath.Join(root, "tmp/devlink")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRoot(root, "/tmp/devlink/../other")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/other" {
		t.Fatalf("resolved workdir = %q, want /home/other", got)
	}

	// Starting must accept the kernel-resolved directory even though it does
	// not exist when the path is collapsed lexically.
	g := testGuest(t)
	g.root = root
	_, err = g.startProc(procSpec{argv: []string{"/bin/sh"}, dir: "/tmp/devlink/../other"}, nil)
	if err == nil {
		t.Fatal("starting a missing executable succeeded")
	}
	if strings.Contains(err.Error(), "chdir") {
		t.Fatalf("kernel-faithful workdir was rejected: %v", err)
	}
}

// A relative workdir must be resolved inside the workload root before it is
// validated or passed to os.StartProcess; the guest init's cwd after chroot is
// outside the root, so "tmp" used to mean the initramfs /tmp.
func TestStartProcNormalizesRelativeWorkdir(t *testing.T) {
	g := testGuest(t)
	_, err := g.startProc(procSpec{argv: []string{"/bin/sh"}, dir: "relative/dir"}, nil)
	if err == nil {
		t.Fatal("startProc accepted a missing relative workdir")
	}
	if want := "chdir /relative/dir: no such file or directory"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}

	// ".." is clamped at the root instead of escaping to the guest initramfs.
	// The temp root has /etc, so validation of "../../etc" must pass and the
	// failure must come from starting the (missing) executable.
	_, err = g.startProc(procSpec{argv: []string{"/does/not/exist"}, dir: "../../etc"}, nil)
	if err == nil {
		t.Fatal("starting a missing executable unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "chdir") {
		t.Fatalf("dot-dot workdir was not normalized inside the root: %v", err)
	}
}

// TestCheckDirAccessNamesInaccessibleWorkdir verifies that a workdir the
// target account cannot search is reported as such, instead of surfacing from
// the child as "fork/exec <program>: permission denied" and blaming the
// command. The owner and group cases must stay allowed.
func TestCheckDirAccessNamesInaccessibleWorkdir(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "home/dev")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}

	outsider := &account{uid: st.Uid + 1, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}
	err = checkDirAccess(root, "/home/dev", outsider)
	if err == nil {
		t.Fatal("inaccessible workdir was accepted")
	}
	if want := "chdir /home/dev: permission denied"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}

	owner := &account{uid: st.Uid, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}
	if err := checkDirAccess(root, "/home/dev", owner); err != nil {
		t.Fatalf("owner was denied the workdir: %v", err)
	}
	group := &account{uid: st.Uid + 1, gid: st.Gid, groups: []uint32{st.Gid}}
	if err := checkDirAccess(root, "/home/dev", group); err != nil {
		t.Fatalf("group member was denied the workdir: %v", err)
	}
	rootUser := &account{uid: 0}
	if err := checkDirAccess(root, "/home/dev", rootUser); err != nil {
		t.Fatalf("root was denied the workdir: %v", err)
	}
}

// A workdir reached through a symlink must be checked along the resolved
// path. The symlink target can be searchable while its real parent is not, so
// a lexical walk passed and the child failed with a permission error blamed on
// the program.
func TestCheckDirAccessResolvesSymlinkedWorkdir(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "private")
	if err := os.MkdirAll(filepath.Join(private, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The target is searchable for everyone, but reaching it through
	// /private is not.
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/private/sub", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}
	outsider := &account{uid: st.Uid + 1, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}

	// The target itself (what the old lexical check saw) is accessible.
	target, err := statInRoot(root, "/link")
	if err != nil || !target.IsDir() {
		t.Fatalf("symlink target: %v, %v", target, err)
	}
	if !canSearchDir(target, outsider) {
		t.Fatal("test setup: symlink target is not searchable")
	}

	err = checkDirAccess(root, "/link", outsider)
	if err == nil {
		t.Fatal("symlinked workdir through an unsearchable directory was accepted")
	}
	if want := "chdir /link: permission denied for uid"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

// A ".." after an unsearchable directory must not hide that directory from the
// workdir preflight. The kernel searches /locked before it applies "..", so
// chdir fails there even though the canonical workdir (what the old check
// walked) is accessible. Both the literal and the symlinked spelling must name
// the workdir instead of failing later as "start <program>: permission denied".
func TestCheckDirAccessChecksComponentsRemovedByDotDot(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "tmp", "w4")
	if err := os.MkdirAll(filepath.Join(base, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "locked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/w4/locked", filepath.Join(base, "lockedlnk")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}
	outsider := &account{uid: st.Uid + 1, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}

	// The bug's premise: the canonical workdir no longer contains "locked".
	resolved, err := resolveInRoot(root, "/tmp/w4/locked/../real")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "/tmp/w4/real" {
		t.Fatalf("resolved workdir = %q, want /tmp/w4/real", resolved)
	}

	for _, dir := range []string{"/tmp/w4/locked/../real", "/tmp/w4/lockedlnk/../real"} {
		err := checkDirAccess(root, dir, outsider)
		if err == nil {
			t.Fatalf("checkDirAccess(%q) accepted a workdir behind an unsearchable component", dir)
		}
		if want := "chdir " + dir + ": permission denied for uid " + strconv.Itoa(int(outsider.uid)); !strings.Contains(err.Error(), want) {
			t.Fatalf("checkDirAccess(%q) error = %q, want it to contain %q", dir, err, want)
		}
	}

	// The same workdir must still start far enough to be reported as a chdir
	// failure (126) rather than as a failure of the executable.
	g := testGuest(t)
	g.root = root
	_, err = g.startProc(procSpec{
		argv: []string{"/bin/sh"},
		dir:  "/tmp/w4/locked/../real",
		user: strconv.FormatUint(uint64(outsider.uid), 10),
	}, nil)
	if err == nil {
		t.Fatal("startProc accepted a workdir behind an unsearchable component")
	}
	if want := "chdir /tmp/w4/locked/../real: permission denied for uid"; !strings.Contains(err.Error(), want) {
		t.Fatalf("startProc error = %q, want it to contain %q", err, want)
	}
	if code := startExitCode(err); code != 126 {
		t.Fatalf("startProc exit code = %d, want 126", code)
	}
}

func TestProcEnvNoProxy(t *testing.T) {
	acct := &account{name: "root", home: "/root", shell: "/bin/sh"}
	for _, tc := range []struct {
		name string
		g    *Guest
		base []string
		want [2]string // NO_PROXY, no_proxy
	}{
		{"no names", &Guest{}, nil, [2]string{"blip", "blip"}},
		{"kubernetes", &Guest{kubeNamespace: "sandbox"}, nil, [2]string{"blip,kube-apiserver", "blip,kube-apiserver"}},
		{"endpoints", &Guest{endpoints: []string{"api.default", "db.default"}}, nil, [2]string{"blip,api.default,db.default", "blip,api.default,db.default"}},
		{"all", &Guest{kubeNamespace: "sandbox", endpoints: []string{"api.default"}}, nil, [2]string{"blip,kube-apiserver,api.default", "blip,kube-apiserver,api.default"}},
		{"claim override", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=corp.example"}, [2]string{"blip,kube-apiserver,corp.example", "blip,kube-apiserver,corp.example"}},
		{"both spellings merge", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=claim.example", "no_proxy=extra.example"}, [2]string{"blip,kube-apiserver,claim.example,extra.example", "blip,kube-apiserver,claim.example,extra.example"}},
		{"duplicates and spaces", &Guest{kubeNamespace: "sandbox", endpoints: []string{"api.default"}}, []string{"NO_PROXY= blip, ,corp.example ,api.default"}, [2]string{"blip,kube-apiserver,api.default,corp.example", "blip,kube-apiserver,api.default,corp.example"}},
		{"explicit empty keeps guest names", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=", "no_proxy="}, [2]string{"blip,kube-apiserver", "blip,kube-apiserver"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.g.procEnv(acct, tc.base)
			for i, key := range []string{"NO_PROXY", "no_proxy"} {
				var vals []string
				for _, entry := range env {
					if v, ok := strings.CutPrefix(entry, key+"="); ok {
						vals = append(vals, v)
					}
				}
				if len(vals) != 1 || vals[0] != tc.want[i] {
					t.Fatalf("%s entries = %v, want %q", key, vals, tc.want[i])
				}
			}
		})
	}
}
