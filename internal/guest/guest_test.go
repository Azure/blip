package guest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
)

// The shutdown path kills every process in the work cgroup, unmounts and
// powers off. Outside PID 1 all of that must be a no-op: these tests run on
// developer machines (see AGENTS.md).
func TestShutdownIsNoOpOutsidePID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("running as PID 1")
	}
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()

	dir := t.TempDir()
	cg := filepath.Join(dir, "cgroup")
	root := filepath.Join(dir, "root")
	for _, d := range []string{cg, root, filepath.Join(root, "data")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	procs := strconv.Itoa(child.Process.Pid) + "\n" + strconv.Itoa(os.Getpid()) + "\n"
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(procs), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &Guest{
		root:     root,
		cgroup:   cg,
		cgroupFD: -1,
		rootDev:  "/dev/null",
		mounts:   map[string]*mount{"a": {id: "a", path: "/data", target: filepath.Join(root, "data")}},
		sessions: map[string]*session{},
		claim:    &wire.Claim{ID: "root"},
	}

	start := time.Now()
	g.shutdown()
	stopWork(cg, time.Second)
	powerOff()
	if err := unmount(root, 1); err != nil {
		t.Fatalf("unmount outside PID 1: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown waited %v; the grace period must not apply outside PID 1", d)
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated child was killed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(cg, "cgroup.kill")); len(b) != 0 {
		t.Fatalf("cgroup.kill was written")
	}
}

func TestClaimAndMountRefuseOutsidePID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("running as PID 1")
	}
	g := &Guest{root: t.TempDir(), cgroupFD: -1, mounts: map[string]*mount{}, sessions: map[string]*session{}}
	if err := g.doClaim(wire.Claim{ID: "x", Serial: "x"}); err != errNotInit {
		t.Fatalf("claim: %v", err)
	}
	g.claim = &wire.Claim{ID: "x"}
	if err := g.doMount(wire.Mount{ID: "m", Serial: "m", Path: "/data"}); err != errNotInit {
		t.Fatalf("mount: %v", err)
	}
}

func TestRing(t *testing.T) {
	r := ring{max: 10}
	r.add(wire.TStdout, []byte("aaaa"))
	r.add(wire.TStderr, []byte("bbbb"))
	frames, next, gap := r.since(0)
	if len(frames) != 2 || next != 2 || gap {
		t.Fatalf("since(0) = %d frames, next %d, gap %v", len(frames), next, gap)
	}
	r.add(wire.TStdout, []byte("cccc")) // 12 bytes > 10: drops "aaaa"
	frames, next, gap = r.since(0)
	if len(frames) != 2 || string(frames[0].data) != "bbbb" || frames[0].t != wire.TStderr || next != 3 || !gap {
		t.Fatalf("after overflow: %v next %d gap %v", frames, next, gap)
	}
	frames, _, gap = r.since(2)
	if len(frames) != 1 || gap {
		t.Fatalf("since(2): %v gap %v", frames, gap)
	}
	frames, _, gap = r.since(3)
	if len(frames) != 0 || gap {
		t.Fatalf("since(3): %v gap %v", frames, gap)
	}
	big := ring{max: 4}
	big.add(wire.TStdout, []byte("0123456789")) // a single oversized frame is kept
	if frames, _, _ := big.since(0); len(frames) != 1 {
		t.Fatalf("oversized frame dropped")
	}
	r.clear()

	frames, next, gap = r.since(0)
	if len(frames) != 0 || next != 3 || !gap {
		t.Fatalf("after clear: %v next %d gap %v", frames, next, gap)
	}
}

// Frames a client has not received yet must survive ring pressure. Without
// this, a command producing output faster than a client could receive would
// deliver a silently truncated stream.
func TestRingPinned(t *testing.T) {
	r := ring{max: 10}
	r.addPinned(wire.TStdout, []byte("aaaa"), 0)
	r.addPinned(wire.TStdout, []byte("bbbb"), 0)
	r.addPinned(wire.TStdout, []byte("cccc"), 0)
	frames, _, gap := r.since(0)
	if gap || len(frames) != 3 {
		t.Fatalf("pinned output dropped: %d frames, gap %v", len(frames), gap)
	}
	// The client caught up; only now may old frames be reclaimed.
	r.trim(r.next())
	if r.size > r.max {
		t.Fatalf("ring size %d after trim, max %d", r.size, r.max)
	}
	frames, _, gap = r.since(0)
	if !gap || len(frames) == 0 {
		t.Fatalf("caught-up frames were not reclaimed: %d frames, gap %v", len(frames), gap)
	}
}

func testSession(id string) *session {
	s := &session{g: &Guest{sessions: map[string]*session{}}, id: id, out: ring{max: ringSize}}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// A command that fails before any client attaches must keep its stderr for
// the caller that attaches later.
func TestFailedSessionKeepsOutputWithoutClient(t *testing.T) {
	g := &Guest{sessions: map[string]*session{}}
	s := g.failedSession("exec-1", []string{"missing"}, errors.New("exec: missing: no such file"))
	if s.attached {
		t.Fatal("session marked as attached")
	}
	if frames, _, _ := s.out.since(0); len(frames) == 0 {
		t.Fatal("no output recorded")
	}
	if got := s.tail(exitOutputMax); !strings.Contains(got, "no such file") {
		t.Fatalf("stderr lost before a client attached: %q", got)
	}
}

func TestExecProcSpecInheritsBlipDefaults(t *testing.T) {
	claim := &wire.Claim{WorkingDir: "/work", User: "dev"}
	spec := execProcSpec(claim, wire.Open{Argv: []string{"pwd"}})
	if spec.dir != "/work" || spec.user != "dev" || len(spec.argv) != 1 || spec.argv[0] != "pwd" {
		t.Fatalf("defaults not inherited: %+v", spec)
	}
	spec = execProcSpec(claim, wire.Open{Argv: []string{"id"}, WorkingDir: "/tmp", User: "root"})
	if spec.dir != "/tmp" || spec.user != "root" {
		t.Fatalf("explicit values not used: %+v", spec)
	}
}

func TestGuestHostnameFitsKernelLimit(t *testing.T) {
	if got := guestHostname("alice.default"); got != "alice.default" {
		t.Fatalf("short hostname = %q", got)
	}
	long := strings.Repeat("a", 70)
	got := guestHostname(long)
	if len(got) > 64 || len(got) == 0 {
		t.Fatalf("long hostname = %q (%d bytes)", got, len(got))
	}
	if !strings.HasPrefix(long, got) {
		t.Fatalf("long hostname %q is not a prefix of %q", got, long)
	}
}

func TestHostsFile(t *testing.T) {
	got := hostsFile("alice.default", "", nil)
	for _, want := range []string{
		"127.0.0.1 localhost\n",
		"127.0.1.1 alice.default\n",
		"::1 localhost",
		"127.0.2.1 blip\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("hostsFile = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "127.0.2.2") {
		t.Fatalf("hostsFile without names wrote a proxy line: %q", got)
	}
	if got := hostsFile("alice.default", "sandbox", nil); !strings.Contains(got, "127.0.2.2 kube-apiserver\n") {
		t.Fatalf("hostsFile with Kubernetes = %q", got)
	}
	if got := hostsFile("alice.default", "", []string{"api.default", "db.default"}); !strings.Contains(got, "127.0.2.2 api.default db.default\n") {
		t.Fatalf("hostsFile with endpoints = %q", got)
	}
	if got := hostsFile("alice.default", "sandbox", []string{"api.default"}); !strings.Contains(got, "127.0.2.2 kube-apiserver api.default\n") {
		t.Fatalf("hostsFile with Kubernetes and endpoints = %q", got)
	}
	if got := hostsFile("bad\nname", "", nil); strings.Contains(got, "bad") {
		t.Fatalf("hostsFile accepted a host name with whitespace: %q", got)
	}
}

// A finished command must leave the session list; a long-lived blip runs one
// session per exec and would otherwise grow without bound.
func TestFinishedSessionIsForgotten(t *testing.T) {
	g := &Guest{sessions: map[string]*session{}}
	s := &session{g: g, id: "exec-1", out: ring{max: ringSize}}
	s.cond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.inMu)
	g.sessions[s.id] = s
	s.finish(wire.Exit{Code: 0})
	g.mu.Lock()
	_, kept := g.sessions[s.id]
	g.mu.Unlock()
	if kept {
		t.Fatal("finished session is still listed")
	}
}

// Once a client has attached and detached, the replay output is dropped.
func TestSessionReplayDroppedAfterAttachAndDetach(t *testing.T) {
	s := testSession("exec-2")
	s.out.add(wire.TStderr, []byte("boom\n"))
	s.finish(wire.Exit{Code: 1})
	if got := s.tail(exitOutputMax); got != "boom\n" {
		t.Fatalf("output lost before a client attached: %q", got)
	}

	s.mu.Lock()
	s.clients++
	s.attached = true
	s.mu.Unlock()
	s.mu.Lock()
	s.clients--
	s.clearReplayLocked()
	s.mu.Unlock()
	if got := s.tail(exitOutputMax); got != "" {
		t.Fatalf("output kept after attach and detach: %q", got)
	}
}

func TestDeliveryDeadline(t *testing.T) {
	t0 := time.Now()
	// No client at entry: the unattached timeout applies.
	d := newDeliveryDeadline(time.Second, 10*time.Second, 0, t0)
	if want := t0.Add(time.Second); !d.deadline.Equal(want) {
		t.Fatalf("initial deadline = %v, want %v", d.deadline, want)
	}
	if d.expired(t0.Add(time.Second-time.Millisecond), 0, false) {
		t.Fatal("expired before the unattached timeout")
	}
	if !d.expired(t0.Add(time.Second), 0, false) {
		t.Fatal("did not expire at the unattached timeout")
	}

	// The first client to attach switches to the attached timeout, once.
	d = newDeliveryDeadline(time.Second, 10*time.Second, 0, t0)
	attach := t0.Add(500 * time.Millisecond)
	if d.expired(attach, 1, false) {
		t.Fatal("expired as the first client attached")
	}
	if want := attach.Add(10 * time.Second); !d.deadline.Equal(want) {
		t.Fatalf("deadline after attach = %v, want %v", d.deadline, want)
	}
	// A client that never consumes cannot extend it again.
	if d.expired(attach.Add(5*time.Second), 1, false) {
		t.Fatal("expired while the attached timeout was still running")
	}
	if want := attach.Add(10 * time.Second); !d.deadline.Equal(want) {
		t.Fatalf("deadline extended to %v, want %v", d.deadline, want)
	}
	if !d.expired(attach.Add(10*time.Second), 1, false) {
		t.Fatal("did not expire with a client that never read")
	}

	// A client already connected at entry uses the attached timeout.
	d = newDeliveryDeadline(time.Second, 10*time.Second, 1, t0)
	if want := t0.Add(10 * time.Second); !d.deadline.Equal(want) {
		t.Fatalf("deadline with a client at entry = %v, want %v", d.deadline, want)
	}
	// Delivery ends the wait regardless of the deadline.
	if !d.expired(t0, 1, true) {
		t.Fatal("did not stop after delivery")
	}
}

// waitDelivered must return when the client neither reads output nor
// disconnects, instead of waiting for the runtime's hard kill.
func TestWaitDeliveredStalledClient(t *testing.T) {
	s := testSession("exec-3")
	s.mu.Lock()
	s.clients, s.attached = 1, true
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.waitDelivered(time.Second, 100*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitDelivered did not return with a stalled client")
	}
}

// waitDelivered also returns when no client ever attaches.
func TestWaitDeliveredNoClient(t *testing.T) {
	s := testSession("exec-4")
	start := time.Now()
	s.waitDelivered(100*time.Millisecond, time.Second)
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("waitDelivered without a client took %v", d)
	}
}

func TestCheckMountPath(t *testing.T) {
	existing := []string{"/data"}
	for p, ok := range map[string]bool{
		"/work":              true,
		"/mnt/a/b":           true,
		"/datax":             true,
		"/":                  false,
		"relative":           false,
		"/a/../b":            false,
		"/data":              false,
		"/data/sub":          false,
		"/proc/x":            false,
		"/dev":               false,
		"/run":               false,
		"/run/blip":          false,
		"/run/blip/metadata": false,
		"/run/blip-collect":  false,
		// Collect's own generated mounts below its reserved root are
		// accepted; deeper or user paths are not.
		"/run/blip-collect/data":                true,
		"/run/blip-collect/data/x":              false,
		"/run/work":                             true,
		"/run/blip-collector":                   true,
		"/" + strings.Repeat("a", 300):          false,
		"/" + strings.Repeat("a", 260):          false,
		"/" + strings.Repeat("a", 255):          true,
		"/" + strings.Repeat("abcdefghij/", 20): true,
	} {
		err := checkMountPath(p, existing)
		if (err == nil) != ok {
			t.Errorf("checkMountPath(%q) = %v, want ok=%v", p, err, ok)
		}
	}
	if err := checkMountPath("/", nil); err == nil {
		t.Errorf("/ accepted")
	}
	if err := checkMountPath("/srv", []string{"/srv/inner"}); err == nil {
		t.Errorf("parent of existing mount accepted")
	}
}

// TestCheckMountPathResolvesAliases reproduces two states mounted at different
// written paths that the guest resolves to one directory. The written path
// check must already see the conflict; doMount additionally checks the actual
// target for image-specific aliases.
func TestCheckMountPathResolvesAliases(t *testing.T) {
	for _, tc := range []struct {
		name, existing, added string
	}{
		{"bin", "/bin/x", "/usr/bin/x"},
		{"sbin", "/sbin/x", "/usr/sbin/x"},
		{"lib", "/lib/x", "/usr/lib/x"},
		{"mail spool", "/var/spool/mail/x", "/var/mail/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, paths := range [][2]string{{tc.existing, tc.added}, {tc.added, tc.existing}} {
				if err := checkMountPath(paths[0], []string{paths[1]}); err == nil {
					t.Errorf("checkMountPath(%q) accepted alias of existing %q", paths[0], paths[1])
				}
			}
		})
	}
}

// TestCheckMountTargetUsesResolvedDirectory covers an image-specific symlink
// the offline alias list cannot know: the guest must compare the directories
// it actually opened, not the written paths.
func TestCheckMountTargetUsesResolvedDirectory(t *testing.T) {
	root := t.TempDir()
	existing := []*mount{{
		id:     "lower",
		path:   "/var/spool/mail/x",
		target: filepath.Join(root, "var/mail/x"),
	}}
	// The same resolved directory through another spelling is a duplicate.
	err := checkMountTarget(root, "/var/mail/x", filepath.Join(root, "var/mail/x"), existing)
	if err == nil || !strings.Contains(err.Error(), "resolves to /var/mail/x") ||
		!strings.Contains(err.Error(), "overlaps mount lower at /var/spool/mail/x") {
		t.Fatalf("same target: %v", err)
	}
	// Nesting the other way is an overlap too.
	err = checkMountTarget(root, "/var/mail/x/sub", filepath.Join(root, "var/mail/x/sub"), existing)
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("nested target: %v", err)
	}
	// A sibling stays legal.
	if err := checkMountTarget(root, "/var/mail/y", filepath.Join(root, "var/mail/y"), existing); err != nil {
		t.Fatalf("sibling target rejected: %v", err)
	}
}

func TestMkdirInRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "run"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var/spool"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var/mail"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "proc"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644))
	must(os.Symlink("/run", filepath.Join(root, "var/run")))
	must(os.Symlink("../mail", filepath.Join(root, "var/spool/mail")))
	must(os.Symlink("/etc/hosts", filepath.Join(root, "hosts-link")))
	must(os.Symlink("/proc", filepath.Join(root, "proc-link")))
	must(os.Symlink(outside, filepath.Join(root, "escape")))

	fd, err := mkdirInRoot(root, "/a/b/c", false)
	must(err)
	p, _ := fdPath(fd)
	syscall.Close(fd)
	if p != filepath.Join(root, "a/b/c") {
		t.Fatalf("created %s", p)
	}
	// Guest-owned directories are still created without following symlinks;
	// only user mount points use Linux mount semantics below.
	if _, err := mkdirInRoot(root, "/var/run/x", false); err == nil {
		t.Fatalf("symlink component accepted without follow")
	}
	if _, err := mkdirInRoot(root, "/var/spool/mail/x", false); err == nil ||
		!strings.Contains(err.Error(), "/var/spool/mail is a symlink or not a directory") {
		t.Fatalf("mail spool symlink: %v", err)
	}
	if _, err := mkdirInRoot(root, "/escape/x", false); err == nil {
		t.Fatalf("escaping symlink accepted without follow")
	}
	fd, err = mkdirInRoot(root, "/var/run/secrets/sa", true)
	must(err)
	p, _ = fdPath(fd)
	syscall.Close(fd)
	if p != filepath.Join(root, "run/secrets/sa") {
		t.Fatalf("followed symlink to %s", p)
	}
	// A user mount point may follow a directory symlink inside the root, as
	// Linux mount does for /usr/share/doc/gcc-13 and /var/spool/mail.
	fd, err = mkdirInRoot(root, "/var/spool/mail/x", true)
	must(err)
	p, _ = fdPath(fd)
	syscall.Close(fd)
	if p != filepath.Join(root, "var/mail/x") {
		t.Fatalf("followed mail spool symlink to %s", p)
	}
	if err := validateMountTarget(root, "/var/spool/mail/x"); err != nil {
		t.Fatalf("directory symlink target rejected: %v", err)
	}
	// A symlink to a regular file is still not a mount point.
	if _, err := mkdirInRoot(root, "/hosts-link", true); err == nil ||
		!strings.Contains(err.Error(), "/hosts-link is a symlink or not a directory") {
		t.Fatalf("file symlink: %v", err)
	}
	// A symlink that resolves to a guest-reserved directory is rejected even
	// though its written path looks ordinary.
	if err := validateMountTarget(root, "/proc-link"); err == nil ||
		!strings.Contains(err.Error(), "reserves") {
		t.Fatalf("reserved symlink target: %v", err)
	}
	// The absolute symlink resolves inside the root, where its target does
	// not exist: either an error or a directory inside the root is fine.
	if fd, err = mkdirInRoot(root, "/escape/y", true); err == nil {
		p, _ = fdPath(fd)
		syscall.Close(fd)
		if !strings.HasPrefix(p, root+"/") {
			t.Fatalf("absolute symlink escaped the root: %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "y")); err == nil {
		t.Fatalf("directory created outside the root")
	}
}

// TestEnsureRunLock reproduces the base image's dangling /var/lock: /run is a
// fresh tmpfs with no /run/lock, so a /var/lock mount point cannot be created
// until setup restores the target directory.
func TestEnsureRunLock(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "run"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var"), 0o755))
	must(os.Symlink("/run/lock", filepath.Join(root, "var/lock")))

	if _, err := mkdirInRoot(root, "/var/lock/x", true); err == nil {
		t.Fatal("mount point created through a dangling /var/lock")
	}
	must(ensureRunLock(root))
	info, err := os.Stat(filepath.Join(root, "run/lock"))
	must(err)
	if !info.IsDir() || info.Mode().Perm() != 0o755 {
		t.Fatalf("/run/lock is %v, want a 0755 directory", info.Mode())
	}
	fd, err := mkdirInRoot(root, "/var/lock/x", true)
	must(err)
	p, err := fdPath(fd)
	syscall.Close(fd)
	must(err)
	if p != filepath.Join(root, "run/lock/x") {
		t.Fatalf("mount point resolved to %s", p)
	}
	// Setup may run on a root that already has the directory.
	must(ensureRunLock(root))
}

func TestMountPointInRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "usr/share/doc/gcc-13-x86-64-linux-gnu"), 0o755))
	must(os.Symlink("gcc-13-x86-64-linux-gnu", filepath.Join(root, "usr/share/doc/gcc-13")))
	must(os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644))
	must(os.Symlink("hosts", filepath.Join(root, "etc/hosts-link")))
	must(os.MkdirAll(filepath.Join(root, "run/blip"), 0o755))
	must(os.Symlink("/run/blip", filepath.Join(root, "reserved-link")))
	must(os.MkdirAll(filepath.Join(root, "run/blip-collect"), 0o755))
	must(os.Symlink(outside, filepath.Join(root, "escape")))

	// The dev image's package documentation alias resolves to a directory
	// inside the root, so the mount point is created in the real directory.
	fd, target, err := mountPointInRoot(root, "/usr/share/doc/gcc-13/probe")
	must(err)
	syscall.Close(fd)
	if target != filepath.Join(root, "usr/share/doc/gcc-13-x86-64-linux-gnu/probe") {
		t.Fatalf("mount point resolved to %s", target)
	}
	// Collect's generated mounts are allowed below its reserved root.
	fd, target, err = mountPointInRoot(root, "/run/blip-collect/data")
	must(err)
	syscall.Close(fd)
	if target != filepath.Join(root, "run/blip-collect/data") {
		t.Fatalf("collect mount point resolved to %s", target)
	}
	// A symlink to a regular file is not a directory.
	if _, _, err := mountPointInRoot(root, "/etc/hosts-link/x"); err == nil ||
		!strings.Contains(err.Error(), "is a symlink or not a directory") {
		t.Fatalf("file symlink mount point: %v", err)
	}
	// A symlink that resolves to a guest-reserved directory is rejected.
	if _, _, err := mountPointInRoot(root, "/reserved-link/x"); err == nil ||
		!strings.Contains(err.Error(), "reserves") {
		t.Fatalf("reserved symlink mount point: %v", err)
	}
	// An absolute symlink resolves inside the root and never creates the
	// directory outside it.
	if fd, target, err = mountPointInRoot(root, "/escape/y"); err == nil {
		syscall.Close(fd)
		if !strings.HasPrefix(target, root+"/") {
			t.Fatalf("absolute symlink escaped the root: %s", target)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "y")); err == nil {
		t.Fatalf("directory created outside the root")
	}
}

func TestLookupAccount(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/group"), []byte("root:x:0:\nalice:x:1000:\nwheel:x:10:alice,bob\ndocker:x:999:alice\n"), 0o644)

	a, err := lookupAccount(root, "")
	if err != nil || a.uid != 0 || a.gid != 0 || a.shell != "/bin/bash" || a.home != "/root" {
		t.Fatalf("root: %+v %v", a, err)
	}
	a, err = lookupAccount(root, "alice")
	if err != nil || a.uid != 1000 || a.gid != 1000 || a.shell != "/bin/zsh" || len(a.groups) != 3 {
		t.Fatalf("alice: %+v %v", a, err)
	}
	a, err = lookupAccount(root, "1000:wheel")
	if err != nil || a.uid != 1000 || a.gid != 10 || a.home != "/home/alice" {
		t.Fatalf("1000:wheel: %+v %v", a, err)
	}
	a, err = lookupAccount(root, "4242:4243")
	if err != nil || a.uid != 4242 || a.gid != 4243 || a.home != "/" {
		t.Fatalf("numeric: %+v %v", a, err)
	}
	if _, err := lookupAccount(root, "nobody"); err == nil {
		t.Fatalf("unknown user accepted")
	}
	if _, err := lookupAccount(t.TempDir(), "root"); err != nil {
		t.Fatalf("root without /etc/passwd: %v", err)
	}
}

func TestMergeEnv(t *testing.T) {
	got := strings.Join(mergeEnv([]string{"A=1", "B=2"}, []string{"B=3", "C=4"}, []string{"A=5"}), " ")
	if got != "A=5 B=3 C=4" {
		t.Fatalf("mergeEnv = %s", got)
	}
}

func TestParseSignal(t *testing.T) {
	for _, n := range []string{"HUP", "SIGHUP"} {
		if s, err := parseSignal(n); err != nil || s != syscall.SIGHUP {
			t.Fatalf("%s: %v %v", n, s, err)
		}
	}
	if _, err := parseSignal("NOPE"); err == nil {
		t.Fatalf("unknown signal accepted")
	}
	if signalName(syscall.SIGTERM) != "TERM" {
		t.Fatalf("signalName(TERM) = %s", signalName(syscall.SIGTERM))
	}
}
