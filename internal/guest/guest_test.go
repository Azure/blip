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
		"/run/work":          true,
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
	must(os.MkdirAll(filepath.Join(root, "mail"), 0o755))
	must(os.Symlink("/run", filepath.Join(root, "var/run")))
	must(os.Symlink("../mail", filepath.Join(root, "var/spool/mail")))
	must(os.Symlink(outside, filepath.Join(root, "escape")))

	fd, err := mkdirInRoot(root, "/a/b/c", false)
	must(err)
	p, _ := fdPath(fd)
	syscall.Close(fd)
	if p != filepath.Join(root, "a/b/c") {
		t.Fatalf("created %s", p)
	}
	if _, err := mkdirInRoot(root, "/var/run/x", false); err == nil {
		t.Fatalf("symlink component accepted without follow")
	}
	// The standard base image's /var/spool/mail -> ../mail is the same
	// class of directory symlink, so the guest rejects a mount below it.
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
