package guest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/wire"
)

// testRoot creates a minimal root filesystem with an /etc/passwd that knows
// only root, plus a regular file for workdir-not-a-directory checks.
func testRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/group"), []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "not-a-dir"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func testGuest(t *testing.T) *Guest {
	t.Helper()
	return &Guest{
		root:     testRoot(t),
		cgroupFD: -1,
		reaper:   newReaper(),
		mounts:   map[string]*mount{},
		frozen:   map[string]*frozenFS{},
		sessions: map[string]*session{},
		openIDs:  map[string]*openRecord{},
	}
}

// A process that cannot start must come back as an error from startSession.
// It must never panic and must not leave a half-initialized session behind.
func TestStartSessionStartFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec procSpec
		want string
	}{
		{
			name: "missing executable",
			spec: procSpec{argv: []string{"blip-test-no-such-binary"}},
			want: "blip-test-no-such-binary: command not found",
		},
		{
			name: "missing absolute executable",
			spec: procSpec{argv: []string{"/does/not/exist"}},
			// chroot itself may fail first when the test is not root, so
			// only require an error here.
		},
		{
			name: "missing working directory",
			spec: procSpec{argv: []string{"/bin/sh"}, dir: "/no/such/dir"},
			want: "chdir /no/such/dir: no such file or directory",
		},
		{
			name: "relative working directory",
			spec: procSpec{argv: []string{"/bin/sh"}, dir: "relative/dir"},
			// Relative workdirs are anchored at the root before validation.
			want: "chdir /relative/dir: no such file or directory",
		},
		{
			name: "working directory is a file",
			spec: procSpec{argv: []string{"/bin/sh"}, dir: "/not-a-dir"},
			want: "chdir /not-a-dir: not a directory",
		},
		{
			name: "unknown user",
			spec: procSpec{argv: []string{"/bin/sh"}, user: "no-such-user-xyz"},
			want: `user "no-such-user-xyz" not found in /etc/passwd`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := testGuest(t)
			s, err := g.startSession("exec-1", tc.spec, nil, true)
			if err == nil {
				if s != nil {
					s.closeInput()
				}
				t.Fatalf("startSession(%v, dir %q, user %q) succeeded", tc.spec.argv, tc.spec.dir, tc.spec.user)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
			g.mu.Lock()
			_, registered := g.sessions["exec-1"]
			g.mu.Unlock()
			if registered {
				t.Fatal("failed start registered a session")
			}
		})
	}
}

// attachAndRead attaches a client to s and returns its output and exit status.
// It fails the test if serve panics (which would kill PID 1 in a real guest) or
// does not finish.
func attachAndRead(t *testing.T, s *session) (string, wire.Exit) {
	t.Helper()
	srv, cli := net.Pipe()
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))

	serveDone := make(chan any, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				serveDone <- fmt.Errorf("session serve panicked: %v", r)
				return
			}
			serveDone <- nil
		}()
		s.serve(wire.NewConn(srv), srv, false)
	}()

	c := wire.NewConn(cli)
	var out strings.Builder
	for {
		typ, payload, err := c.Read()
		if err != nil {
			select {
			case serr := <-serveDone:
				if serr != nil {
					t.Fatal(serr)
				}
			default:
			}
			t.Fatalf("read from failed session: %v (output %q)", err, out.String())
		}
		switch typ {
		case wire.TStdout, wire.TStderr:
			out.Write(payload)
		case wire.TExited:
			var ex wire.Exit
			if err := wire.Decode(payload, &ex); err != nil {
				t.Fatalf("decode exit: %v", err)
			}
			select {
			case err := <-serveDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("session serve did not return after the exit status")
			}
			return out.String(), ex
		}
	}
}

// The root directory always exists; validating it must not reject it. It used
// to be passed to openat2 as an empty path, which returns ENOENT.
func TestStartSessionRootWorkingDirectoryNotRejected(t *testing.T) {
	g := testGuest(t)
	_, err := g.startSession("exec-1", procSpec{argv: []string{"/bin/sh"}, dir: "/"}, nil, true)
	if err == nil {
		t.Fatal("starting a missing executable unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "chdir") {
		t.Fatalf("workdir / was rejected: %v", err)
	}
}

// A primary command that cannot start must produce a normal failed session:
// the error on stderr, exit status 127, and a clean shutdown. Previously the
// failed session had a nil pumps channel and attaching panicked, which killed
// guest init and turned a state-backed blip into SaveFailed.
func TestFailedPrimaryCommandDoesNotPanic(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("running as PID 1")
	}
	for _, tc := range []struct {
		name string
		spec procSpec
		want string
		code int
	}{
		{
			name: "missing executable",
			spec: procSpec{argv: []string{"blip-test-no-such-binary"}},
			want: "command not found",
			code: 127,
		},
		{
			name: "missing absolute executable",
			spec: procSpec{argv: []string{"/does/not/exist"}},
			// chroot may fail first when the test is not root (EPERM, 126).
			// In a guest this is ENOENT and 127.
		},
		{
			name: "missing working directory",
			spec: procSpec{argv: []string{"/bin/sh"}, dir: "/no/such/dir"},
			want: "chdir /no/such/dir: no such file or directory",
			code: 126,
		},
		{
			name: "unknown user",
			spec: procSpec{argv: []string{"/bin/sh"}, user: "no-such-user-xyz"},
			want: `user "no-such-user-xyz" not found in /etc/passwd`,
			code: 126,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := testGuest(t)
			g.claim = &wire.Claim{
				ID:         "root",
				Command:    tc.spec.argv,
				WorkingDir: tc.spec.dir,
				User:       tc.spec.user,
			}
			g.startPrimary()

			g.mu.Lock()
			s := g.sessions[wire.PrimarySession]
			ex := g.exit
			g.mu.Unlock()
			if s == nil {
				t.Fatal("primary start failure did not register a session")
			}
			if info := s.info(); !info.Exited {
				t.Fatal("failed primary session is not marked exited")
			}
			if ex == nil {
				t.Fatal("primary start failure did not report an exit status")
			}
			if tc.code != 0 && ex.Code != tc.code {
				t.Fatalf("exit code = %d, want %d", ex.Code, tc.code)
			}

			output, status := attachAndRead(t, s)
			if tc.want != "" && !strings.Contains(output, tc.want) {
				t.Fatalf("client output = %q, want it to contain %q", output, tc.want)
			}
			if tc.code != 0 && status.Code != tc.code {
				t.Fatalf("client exit code = %d, want %d", status.Code, tc.code)
			}

			// Delivering the exit status must let the guest shut down
			// cleanly (and save a state disk) instead of panicking.
			deadline := time.Now().Add(10 * time.Second)
			for {
				g.mu.Lock()
				stopping := g.stopping
				g.mu.Unlock()
				if stopping {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("guest did not shut down after the failed primary exited")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// A primary command that cannot start keeps the conventional status: a
// missing command is 127, while a workdir or credential configuration error
// is 126 and not "command not found".
func TestStartFailureExitStatus(t *testing.T) {
	g := testGuest(t)
	for _, tc := range []struct {
		name string
		spec procSpec
		code int
	}{
		{"command not found", procSpec{argv: []string{"blip-test-no-such-binary"}}, 127},
		{"workdir missing", procSpec{argv: []string{"/bin/sh"}, dir: "/no/such/dir"}, 126},
		{"unknown user", procSpec{argv: []string{"/bin/sh"}, user: "no-such-user-xyz"}, 126},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := g.startProc(tc.spec, nil)
			if err == nil {
				t.Fatal("startProc succeeded")
			}
			if got := startExitCode(err); got != tc.code {
				t.Fatalf("startExitCode(%v) = %d, want %d", err, got, tc.code)
			}
		})
	}
}

// execve's ENOENT means the command is missing (127); EACCES, EPERM and
// ENOEXEC mean it exists but cannot run (126).
func TestClassifyStart(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{&os.PathError{Op: "fork/exec", Path: "x", Err: unix.ENOENT}, 127},
		{&os.PathError{Op: "fork/exec", Path: "x", Err: unix.EACCES}, 126},
		{&os.PathError{Op: "fork/exec", Path: "x", Err: unix.EPERM}, 126},
		{&os.PathError{Op: "fork/exec", Path: "x", Err: unix.ENOEXEC}, 126},
	} {
		if got := classifyStart(tc.err); got != tc.code {
			t.Errorf("classifyStart(%v) = %d, want %d", tc.err, got, tc.code)
		}
	}
}

// An exec start failure is rejected with the conventional exit status so the
// CLI can return it instead of a plain exit 1.
func TestExecStartFailureCarriesExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		msg  string
	}{
		{"not executable", 126, "start /etc/passwd: permission denied"},
		{"not found", 127, "nosuchcmd: command not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := testGuest(t)
			g.claim = &wire.Claim{ID: "root"}
			g.startProcess = func(s procSpec, base []string) (*proc, []string, error) {
				return nil, nil, startFail(tc.code, errors.New(tc.msg))
			}
			srv, cli := sessionPair(t)
			defer cli.Close()
			c := wire.NewConn(cli)
			go g.serveSession(srv)
			if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"x"}}); err != nil {
				t.Fatal(err)
			}
			typ, payload, err := c.Read()
			if err != nil || typ != wire.TOpened {
				t.Fatalf("read = %d, %v", typ, err)
			}
			var o wire.Opened
			if err := wire.Decode(payload, &o); err != nil {
				t.Fatal(err)
			}
			if o.Code != tc.code || o.Error != tc.msg {
				t.Fatalf("opened = %+v, want code %d and %q", o, tc.code, tc.msg)
			}
		})
	}
}

// A start error containing a very long path is escaped by JSON. The reply must
// still fit one frame, otherwise WriteJSON fails, the client sees EOF, and it
// reports "the VM is not reachable" instead of the real 126.
func TestExecStartFailureBoundsOversizedError(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root"}
	long := strings.Repeat("\x01", 130_000)
	huge := fmt.Errorf("start /tmp/%s: %w", long,
		&os.PathError{Op: "fork/exec", Path: "/tmp/" + long, Err: unix.ENAMETOOLONG})
	g.startProcess = func(procSpec, []string) (*proc, []string, error) {
		return nil, nil, startFail(126, huge)
	}
	srv, cli := sessionPair(t)
	defer cli.Close()
	c := wire.NewConn(cli)
	go g.serveSession(srv)
	if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := c.Read()
	if err != nil || typ != wire.TOpened {
		t.Fatalf("read = %d, %v", typ, err)
	}
	if len(payload) > wire.MaxFrame {
		t.Fatalf("TOpened payload = %d bytes, over MaxFrame %d", len(payload), wire.MaxFrame)
	}
	var o wire.Opened
	if err := wire.Decode(payload, &o); err != nil {
		t.Fatal(err)
	}
	if o.Code != 126 {
		t.Fatalf("Code = %d, want 126", o.Code)
	}
	if len(o.Error) > maxErrorText || !strings.Contains(o.Error, truncatedMarker) {
		t.Fatalf("error not bounded: %d bytes, %q", len(o.Error), o.Error)
	}
	if !utf8.ValidString(o.Error) {
		t.Fatalf("bounded error is not valid UTF-8: %q", o.Error)
	}
}

// The primary command's start failure is replayed as stderr rather than a
// TOpened. That frame must be bounded too, or an attaching client cannot read
// it and the exit status is lost.
func TestFailedSessionBoundsOversizedStartError(t *testing.T) {
	g := &Guest{sessions: map[string]*session{}}
	huge := errors.New("start /tmp/" + strings.Repeat("\x01", 130_000))
	s := g.failedSession("exec-1", []string{"x"}, huge)
	frames, _, _ := s.out.since(0)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if len(frames[0].data) > maxErrorText+1 {
		t.Fatalf("stderr frame = %d bytes, want at most %d", len(frames[0].data), maxErrorText+1)
	}
	if !strings.Contains(string(frames[0].data), truncatedMarker) {
		t.Fatalf("stderr was not visibly truncated: %d bytes", len(frames[0].data))
	}
	if !utf8.Valid(frames[0].data) {
		t.Fatal("bounded stderr is not valid UTF-8")
	}
}
