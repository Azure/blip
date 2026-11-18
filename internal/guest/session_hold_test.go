package guest

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/wire"
)

// fakePrimary starts a primary command whose output is the returned pipe's
// write end. Tests run outside the guest and cannot chroot, so startPrimary
// uses this instead of starting a real workload.
func fakePrimary(t *testing.T, g *Guest) (*os.File, chan unix.WaitStatus) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	wait := make(chan unix.WaitStatus, 1)
	g.startProcess = func(s procSpec, base []string) (*proc, []string, error) {
		return &proc{wait: wait, tty: r}, s.argv, nil
	}
	t.Cleanup(func() {
		w.Close()
		r.Close()
		select {
		case wait <- unix.WaitStatus(0):
		default:
		}
		// Never leave a pump blocked on a release that will not come.
		g.mu.Lock()
		for _, s := range g.sessions {
			s.releasePumps()
		}
		g.mu.Unlock()
	})
	return w, wait
}

func primarySession(t *testing.T, g *Guest) *session {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.sessions[wire.PrimarySession]
	if s == nil {
		t.Fatal("primary session is not registered")
	}
	return s
}

// started reports whether the session's output pumps were released.
func started(s *session) bool {
	select {
	case <-s.pumpsReady:
		return true
	default:
		return false
	}
}

func waitStopping(t *testing.T, g *Guest, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		g.mu.Lock()
		stopping := g.stopping
		g.mu.Unlock()
		if stopping {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("guest did not shut down")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A primary command that expects a client must not pump output before the
// client attaches: a burst larger than the replay ring would otherwise be
// trimmed (and silently lost) during the attach handshake.
func TestPrimaryHoldsOutputUntilClientAttaches(t *testing.T) {
	g := testGuest(t)
	out, wait := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	if started(s) {
		t.Fatal("output pumps started before a client attached")
	}

	chunk := bytes.Repeat([]byte("0123456789abcdef\n"), 1024)
	chunks := (2<<20 + len(chunk) - 1) / len(chunk)
	total := chunks * len(chunk)
	go func() {
		for range chunks {
			if _, err := out.Write(chunk); err != nil {
				return
			}
		}
		out.Close()
		wait <- unix.WaitStatus(0)
	}()
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	frames := len(s.out.frames)
	s.mu.Unlock()
	if frames != 0 {
		t.Fatalf("%d output frames were pumped before the client attached", frames)
	}

	got, ex := attachAndRead(t, s)
	if len(got) != total {
		t.Fatalf("client received %d bytes, want %d", len(got), total)
	}
	if ex.Code != 0 {
		t.Fatalf("exit code = %d, want 0", ex.Code)
	}
}

// Without WaitForClient the command starts immediately, as detached runs rely
// on, and its early output is recorded for a late caller.
func TestPrimaryStartsWithPumpsWithoutWaitForClient(t *testing.T) {
	g := testGuest(t)
	out, _ := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}}
	g.startPrimary()
	s := primarySession(t, g)
	if !started(s) {
		t.Fatal("output pumps were held without WaitForClient")
	}
	if _, err := out.Write([]byte("early\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		frames := len(s.out.frames)
		s.mu.Unlock()
		if frames > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("early output was not pumped without a client")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A caller that never arrives must not keep the command blocked on its output
// pipe forever.
func TestPrimaryPumpHoldFallback(t *testing.T) {
	old := waitForClientTimeout
	waitForClientTimeout = 100 * time.Millisecond
	t.Cleanup(func() { waitForClientTimeout = old })

	g := testGuest(t)
	fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	select {
	case <-s.pumpsReady:
	case <-time.After(3 * time.Second):
		t.Fatal("pumps stayed held after the fallback timeout")
	}
}

// Shutdown must release held pumps so a terminating process cannot stay
// blocked writing output.
func TestShutdownReleasesHeldPumps(t *testing.T) {
	old := waitForClientTimeout
	waitForClientTimeout = time.Hour
	t.Cleanup(func() { waitForClientTimeout = old })

	g := testGuest(t)
	fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	if started(s) {
		t.Fatal("output pumps started before a client attached")
	}
	g.shutdown()
	if !started(s) {
		t.Fatal("shutdown did not release held pumps")
	}
}

// sessionPair returns two connected stream files for serveSession tests.
func sessionPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := os.NewFile(uintptr(fds[0]), "session-server")
	cli := os.NewFile(uintptr(fds[1]), "session-client")
	t.Cleanup(func() {
		srv.Close()
		cli.Close()
	})
	return srv, cli
}

// A detached run (no client, no WaitForClient) must not linger after its
// command exits; that delay was paid by blip run -d and blip wait.
func TestPrimaryExitShutsDownWithoutClient(t *testing.T) {
	g := testGuest(t)
	out, wait := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"true"}}
	g.startPrimary()
	out.Close()
	wait <- unix.WaitStatus(0)
	waitStopping(t, g, 2*time.Second)
}

// A run that expects a client keeps the replay until the client attaches,
// then delivers the final output and exit status before shutting down.
func TestPrimaryExitWaitsForExpectedClient(t *testing.T) {
	g := testGuest(t)
	out, wait := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"echo"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)

	if _, err := out.Write([]byte("bye\n")); err != nil {
		t.Fatal(err)
	}
	out.Close()
	wait <- unix.WaitStatus(0)

	deadline := time.Now().Add(5 * time.Second)
	for !s.info().Exited {
		if time.Now().After(deadline) {
			t.Fatal("primary session did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	g.mu.Lock()
	stopping := g.stopping
	g.mu.Unlock()
	if stopping {
		t.Fatal("guest shut down before the expected client attached")
	}

	got, ex := attachAndRead(t, s)
	if got != "bye\n" || ex.Code != 0 {
		t.Fatalf("client got %q exit %+v, want %q exit 0", got, ex, "bye\n")
	}
	waitStopping(t, g, 5*time.Second)
}

// An exec after the primary exited could still write a durable root after the
// guest reported its final status, so it must be rejected.
func TestExecRejectedAfterPrimaryExit(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root"}
	g.exit = &wire.Exit{Code: 0, Reason: "Completed"}

	srv, cliFile := sessionPair(t)
	_ = cliFile.SetDeadline(time.Now().Add(5 * time.Second))
	c := wire.NewConn(cliFile)
	go g.serveSession(srv)
	if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh"}}); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := c.Read()
	if err != nil {
		t.Fatal(err)
	}
	var o wire.Opened
	if err := wire.Decode(payload, &o); typ != wire.TOpened || err != nil || !strings.Contains(o.Error, "primary command has exited") {
		t.Fatalf("exec after exit: frame %d %q %v", typ, o.Error, err)
	}
	g.mu.Lock()
	sessions := len(g.sessions)
	g.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("exec after the primary exited started %d session(s)", sessions)
	}
}

// Attaching is still allowed after the primary exited: the caller replays the
// final output and exit status.
func TestAttachAfterPrimaryExitReplaysOutput(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root", WaitForClient: true}
	s := newSession(g, wire.PrimarySession, []string{"echo"}, false)
	s.out.add(wire.TStdout, []byte("bye\n"))
	g.sessions[wire.PrimarySession] = s
	s.finish(wire.Exit{Code: 7})
	if g.exit == nil {
		t.Fatal("primary exit was not recorded")
	}

	srv, cliFile := sessionPair(t)
	_ = cliFile.SetDeadline(time.Now().Add(5 * time.Second))
	c := wire.NewConn(cliFile)
	go g.serveSession(srv)
	if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenAttach}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for {
		typ, payload, err := c.Read()
		if err != nil {
			t.Fatalf("read after attach: %v (output %q)", err, out.String())
		}
		switch typ {
		case wire.TStdout, wire.TStderr:
			out.Write(payload)
		case wire.TExited:
			var ex wire.Exit
			if err := wire.Decode(payload, &ex); err != nil {
				t.Fatal(err)
			}
			if out.String() != "bye\n" || ex.Code != 7 {
				t.Fatalf("replay %q exit %+v, want %q exit 7", out.String(), ex, "bye\n")
			}
			waitStopping(t, g, 5*time.Second)
			return
		}
	}
}
