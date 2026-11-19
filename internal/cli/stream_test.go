package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// openTestPTY returns the master and slave sides of a new pseudo-terminal.
func openTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Skipf("unlock PTY: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Skipf("PTY number: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Skipf("open PTY slave: %v", err)
	}
	t.Cleanup(func() {
		master.Close()
		slave.Close()
	})
	return master, slave
}

// A TTY stream puts the local terminal in raw mode. A termination signal must
// therefore be forwarded to the guest (whose session may still be running),
// and the terminal must be restored when the stream returns instead of being
// left in raw mode by the signal's default action. Previously signals were
// only forwarded for non-TTY sessions, so killing a TTY exec left both the
// remote command and the local terminal behind.
func TestStreamTTYForwardsSignalsAndRestoresTerminal(t *testing.T) {
	master, slave := openTestPTY(t)
	_ = master

	// Register before stream starts: a SIGTERM that arrives while the stream
	// is still installing its own handler would otherwise terminate the test
	// process. Both channels receive each signal.
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	signals := make(chan string, 8)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		for ev := range s.Events {
			if ev.Signal != "" {
				signals <- ev.Signal
			}
			if ev.Signal == "TERM" || ev.Disconnected {
				return wire.Exit{}
			}
		}
		return wire.Exit{}
	}}
	client := &session.Client{Connect: guest.Connect}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{
		Mode: wire.OpenExec, Argv: []string{"sh"}, TTY: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a := &app{env: &Env{In: slave, Out: io.Discard, Err: io.Discard, Terminal: true}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.stream(ctx, s, streamOpts{blip: "test"}) }()

	// Wait until the stream has made the terminal raw, then keep sending
	// SIGTERM until the guest sees one. Retrying removes the race between the
	// signal and forwardSignals registering its channel.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); err == nil && st.Lflag&unix.ICANON == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never made the terminal raw")
		}
		time.Sleep(10 * time.Millisecond)
	}

	forwarded := false
	for !forwarded {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case sig := <-signals:
			if sig != "TERM" {
				t.Fatalf("guest received signal %q, want TERM", sig)
			}
			forwarded = true
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGTERM was not forwarded to the TTY session")
		}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream returned %v, want success after the guest exited", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not return after the guest received the signal")
	}

	st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if st.Lflag&unix.ICANON == 0 || st.Lflag&unix.ECHO == 0 {
		t.Fatalf("terminal left raw: lflag=%#x, want ICANON and ECHO", st.Lflag)
	}
}

// The guest cannot be assumed to act on a forwarded signal: an interactive
// shell ignores SIGTERM. The client must still stop within a bounded grace
// after forwarding, or a supervisor ("timeout", systemd, CI) can only SIGKILL
// it and leave a real terminal in raw mode.
func TestStreamTTYSignalIgnoredByGuestDetaches(t *testing.T) {
	master, slave := openTestPTY(t)
	_ = master

	// Register before stream starts so the test process survives outlasting
	// any SIGTERM that arrives before forwardSignals installs its handler.
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	signals := make(chan string, 8)
	disconnected := make(chan struct{}, 1)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		for ev := range s.Events {
			if ev.Signal != "" {
				select {
				case signals <- ev.Signal:
				default:
				}
			}
			if ev.Disconnected {
				select {
				case disconnected <- struct{}{}:
				default:
				}
				return wire.Exit{}
			}
		}
		return wire.Exit{}
	}}
	client := &session.Client{Connect: guest.Connect}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{
		Mode: wire.OpenExec, Argv: []string{"bash"}, TTY: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a := &app{env: &Env{
		In: slave, Out: io.Discard, Err: io.Discard, Terminal: true,
		// A stream that errors consults the Blip lifecycle. These tests have
		// no API server, so report it unreachable and keep the failure local.
		Connect: func(KubeFlags) (*Clients, error) { return nil, errors.New("no API server in test") },
	}}
	// Detach quickly so the test does not wait for the production grace.
	a.signalGrace = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.stream(ctx, s, streamOpts{blip: "test"}) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); err == nil && st.Lflag&unix.ICANON == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never made the terminal raw")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Give forwardSignals a moment to install its channel once the stream is
	// under way. Retrying below still covers the remaining race.
	time.Sleep(20 * time.Millisecond)

	forwarded := false
	for !forwarded {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case sig := <-signals:
			if sig != "TERM" {
				t.Fatalf("guest received signal %q, want TERM", sig)
			}
			forwarded = true
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGTERM was not forwarded to the TTY session")
		}
	}

	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never detached after the guest ignored the signal")
	}

	select {
	case err := <-done:
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != 128+int(unix.SIGTERM) {
			t.Fatalf("stream returned %v, want exit status %d", err, 128+int(unix.SIGTERM))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not return after forwarding a signal the guest ignored")
	}

	st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if st.Lflag&unix.ICANON == 0 || st.Lflag&unix.ECHO == 0 {
		t.Fatalf("terminal left raw after detach: lflag=%#x, want ICANON and ECHO", st.Lflag)
	}
}

// exec -t must make the local terminal raw before opening the session. A
// terminal that is still canonical when the open begins interprets startup
// keystrokes locally: Ctrl-C would signal this process instead of becoming a
// byte for the guest. The live timing bug needs a real user typing into the
// CLI's controlling terminal; here a PTY stands in for that terminal and the
// connector injects a keystroke at the start of the open.
func TestExecSessionRawBeforeOpenKeepsStartupInput(t *testing.T) {
	master, slave := openTestPTY(t)

	// A misdirected Ctrl-C belongs to the pty, not this test process.
	own := make(chan os.Signal, 1)
	signal.Notify(own, syscall.SIGINT)
	defer signal.Stop(own)

	got := make(chan string, 1)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		buf := make([]byte, 1)
		if _, err := io.ReadFull(s.Stdin, buf); err != nil {
			got <- ""
			return wire.Exit{}
		}
		got <- string(buf)
		return wire.Exit{}
	}}
	connect := session.Connector(func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			return nil, err
		}
		if st.Lflag&unix.ICANON != 0 {
			return nil, errors.New("terminal still canonical during session open")
		}
		// Type Ctrl-C while the session is opening. With the terminal already
		// raw it stays queued as a byte for the guest's stdin.
		if _, err := master.Write([]byte{0x03}); err != nil {
			return nil, err
		}
		return guest.Connect(ctx, namespace, pod)
	})
	a := &app{env: &Env{
		In: slave, Out: io.Discard, Err: io.Discard, Terminal: true,
		Connect: func(KubeFlags) (*Clients, error) {
			return &Clients{Sessions: &session.Client{Connect: connect}, Namespace: ns}, nil
		},
	}}
	if err := a.execSession(context.Background(), "agent", "pod-agent", []string{"cat"}, &execFlags{}, true); err != nil {
		t.Fatal(err)
	}
	select {
	case in := <-got:
		if in != "\x03" {
			t.Fatalf("guest stdin = %q, want the startup Ctrl-C byte", in)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guest session never finished")
	}
}

// A failed open must restore the terminal that execSession made raw before it
// started waiting on the cluster.
func TestExecSessionRestoresTerminalWhenOpenFails(t *testing.T) {
	master, slave := openTestPTY(t)
	_ = master

	rawDuringOpen := false
	connect := session.Connector(func(context.Context, string, string) (io.ReadWriteCloser, error) {
		st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err == nil && st.Lflag&unix.ICANON == 0 {
			rawDuringOpen = true
		}
		return nil, errors.New("no API server in test")
	})
	a := &app{env: &Env{
		In: slave, Out: io.Discard, Err: io.Discard, Terminal: true,
		Connect: func(KubeFlags) (*Clients, error) {
			return &Clients{Sessions: &session.Client{Connect: connect}, Namespace: ns}, nil
		},
	}}
	if err := a.execSession(context.Background(), "agent", "pod-agent", []string{"sh"}, &execFlags{}, true); err == nil {
		t.Fatal("execSession succeeded with no API server")
	}
	if !rawDuringOpen {
		t.Fatal("terminal was not raw while the session opened")
	}
	st, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if st.Lflag&unix.ICANON == 0 || st.Lflag&unix.ECHO == 0 {
		t.Fatalf("terminal left raw after a failed open: lflag=%#x, want ICANON and ECHO", st.Lflag)
	}
}
