package cli

import (
	"context"
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
