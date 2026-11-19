package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// testApp returns an app whose stream has no local terminal, but still
// forwards signals like an attached session does.
func testApp(in io.Reader, out, errOut io.Writer) *app {
	return &app{env: &Env{
		In: in, Out: out, Err: errOut, Terminal: true,
		Connect: func(KubeFlags) (*Clients, error) { return nil, errors.New("no API server in test") },
	}}
}

// awaitSignal sends sig to this process until check reports that the guest
// has observed it. Both the test and the stream receive the signal.
func awaitSignal(t *testing.T, sig syscall.Signal, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = syscall.Kill(os.Getpid(), sig)
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("guest never observed the forwarded signal")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStreamSignalGraceAllowsHandledShutdown verifies that a command which
// handles SIGTERM but needs longer than the old two-second grace to clean up
// finishes normally instead of being detached and reported as 143.
func TestStreamSignalGraceAllowsHandledShutdown(t *testing.T) {
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	observed := make(chan struct{}, 1)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		for ev := range s.Events {
			if ev.Signal == "TERM" || ev.Disconnected {
				select {
				case observed <- struct{}{}:
				default:
				}
				break
			}
		}
		// A graceful shutdown that takes longer than the old 2 s grace.
		time.Sleep(3 * time.Second)
		s.Stdout("CLEAN\n")
		return wire.Exit{}
	}}
	client := &session.Client{Connect: guest.Connect}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{
		Mode: wire.OpenExec, Argv: []string{"sh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var out bytes.Buffer
	a := testApp(strings.NewReader(""), &out, io.Discard)
	done := make(chan error, 1)
	go func() { done <- a.stream(context.Background(), s, streamOpts{blip: "test", sendEOF: true}) }()

	awaitSignal(t, syscall.SIGTERM, func() bool {
		select {
		case <-observed:
			return true
		default:
			return false
		}
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream returned %v, want success after handled shutdown", err)
		}
		if out.String() != "CLEAN\n" {
			t.Fatalf("output = %q, want %q", out.String(), "CLEAN\n")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("stream did not return after the command finished its shutdown")
	}
}

// gateWriter blocks the first write until gate is closed, modelling a local
// stdout consumer that is slower than the signal grace.
type gateWriter struct {
	gate    chan struct{}
	once    sync.Once
	started chan struct{}
	mu      sync.Mutex
	buf     bytes.Buffer
}

func (w *gateWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.gate
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// TestStreamSignalGraceWaitsForBackpressuredOutput verifies that output the
// command produced before exiting is not cut off by the signal grace. The
// client is only blocked writing stdout, not waiting on an unresponsive guest,
// so it must deliver the output and the command's own exit status.
func TestStreamSignalGraceWaitsForBackpressuredOutput(t *testing.T) {
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	const output = 64 << 10
	observed := make(chan struct{}, 1)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		for ev := range s.Events {
			if ev.Signal == "TERM" || ev.Disconnected {
				select {
				case observed <- struct{}{}:
				default:
				}
				break
			}
		}
		s.Stdout(strings.Repeat("x", output))
		return wire.Exit{}
	}}
	client := &session.Client{Connect: guest.Connect}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{
		Mode: wire.OpenExec, Argv: []string{"sh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	w := &gateWriter{gate: make(chan struct{}), started: make(chan struct{})}
	a := testApp(strings.NewReader(""), w, io.Discard)
	a.signalGrace = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.stream(context.Background(), s, streamOpts{blip: "test", sendEOF: true}) }()

	awaitSignal(t, syscall.SIGTERM, func() bool {
		select {
		case <-observed:
			return true
		default:
			return false
		}
	})
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("guest output never reached the local writer")
	}
	// Block the writer well past the grace: the frame is received but not yet
	// written, so the client must keep waiting instead of reporting 143.
	time.Sleep(900 * time.Millisecond)
	close(w.gate)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream returned %v, want success after the command exited 0", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("stream did not return after the blocked writer resumed")
	}
	w.mu.Lock()
	n := w.buf.Len()
	w.mu.Unlock()
	if n != output {
		t.Fatalf("delivered %d of %d output bytes", n, output)
	}
}

// blockingWriter blocks every write until the test ends. It models a local
// stdout consumer that never drains, so Copy stays inside Write forever.
type blockingWriter struct {
	started chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	select {} // never returns; the process must exit without this write.
}

// TestStreamSignalGraceMaxAbandonsBlockedOutput is the w7-10 defect 2
// regression: after a forwarded signal's hard grace, a stdout consumer that
// never reads must not keep the client alive past signalGraceMax. The client
// must stop waiting for the blocked write, detach, and report 143.
func TestStreamSignalGraceMaxAbandonsBlockedOutput(t *testing.T) {
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	disconnected := make(chan struct{}, 1)
	observed := make(chan struct{}, 1)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		s.Stdout(strings.Repeat("x", 64<<10))
		for ev := range s.Events {
			switch {
			case ev.Signal == "TERM":
				select {
				case observed <- struct{}{}:
				default:
				}
			case ev.Disconnected:
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
		Mode: wire.OpenExec, Argv: []string{"sh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	w := &blockingWriter{started: make(chan struct{})}
	a := testApp(strings.NewReader(""), w, io.Discard)
	a.signalGrace = 200 * time.Millisecond
	a.signalGraceMax = 500 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.stream(context.Background(), s, streamOpts{blip: "test", sendEOF: true}) }()

	awaitSignal(t, syscall.SIGTERM, func() bool {
		select {
		case <-observed:
			return true
		default:
			return false
		}
	})
	select {
	case <-w.started:
	case <-time.After(2 * time.Second):
		t.Fatal("guest output never reached the local writer")
	}

	start := time.Now()
	select {
	case err := <-done:
		var exitErr *ExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 128+int(syscall.SIGTERM) {
			t.Fatalf("stream returned %v, want exit 143", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("stream took %v after the hard grace, want <= 3s", elapsed)
		}
	case <-time.After(5 * time.Second):
		select {
		case <-w.started:
			t.Fatal("client stayed blocked in stdout.Write past signalGraceMax")
		default:
			t.Fatal("stream did not return after signalGraceMax")
		}
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("guest command was not torn down after detach")
	}
}

// blockedStdinConn answers the session open, then blocks every stdin write
// until it is closed. It models a guest whose stdin transport is full and that
// is not reading further frames, which is what serialized a forwarded signal
// behind a blocked stdin write.
type blockedStdinConn struct {
	opened    *bytes.Reader
	mu        sync.Mutex
	wroteOpen bool
	blocked   chan struct{}
	blockOnce sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func newBlockedStdinConn(opened []byte) *blockedStdinConn {
	return &blockedStdinConn{
		opened:  bytes.NewReader(opened),
		blocked: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (c *blockedStdinConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.opened.Len() > 0 {
		n, err := c.opened.Read(p)
		c.mu.Unlock()
		return n, err
	}
	c.mu.Unlock()
	<-c.closed
	return 0, io.EOF
}

func (c *blockedStdinConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.wroteOpen {
		c.wroteOpen = true
		c.mu.Unlock()
		return len(p), nil
	}
	c.mu.Unlock()
	c.blockOnce.Do(func() { close(c.blocked) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockedStdinConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// TestStreamSignalIsNotSerializedBehindBlockedStdin is the w7-10 defect 3
// client regression: when stdin is stuck on a backpressured transport, a
// SIGTERM must still reach the grace timer and detach at signalGraceMax. It
// used to wait for the blocked wire write, so the client lived for tens of
// seconds and the guest command kept draining input after the client went
// away.
func TestStreamSignalIsNotSerializedBehindBlockedStdin(t *testing.T) {
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGTERM)
	defer signal.Stop(own)

	var ack bytes.Buffer
	aw := wire.NewConn(&ack)
	if err := aw.WriteJSON(wire.TOpened, wire.Opened{Session: "blocked"}); err != nil {
		t.Fatal(err)
	}
	conn := newBlockedStdinConn(ack.Bytes())
	client := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return conn, nil
	}}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a := testApp(strings.NewReader(strings.Repeat("x", 1<<20)), io.Discard, io.Discard)
	a.signalGrace = 200 * time.Millisecond
	a.signalGraceMax = 400 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.stream(context.Background(), s, streamOpts{blip: "test", sendEOF: true}) }()

	select {
	case <-conn.blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("stdin write never blocked")
	}

	start := time.Now()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case err := <-done:
			var exitErr *ExitError
			if !errors.As(err, &exitErr) || exitErr.Code != 128+int(syscall.SIGTERM) {
				t.Fatalf("stream returned %v, want exit 143", err)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("stream took %v with a blocked stdin write, want <= 3s", elapsed)
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("transport was not closed when the stream detached")
			}
			return
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("stream stayed blocked behind a backpressured stdin write")
		}
	}
}
