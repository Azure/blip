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
