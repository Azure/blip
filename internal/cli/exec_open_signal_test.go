package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// TestExecOpenSignalRestoresTerminal signals the CLI while a TTY session open
// is still blocked. MakeRaw runs before the open, so the signal must restore
// the terminal and exit 143 instead of using the default disposition and
// leaving the caller's terminal raw.
func TestExecOpenSignalRestoresTerminal(t *testing.T) {
	_, slave := openTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestExecOpenSignalHelper$")
	cmd.Env = append(os.Environ(), "BLIP_EXEC_OPEN_SIGNAL_HELPER=1")
	cmd.Stdin = slave
	cmd.Stdout = io.Discard
	marker, markerW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer marker.Close()
	cmd.Stderr = markerW
	if err := cmd.Start(); err != nil {
		markerW.Close()
		t.Fatal(err)
	}
	markerW.Close()

	opened := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(marker)
		for sc.Scan() {
			if sc.Text() == "BLIP_OPEN_BLOCKED" {
				opened <- true
				return
			}
		}
		opened <- false
	}()
	select {
	case ok := <-opened:
		if !ok {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("helper exited before its session open blocked")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("helper never reached the blocked session open")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper did not exit after SIGTERM during session open")
	}
	if code := cmd.ProcessState.ExitCode(); code != 143 {
		t.Fatalf("exit code = %d, want 143 (status %v)", code, cmd.ProcessState)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal was not restored: before %+v after %+v", before, after)
	}
}

// TestExecOpenSignalHelper is the subprocess for
// TestExecOpenSignalRestoresTerminal. Its session connector blocks after
// MakeRaw until the parent sends a signal; the early signal watcher must
// restore the terminal and exit with 128+SIGTERM.
func TestExecOpenSignalHelper(t *testing.T) {
	if os.Getenv("BLIP_EXEC_OPEN_SIGNAL_HELPER") != "1" {
		return
	}
	env := &Env{
		In: os.Stdin, Out: io.Discard, Err: os.Stderr, Terminal: true,
		Connect: func(KubeFlags) (*Clients, error) {
			return &Clients{
				Namespace: ns,
				Sessions: &session.Client{Connect: func(ctx context.Context, _, _ string) (io.ReadWriteCloser, error) {
					fmt.Fprintln(os.Stderr, "BLIP_OPEN_BLOCKED")
					<-ctx.Done()
					return nil, ctx.Err()
				}},
			}, nil
		},
	}
	a := &app{env: env}
	err := a.execSession(context.Background(), "test", "pod", []string{"sh"}, &execFlags{}, true)
	fmt.Fprintf(os.Stderr, "execSession returned: %v\n", err)
	os.Exit(1)
}

// notifyWriter reports the first write, which only happens once stream has
// taken over signal forwarding and started copying guest output.
type notifyWriter struct {
	once sync.Once
	ch   chan struct{}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ch) })
	return len(p), nil
}

// TestExecSessionHandsSignalsToForwarder verifies that the early watcher is
// retired once streaming starts: a raw Ctrl-C byte still reaches the guest as
// input, and a later SIGTERM is forwarded instead of being consumed twice or
// exiting the client directly.
func TestExecSessionHandsSignalsToForwarder(t *testing.T) {
	master, slave := openTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	input := make(chan byte, 1)
	forwarded := make(chan string, 4)
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		s.Stdout("READY\n")
		var b [1]byte
		if n, _ := s.Stdin.Read(b[:]); n > 0 {
			input <- b[0]
		}
		for ev := range s.Events {
			if ev.Signal == "" {
				continue
			}
			forwarded <- ev.Signal
			if ev.Signal == "TERM" {
				return wire.Exit{}
			}
		}
		return wire.Exit{}
	}}

	out := &notifyWriter{ch: make(chan struct{})}
	a := &app{env: &Env{
		In: slave, Out: out, Err: io.Discard, Terminal: true,
		Connect: func(KubeFlags) (*Clients, error) {
			return &Clients{Namespace: ns, Sessions: &session.Client{Connect: guest.Connect}}, nil
		},
	}}
	done := make(chan error, 1)
	go func() {
		done <- a.execSession(context.Background(), "test", "pod", []string{"sh"}, &execFlags{}, true)
	}()

	select {
	case <-out.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never delivered guest output")
	}
	// Raw mode must pass Ctrl-C through as ordinary input, not turn it into a
	// local signal now that a handler is installed.
	if _, err := master.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-input:
		if b != 3 {
			t.Fatalf("guest received byte %#x, want Ctrl-C 0x03", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guest never received the raw Ctrl-C byte")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case sig := <-forwarded:
		if sig != "TERM" {
			t.Fatalf("guest received signal %q, want TERM", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM was not forwarded after the session open")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execSession returned %v, want success", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("execSession did not return after the guest exited")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal was not restored: before %+v after %+v", before, after)
	}
}
