package guest

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
)

// TestServeStopsPromptlyWhenClientClosesWithFullInputQueue is the w7-10
// defect 3 regression: a client that detached while its stdin upload filled
// the guest queue must not leave the frame loop waiting for pump space. The
// command has to be terminated promptly instead of draining an upload whose
// client is gone.
func TestServeStopsPromptlyWhenClientClosesWithFullInputQueue(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	g, _ := lifecycleGuest(t)
	s := newSession(g, "exec-detach", nil, false)
	s.proc = &proc{pid: cmd.Process.Pid, stdin: w}
	go s.pumpInput()
	defer s.closeInput()

	// The hard bound is full and the pump has nothing to write, so the next
	// stdin frame blocks the frame loop exactly like a slow reader at the
	// transport bound.
	s.inMu.Lock()
	s.inBytes = maxQueuedInput
	s.inFullSince = time.Now()
	s.inMu.Unlock()

	srv, cli := sessionPair(t)
	served := make(chan struct{})
	go func() {
		s.serve(wire.NewConn(srv), srv, false)
		close(served)
	}()
	c := wire.NewConn(cli)
	if err := c.Write(wire.TStdin, []byte("blocked input")); err != nil {
		t.Fatal(err)
	}
	// Let serve reach queueInput and block there.
	time.Sleep(50 * time.Millisecond)
	_ = cli.Close()

	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("serve stayed blocked in a full stdin queue after the client closed")
	}
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("detached exec command was not terminated")
	}
}

// TestServeDoesNotStopDeliveringInputForAnOpenPeer guards the normal path: the
// peer-close watcher must not treat readable data as a closed connection.
func TestServeDoesNotStopDeliveringInputForAnOpenPeer(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	g, _ := lifecycleGuest(t)
	s := newSession(g, "exec-open", nil, false)
	s.proc = &proc{stdin: w}
	go s.pumpInput()
	defer s.closeInput()

	srv, cli := sessionPair(t)
	served := make(chan struct{})
	go func() {
		s.serve(wire.NewConn(srv), srv, false)
		close(served)
	}()
	c := wire.NewConn(cli)
	if err := c.Write(wire.TStdin, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	// The input reaches the process while the peer stays open.
	buf := make([]byte, 5)
	got := make(chan struct{})
	var mu sync.Mutex
	var n int
	go func() {
		mu.Lock()
		n, _ = r.Read(buf)
		mu.Unlock()
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("stdin was not delivered while the peer was open")
	}
	mu.Lock()
	defer mu.Unlock()
	if string(buf[:n]) != "hello" {
		t.Fatalf("stdin = %q, want hello", buf[:n])
	}
	_ = cli.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after the client closed")
	}
}
