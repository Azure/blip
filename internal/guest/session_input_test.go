package guest

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
)

func newInputTestSession(stdin *os.File, pid int) *session {
	s := &session{proc: &proc{pid: pid, stdin: stdin}, out: ring{max: RingSize}}
	s.cond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.inMu)
	go s.pumpInput()
	return s
}

// TestSignalWhileStdinIsBlocked verifies that a process which does not read
// its stdin can still be interrupted. Writing the pipe directly from the
// frame loop used to block signal and resize frames behind the unread input.
func TestSignalWhileStdinIsBlocked(t *testing.T) {
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

	s := newInputTestSession(w, cmd.Process.Pid)
	defer s.closeInput()

	// More than a pipe buffer, so the input pump is stuck in write when the
	// signal frame arrives.
	if err := s.queueInput(bytes.Repeat([]byte("x"), 1<<20)); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(wire.Signal{Name: "TERM"})
	done := make(chan struct{})
	go func() {
		_ = s.input(wire.TSignal, payload)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("signal frame blocked behind unread stdin")
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("process did not receive the signal")
	}
}

// TestTTYInputOverflowDoesNotBlockSignals verifies that a client typing into
// a terminal session whose process never reads stdin is not disconnected.
// Dropping the excess input keeps the connection (and the signal path) alive,
// so Ctrl-C still works instead of returning a mystery "connection lost"
// error.
func TestTTYInputOverflowDoesNotBlockSignals(t *testing.T) {
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

	s := newInputTestSession(w, cmd.Process.Pid)
	s.tty = true
	defer s.closeInput()

	if err := s.queueInput(make([]byte, maxPendingInput+1)); err != nil {
		t.Fatalf("queueInput returned %v, want the excess input dropped", err)
	}
	if !s.takeDropped() {
		t.Fatal("overflow was not reported")
	}

	payload, _ := json.Marshal(wire.Signal{Name: "TERM"})
	done := make(chan struct{})
	go func() {
		_ = s.input(wire.TSignal, payload)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("signal frame blocked behind overflowed stdin")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("process did not receive the signal after input overflow")
	}
}

// TestNonTTYInputWaitsInsteadOfDropping verifies that a bulk stream such as
// sftp or scp is never silently truncated. Once the queue is full, the next
// frame waits for the pump to make space instead of being discarded.
func TestNonTTYInputWaitsInsteadOfDropping(t *testing.T) {
	s := &session{out: ring{max: RingSize}}
	s.inCond = sync.NewCond(&s.inMu)
	defer s.closeInput()

	if err := s.queueInput(make([]byte, maxPendingInput)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.queueInput([]byte("tail")) }()
	select {
	case err := <-done:
		t.Fatalf("queueInput returned %v instead of waiting for space", err)
	case <-time.After(100 * time.Millisecond):
	}
	// The pump takes the queued frames and signals that space is available.
	s.inMu.Lock()
	s.inQueue, s.inBytes = nil, 0
	s.inCond.Broadcast()
	s.inMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queueInput did not resume after space was freed")
	}
	if s.takeDropped() {
		t.Fatal("non-terminal input was dropped")
	}
}

// TestPumpCopiesReadBuffer verifies that each output frame owns its bytes.
// Reusing one read buffer made every frame alias the latest read, which
// corrupted downloads larger than one 32KiB read.
func TestPumpCopiesReadBuffer(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := &session{out: ring{max: RingSize}}
	s.cond = sync.NewCond(&s.mu)
	go s.pump(r, wire.TStdout)

	chunks := [][]byte{bytes.Repeat([]byte("a"), 40<<10), bytes.Repeat([]byte("b"), 40<<10)}
	for i, chunk := range chunks {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			s.mu.Lock()
			n := len(s.out.frames)
			s.mu.Unlock()
			if n > i {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("frame %d was not read", i)
			}
			time.Sleep(time.Millisecond)
		}
	}
	_ = w.Close()
	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	defer s.mu.Unlock()
	var got []byte
	for _, f := range s.out.frames {
		got = append(got, f.data...)
	}
	want := bytes.Join(chunks, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("output has %d bytes, want %d; first difference at %d",
			len(got), len(want), firstDifference(got, want))
	}
}

func firstDifference(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// TestQueuedInputPreservesOrder checks that stdin and its end-of-file marker
// are written in order by the input pump.
func TestQueuedInputPreservesOrder(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := newInputTestSession(w, 0)
	defer s.closeInput()

	if err := s.queueInput([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if err := s.queueInput([]byte("world")); err != nil {
		t.Fatal(err)
	}
	s.queueEOF()

	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		got <- b
	}()
	select {
	case b := <-got:
		if string(b) != "hello world" {
			t.Fatalf("stdin = %q, want %q", b, "hello world")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdin was not closed after EOF")
	}
}
