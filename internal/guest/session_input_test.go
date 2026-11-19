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
	s := &session{proc: &proc{pid: pid, stdin: stdin}, out: ring{max: ringSize}}
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
	s := &session{out: ring{max: ringSize}}
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

// TestNonTTYInputStallDropsAndKeepsSignalsResponsive verifies that a bulk
// client feeding a process which never reads cannot block the frame loop
// forever. Once the 8 MiB queue stops making progress, further input is
// dropped (with a notice) so a later SIGINT/SIGTERM is still delivered.
func TestNonTTYInputStallDropsAndKeepsSignalsResponsive(t *testing.T) {
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

	// Queue well past maxPendingInput. sleep never reads, so the pump blocks
	// in write and the queue can only drain the first pipe-sized batch.
	block := bytes.Repeat([]byte("x"), 1<<20)
	queued := make(chan struct{})
	go func() {
		for i := 0; i < 32; i++ {
			if err := s.queueInput(block); err != nil {
				break
			}
		}
		close(queued)
	}()
	select {
	case <-queued:
	case <-time.After(4 * time.Second):
		t.Fatal("non-terminal input wedged behind a process that is not reading")
	}
	if !s.takeDropped() {
		t.Fatal("input overflow was not reported")
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
		t.Fatal("signal frame blocked behind stalled stdin")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("process did not receive the signal after stdin stalled")
	}
}

// TestInputDropNoticeIsThrottled verifies that a flood of dropped frames
// produces one notice instead of one per frame.
func TestInputDropNoticeIsThrottled(t *testing.T) {
	s := &session{out: ring{max: ringSize}, tty: true}
	s.inCond = sync.NewCond(&s.inMu)
	s.inBytes = maxPendingInput // full: every frame below is dropped

	for i := 0; i < 8; i++ {
		if err := s.queueInput([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if !s.takeDropped() {
		t.Fatal("first overflow was not reported")
	}
	for i := 0; i < 8; i++ {
		if err := s.queueInput([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if s.takeDropped() {
		t.Fatal("stdin-discarded notice repeated immediately after a flood")
	}
}

// TestNonTTYInputExactlyMaxIsNotDropped keeps the normal byte-stream path
// intact: a full 8 MiB queued to a process that is reading is delivered
// whole.
func TestNonTTYInputExactlyMaxIsNotDropped(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command("cat")
	cmd.Stdin = r
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	s := newInputTestSession(w, cmd.Process.Pid)
	defer s.closeInput()

	copied := make(chan int, 1)
	go func() {
		n, _ := io.Copy(io.Discard, stdout)
		copied <- int(n)
	}()

	if err := s.queueInput(bytes.Repeat([]byte("z"), maxPendingInput)); err != nil {
		t.Fatal(err)
	}
	s.queueEOF()
	select {
	case n := <-copied:
		if n != maxPendingInput {
			t.Fatalf("delivered %d bytes, want %d", n, maxPendingInput)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("8 MiB of stdin was not delivered")
	}
	if s.takeDropped() {
		t.Fatal("input within maxPendingInput was dropped")
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
	s := &session{out: ring{max: ringSize}}
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

// TestTTYEOFEndsPartialLineInput verifies that a piped caller whose input
// does not end in a newline still ends a terminal session. A single VEOF only
// delivers the partial line in canonical mode; the second VEOF is what makes
// read(2) return 0, so commands like `wc -c` no longer hang waiting for EOF.
func TestTTYEOFEndsPartialLineInput(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("open PTY: %v", err)
	}
	defer master.Close()

	cmd := exec.Command("cat")
	cmd.Stdin = slave
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slave.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Skipf("start cat on PTY: %v", err)
	}
	// The child owns the slave side; the parent's copy would otherwise keep
	// the terminal open and hide EOF handling.
	slave.Close()
	defer func() { _ = cmd.Process.Kill() }()

	s := &session{proc: &proc{tty: master}, tty: true, out: ring{max: ringSize}}
	s.inCond = sync.NewCond(&s.inMu)
	go s.pumpInput()
	defer s.closeInput()

	if err := s.queueInput([]byte("XYZ")); err != nil {
		t.Fatal(err)
	}
	s.queueEOF()

	copied := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdout)
		copied <- string(b)
	}()
	select {
	case got := <-copied:
		if got != "XYZ" {
			t.Fatalf("terminal input = %q, want %q", got, "XYZ")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal input did not reach EOF after piped stdin closed")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cat did not exit cleanly after EOF: %v", err)
	}
}

// TestTTYRawEOFEndsSessionWithoutVEOFData verifies that piped stdin EOF ends a
// program which put the terminal into raw mode. A raw-mode reader interprets
// the canonical VEOF bytes as ordinary data, so it both received 004 004 and
// waited forever. The guest must end the session without injecting those bytes
// as input.
func TestTTYRawEOFEndsSessionWithoutVEOFData(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("open PTY: %v", err)
	}
	defer master.Close()

	cmd := exec.Command("sh", "-c", "stty raw -echo; cat")
	cmd.Stdin = slave
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slave.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Skipf("start cat on PTY: %v", err)
	}
	slave.Close()
	defer func() { _ = cmd.Process.Kill() }()

	s := &session{proc: &proc{tty: master}, tty: true, out: ring{max: ringSize}}
	s.inCond = sync.NewCond(&s.inMu)
	go s.pumpInput()
	defer s.closeInput()

	if err := s.queueInput([]byte("abc")); err != nil {
		t.Fatal(err)
	}

	// The terminal is only known to be raw once cat has returned the partial
	// line without a newline. Reading that output also proves the data was
	// delivered before EOF.
	var (
		mu  sync.Mutex
		got bytes.Buffer
	)
	eof := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				got.Write(buf[:n])
				mu.Unlock()
			}
			if rerr != nil {
				close(eof)
				return
			}
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		seen := got.Len() >= 3
		mu.Unlock()
		if seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("raw-mode cat did not receive the piped bytes")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.queueEOF()

	select {
	case <-eof:
	case <-time.After(5 * time.Second):
		t.Fatal("raw-mode cat still waits for input after piped stdin closed")
	}
	mu.Lock()
	out := got.Bytes()
	mu.Unlock()
	if bytes.Contains(out, []byte{4}) {
		t.Fatalf("raw-mode reader received VEOF as data: %q", out)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("raw-mode cat did not exit after EOF")
	}
}

// TestTTYRawEOFSubmitsPartialLine verifies that a piped final line without a
// newline is still executed by a raw-mode reader. The guest submits the line
// the reader is holding and then delivers a canonical VEOF, instead of
// appending VEOF bytes to the raw line buffer.
func TestTTYRawEOFSubmitsPartialLine(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("open PTY: %v", err)
	}
	defer master.Close()

	cmd := exec.Command("sh", "-c", "stty raw -echo; echo READY; IFS= read -r x; echo GOT=$x")
	cmd.Stdin = slave
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slave.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Skipf("start shell on PTY: %v", err)
	}
	slave.Close()
	defer func() { _ = cmd.Process.Kill() }()

	s := &session{proc: &proc{tty: master}, tty: true, out: ring{max: ringSize}}
	s.inCond = sync.NewCond(&s.inMu)
	go s.pumpInput()
	defer s.closeInput()

	var (
		mu  sync.Mutex
		got bytes.Buffer
	)
	exited := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				got.Write(buf[:n])
				mu.Unlock()
			}
			if rerr != nil {
				close(exited)
				return
			}
		}
	}()

	// Queue the partial line only after the shell has set raw mode, so the
	// test exercises the raw EOF path regardless of startup timing.
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			seen := bytes.Contains(got.Bytes(), []byte(want))
			mu.Unlock()
			if seen {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("reader did not print %q", want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("READY")

	if err := s.queueInput([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	s.queueEOF()

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("raw-mode read did not finish after piped stdin closed")
	}
	mu.Lock()
	out := got.String()
	mu.Unlock()
	if !bytes.Contains([]byte(out), []byte("GOT=abc")) {
		t.Fatalf("partial line was not executed: %q", out)
	}
	if bytes.Contains([]byte(out), []byte{4}) {
		t.Fatalf("raw-mode reader received VEOF as data: %q", out)
	}
}

// TestNonTTYSlowReaderReceivesWholeStream verifies that a slow but steadily
// reading process is not mistaken for one that stopped reading. Input that was
// dequeued and is being written must still count against the queue limit, and
// progress within that batch must reset the stall clock. Otherwise 20 MB
// uploads were silently truncated while the client exited 0.
func TestNonTTYSlowReaderReceivesWholeStream(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	const total = 20 << 20
	const chunkSize = 1 << 20

	var (
		mu       sync.Mutex
		received int
	)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Read(buf)
			mu.Lock()
			received += n
			mu.Unlock()
			if rerr != nil {
				return
			}
			// Slow, but never stalled: the pipe always makes progress.
			time.Sleep(30 * time.Millisecond)
		}
	}()

	s := newInputTestSession(w, 0)
	defer s.closeInput()

	block := bytes.Repeat([]byte("x"), chunkSize)
	for sent := 0; sent < total; sent += chunkSize {
		if err := s.queueInput(block); err != nil {
			t.Fatal(err)
		}
	}
	s.queueEOF()

	select {
	case <-readDone:
	case <-time.After(60 * time.Second):
		t.Fatal("slow reader never reached EOF")
	}
	mu.Lock()
	n := received
	mu.Unlock()
	if n != total {
		t.Fatalf("slow reader received %d of %d stdin bytes: input was truncated", n, total)
	}
	if s.takeDropped() {
		t.Fatal("stdin was dropped for a slow but steadily reading process")
	}
}

// TestNonTTYInputLossIsNotReportedAsSuccess verifies that if the guest really
// must discard a non-terminal byte stream, the command does not report success
// as if the whole stream had been delivered.
func TestNonTTYInputLossIsNotReportedAsSuccess(t *testing.T) {
	g := &Guest{sessions: map[string]*session{}}
	s := &session{g: g, id: "exec-lost", out: ring{max: ringSize}}
	s.cond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.inMu)
	// No pump and a full queue: the next frame makes no progress and is
	// discarded after inputStallTimeout.
	s.inBytes = maxPendingInput
	if err := s.queueInput([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if !s.takeDropped() {
		t.Fatal("lost input was not reported")
	}
	s.finish(wire.Exit{Code: 0})
	if s.status.Code == 0 {
		t.Fatal("a command that lost stdin reported exit status 0")
	}
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
