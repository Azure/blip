package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	sessionclient "github.com/Azure/blip/internal/session"
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

	// More than the queue budget, so the input pump is stuck in write and the
	// frame loop used to block waiting for space when the signal frame
	// arrived. The backlog absorbs it without blocking.
	if err := s.queueInput(bytes.Repeat([]byte("x"), maxPendingInput+(1<<20))); err != nil {
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

// TestSignalWhileStdinQueueIsFull verifies that a forwarded signal still
// reaches a process that has stopped reading after the full hard stdin bound.
// The frame loop may wait for pump space, but the stall escape must release it
// so later control frames are read rather than lost behind unread input.
func TestSignalWhileStdinQueueIsFull(t *testing.T) {
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

	old := inputStallTimeout
	inputStallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { inputStallTimeout = old })

	s := newInputTestSession(w, cmd.Process.Pid)
	defer s.closeInput()

	if err := s.queueInput(make([]byte, maxQueuedInput)); err != nil {
		t.Fatal(err)
	}
	// This frame cannot fit and the process never reads, so only the stall
	// escape lets queueInput return.
	blocked := make(chan error, 1)
	go func() { blocked <- s.queueInput(make([]byte, 1<<20)) }()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queueInput did not shed input after a progress-free stall")
	}
	if !s.inTruncated {
		t.Fatal("shed input was not recorded as truncated")
	}
	if !s.takeDropped() {
		t.Fatal("shed input was not reported to the client")
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
		t.Fatal("signal frame blocked behind a full stdin queue")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("process did not receive the signal after the queue was shed")
	}
}

// TestServeDeliversSignalAfterFullInputQueue exercises the real frame loop:
// a client floods stdin past the hard bound to a process that never reads,
// then sends a signal. The serve loop must not stay blocked in queueInput.
func TestServeDeliversSignalAfterFullInputQueue(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	old := inputStallTimeout
	inputStallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { inputStallTimeout = old })

	g, _ := lifecycleGuest(t)
	s := newSession(g, "exec-wire", nil, false)
	s.proc = &proc{pid: cmd.Process.Pid, stdin: wr}
	go s.pumpInput()
	defer s.closeInput()

	clientNet, guestNet := net.Pipe()
	defer clientNet.Close()
	go s.serve(wire.NewConn(guestNet), guestNet, false)

	client := wire.NewConn(clientNet)
	// Drain notices and output so the guest's frame loop never blocks writing
	// a dropped-input notice to a client that is not reading.
	go func() {
		for {
			if _, _, err := client.Read(); err != nil {
				return
			}
		}
	}()
	wrote := make(chan error, 1)
	go func() {
		chunk := make([]byte, 32<<10)
		for sent := 0; sent < maxQueuedInput+(1<<20); sent += len(chunk) {
			if err := client.Write(wire.TStdin, chunk); err != nil {
				wrote <- err
				return
			}
		}
		wrote <- client.WriteJSON(wire.TSignal, wire.Signal{Name: "TERM"})
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signal frame stayed blocked behind a full stdin queue")
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not receive the signal")
	}
}

// TestClientSignalWhileStdinWriteIsBlocked exercises the client's real write
// path: Session.Write holds the wire write serialization while stdin is
// backpressured, and Session.Signal must still reach the guest. This is the
// ordering that made a forwarded SIGTERM hang behind a full stdin queue.
func TestClientSignalWhileStdinWriteIsBlocked(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	old := inputStallTimeout
	inputStallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { inputStallTimeout = old })

	g, _ := lifecycleGuest(t)
	s := newSession(g, "exec-signal", nil, false)
	s.proc = &proc{pid: cmd.Process.Pid, stdin: wr}
	go s.pumpInput()
	defer s.closeInput()
	g.mu.Lock()
	g.sessions[s.id] = s
	g.mu.Unlock()

	c := &sessionclient.Client{Connect: lifecycleConnector(t, g)}
	sess, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach, Session: s.id})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// Drain output/notices so the guest is never blocked writing to a client
	// that is not reading while the test backpressures stdin.
	go func() {
		for {
			if _, err := sess.Recv(); err != nil {
				return
			}
		}
	}()
	go func() {
		chunk := make([]byte, 32<<10)
		for sent := 0; sent < maxQueuedInput+(1<<20); sent += len(chunk) {
			if _, err := sess.Write(chunk); err != nil {
				return
			}
		}
	}()
	// Let the writer fill the queue and block inside the wire write.
	time.Sleep(200 * time.Millisecond)

	signaled := make(chan error, 1)
	go func() { signaled <- sess.Signal("TERM") }()
	select {
	case err := <-signaled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Signal stayed blocked behind a backpressured stdin write")
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not receive the forwarded signal")
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

	if err := s.queueInput(make([]byte, maxQueuedInput)); err != nil {
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

// TestNonTTYInputWaitsForSlowReader verifies that a byte stream is never
// truncated when the command pauses before reading it. A full queue makes the
// writer wait for the pump to free space; a command that starts reading after
// a pause still receives every byte.
func TestNonTTYInputWaitsForSlowReader(t *testing.T) {
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
		// The bug reproduced with a command that did not read for two
		// seconds after startup; nothing may be discarded while it waits.
		time.Sleep(2 * time.Second)
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Read(buf)
			mu.Lock()
			received += n
			mu.Unlock()
			if rerr != nil {
				return
			}
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

// ttyReader is a command started on a PTY in its own session. The session's
// input pump feeds its terminal exactly like an exec session in the guest.
type ttyReader struct {
	master *os.File
	cmd    *exec.Cmd
	s      *session
	mu     sync.Mutex
	out    bytes.Buffer
}

func startTTYReader(t *testing.T, script string) *ttyReader {
	t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("open PTY: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdin = slave
	cmd.Stdout = outW
	cmd.Stderr = outW
	// Own session and controlling terminal, so the guest's SIGSTOP/SIGCONT
	// restart reaches the reader like it does for an exec session.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		outR.Close()
		outW.Close()
		t.Skipf("start %q on PTY: %v", script, err)
	}
	slave.Close()
	outW.Close()

	r := &ttyReader{master: master, cmd: cmd}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := outR.Read(buf)
			if n > 0 {
				r.mu.Lock()
				r.out.Write(buf[:n])
				r.mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()
	r.s = &session{proc: &proc{pid: cmd.Process.Pid, tty: master}, tty: true, out: ring{max: ringSize}}
	r.s.inCond = sync.NewCond(&r.s.inMu)
	go r.s.pumpInput()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		r.s.closeInput()
		master.Close()
	})
	return r
}

func (r *ttyReader) output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

func (r *ttyReader) waitFor(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out := r.output()
		if bytes.Contains([]byte(out), []byte(want)) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("output %q never contained %q", out, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// feed queues stdin and its end of input, like an attached client sending a
// piped stream.
func (r *ttyReader) feed(t *testing.T, input string) {
	t.Helper()
	if input != "" {
		if err := r.s.queueInput([]byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	r.s.queueEOF()
}

func assertNoNUL(t *testing.T, out string) {
	t.Helper()
	if bytes.Contains([]byte(out), []byte{0}) {
		t.Fatalf("stdin EOF was delivered as NUL data: %q", out)
	}
}

// TestTTYRawEOFIsByteExact is the regression for a piped stream read by a raw
// terminal: EOF must not append a newline or any other byte. wc must count
// exactly the three bytes that were sent.
func TestTTYRawEOFIsByteExact(t *testing.T) {
	r := startTTYReader(t, "stty raw -echo; wc -c; echo DONE=$?")
	r.feed(t, "abc")
	out := r.waitFor(t, "DONE=")
	assertNoNUL(t, out)
	if out != "3\nDONE=0\n" {
		t.Fatalf("output = %q, want %q", out, "3\nDONE=0\n")
	}
}

// TestTTYRawEOFAfterNewline ends a raw reader whose input ends with a newline.
// The newline must not be turned into a hangup or followed by NUL data.
func TestTTYRawEOFAfterNewline(t *testing.T) {
	r := startTTYReader(t, "stty raw -echo; cat; echo DONE=$?")
	r.feed(t, "hello\n")
	out := r.waitFor(t, "DONE=")
	assertNoNUL(t, out)
	if out != "hello\nDONE=0\n" {
		t.Fatalf("output = %q, want %q", out, "hello\nDONE=0\n")
	}
}

// TestTTYRawEOFEmptyInput delivers EOF to a raw reader that never received a
// byte. read(2) must return 0 instead of the process group being hung up.
func TestTTYRawEOFEmptyInput(t *testing.T) {
	r := startTTYReader(t, "stty raw -echo; echo READY; IFS= read -r x; echo GOT=$x; echo DONE=$?")
	r.feed(t, "")
	out := r.waitFor(t, "DONE=")
	if out != "READY\nGOT=\nDONE=0\n" {
		t.Fatalf("output = %q, want %q", out, "READY\nGOT=\nDONE=0\n")
	}
}

// TestTTYRawEOFAfterStartupDelay covers a program that enters raw mode after
// the client already sent its input and EOF. The bytes must arrive unchanged
// (no NULs from VEOF) and the reader must still see EOF. The delays reach past
// the old fixed settle and recovery windows so a startup that thinks for
// seconds before switching to raw mode is covered too.
func TestTTYRawEOFAfterStartupDelay(t *testing.T) {
	for _, delay := range []string{"0.1", "0.4", "0.7", "1.0", "1.5", "3.0"} {
		t.Run("sleep-"+delay, func(t *testing.T) {
			r := startTTYReader(t, "sleep "+delay+"; stty raw -echo; cat; echo DONE=$?")
			r.feed(t, "abc")
			out := r.waitFor(t, "DONE=")
			assertNoNUL(t, out)
			if out != "abcDONE=0\n" {
				t.Fatalf("output = %q, want %q", out, "abcDONE=0\n")
			}
		})
	}
}

// TestTTYEOFLateCanonicalReader covers a client that sends its input and EOF
// before the command starts reading. After ttyEOFTimeout the guest queues the
// fallback marker; for an unterminated last line that marker only releases the
// partial line, so a second one must follow or a reader that starts at 6-8 s
// blocks forever. The other cases are the trailing-newline and complete-line
// controls, which need the same single-marker behavior as before.
func TestTTYEOFLateCanonicalReader(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"partial-line", "partial-no-newline"},
		{"trailing-newline", "hello\n"},
		{"partial-after-complete-lines", "alpha\nbeta"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := startTTYReader(t, "stty -echo; sleep 8; cat; echo DONE=$?")
			r.feed(t, tc.input)
			out := r.waitFor(t, "DONE=")
			assertNoNUL(t, out)
			want := tc.input + "DONE=0\n"
			if out != want {
				t.Fatalf("output = %q, want %q", out, want)
			}
		})
	}
}

// TestTTYCanonicalEOFIsPrompt verifies that a canonical reader whose stdin
// already ended gets EOF without paying a fixed startup-settle delay. It also
// covers the partial-line case, which needs a second marker after the first
// one delivers the buffered line.
func TestTTYCanonicalEOFIsPrompt(t *testing.T) {
	for _, input := range []string{"", "abc"} {
		name := "empty"
		if input != "" {
			name = "partial-line"
		}
		t.Run(name, func(t *testing.T) {
			r := startTTYReader(t, "cat; echo DONE=$?")
			start := time.Now()
			r.feed(t, input)
			out := r.waitFor(t, "DONE=")
			elapsed := time.Since(start)
			assertNoNUL(t, out)
			if out != input+"DONE=0\n" {
				t.Fatalf("output = %q, want %q", out, input+"DONE=0\n")
			}
			// The previous implementation always waited ttyEOFSettle (500ms)
			// before it would deliver a canonical EOF.
			if elapsed >= 400*time.Millisecond {
				t.Fatalf("canonical EOF took %v; it should not wait for a startup settle", elapsed)
			}
		})
	}
}

// TestTTYRawThenCanonicalRestoreDoesNotHang covers a program that briefly
// enters raw mode and restores canonical mode before reading to EOF. The old
// fallback assumed canonical mode at the check meant EOF had been consumed,
// so the read blocked forever.
func TestTTYRawThenCanonicalRestoreDoesNotHang(t *testing.T) {
	r := startTTYReader(t, "sleep 0.1; stty raw -echo; sleep 0.1; stty sane; cat; echo DONE=$?")
	r.feed(t, "abc")
	out := r.waitFor(t, "DONE=")
	assertNoNUL(t, out)
	if out != "abcDONE=0\n" {
		t.Fatalf("output = %q, want %q", out, "abcDONE=0\n")
	}
}

// TestTTYInteractiveShellEOFExitsCleanly pipes a script to an interactive
// shell. The shell switches the terminal to raw mode while reading; EOF must
// end it cleanly instead of hanging it up (SIGHUP, exit 129).
func TestTTYInteractiveShellEOFExitsCleanly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	r := startTTYReader(t, "bash -i; echo DONE=$?")
	r.feed(t, "echo BASH_OK\n")
	out := r.waitFor(t, "DONE=")
	assertNoNUL(t, out)
	if !bytes.Contains([]byte(out), []byte("BASH_OK")) {
		t.Fatalf("shell did not run the piped command: %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("DONE=0")) {
		t.Fatalf("interactive shell did not exit cleanly: %q", out)
	}
}

// TestTTYRawEOFSubmitsPartialLine verifies that a piped partial line reaches a
// raw reader and is followed by EOF without VEOF appearing as input.
func TestTTYRawEOFSubmitsPartialLine(t *testing.T) {
	r := startTTYReader(t, "stty raw -echo; echo READY; IFS= read -r x; echo GOT=$x; echo DONE=$?")
	r.waitFor(t, "READY")
	r.feed(t, "abc")
	out := r.waitFor(t, "DONE=")
	assertNoNUL(t, out)
	if !bytes.Contains([]byte(out), []byte("GOT=abc")) {
		t.Fatalf("partial line was not executed: %q", out)
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

// TestNonTTYInputIsNeverDropped verifies that a full non-terminal queue makes
// the writer wait instead of discarding bytes. The wait ends when the session
// closes, so a command that exits cannot wedge the client.
func TestNonTTYInputIsNeverDropped(t *testing.T) {
	s := &session{out: ring{max: ringSize}}
	s.inCond = sync.NewCond(&s.inMu)
	s.inBytes = maxQueuedInput
	done := make(chan error, 1)
	go func() { done <- s.queueInput([]byte("tail")) }()
	select {
	case err := <-done:
		t.Fatalf("queueInput returned %v instead of waiting for space", err)
	case <-time.After(200 * time.Millisecond):
	}
	if s.takeDropped() {
		t.Fatal("non-terminal input was dropped")
	}
	s.closeInput()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queueInput did not return after the session closed")
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
