package session

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
)

func frameBytesForTest(t *testing.T, typ wire.Type, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	c := wire.NewConn(&b)
	var err error
	if data, ok := v.([]byte); ok {
		err = c.Write(typ, data)
	} else {
		err = c.WriteJSON(typ, v)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type spoolTestWriter struct {
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	buf     bytes.Buffer
}

func (w *spoolTestWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { <-w.release })
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *spoolTestWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

// TestCopySpoolsOutputPastReadAhead is the w7-10 defect 1 regression: a local
// stdout consumer that stalls for longer than the transport's idle timeout
// while more than outputReadAhead is buffered must not make the client stop
// reading the transport, lose the tail, or turn a successful command into a
// failed exec. The excess is spooled to a temporary file and delivered in
// order once the consumer resumes.
func TestCopySpoolsOutputPastReadAhead(t *testing.T) {
	dir := t.TempDir()
	oldDir := outputSpoolDir
	outputSpoolDir = dir
	t.Cleanup(func() { outputSpoolDir = oldDir })

	const total = 12 << 20
	const chunkSize = 32 << 10
	data := bytes.Repeat([]byte("s"), total)
	var transcript bytes.Buffer
	transcript.Write(frameBytesForTest(t, wire.TOpened, wire.Opened{Session: "stall"}))
	for off := 0; off < total; off += chunkSize {
		transcript.Write(frameBytesForTest(t, wire.TStdout, data[off:min(off+chunkSize, total)]))
	}
	transcript.Write(frameBytesForTest(t, wire.TExited, wire.Exit{Code: 0}))

	conn := &idleTestConn{
		r:    bytes.NewReader(transcript.Bytes()),
		last: time.Now(),
		idle: 200 * time.Millisecond,
	}
	client := &Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return conn, nil
	}}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	w := &spoolTestWriter{release: make(chan struct{})}
	time.AfterFunc(600*time.Millisecond, func() { close(w.release) })
	exit, err := s.Copy(w, io.Discard, nil)
	if err != nil {
		t.Fatalf("Copy returned %v, want success", err)
	}
	if exit == nil || exit.Code != 0 {
		t.Fatalf("exit = %+v, want code 0", exit)
	}
	if got := w.Len(); got != total {
		t.Fatalf("delivered %d of %d output bytes", got, total)
	}
	if !bytes.Equal(w.buf.Bytes(), data) {
		t.Fatal("spooled output was not delivered in order")
	}
	spooled, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(spooled) != 0 {
		t.Fatalf("spool files were not cleaned up: %v", spooled)
	}
}

// TestOutputQueueSpoolIsUnlinkedWhileOpen is the w8-12 F3 regression: a
// SIGKILLed client never runs cleanup, so the spool must not keep a named file
// in the temp directory. The open descriptor still holds the data.
func TestOutputQueueSpoolIsUnlinkedWhileOpen(t *testing.T) {
	dir := t.TempDir()
	oldDir := outputSpoolDir
	outputSpoolDir = dir
	t.Cleanup(func() { outputSpoolDir = oldDir })

	q := newOutputQueue(16)
	defer q.cleanup()
	frames := []Frame{
		{Type: wire.TStdout, Data: []byte("0123456789abcdef")},
		{Type: wire.TStderr, Data: []byte("fedcba9876543210")},
	}
	for _, f := range frames {
		if !q.put(f) {
			t.Fatal("put failed")
		}
	}
	if q.spool == nil {
		t.Fatal("the second frame was not spooled")
	}
	if _, err := os.Stat(q.spool.Name()); !os.IsNotExist(err) {
		t.Fatalf("spool path still exists: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("spool kept a named temp file: %v", entries)
	}
	for _, want := range frames {
		got, err := q.get()
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("get = %+v, want %+v", got, want)
		}
	}
	// A graceful close still releases the descriptor and leaves nothing named.
	q.cleanup()
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("spool files were not cleaned up: %v", entries)
	}
}

// idleTestConn tears down the stream when it is not read for idle, like the
// pod-exec transport did after a stalled local consumer.
type idleTestConn struct {
	r    *bytes.Reader
	last time.Time
	idle time.Duration
}

func (c *idleTestConn) Read(p []byte) (int, error) {
	if time.Since(c.last) > c.idle {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := c.r.Read(p)
	c.last = time.Now()
	return n, err
}
func (c *idleTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *idleTestConn) Close() error                { return nil }

// TestCopySpoolLimitFailsInsteadOfTruncating verifies that when output cannot
// be held or spooled, Copy reports an error instead of returning the
// command's successful status for a truncated stream.
func TestCopySpoolLimitFailsInsteadOfTruncating(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldMax := outputSpoolDir, outputSpoolMax
	outputSpoolDir, outputSpoolMax = dir, 64<<10
	t.Cleanup(func() { outputSpoolDir, outputSpoolMax = oldDir, oldMax })

	const total = 10 << 20
	data := bytes.Repeat([]byte("x"), total)
	var transcript bytes.Buffer
	transcript.Write(frameBytesForTest(t, wire.TOpened, wire.Opened{Session: "limit"}))
	for off := 0; off < total; off += 32 << 10 {
		transcript.Write(frameBytesForTest(t, wire.TStdout, data[off:min(off+32<<10, total)]))
	}
	transcript.Write(frameBytesForTest(t, wire.TExited, wire.Exit{Code: 0}))

	client := &Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return &idleTestConn{r: bytes.NewReader(transcript.Bytes()), last: time.Now(), idle: time.Hour}, nil
	}}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	w := &spoolTestWriter{release: make(chan struct{})}
	go func() {
		// Stall until Copy has hit the spool limit.
		time.Sleep(300 * time.Millisecond)
		close(w.release)
	}()
	exit, err := s.Copy(w, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "spool limit") {
		t.Fatalf("Copy = %+v, %v; want a spool-limit error", exit, err)
	}
	if exit != nil {
		t.Fatalf("Copy reported exit %+v after truncation", exit)
	}
}
