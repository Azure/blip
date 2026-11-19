package session_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// transcriptConn preserves the real client's request serialization and wire
// decoder while deterministically cutting a remote transcript at any byte.
type transcriptConn struct {
	*bytes.Reader
	request bytes.Buffer
	closed  bool
}

func (c *transcriptConn) Write(p []byte) (int, error) { return c.request.Write(p) }
func (c *transcriptConn) Close() error                { c.closed = true; return nil }

func transcriptClient(data []byte) (*session.Client, *transcriptConn) {
	c := &transcriptConn{Reader: bytes.NewReader(data)}
	return &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) { return c, nil }}, c
}

func encodedFrame(t *testing.T, typ wire.Type, v any) []byte {
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

func TestOpenEveryTornAcknowledgementIsUnreachable(t *testing.T) {
	ack := encodedFrame(t, wire.TOpened, wire.Opened{Session: "existing"})
	for cut := 0; cut < len(ack); cut++ {
		t.Run(fmt.Sprintf("cut-%d", cut), func(t *testing.T) {
			c, transport := transcriptClient(ack[:cut])
			_, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec, OpenID: "same-attempt"})
			if !errors.Is(err, session.ErrUnreachable) || !transport.closed {
				t.Fatalf("cut %d: err=%v closed=%v", cut, err, transport.closed)
			}
			// The retry ID must reach the actual wire, not just a fake guest API.
			typ, payload, err := wire.NewConn(&transport.request).Read()
			var open wire.Open
			if err != nil || typ != wire.TOpen || wire.Decode(payload, &open) != nil || open.OpenID != "same-attempt" {
				t.Fatalf("retry identity lost: type=%d payload=%s err=%v", typ, payload, err)
			}
		})
	}
}

func TestCopyRequiresCompleteExitFrame(t *testing.T) {
	ack := encodedFrame(t, wire.TOpened, wire.Opened{Session: "command"})
	output := encodedFrame(t, wire.TStdout, []byte("committed"))
	exit := encodedFrame(t, wire.TExited, wire.Exit{Code: 17})
	for cut := 0; cut <= len(exit); cut++ {
		data := append(append(append([]byte(nil), ack...), output...), exit[:cut]...)
		c, _ := transcriptClient(data)
		s, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		status, err := s.Copy(&out, io.Discard, nil)
		s.Close()
		if out.String() != "committed" {
			t.Fatalf("cut %d lost complete output: %q", cut, out.String())
		}
		if cut < len(exit) {
			if !errors.Is(err, session.ErrDisconnected) || status != nil {
				t.Fatalf("cut %d invented an exit: %+v %v", cut, status, err)
			}
		} else if err != nil || status.Code != 17 {
			t.Fatalf("complete exit: %+v %v", status, err)
		}
	}
}

// idleConn models a transport that tears the exec stream down when it is not
// read for idle. The real pod-exec path can drop an idle stream while the
// local stdout consumer is stalled, which used to lose the tail of a command
// that had already exited.
type idleConn struct {
	r    *bytes.Reader
	last time.Time
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if time.Since(c.last) > c.idle {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := c.r.Read(p)
	c.last = time.Now()
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *idleConn) Close() error                { return nil }

// stallWriter blocks the first write until gate is closed, modelling a local
// stdout consumer that is not reading.
type stallWriter struct {
	gate chan struct{}
	once sync.Once
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (w *stallWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { <-w.gate })
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *stallWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

// A local consumer that stalls for a while must not lose output the guest
// already sent, even if the transport would have torn down an idle stream.
// The client reads ahead into a bounded queue while the writer is blocked, so
// a command that exits 0 still delivers every byte and rc 0.
func TestCopyKeepsOutputThroughStalledConsumer(t *testing.T) {
	const total = 5_000_000
	data := bytes.Repeat([]byte("a"), total)
	var transcript bytes.Buffer
	transcript.Write(encodedFrame(t, wire.TOpened, wire.Opened{Session: "s"}))
	for off := 0; off < total; off += 32 << 10 {
		end := min(off+(32<<10), total)
		transcript.Write(encodedFrame(t, wire.TStdout, data[off:end]))
	}
	transcript.Write(encodedFrame(t, wire.TExited, wire.Exit{Code: 0}))

	c := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return &idleConn{r: bytes.NewReader(transcript.Bytes()), last: time.Now(), idle: 200 * time.Millisecond}, nil
	}}
	s, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec, Argv: []string{"cat"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	w := &stallWriter{gate: make(chan struct{})}
	closed := make(chan struct{})
	time.AfterFunc(600*time.Millisecond, func() {
		close(w.gate)
		close(closed)
	})
	exit, err := s.Copy(w, io.Discard, nil)
	<-closed
	if err != nil {
		t.Fatalf("Copy returned %v, want success", err)
	}
	if exit == nil || exit.Code != 0 {
		t.Fatalf("exit = %+v, want code 0", exit)
	}
	if got := w.Len(); got != total {
		t.Fatalf("delivered %d of %d output bytes", got, total)
	}
}

// A transport failure before the exit status must still be reported (never a
// silent rc 0), while every frame that was received is delivered first.
func TestCopyReportsLostExitAfterDeliveringQueuedFrames(t *testing.T) {
	const total = 1 << 20
	data := bytes.Repeat([]byte("b"), total)
	var transcript bytes.Buffer
	transcript.Write(encodedFrame(t, wire.TOpened, wire.Opened{Session: "s"}))
	for off := 0; off < total; off += 32 << 10 {
		end := min(off+(32<<10), total)
		transcript.Write(encodedFrame(t, wire.TStdout, data[off:end]))
	}
	c := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		// No TExited: the stream ends after the output.
		return &transcriptConn{Reader: bytes.NewReader(transcript.Bytes())}, nil
	}}
	s, err := c.Open(context.Background(), "ns", "pod", wire.Open{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out bytes.Buffer
	exit, err := s.Copy(&out, io.Discard, nil)
	if !errors.Is(err, session.ErrDisconnected) || exit != nil {
		t.Fatalf("exit=%+v err=%v, want ErrDisconnected and no exit", exit, err)
	}
	if out.Len() != total {
		t.Fatalf("delivered %d of %d received bytes", out.Len(), total)
	}
}

func TestClientRejectsMalformedControlPayloads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     wire.Type
		payload []byte
	}{
		{"wrong-open-type", wire.TStdout, []byte("not an ack")},
		{"invalid-open-json", wire.TOpened, []byte("{")},
		{"wrong-open-shape", wire.TOpened, []byte(`{"session":7}`)},
		{"empty-open", wire.TOpened, nil},
		{"null-open", wire.TOpened, []byte("null")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, transport := transcriptClient(encodedFrame(t, tc.typ, tc.payload))
			if _, err := c.Open(context.Background(), "ns", "pod", wire.Open{}); err == nil || errors.Is(err, session.ErrUnreachable) || !transport.closed {
				t.Fatalf("protocol error misclassified: %v closed=%v", err, transport.closed)
			}
		})
	}
	for _, typ := range []wire.Type{wire.TNotice, wire.TExited} {
		for _, payload := range [][]byte{[]byte("{"), nil, []byte("null"), []byte(" \n ")} {
			data := append(encodedFrame(t, wire.TOpened, wire.Opened{}), encodedFrame(t, typ, payload)...)
			c, _ := transcriptClient(data)
			s, err := c.Open(context.Background(), "ns", "pod", wire.Open{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Recv(); err == nil {
				t.Fatalf("accepted malformed frame %d: %q", typ, payload)
			}
			s.Close()
		}
	}
}
