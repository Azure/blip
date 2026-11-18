package session_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

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
