package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

func TestExecSessionStreamsAndExits(t *testing.T) {
	g := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		in := s.ReadAll()
		s.Stdout("out:" + in)
		s.Stderr("err")
		s.Notice("dropped")
		return wire.Exit{Code: 3}
	}}
	c := &session.Client{Connect: g.Connect}
	s, err := c.Open(context.Background(), "ns", "pod-1", wire.Open{Mode: wire.OpenExec, Argv: []string{"cat"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Opened.Session == "" {
		t.Fatal("no session id")
	}
	big := strings.Repeat("x", 100<<10)
	go func() {
		s.Write([]byte(big))
		s.CloseStdin()
	}()
	var out, errb bytes.Buffer
	var notices []string
	exit, err := s.Copy(&out, &errb, func(m string) { notices = append(notices, m) })
	if err != nil {
		t.Fatal(err)
	}
	if exit.Code != 3 || out.String() != "out:"+big || errb.String() != "err" || len(notices) != 1 {
		t.Fatalf("exit=%v out=%d err=%q notices=%v", exit, out.Len(), errb.String(), notices)
	}
	if r := g.Opens()[0]; r.Pod != "pod-1" || r.Open.Argv[0] != "cat" {
		t.Fatalf("open = %+v", r)
	}
}

func TestSignalsAndResize(t *testing.T) {
	g := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		r := s.NextEvent()
		sig := s.NextEvent()
		if r.Resize == nil || r.Resize.Rows != 40 || sig.Signal != "INT" {
			return wire.Exit{Code: 99}
		}
		return wire.Exit{Code: 130, Signal: "INT"}
	}}
	c := &session.Client{Connect: g.Connect}
	s, err := c.Open(context.Background(), "ns", "p", wire.Open{Mode: wire.OpenExec, TTY: true})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Opened.TTY {
		t.Fatal("want tty")
	}
	s.Resize(40, 100)
	s.Signal("INT")
	exit, err := s.Copy(io.Discard, io.Discard, nil)
	if err != nil || exit.Code != 130 || exit.Signal != "INT" {
		t.Fatalf("exit=%v err=%v", exit, err)
	}
}

type closedWriteConn struct{}

func (closedWriteConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (closedWriteConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (closedWriteConn) Close() error              { return nil }

func TestOpenClosedPipeIsUnreachable(t *testing.T) {
	c := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return closedWriteConn{}, nil
	}}
	_, err := c.Open(context.Background(), "ns", "p", wire.Open{Mode: wire.OpenExec})
	if !errors.Is(err, session.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

// An Open whose encoded argv and env exceed one wire frame is rejected
// locally and must not look like a VM lifecycle race that callers retry.
func TestOpenOversizedRequestIsTooLarge(t *testing.T) {
	var request bytes.Buffer
	closed := false
	c := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return &recordingConn{request: &request, closed: &closed}, nil
	}}
	big := strings.Repeat("z", 120_000)
	o := wire.Open{Mode: wire.OpenExec, Argv: []string{"true"}, OpenID: "too-big"}
	for i := 0; i < 10; i++ {
		o.Env = append(o.Env, fmt.Sprintf("K%d=%s", i, big))
	}
	_, openErr := c.Open(context.Background(), "ns", "p", o)
	if openErr == nil {
		t.Fatal("oversized Open succeeded")
	}
	payload, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(openErr, session.ErrRequestTooLarge) {
		t.Fatalf("err = %v, want ErrRequestTooLarge", openErr)
	}
	if errors.Is(openErr, session.ErrUnreachable) || strings.Contains(openErr.Error(), "not reachable") {
		t.Fatalf("oversized request misclassified as VM lifecycle failure: %v", openErr)
	}
	if !strings.Contains(openErr.Error(), "request too large") || !strings.Contains(openErr.Error(), fmt.Sprintf("%d bytes", len(payload))) {
		t.Fatalf("error does not explain the size: %v", openErr)
	}
	if !closed || request.Len() != 0 {
		t.Fatalf("closed=%v wrote=%d bytes; want close and no write", closed, request.Len())
	}
}

// A 200 KB argv of JSON HTML metacharacters is well under the frame limit.
// HTML escaping must not reject it at about one sixth of the real limit.
func TestOpenHTMLMetacharactersAreNotOversized(t *testing.T) {
	lt := strings.Repeat("<", 100_000)
	amp := strings.Repeat("&", 100_000)
	g := &fakeguest.Guest{}
	c := &session.Client{Connect: g.Connect}
	s, err := c.Open(context.Background(), "ns", "p", wire.Open{
		Mode: wire.OpenExec,
		Argv: []string{"true", lt, amp},
	})
	if err != nil {
		t.Fatalf("Open rejected HTML metacharacters: %v", err)
	}
	s.Close()
	opens := g.Opens()
	if len(opens) != 1 || len(opens[0].Open.Argv) != 3 ||
		opens[0].Open.Argv[1] != lt || opens[0].Open.Argv[2] != amp {
		t.Fatalf("guest received changed argv: %+v", opens)
	}
}

// Invalid UTF-8 would be silently rewritten to U+FFFD by encoding/json. The
// client rejects it before connecting so a command never runs with different
// arguments or environment than the caller supplied.
func TestOpenRejectsInvalidUTF8BeforeSending(t *testing.T) {
	bad := string([]byte{0xff, 0xfe, 'A'})
	for _, tc := range []struct {
		name string
		o    wire.Open
		want string
	}{
		{"argv", wire.Open{Mode: wire.OpenExec, Argv: []string{"true", bad}}, "argv[1]"},
		{"env", wire.Open{Mode: wire.OpenExec, Argv: []string{"true"}, Env: []string{"BAD=" + bad}}, "env[0]"},
		{"workdir", wire.Open{Mode: wire.OpenExec, Argv: []string{"true"}, WorkingDir: "/tmp/" + bad}, "workingDir"},
		{"user", wire.Open{Mode: wire.OpenExec, Argv: []string{"true"}, User: bad}, "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var request bytes.Buffer
			connected := false
			c := &session.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
				connected = true
				return &recordingConn{request: &request, closed: new(bool)}, nil
			}}
			_, err := c.Open(context.Background(), "ns", "p", tc.o)
			if !errors.Is(err, session.ErrInvalidUTF8) {
				t.Fatalf("err = %v, want ErrInvalidUTF8", err)
			}
			if errors.Is(err, session.ErrUnreachable) || errors.Is(err, session.ErrRequestTooLarge) {
				t.Fatalf("invalid UTF-8 misclassified: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "UTF-8") {
				t.Fatalf("error does not name the field: %v", err)
			}
			if connected || request.Len() != 0 {
				t.Fatalf("connected=%v wrote=%d bytes; want rejection before send", connected, request.Len())
			}
		})
	}
}

// recordingConn records the request bytes and whether the client closed it.
type recordingConn struct {
	request *bytes.Buffer
	closed  *bool
}

func (c *recordingConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error) { return c.request.Write(p) }
func (c *recordingConn) Close() error {
	*c.closed = true
	return nil
}

func TestOpenError(t *testing.T) {
	g := &fakeguest.Guest{OpenError: "no such session"}
	c := &session.Client{Connect: g.Connect}
	_, err := c.Open(context.Background(), "ns", "p", wire.Open{Mode: wire.OpenAttach, Session: "x"})
	if err == nil || err.Error() != "no such session" {
		t.Fatalf("err = %v", err)
	}
}

func TestDisconnectBeforeExit(t *testing.T) {
	release := make(chan struct{})
	g := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		<-release
		return wire.Exit{}
	}}
	c := &session.Client{Connect: g.Connect}
	s, err := c.Open(context.Background(), "ns", "p", wire.Open{Mode: wire.OpenAttach})
	if err != nil {
		t.Fatal(err)
	}
	defer close(release)
	go s.Close()
	_, err = s.Copy(io.Discard, io.Discard, nil)
	if !errors.Is(err, session.ErrDisconnected) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("err = %v", err)
	}
}
