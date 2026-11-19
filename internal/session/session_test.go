package session_test

import (
	"bytes"
	"context"
	"errors"
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
