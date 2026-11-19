// Package session is the client side of guest sessions. A Connector reaches
// the guest session port of a VM pod (normally through pod exec of
// `blip-runtime bridge 1025`); the session then speaks internal/wire.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Azure/blip/internal/wire"
)

// ErrUnreachable means the VM went away before it answered an open request.
// Callers that can recreate the sandbox may retry; the command did not get a
// chance to report an outcome.
var ErrUnreachable = errors.New("the VM is not reachable; it may have stopped or crashed")

// Connector opens a byte stream to the guest session port of a VM pod. The
// stream lives until it is closed or ctx is done. Callers that must still
// signal a guest after their own request is gone have to pass a context that
// outlives that request.
type Connector func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error)

// Client opens guest sessions.
type Client struct {
	Connect Connector
}

// Open starts or joins a session (o.Mode exec or attach). A caller that may
// retry after ErrUnreachable should reuse o.OpenID across attempts: the guest
// attaches to a session it already started instead of running the command
// again. An empty OpenID preserves the old behavior for existing clients.
func (c *Client) Open(ctx context.Context, namespace, pod string, o wire.Open) (*Session, error) {
	rwc, err := c.Connect(ctx, namespace, pod)
	if err != nil {
		return nil, err
	}
	conn := wire.NewConn(rwc)
	if err := conn.WriteJSON(wire.TOpen, o); err != nil {
		rwc.Close()
		// A pod that stopped between ensure and exec can close the pipe
		// here. A transport error does not prove the guest saw no bytes:
		// retries must preserve OpenID even when the request write failed.
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	t, payload, err := conn.Read()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		rwc.Close()
		// The guest may have received the open even though its answer was
		// lost, so a retry must carry the same OpenID.
		return nil, ErrUnreachable
	}
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("open session: %w", err)
	}
	if t != wire.TOpened {
		rwc.Close()
		return nil, fmt.Errorf("open session: unexpected frame type %d", t)
	}
	s := &Session{rwc: rwc, conn: conn}
	if err := wire.Decode(payload, &s.Opened); err != nil {
		rwc.Close()
		return nil, fmt.Errorf("open session: %w", err)
	}
	if s.Opened.Error != "" {
		rwc.Close()
		return nil, errors.New(s.Opened.Error)
	}
	return s, nil
}

// Session is one open guest session. Send methods are safe for concurrent
// use; Recv and Copy must be called from one goroutine.
type Session struct {
	Opened wire.Opened
	rwc    io.ReadWriteCloser
	conn   *wire.Conn
	once   sync.Once
}

// Frame is one message from the guest.
type Frame struct {
	Type   wire.Type // TStdout, TStderr, TExited or TNotice
	Data   []byte
	Exit   *wire.Exit
	Notice string
}

const chunk = 32 << 10

// Write sends stdin.
func (s *Session) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := min(len(p), chunk)
		if err := s.conn.Write(wire.TStdin, p[:c]); err != nil {
			return n, err
		}
		n += c
		p = p[c:]
	}
	return n, nil
}

// CloseStdin sends end of input.
func (s *Session) CloseStdin() error { return s.conn.WriteJSON(wire.TStdinEOF, struct{}{}) }

func (s *Session) Resize(rows, cols uint16) error {
	return s.conn.WriteJSON(wire.TResize, wire.Resize{Rows: rows, Cols: cols})
}

// Signal sends a signal by name, e.g. "INT" or "HUP".
func (s *Session) Signal(name string) error {
	return s.conn.WriteJSON(wire.TSignal, wire.Signal{Name: name})
}

// Close disconnects. The guest keeps the session running.
func (s *Session) Close() error {
	var err error
	s.once.Do(func() { err = s.rwc.Close() })
	return err
}

// Recv returns the next frame. It returns io.EOF when the stream ends.
func (s *Session) Recv() (Frame, error) {
	for {
		t, payload, err := s.conn.Read()
		if err != nil {
			return Frame{}, err
		}
		switch t {
		case wire.TStdout, wire.TStderr:
			return Frame{Type: t, Data: payload}, nil
		case wire.TExited:
			var e wire.Exit
			if err := wire.Decode(payload, &e); err != nil {
				return Frame{}, err
			}
			return Frame{Type: t, Exit: &e}, nil
		case wire.TNotice:
			var n wire.Notice
			if err := wire.Decode(payload, &n); err != nil {
				return Frame{}, err
			}
			return Frame{Type: t, Notice: n.Message}, nil
		}
	}
}

// ErrDisconnected means the stream ended before the session exited.
var ErrDisconnected = errors.New("connection to the session was lost")

// Copy writes output until the session exits and returns its exit status.
// notice may be nil.
func (s *Session) Copy(stdout, stderr io.Writer, notice func(string)) (*wire.Exit, error) {
	for {
		f, err := s.Recv()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrDisconnected
		}
		if err != nil {
			return nil, err
		}
		switch f.Type {
		case wire.TStdout:
			if _, err := stdout.Write(f.Data); err != nil {
				return nil, err
			}
		case wire.TStderr:
			if _, err := stderr.Write(f.Data); err != nil {
				return nil, err
			}
		case wire.TNotice:
			if notice != nil {
				notice(f.Notice)
			}
		case wire.TExited:
			return f.Exit, nil
		}
	}
}
