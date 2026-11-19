// Package fakeguest is an in-memory guest session server for tests. It speaks
// internal/wire like blip-guest on the session port.
package fakeguest

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Azure/blip/internal/wire"
)

// Guest implements session.Connector through its Connect method.
type Guest struct {
	// Run handles exec and attach sessions and returns the exit status.
	// The default exits 0 immediately.
	Run func(s *Session) wire.Exit
	// OpenError, if set, rejects exec and attach requests.
	OpenError string

	mu    sync.Mutex
	opens []Request
	next  int
}

// Request is one received Open.
type Request struct {
	Pod  string
	Open wire.Open
}

// Opens returns every Open received so far.
func (g *Guest) Opens() []Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Request(nil), g.opens...)
}

func (g *Guest) Connect(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	go g.serve(pod, server)
	return client, nil
}

// Session is one guest session seen by Run.
type Session struct {
	Pod  string
	Open wire.Open
	ID   string
	// Stdin ends at StdinEOF or when the client disconnects.
	Stdin io.Reader
	// Events receives signals, resizes and the disconnect.
	Events chan Event
	conn   *wire.Conn
}

type Event struct {
	Signal       string
	Resize       *wire.Resize
	Disconnected bool
}

func (s *Session) Stdout(p string)  { s.conn.Write(wire.TStdout, []byte(p)) }
func (s *Session) Stderr(p string)  { s.conn.Write(wire.TStderr, []byte(p)) }
func (s *Session) Notice(m string)  { s.conn.WriteJSON(wire.TNotice, wire.Notice{Message: m}) }
func (s *Session) ReadAll() string  { b, _ := io.ReadAll(s.Stdin); return string(b) }
func (s *Session) NextEvent() Event { return <-s.Events }
func (s *Session) send(e Event) {
	select {
	case s.Events <- e:
	default:
	}
}
func (g *Guest) record(r Request) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.opens = append(g.opens, r)
	g.next++
	return g.next
}

func (g *Guest) serve(pod string, c net.Conn) {
	defer c.Close()
	conn := wire.NewConn(c)
	t, payload, err := conn.Read()
	if err != nil || t != wire.TOpen {
		return
	}
	var o wire.Open
	if err := wire.Decode(payload, &o); err != nil {
		return
	}
	n := g.record(Request{Pod: pod, Open: o})
	if g.OpenError != "" {
		conn.WriteJSON(wire.TOpened, wire.Opened{Error: g.OpenError})
		return
	}
	id := o.Session
	if o.Mode == wire.OpenExec {
		id = fmt.Sprintf("s%d", n)
	} else if id == "" {
		id = wire.PrimarySession
	}
	conn.WriteJSON(wire.TOpened, wire.Opened{Session: id, TTY: o.TTY})
	pr, pw := io.Pipe()
	s := &Session{Pod: pod, Open: o, ID: id, Stdin: pr, Events: make(chan Event, 64), conn: conn}
	go func() {
		for {
			t, p, err := conn.Read()
			if err != nil {
				pw.CloseWithError(io.EOF)
				s.send(Event{Disconnected: true})
				return
			}
			switch t {
			case wire.TStdin:
				pw.Write(p)
			case wire.TStdinEOF:
				pw.Close()
			case wire.TResize:
				var r wire.Resize
				wire.Decode(p, &r)
				s.send(Event{Resize: &r})
			case wire.TSignal:
				var sig wire.Signal
				wire.Decode(p, &sig)
				s.send(Event{Signal: sig.Name})
			}
		}
	}()
	exit := wire.Exit{}
	if g.Run != nil {
		exit = g.Run(s)
	}
	conn.WriteJSON(wire.TExited, exit)
}
