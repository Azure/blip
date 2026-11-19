// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Azure/blip/internal/wire"
)

const (
	// stdioBufferMax is the output retained per stream. A node agent that
	// reconnects is replayed from the start of this history.
	stdioBufferMax = 256 << 10
)

// streamBuf is one output stream with absolute byte offsets. data[0] is the
// byte at offset start; end is the offset just past the last retained byte.
type streamBuf struct {
	data  []byte
	start uint64
}

func (b *streamBuf) end() uint64 { return b.start + uint64(len(b.data)) }

func (b *streamBuf) append(p []byte) {
	b.data = append(b.data, p...)
}

// drop forgets everything before the absolute offset until.
func (b *streamBuf) drop(until uint64) {
	if until <= b.start {
		return
	}
	if until > b.end() {
		until = b.end()
	}
	n := int(until - b.start)
	b.data = b.data[n:]
	b.start = until
}

// since returns the retained bytes from off on. An offset older than the
// retained history returns everything still buffered.
func (b *streamBuf) since(off uint64) []byte {
	if off < b.start {
		return b.data
	}
	n := off - b.start
	if n > uint64(len(b.data)) {
		return nil
	}
	return b.data[n:]
}

func (b *streamBuf) tail(max int) string {
	if max <= 0 || len(b.data) == 0 {
		return ""
	}
	p := b.data
	if len(p) > max {
		p = p[len(p)-max:]
		if i := bytes.IndexByte(p, '\n'); i >= 0 && i < len(p)-1 {
			p = p[i+1:]
		}
	}
	return strings.ToValidUTF8(string(p), "")
}

// stdio serves the primary command's output and input on the stdio port. One
// connection is current; a new one replaces it. Output is retained so a
// reconnecting node agent is replayed the history it missed.
type stdio struct {
	mu   sync.Mutex
	cond *sync.Cond

	out streamBuf
	err streamBuf

	stdin  *os.File
	exit   *wire.Exit
	conn   *stdioConn
	closed bool
}

type stdioConn struct {
	f      io.ReadWriteCloser
	w      *wire.Conn
	out    uint64 // next stdout offset to send
	err    uint64 // next stderr offset to send
	closed bool
}

func newStdio() *stdio {
	s := &stdio{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stdio) buf(t wire.Type) *streamBuf {
	if t == wire.TStderr {
		return &s.err
	}
	return &s.out
}

func (c *stdioConn) cursor(t wire.Type) uint64 {
	if t == wire.TStderr {
		return c.err
	}
	return c.out
}

// attach makes f the current stdio connection and sends StdioHello first.
// The previous connection, if any, is closed.
func (s *stdio) attach(f io.ReadWriteCloser) *stdioConn {
	if s == nil {
		f.Close()
		return nil
	}
	c := &stdioConn{f: f, w: wire.NewConn(f)}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		f.Close()
		return nil
	}
	old := s.conn
	// Replay everything retained. The agent drops records it already has,
	// which also covers output produced before its first connection.
	c.out, c.err = s.out.start, s.err.start
	s.conn = c
	exit := s.exit
	s.mu.Unlock()
	if old != nil {
		s.mu.Lock()
		old.closed = true
		s.mu.Unlock()
		old.f.Close()
	}
	if err := c.w.WriteJSON(wire.TStdioHello, wire.StdioHello{Exit: exit}); err != nil {
		f.Close()
		s.detach(c)
		return nil
	}
	go s.writeLoop(c)
	return c
}

func (s *stdio) detach(c *stdioConn) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.conn == c {
		s.conn = nil
	}
	c.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// append accepts one output chunk from a pump. It never drops bytes a
// connection has not consumed: when the buffer is full the pump blocks until
// a connection is attached and output drains.
func (s *stdio) append(t wire.Type, p []byte) {
	if s == nil || len(p) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buf(t)
	for !s.closed && len(b.data)+len(p) > stdioBufferMax {
		need := uint64(len(b.data) + len(p) - stdioBufferMax)
		var allowed uint64
		if s.conn != nil && s.conn.cursor(t) > b.start {
			allowed = s.conn.cursor(t) - b.start
		}
		drop := min(need, allowed)
		if drop == 0 {
			if len(b.data) == 0 {
				break
			}
			s.cond.Wait()
			continue
		}
		b.drop(b.start + drop)
	}
	if s.closed {
		return
	}
	b.append(p)
	s.cond.Broadcast()
}

// writeLoop replays retained output then follows live output until the
// connection closes or the exit status has been delivered.
func (s *stdio) writeLoop(c *stdioConn) {
	preferErr := false
	for {
		s.mu.Lock()
		if c.closed {
			s.mu.Unlock()
			return
		}
		var typ wire.Type
		var off uint64
		var data []byte
		out := s.out.since(c.out)
		errb := s.err.since(c.err)
		switch {
		case preferErr && len(errb) > 0:
			typ, off, data = wire.TStderr, c.err, errb
		case len(out) > 0:
			typ, off, data = wire.TStdout, c.out, out
		case len(errb) > 0:
			typ, off, data = wire.TStderr, c.err, errb
		}
		if len(data) > 0 {
			if len(data) > wire.MaxFrame-8 {
				data = data[:wire.MaxFrame-8]
			}
			preferErr = typ == wire.TStdout
			s.mu.Unlock()
			if err := c.w.Write(typ, wire.EncodeData(off, data)); err != nil {
				c.f.Close()
				return
			}
			s.mu.Lock()
			if s.conn == c {
				if typ == wire.TStdout {
					c.out = off + uint64(len(data))
				} else {
					c.err = off + uint64(len(data))
				}
				s.cond.Broadcast()
			}
			s.mu.Unlock()
			continue
		}
		if s.exit != nil && c.out >= s.out.end() && c.err >= s.err.end() {
			ex := *s.exit
			s.mu.Unlock()
			_ = c.w.WriteJSON(wire.TExited, ex)
			return
		}
		s.cond.Wait()
		s.mu.Unlock()
	}
}

// serveStdio serves one connection on the stdio port.
func (g *Guest) serveStdio(f io.ReadWriteCloser) {
	c := g.stdio.attach(f)
	if c == nil {
		return
	}
	defer func() {
		g.stdio.detach(c)
		f.Close()
	}()
	for {
		t, payload, err := c.w.Read()
		if err != nil {
			return
		}
		switch t {
		case wire.TStdin:
			g.stdio.writeStdin(payload)
		case wire.TStdinEOF:
			g.stdio.closeStdin()
		}
	}
}

// setStdin gives the stdio server the primary command's input pipe.
func (s *stdio) setStdin(f *os.File) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stdin = f
	s.mu.Unlock()
}

// writeStdin writes host input to the command. A full pipe blocks the host's
// frame loop, which is the only consumer of that input.
func (s *stdio) writeStdin(p []byte) {
	if s == nil || len(p) == 0 {
		return
	}
	s.mu.Lock()
	f := s.stdin
	s.mu.Unlock()
	if f != nil {
		_, _ = f.Write(p)
	}
}

// closeStdin ends the command's input.
func (s *stdio) closeStdin() {
	if s == nil {
		return
	}
	s.mu.Lock()
	f := s.stdin
	s.stdin = nil
	s.mu.Unlock()
	if f != nil {
		f.Close()
	}
}

// setExit records the primary command's exit status and wakes the writer so
// it can flush the remaining output and send Exited.
func (s *stdio) setExit(ex wire.Exit) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.exit = &ex
	s.cond.Broadcast()
	s.mu.Unlock()
}

// tail returns the end of the command's output for a failed exit.
func (s *stdio) tail(max int) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.err.tail(max); t != "" {
		return t
	}
	return s.out.tail(max)
}

// close releases the buffers, input pipe and current connection. Pumps that
// are blocked on a full buffer return, so shutdown cannot deadlock on them.
func (s *stdio) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	c := s.conn
	s.conn = nil
	f := s.stdin
	s.stdin = nil
	if c != nil {
		c.closed = true
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	if f != nil {
		f.Close()
	}
	if c != nil {
		c.f.Close()
	}
}
