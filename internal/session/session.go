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
	"sync/atomic"
	"unicode/utf8"

	"github.com/Azure/blip/internal/wire"
)

// ErrUnreachable means the VM went away before it answered an open request.
// Callers that can recreate the sandbox may retry; the command did not get a
// chance to report an outcome.
var ErrUnreachable = errors.New("the VM is not reachable; it may have stopped or crashed")

// ErrRequestTooLarge means the open request does not fit in one wire frame.
// It is a local validation error: nothing was sent, so retrying cannot help
// and the VM cannot be at fault.
var ErrRequestTooLarge = errors.New("request too large")

// ErrInvalidUTF8 means one of an Open's user-supplied strings is not valid
// UTF-8. JSON would silently replace the bad bytes with U+FFFD, so the client
// rejects the request instead of running a command with different arguments,
// environment, working directory or user than the caller asked for.
var ErrInvalidUTF8 = errors.New("session open requires valid UTF-8")

// ValidateStrings rejects request strings that JSON cannot carry without
// changing them. An Open validates its argv, env, working directory and user
// with it, and a Blip created by run uses it for the same fields so the two
// paths reject the same bytes before any object exists.
func ValidateStrings(argv, env []string, workingDir, user string) error {
	for i, s := range argv {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%w: argv[%d] contains invalid UTF-8", ErrInvalidUTF8, i)
		}
	}
	for i, s := range env {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%w: env[%d] contains invalid UTF-8", ErrInvalidUTF8, i)
		}
	}
	if !utf8.ValidString(workingDir) {
		return fmt.Errorf("%w: workingDir contains invalid UTF-8", ErrInvalidUTF8)
	}
	if !utf8.ValidString(user) {
		return fmt.Errorf("%w: user contains invalid UTF-8", ErrInvalidUTF8)
	}
	return nil
}

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
	if err := ValidateStrings(o.Argv, o.Env, o.WorkingDir, o.User); err != nil {
		return nil, err
	}
	rwc, err := c.Connect(ctx, namespace, pod)
	if err != nil {
		return nil, err
	}
	conn := wire.NewConn(rwc)
	if err := conn.WriteJSON(wire.TOpen, o); err != nil {
		rwc.Close()
		var sizeErr *wire.FrameSizeError
		if errors.As(err, &sizeErr) {
			// argv and env share one Open frame. Rejecting it locally must
			// not look like a VM lifecycle race: a retry reusing OpenID
			// would fail the same way.
			return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte frame limit; argv and env are sent in one frame", ErrRequestTooLarge, sizeErr.Size, wire.MaxFrame)
		}
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
		if s.Opened.Code != 0 {
			return nil, &OpenError{Message: s.Opened.Error, Code: s.Opened.Code}
		}
		return nil, errors.New(s.Opened.Error)
	}
	return s, nil
}

// OpenError is a rejected session open. Code is the conventional shell status
// when the guest failed to start the command (126 not executable, 127 command
// not found), so a caller can report it instead of a generic exit 1.
type OpenError struct {
	Message string
	Code    int
}

func (e *OpenError) Error() string { return e.Message }

// Session is one open guest session. Send methods are safe for concurrent
// use; Recv and Copy must be called from one goroutine.
type Session struct {
	Opened wire.Opened
	rwc    io.ReadWriteCloser
	conn   *wire.Conn
	once   sync.Once

	// progress counts completed output writes, and pending counts output
	// frames received but not yet written to the caller's writer. A caller
	// waiting for the command to react to a signal uses both to tell a
	// command that is still shutting down (or output the client is still
	// draining) from one that ignores the signal.
	progress atomic.Int64
	pending  atomic.Int64
}

// Progress reports how much output has been copied to the caller's writers.
// It is monotonic and safe to read from another goroutine.
func (s *Session) Progress() int64 { return s.progress.Load() }

// PendingOutput reports output frames that have been received but not yet
// written. A nonzero value means the client is still delivering output the
// command already produced, not waiting on the guest.
func (s *Session) PendingOutput() int64 { return s.pending.Load() }

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

// Close disconnects. A primary command keeps running without a client; an
// exec command is terminated once its last client goes away.
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

// outputReadAhead bounds output that the client has received from the guest
// but not yet written to the caller. Reading the transport while a local
// stdout consumer is stalled keeps the transport from going idle (some
// transports tear an idle exec stream down after a few seconds) and lets the
// client retain output the command already produced. Beyond this bound the
// transport is backpressured exactly as before, so memory stays bounded.
const outputReadAhead = 8 << 20

// outputQueue decouples the transport reader from the caller's writer. Only
// the reader goroutine calls put and only Copy calls get.
type outputQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	frames []Frame
	bytes  int
	max    int
	done   bool
	err    error
}

func newOutputQueue(max int) *outputQueue {
	q := &outputQueue{max: max}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func frameBytes(f Frame) int {
	if f.Type == wire.TStdout || f.Type == wire.TStderr {
		return len(f.Data)
	}
	return 0
}

// put appends one frame, waiting while the writer is behind. It reports false
// when the queue was stopped because the writer failed.
func (q *outputQueue) put(f Frame) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := frameBytes(f)
	for !q.done && q.bytes+n > q.max && len(q.frames) > 0 {
		q.cond.Wait()
	}
	if q.done {
		return false
	}
	q.frames = append(q.frames, f)
	q.bytes += n
	q.cond.Signal()
	return true
}

// get removes the next frame. It returns the reader's error once every
// received frame has been consumed, so no complete frame is discarded by a
// transport failure.
func (q *outputQueue) get() (Frame, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.frames) == 0 && !q.done {
		q.cond.Wait()
	}
	if len(q.frames) > 0 {
		f := q.frames[0]
		q.frames = q.frames[1:]
		q.bytes -= frameBytes(f)
		q.cond.Broadcast()
		return f, nil
	}
	if q.err != nil {
		return Frame{}, q.err
	}
	return Frame{}, io.EOF
}

// finish records the reader's terminal error and wakes the consumer.
func (q *outputQueue) finish(err error) {
	q.mu.Lock()
	q.done = true
	q.err = err
	q.cond.Broadcast()
	q.mu.Unlock()
}

// stop abandons the queue because the caller's writer failed. It returns the
// number of data frames that were queued but never written, so pending-output
// accounting is released.
func (q *outputQueue) stop() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, f := range q.frames {
		if frameBytes(f) > 0 {
			n++
		}
	}
	q.frames = nil
	q.bytes = 0
	q.done = true
	q.err = io.EOF
	q.cond.Broadcast()
	return n
}

// Copy writes output until the session exits and returns its exit status.
// notice may be nil.
//
// A reader goroutine drains the transport into a bounded queue so a slow local
// stdout consumer cannot make the transport idle (which used to lose the tail
// of a command that had already exited) and so every complete frame received
// before a transport failure is still delivered. If the queue bound is
// reached, the transport is backpressured: a live consumer drains it and gets
// every byte, while a dead peer still fails with ErrDisconnected instead of
// silently reporting success.
func (s *Session) Copy(stdout, stderr io.Writer, notice func(string)) (*wire.Exit, error) {
	q := newOutputQueue(outputReadAhead)
	go func() {
		for {
			f, err := s.Recv()
			if err != nil {
				q.finish(err)
				return
			}
			if f.Type == wire.TStdout || f.Type == wire.TStderr {
				// Count frames the reader has received but the caller has
				// not written yet, so signal-grace progress tracking knows a
				// stalled writer is still delivering output.
				s.pending.Add(1)
				if !q.put(f) {
					s.pending.Add(-1)
					return
				}
				continue
			}
			q.put(f)
			if f.Type == wire.TExited {
				q.finish(nil)
				return
			}
		}
	}()
	for {
		f, err := q.get()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrDisconnected
			}
			return nil, err
		}
		switch f.Type {
		case wire.TStdout:
			_, err := stdout.Write(f.Data)
			s.pending.Add(-1)
			s.progress.Add(1)
			if err != nil {
				s.pending.Add(-int64(q.stop()))
				return nil, err
			}
		case wire.TStderr:
			_, err := stderr.Write(f.Data)
			s.pending.Add(-1)
			s.progress.Add(1)
			if err != nil {
				s.pending.Add(-int64(q.stop()))
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
