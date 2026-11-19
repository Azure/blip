// Package session is the client side of guest sessions. A Connector reaches
// the guest session port of a VM pod (normally through pod exec of
// `blip-runtime bridge 1025`); the session then speaks internal/wire.
package session

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

// outputReadAhead bounds output that the client keeps in memory after it has
// been received from the guest but not yet written to the caller. Reading the
// transport while a local stdout consumer is stalled keeps the transport from
// going idle (some transports tear an idle exec stream down after a few
// seconds). Beyond this bound complete frames are spooled to a temporary file
// instead of stopping the reader, so a long stall cannot make the transport
// time out and lose the tail of output the command already produced.
const outputReadAhead = 8 << 20

// outputSpoolMax bounds the temporary file used for output that does not fit
// in memory. Exceeding it is reported as an error, never as a successful exit:
// a caller must not mistake a truncated stream for the command's result.
var outputSpoolMax int64 = 512 << 20

// outputSpoolDir overrides the directory used for spool files. Tests set it to
// a private directory; an empty value uses os.TempDir.
var outputSpoolDir string

// outputQueue decouples the transport reader from the caller's writer. Only
// the reader goroutine calls put and only the Copy consumer calls get.
type outputQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	frames []Frame
	bytes  int
	max    int
	done   bool
	err    error

	// Frames that do not fit in memory are written in order to one temporary
	// file. spoolWrite is the committed end of the file, spoolRead the next
	// record to deliver, and spoolBytes the unread amount (for the bound).
	spool      *os.File
	spoolPath  string
	spoolRead  int64
	spoolWrite int64
	spoolBytes int64
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

// put appends one frame. It never waits for the local consumer: output that
// does not fit in memory is spooled to disk. It reports false when the queue
// was stopped or the spool failed; the failure is returned by get.
func (q *outputQueue) put(f Frame) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.done {
		return false
	}
	n := frameBytes(f)
	if q.spool == nil && q.bytes+n <= q.max {
		q.frames = append(q.frames, f)
		q.bytes += n
		q.cond.Signal()
		return true
	}
	if err := q.spoolLocked(f); err != nil {
		q.done = true
		q.err = err
		q.cond.Broadcast()
		return false
	}
	q.cond.Signal()
	return true
}

// spoolLocked appends one frame to the temporary file. The caller holds q.mu.
func (q *outputQueue) spoolLocked(f Frame) error {
	if q.spool == nil {
		dir := outputSpoolDir
		file, err := os.CreateTemp(dir, "blip-output-*")
		if err != nil {
			return fmt.Errorf("session output exceeded memory and could not be spooled: %w", err)
		}
		q.spool = file
		q.spoolPath = file.Name()
	}
	rec, err := encodeSpoolFrame(f)
	if err != nil {
		return err
	}
	if q.spoolBytes+int64(len(rec)) > outputSpoolMax {
		return fmt.Errorf("session output exceeded the %d-byte spool limit while the local consumer was stalled", outputSpoolMax)
	}
	if _, err := q.spool.WriteAt(rec, q.spoolWrite); err != nil {
		return fmt.Errorf("spool session output: %w", err)
	}
	q.spoolWrite += int64(len(rec))
	q.spoolBytes += int64(len(rec))
	return nil
}

func (q *outputQueue) spoolHasDataLocked() bool {
	return q.spool != nil && q.spoolRead < q.spoolWrite
}

// readSpoolLocked reads the next record. The caller holds q.mu.
func (q *outputQueue) readSpoolLocked() (Frame, error) {
	var hdr [5]byte
	if _, err := q.spool.ReadAt(hdr[:], q.spoolRead); err != nil {
		return Frame{}, fmt.Errorf("read spooled session output: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > wire.MaxFrame {
		return Frame{}, fmt.Errorf("read spooled session output: frame too large: %d", n)
	}
	payload := make([]byte, n)
	if _, err := q.spool.ReadAt(payload, q.spoolRead+5); err != nil {
		return Frame{}, fmt.Errorf("read spooled session output: %w", err)
	}
	q.spoolRead += int64(5 + n)
	q.spoolBytes -= int64(5 + n)
	f, err := decodeSpoolFrame(wire.Type(hdr[0]), payload)
	if err != nil {
		return Frame{}, err
	}
	if q.spoolRead == q.spoolWrite && len(q.frames) == 0 {
		// Keep the file for reuse but release its space.
		if err := q.spool.Truncate(0); err != nil {
			return Frame{}, fmt.Errorf("truncate session output spool: %w", err)
		}
		q.spoolRead, q.spoolWrite, q.spoolBytes = 0, 0, 0
	}
	return f, nil
}

// get removes the next frame. It returns the reader's error once every
// received frame has been consumed, so no complete frame is discarded by a
// transport failure.
func (q *outputQueue) get() (Frame, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.frames) == 0 && !q.spoolHasDataLocked() && !q.done {
		q.cond.Wait()
	}
	if len(q.frames) > 0 {
		f := q.frames[0]
		q.frames = q.frames[1:]
		q.bytes -= frameBytes(f)
		q.cond.Broadcast()
		return f, nil
	}
	if q.spoolHasDataLocked() {
		return q.readSpoolLocked()
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

// stop abandons the queue because the caller's writer failed or the transport
// was closed. It returns the number of data frames that were still in memory,
// so the caller can release pending-output accounting.
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
	q.closeSpoolLocked()
	q.cond.Broadcast()
	return n
}

// cleanup releases the spool. It is safe to call while the reader is still
// running: put sees done and stops without touching the closed file.
func (q *outputQueue) cleanup() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.done = true
	q.frames = nil
	q.bytes = 0
	q.closeSpoolLocked()
	q.cond.Broadcast()
}

func (q *outputQueue) closeSpoolLocked() {
	if q.spool == nil {
		return
	}
	name := q.spoolPath
	_ = q.spool.Close()
	q.spool = nil
	q.spoolPath = ""
	q.spoolRead, q.spoolWrite, q.spoolBytes = 0, 0, 0
	if name != "" {
		_ = os.Remove(name)
	}
}

// Spool records are [1 byte type][4 byte big-endian length][payload]. Data
// frames carry their bytes; control frames carry JSON so the queue can spool
// them without reordering output.
func encodeSpoolFrame(f Frame) ([]byte, error) {
	var payload []byte
	switch f.Type {
	case wire.TStdout, wire.TStderr:
		payload = f.Data
	case wire.TNotice:
		b, err := json.Marshal(wire.Notice{Message: f.Notice})
		if err != nil {
			return nil, err
		}
		payload = b
	case wire.TExited:
		if f.Exit == nil {
			return nil, errors.New("spool an exit frame without a status")
		}
		b, err := json.Marshal(*f.Exit)
		if err != nil {
			return nil, err
		}
		payload = b
	default:
		return nil, fmt.Errorf("cannot spool session frame type %d", f.Type)
	}
	rec := make([]byte, 5+len(payload))
	rec[0] = byte(f.Type)
	binary.BigEndian.PutUint32(rec[1:], uint32(len(payload)))
	copy(rec[5:], payload)
	return rec, nil
}

func decodeSpoolFrame(t wire.Type, payload []byte) (Frame, error) {
	switch t {
	case wire.TStdout, wire.TStderr:
		return Frame{Type: t, Data: payload}, nil
	case wire.TNotice:
		var n wire.Notice
		if err := json.Unmarshal(payload, &n); err != nil {
			return Frame{}, fmt.Errorf("decode spooled notice: %w", err)
		}
		return Frame{Type: t, Notice: n.Message}, nil
	case wire.TExited:
		var e wire.Exit
		if err := json.Unmarshal(payload, &e); err != nil {
			return Frame{}, fmt.Errorf("decode spooled exit: %w", err)
		}
		return Frame{Type: t, Exit: &e}, nil
	default:
		return Frame{}, fmt.Errorf("cannot decode spooled session frame type %d", t)
	}
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
	defer q.cleanup()
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
