package guest

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	// consoleMirrorPath is the VM serial console, which the runtime exposes
	// as the pod log.
	consoleMirrorPath = "/dev/console"
	// consoleMirrorPrefix marks mirrored command output in the console log,
	// separating it from the guest's own log lines.
	consoleMirrorPrefix = "blip: "
	// consoleMirrorQueue bounds lines waiting for the console writer. When
	// it is full the oldest lines are dropped rather than blocking the
	// command, so the newest output survives.
	consoleMirrorQueue = 256
	// consoleMirrorLineMax bounds a partial line held between writes. A
	// longer line is flushed as-is instead of growing without bound.
	consoleMirrorLineMax = 4 << 10
)

// consoleMirror copies a primary command's output to the VM serial console
// (the pod log) with a per-line prefix. The output pump only feeds complete
// lines into a bounded queue; a slow or missing console never backpressures
// the command.
type consoleMirror struct {
	w io.Writer

	mu       sync.Mutex
	pending  []byte // partial line waiting for its newline
	dropped  int    // lines discarded while the queue was full
	closed   bool
	started  bool
	lines    chan string
	finished chan struct{}
	stopOnce sync.Once
}

// openConsoleMirror starts a mirror writing to the serial console. A guest (or
// test environment) that cannot open the console gets a nil mirror, which all
// methods tolerate, so the mirror is silently disabled.
func openConsoleMirror() *consoleMirror {
	f, err := os.OpenFile(consoleMirrorPath, os.O_WRONLY, 0)
	if err != nil {
		return nil
	}
	m := newConsoleMirror(f)
	m.start()
	return m
}

// newConsoleMirror returns an unstarted mirror writing to w. Tests pass an
// io.Writer instead of the serial console.
func newConsoleMirror(w io.Writer) *consoleMirror {
	return &consoleMirror{
		w:        w,
		lines:    make(chan string, consoleMirrorQueue),
		finished: make(chan struct{}),
	}
}

// start runs the console writer. It is safe to call once; repeated calls are
// ignored.
func (m *consoleMirror) start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.run()
}

// feed splits raw command output into lines and queues them for the console.
// It never blocks: queue overflow is counted and reported later.
func (m *consoleMirror) feed(data []byte) {
	if m == nil || len(data) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		seg := data
		newline := false
		if i >= 0 {
			seg, data, newline = data[:i], data[i+1:], true
		} else {
			data = nil
		}
		for len(seg) > 0 {
			space := consoleMirrorLineMax - len(m.pending)
			if space == 0 {
				// The buffer reached the cap; flush it as a line instead
				// of letting it grow without bound.
				m.enqueueLocked(string(m.pending))
				m.pending = m.pending[:0]
				space = consoleMirrorLineMax
			}
			n := min(space, len(seg))
			m.pending = append(m.pending, seg[:n]...)
			seg = seg[n:]
		}
		if newline {
			m.enqueueLocked(string(m.pending))
			m.pending = m.pending[:0]
		}
	}
}

// enqueueLocked queues one line without waiting. The caller holds m.mu.
func (m *consoleMirror) enqueueLocked(line string) {
	// The console must not see CR, so a CRLF line ends up as one LF.
	line = strings.TrimSuffix(line, "\r")
	select {
	case m.lines <- line:
	default:
		// The queue is full. Discard the oldest queued line so the window
		// the console (and status.output) keeps is the command's tail.
		select {
		case <-m.lines:
			m.dropped++
		default:
			// The writer drained a line first; nothing was lost.
		}
		// Only this goroutine sends on m.lines, so the slot just freed
		// (or taken by the writer) is available without blocking.
		m.lines <- line
	}
}

// run writes queued lines until the mirror is stopped.
func (m *consoleMirror) run() {
	defer close(m.finished)
	for line := range m.lines {
		m.writeLine(line)
		if len(m.lines) == 0 {
			m.writeDropped()
		}
	}
	m.writeDropped()
}

func (m *consoleMirror) writeLine(line string) {
	_, _ = io.WriteString(m.w, consoleMirrorPrefix+line+"\n")
}

// writeDropped reports, once the queue has drained, how many lines were
// discarded instead of blocking the pump.
func (m *consoleMirror) writeDropped() {
	m.mu.Lock()
	n := m.dropped
	m.dropped = 0
	m.mu.Unlock()
	if n > 0 {
		_, _ = fmt.Fprintf(m.w, "%s%d output lines dropped\n", consoleMirrorPrefix, n)
	}
}

// stop flushes a final partial line, closes the queue, and joins the writer so
// no goroutine outlives the session.
func (m *consoleMirror) stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		m.mu.Lock()
		if len(m.pending) > 0 {
			m.enqueueLocked(string(m.pending))
			m.pending = nil
		}
		m.closed = true
		started := m.started
		close(m.lines)
		m.mu.Unlock()
		if started {
			<-m.finished
		}
		if c, ok := m.w.(io.Closer); ok {
			_ = c.Close()
		}
	})
}
