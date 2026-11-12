package slot

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/meta"
)

// This file has the watchers blipd slot uses to follow the guest without
// an agent: the Cloud Hypervisor event monitor file, the serial console
// log and the metadata disk guest area.

// chEvent is one object of the Cloud Hypervisor event monitor file.
type chEvent struct {
	Source string `json:"source"`
	Event  string `json:"event"`
}

func (e chEvent) String() string { return e.Source + " " + e.Event }

// eventReader reads the event monitor file incrementally. The file is a
// stream of pretty printed JSON objects separated by blank lines.
type eventReader struct {
	path string
	off  int64
	buf  []byte
}

// maxEventBuf bounds the unparsed tail kept between reads.
const maxEventBuf = 1 << 20

// read returns the events appended since the last call.
func (r *eventReader) read() []chEvent {
	f, err := os.Open(r.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < r.off {
		r.off, r.buf = 0, nil // replaced
	}
	if _, err := f.Seek(r.off, io.SeekStart); err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(f, maxEventBuf))
	r.off += int64(len(b))
	r.buf = append(r.buf, b...)
	var out []chEvent
	dec := json.NewDecoder(bytes.NewReader(r.buf))
	var used int64
	for {
		var e chEvent
		if err := dec.Decode(&e); err != nil {
			var se *json.SyntaxError
			if errors.As(err, &se) {
				// Not JSON at all: drop what we have.
				used = int64(len(r.buf))
			}
			break
		}
		used = dec.InputOffset()
		out = append(out, e)
	}
	r.buf = append([]byte(nil), r.buf[used:]...)
	if len(r.buf) > maxEventBuf {
		r.buf = nil
	}
	return out
}

// console copies the serial log to w and keeps its tail for exit
// classification. Cloud Hypervisor truncates the log when the guest
// reboots; the copier starts again from the beginning then.
type console struct {
	path string
	w    io.Writer

	mu   sync.Mutex
	f    *os.File
	off  int64
	tail []byte
}

// consoleTail is how much of the serial log is kept for classification.
const consoleTail = 64 << 10

// poll copies what is new and returns whether the log was truncated (a
// reboot).
func (c *console) poll() (truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		f, err := os.Open(c.path)
		if err != nil {
			return false
		}
		c.f, c.off = f, 0
	}
	if st, err := c.f.Stat(); err == nil {
		cur, cerr := os.Stat(c.path)
		switch {
		case cerr == nil && !os.SameFile(st, cur):
			c.f.Close()
			f, err := os.Open(c.path)
			if err != nil {
				c.f = nil
				return true
			}
			c.f, c.off, c.tail, truncated = f, 0, nil, true
		case st.Size() < c.off:
			c.off, c.tail, truncated = 0, nil, true
		}
	}
	buf := make([]byte, 32<<10)
	for {
		n, err := c.f.ReadAt(buf, c.off)
		if n > 0 {
			c.off += int64(n)
			if c.w != nil {
				_, _ = c.w.Write(buf[:n])
			}
			c.tail = append(c.tail, buf[:n]...)
			if len(c.tail) > consoleTail {
				c.tail = append([]byte(nil), c.tail[len(c.tail)-consoleTail:]...)
			}
		}
		if err != nil || n == 0 {
			return truncated
		}
	}
}

func (c *console) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.tail)
}

func (c *console) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		c.f.Close()
		c.f = nil
	}
}

var (
	reKillInit = regexp.MustCompile(`Attempted to kill init! exitcode=0x([0-9a-fA-F]+)`)
	rePanic    = regexp.MustCompile(`Kernel panic - not syncing: [^\r\n]*`)
)

// parsePanic looks for the kernel panic line in the serial text. It
// returns the line, and the init exit code if PID 1 exited.
func parsePanic(text string) (line string, initCode *int, found bool) {
	m := rePanic.FindAllString(text, -1)
	if len(m) == 0 {
		return "", nil, false
	}
	line = m[len(m)-1]
	if k := reKillInit.FindStringSubmatch(line); k != nil {
		if v, err := strconv.ParseUint(k[1], 16, 32); err == nil {
			code := int((v >> 8) & 0xff)
			initCode = &code
		}
	}
	return line, initCode, true
}

// metaNotify returns a channel that gets a value (coalesced) whenever
// path is modified (inotify IN_MODIFY), and a stop function. If inotify
// fails, the channel never fires and the caller's poll still works.
func metaNotify(path string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		logf("inotify: %v (polling %s)", err, path)
		return ch, func() {}
	}
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY); err != nil {
		logf("inotify watch %s: %v (polling)", path, err)
		unix.Close(fd)
		return ch, func() {}
	}
	f := os.NewFile(uintptr(fd), "inotify")
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := f.Read(buf); err != nil {
				return
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch, func() { f.Close() }
}

// readGuestArea reads the guest area of the metadata image. The guest is
// untrusted; meta bounds the record size and the message.
func readGuestArea(path string) (*meta.GuestData, error) {
	w, err := meta.OpenWriter(path)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	return w.ReadGuest()
}

// readHostArea reads the host data the node wrote, or nil.
func readHostArea(path string) *meta.HostData {
	w, err := meta.OpenWriter(path)
	if err != nil {
		return nil
	}
	defer w.Close()
	h, _, err := w.ReadHost()
	if err != nil {
		return nil
	}
	return h
}

// clip bounds an untrusted guest string.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > n {
		s = s[:n]
	}
	return s
}
