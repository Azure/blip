package guest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Every complete line is prefixed, CRLF becomes LF, and a trailing partial
// line stays buffered until the session ends.
func TestConsoleMirrorPrefixesAndBuffersPartialLines(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	m.start()
	m.feed([]byte("hello\nwor"))
	m.feed([]byte("ld\r\nnext"))
	m.stop()

	want := "blip: hello\nblip: world\nblip: next\n"
	if got := buf.String(); got != want {
		t.Fatalf("console = %q, want %q", got, want)
	}
}

// A partial line longer than the buffer cap is flushed as its own line so the
// pending buffer cannot grow without bound.
func TestConsoleMirrorFlushesOverlongPartialLine(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	m.start()
	long := bytes.Repeat([]byte("x"), consoleMirrorLineMax+5)
	m.feed(long)
	m.stop()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("console has %d lines, want 2: %q", len(lines), buf.String())
	}
	if want := "blip: " + string(long[:consoleMirrorLineMax]); lines[0] != want {
		t.Fatalf("overflow line has %d bytes, want %d", len(lines[0]), len(want))
	}
	if lines[1] != "blip: xxxxx" {
		t.Fatalf("remainder line = %q", lines[1])
	}
}

// A full queue drops the oldest lines instead of blocking the output pump,
// so the surviving window is the command's tail.
func TestConsoleMirrorDropsOldestWhenQueueIsFull(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	const extra = 7
	for i := range consoleMirrorQueue + extra {
		m.feed([]byte(fmt.Sprintf("line-%d\n", i)))
	}
	m.mu.Lock()
	dropped := m.dropped
	m.mu.Unlock()
	if dropped != extra {
		t.Fatalf("dropped %d lines, want %d", dropped, extra)
	}

	m.start()
	m.stop()
	out := buf.String()
	if n := strings.Count(out, "\n"); n != consoleMirrorQueue+1 {
		t.Fatalf("console has %d lines, want %d", n, consoleMirrorQueue+1)
	}
	if strings.Contains(out, "blip: line-0\n") {
		t.Fatal("mirror kept the oldest line instead of dropping it")
	}
	if !strings.Contains(out, fmt.Sprintf("blip: line-%d\n", extra)) ||
		!strings.Contains(out, fmt.Sprintf("blip: line-%d\n", consoleMirrorQueue+extra-1)) {
		t.Fatal("mirror lost the newest lines")
	}
	if !strings.HasSuffix(out, fmt.Sprintf("blip: %d output lines dropped\n", extra)) {
		t.Fatalf("console does not end with the drop notice: %q", out)
	}
}

// A command that writes far more lines than the queue holds must leave the
// newest lines on the console, including its final line.
func TestConsoleMirrorKeepsTailOfLongOutput(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	for i := range 1000 {
		m.feed([]byte(fmt.Sprintf("LINE%04d\n", i)))
	}
	m.start()
	m.stop()
	out := buf.String()
	if strings.Contains(out, "blip: LINE0000\n") {
		t.Fatal("mirror kept the head of the output")
	}
	if !strings.Contains(out, "blip: LINE0999\n") {
		t.Fatalf("mirror lost the final line: %q", out)
	}
	if drop := strings.Index(out, "output lines dropped"); drop < 0 {
		t.Fatal("mirror did not report dropped lines")
	}
	// Every retained line is a contiguous suffix ending at LINE0999.
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, line := range lines {
		if strings.Contains(line, "output lines dropped") {
			lines = lines[:i]
			break
		}
	}
	want := fmt.Sprintf("blip: LINE%04d", 1000-len(lines))
	if lines[0] != want {
		t.Fatalf("retained window starts at %q, want %q", lines[0], want)
	}
}
