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

// A full queue drops lines instead of blocking the output pump, and the drops
// are reported once the queue drains.
func TestConsoleMirrorDropsWhenQueueIsFull(t *testing.T) {
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
	if !strings.Contains(out, "blip: line-0\n") || !strings.Contains(out, fmt.Sprintf("blip: line-%d\n", consoleMirrorQueue-1)) {
		t.Fatal("mirror lost lines that fit in the queue")
	}
	if strings.Contains(out, fmt.Sprintf("blip: line-%d\n", consoleMirrorQueue)) {
		t.Fatal("mirror wrote a dropped line")
	}
	if !strings.HasSuffix(out, fmt.Sprintf("blip: %d output lines dropped\n", extra)) {
		t.Fatalf("console does not end with the drop notice: %q", out)
	}
}
