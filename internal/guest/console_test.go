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
	const lineLen = 70 // fixed line text plus the newline counted by the budget
	capacity := consoleMirrorBudget / lineLen
	const extra = 7
	for i := range capacity + extra {
		line := fmt.Sprintf("line-%05d%s", i, strings.Repeat("x", lineLen-11))
		m.feed([]byte(line + "\n"))
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
	if n := strings.Count(out, "\n"); n != capacity+1 {
		t.Fatalf("console has %d lines, want %d", n, capacity+1)
	}
	if strings.Contains(out, "blip: line-00000") {
		t.Fatal("mirror kept the oldest line instead of dropping it")
	}
	if !strings.Contains(out, "blip: line-00007") ||
		!strings.Contains(out, fmt.Sprintf("blip: line-%05d", capacity+extra-1)) {
		t.Fatal("mirror lost the newest lines")
	}
	if !strings.HasSuffix(out, fmt.Sprintf("blip: %d output lines dropped\n", extra)) {
		t.Fatalf("console does not end with the drop notice: %q", out)
	}
}

// A command that writes far more lines than the budget holds must leave the
// newest lines on the console, including its final line.
func TestConsoleMirrorKeepsTailOfLongOutput(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	const lineLen = 11 // "LINE" + six digits + newline
	total := consoleMirrorBudget/lineLen + 500
	for i := range total {
		m.feed([]byte(fmt.Sprintf("LINE%06d\n", i)))
	}
	m.start()
	m.stop()
	out := buf.String()
	if strings.Contains(out, "blip: LINE000000\n") {
		t.Fatal("mirror kept the head of the output")
	}
	if !strings.Contains(out, fmt.Sprintf("blip: LINE%06d\n", total-1)) {
		t.Fatalf("mirror lost the final line: %q", out)
	}
	if drop := strings.Index(out, "output lines dropped"); drop < 0 {
		t.Fatal("mirror did not report dropped lines")
	}
	// Every retained line is a contiguous suffix ending at the final line.
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, line := range lines {
		if strings.Contains(line, "output lines dropped") {
			lines = lines[:i]
			break
		}
	}
	want := fmt.Sprintf("blip: LINE%06d", total-len(lines))
	if lines[0] != want {
		t.Fatalf("retained window starts at %q, want %q", lines[0], want)
	}
}

// Output smaller than the byte budget is retained in full, even when it spans
// far more lines than the old 256-line window. This is what lets the
// controller's status tail replay a fast 10,000-line command without loss.
func TestConsoleMirrorKeepsTenThousandShortLines(t *testing.T) {
	var buf bytes.Buffer
	m := newConsoleMirror(&buf)
	for i := 1; i <= 10000; i++ {
		m.feed([]byte(fmt.Sprintf("%d\n", i)))
	}
	m.start()
	m.stop()
	out := buf.String()
	if strings.Contains(out, "output lines dropped") {
		t.Fatalf("mirror dropped output below its byte budget: %q", out[len(out)-200:])
	}
	if n := strings.Count(out, "\n"); n != 10000 {
		t.Fatalf("console has %d lines, want 10000", n)
	}
	if !strings.HasPrefix(out, "blip: 1\n") || !strings.HasSuffix(out, "blip: 10000\n") {
		t.Fatalf("console lost the head or tail: %.80q ... %.80q", out, out[len(out)-80:])
	}
}
