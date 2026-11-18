package gateway

import "io"

// crlfWriter adapts Bubble Tea's output to an SSH channel. When Bubble Tea has
// no TTY input (the gateway decodes keystrokes itself) it assumes the terminal
// maps newlines to CRLF and writes a bare LF to return to column zero. SSH
// clients keep their local terminal in raw mode, so that LF only moves down a
// row and the cursor stays where the previous line ended. Multi-line views then
// stair-step to the right, one line width per row.
//
// Translating LF to CRLF restores the column-zero movement Bubble Tea expects.
type crlfWriter struct {
	w    io.Writer
	last byte
}

func (w *crlfWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	last := w.last
	for _, b := range p {
		if b == '\n' && last != '\r' {
			out = append(out, '\r')
		}
		out = append(out, b)
		last = b
	}
	w.last = last
	if _, err := w.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
