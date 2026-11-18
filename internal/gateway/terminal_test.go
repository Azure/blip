package gateway

import (
	"bytes"
	"errors"
	"testing"
)

func TestCRLFWriter(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   string
	}{
		{
			name:   "bare newlines",
			writes: []string{"a\nb\nc"},
			want:   "a\r\nb\r\nc",
		},
		{
			name:   "existing crlf",
			writes: []string{"a\r\nb"},
			want:   "a\r\nb",
		},
		{
			name:   "crlf split across writes",
			writes: []string{"a\r", "\nb"},
			want:   "a\r\nb",
		},
		{
			name:   "newline at start of a write after content",
			writes: []string{"a", "\nb"},
			want:   "a\r\nb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &crlfWriter{w: &buf}
			for _, s := range tt.writes {
				n, err := w.Write([]byte(s))
				if err != nil {
					t.Fatal(err)
				}
				if n != len(s) {
					t.Fatalf("Write returned %d, want %d", n, len(s))
				}
			}
			if got := buf.String(); got != tt.want {
				t.Fatalf("wrote %q, want %q", got, tt.want)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestCRLFWriterReturnsError(t *testing.T) {
	w := &crlfWriter{w: failingWriter{}}
	if _, err := w.Write([]byte("a\n")); err == nil {
		t.Fatal("Write hid the underlying error")
	}
}
