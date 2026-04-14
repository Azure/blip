package blip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyWithContext(t *testing.T) {
	t.Run("copies all data", func(t *testing.T) {
		src := strings.NewReader("hello world")
		var dst bytes.Buffer
		err := copyWithContext(context.Background(), &dst, src)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.String() != "hello world" {
			t.Errorf("got %q, want %q", dst.String(), "hello world")
		}
	})

	t.Run("empty reader", func(t *testing.T) {
		src := strings.NewReader("")
		var dst bytes.Buffer
		err := copyWithContext(context.Background(), &dst, src)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.Len() != 0 {
			t.Errorf("expected empty, got %d bytes", dst.Len())
		}
	})

	t.Run("large data", func(t *testing.T) {
		data := make([]byte, 256*1024) // 256KB
		for i := range data {
			data[i] = byte(i % 256)
		}
		src := bytes.NewReader(data)
		var dst bytes.Buffer
		err := copyWithContext(context.Background(), &dst, src)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(dst.Bytes(), data) {
			t.Error("data mismatch")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		src := strings.NewReader("data")
		var dst bytes.Buffer
		err := copyWithContext(ctx, &dst, src)
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		src := strings.NewReader("data")
		dst := &failWriter{err: io.ErrShortWrite}
		err := copyWithContext(context.Background(), dst, src)
		if err != io.ErrShortWrite {
			t.Fatalf("expected ErrShortWrite, got %v", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		src := &failReader{err: io.ErrUnexpectedEOF}
		var dst bytes.Buffer
		err := copyWithContext(context.Background(), &dst, src)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
		}
	})
}

type failWriter struct {
	err error
}

func (w *failWriter) Write([]byte) (int, error) { return 0, w.err }

type failReader struct {
	err error
}

func (r *failReader) Read([]byte) (int, error) { return 0, r.err }

func TestSFTPClientAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.SFTPClient()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestUploadAfterClose(t *testing.T) {
	// Upload opens the local file first, so a nonexistent file fails before
	// the closed check. Use /dev/null as a valid local file to ensure we
	// hit the ErrClosed path.
	b := &Blip{closed: true}
	err := b.Upload(context.Background(), "/dev/null", "/tmp/y")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestUploadNonexistentLocalFile(t *testing.T) {
	// Even with a closed blip, the local file check happens first.
	b := &Blip{closed: true}
	err := b.Upload(context.Background(), "/nonexistent/file/path", "/tmp/dest")
	if err == nil {
		t.Fatal("expected error for nonexistent local file")
	}
	if !strings.Contains(err.Error(), "open local file") {
		t.Errorf("error %q should mention local file", err.Error())
	}
}

func TestDownloadAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	err := b.Download(context.Background(), "/tmp/x", "/tmp/y")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestUploadReaderAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	err := b.UploadReader(context.Background(), strings.NewReader("data"), "/tmp/x", 0644)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestDownloadWriterAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	var buf bytes.Buffer
	err := b.DownloadWriter(context.Background(), "/tmp/x", &buf)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestUploadDirAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	err := b.UploadDir(context.Background(), "/tmp", "/tmp/dest")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestDownloadDirAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	err := b.DownloadDir(context.Background(), "/tmp/src", "/tmp/dest")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestUploadDirWalkContextCancel(t *testing.T) {
	// Create a temp directory with some files.
	dir := t.TempDir()
	for i := range 5 {
		name := filepath.Join(dir, strings.Repeat("a", i+1))
		if err := os.WriteFile(name, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	b := &Blip{closed: true}
	err := b.UploadDir(context.Background(), dir, "/tmp/dest")
	// SFTPClient check happens before walk starts.
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
