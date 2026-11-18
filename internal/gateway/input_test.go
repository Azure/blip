package gateway

import (
	"io"
	"testing"
	"time"
)

func TestInputLeaseRevocationDoesNotConsumeNextPhase(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	in := newChannelInput(r)
	defer in.close()
	old := in.reader()
	finished := make(chan error, 1)
	go func() {
		_, err := old.Read(make([]byte, 16))
		finished <- err
	}()
	old.Close()
	select {
	case err := <-finished:
		if err != io.EOF {
			t.Fatalf("revoked read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revoked reader did not wake")
	}
	if _, err := w.Write([]byte("next shell")); err != nil {
		t.Fatal(err)
	}
	// Even reads that start after revocation cannot steal queued input.
	if _, err := old.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("revoked read: %v", err)
	}
	next := in.reader()
	buf := make([]byte, 10)
	if _, err := io.ReadFull(next, buf); err != nil || string(buf) != "next shell" {
		t.Fatalf("next reader got %q: %v", buf, err)
	}
}

func TestInputEOFDrainsBufferedBytes(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	in := newChannelInput(r)
	defer in.close()
	go func() {
		w.Write([]byte("last bytes"))
		w.Close()
	}()
	got, err := io.ReadAll(in.reader())
	if err != nil || string(got) != "last bytes" {
		t.Fatalf("read %q: %v", got, err)
	}
	select {
	case <-in.ended:
	case <-time.After(time.Second):
		t.Fatal("SSH input reader did not finish")
	}
}
