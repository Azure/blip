package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
)

type fragmentedStream struct {
	io.Reader
	io.Writer
	fragment int
}

func (s fragmentedStream) Read(p []byte) (int, error) {
	return s.Reader.Read(p[:min(len(p), s.fragment)])
}

func TestConnFragmentationAndEveryTruncation(t *testing.T) {
	var data bytes.Buffer
	w := NewConn(&data)
	if err := w.WriteJSON(TClaim, Claim{ID: "root", Serial: "s1"}); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), data.Bytes()...)
	for _, fragment := range []int{1, 2, 4, 5, 7, 64} {
		t.Run(fmt.Sprintf("fragment-%d", fragment), func(t *testing.T) {
			for cut := 0; cut <= len(encoded); cut++ {
				c := NewConn(fragmentedStream{bytes.NewReader(encoded[:cut]), io.Discard, fragment})
				typ, payload, err := c.Read()
				if cut < len(encoded) {
					want := io.ErrUnexpectedEOF
					if cut == 0 {
						want = io.EOF
					}
					if !errors.Is(err, want) || typ != 0 || payload != nil {
						t.Fatalf("cut %d accepted a torn frame: type=%d payload=%q err=%v", cut, typ, payload, err)
					}
					continue
				}
				var claim Claim
				if err != nil || typ != TClaim || Decode(payload, &claim) != nil || claim.ID != "root" || claim.Serial != "s1" {
					t.Fatalf("fragmented complete frame: type=%d payload=%q err=%v", typ, payload, err)
				}
			}
		})
	}
}

// An over-limit payload is a local validation error with its size, not a
// transport failure; nothing reaches the peer.
func TestConnOversizedWriteIsTypedAndWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	err := NewConn(&buf).Write(TStdin, make([]byte, MaxFrame+1))
	var sizeErr *FrameSizeError
	if !errors.Is(err, ErrFrameTooLarge) || !errors.As(err, &sizeErr) || sizeErr.Size != MaxFrame+1 {
		t.Fatalf("err = %v, want FrameSizeError(%d)", err, MaxFrame+1)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes of an oversized frame", buf.Len())
	}
}

func TestConnRejectsOversizedLengthBeforePayload(t *testing.T) {
	for _, n := range []uint32{MaxFrame + 1, 1 << 31, ^uint32(0)} {
		var hdr [5]byte
		hdr[0] = byte(TStdin)
		binary.BigEndian.PutUint32(hdr[1:], n)
		c := NewConn(fragmentedStream{bytes.NewReader(hdr[:]), io.Discard, 1})
		if _, _, err := c.Read(); err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("length %d reached payload allocation/read: %v", n, err)
		}
	}
}

type shortFrameWriter struct {
	n   int
	err error
}

func (s shortFrameWriter) Read([]byte) (int, error)    { return 0, io.EOF }
func (s shortFrameWriter) Write(p []byte) (int, error) { return min(s.n, len(p)), s.err }

func TestConnWriteCannotReportTruncatedFrameAsSuccess(t *testing.T) {
	for cut := 0; cut < 5+len("payload"); cut++ {
		c := NewConn(shortFrameWriter{n: cut})
		if err := c.Write(TStdin, []byte("payload")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write at %d: %v", cut, err)
		}
	}
	injected := errors.New("transport failed")
	if err := NewConn(shortFrameWriter{n: 3, err: injected}).Write(TStdin, []byte("payload")); !errors.Is(err, injected) {
		t.Fatalf("lost transport error: %v", err)
	}
	if err := NewConn(shortFrameWriter{}).Write(TStdin, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized write succeeded")
	}
}

type recoveringWriter struct {
	bytes.Buffer
	failed bool
}

func (w *recoveringWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return w.Buffer.Write(p[:3])
	}
	return w.Buffer.Write(p)
}

func TestConnWriteFailurePoisonsFraming(t *testing.T) {
	w := &recoveringWriter{}
	c := NewConn(w)
	if err := c.Write(TStdin, []byte("partial")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("first write: %v", err)
	}
	if err := c.WriteJSON(TStdin, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("continued writing into a truncated frame: %v", err)
	}
	if w.Len() != 3 {
		t.Fatal("later frame bytes were appended to the failed frame")
	}
}

func TestConnConcurrentFramesUnderBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		writer, reader := NewConn(a), NewConn(b)
		const writers, frames = 4, 16
		var done sync.WaitGroup
		for id := 0; id < writers; id++ {
			done.Add(1)
			go func() {
				defer done.Done()
				for seq := 0; seq < frames; seq++ {
					payload := []byte{byte(id), byte(seq), 0, 255}
					if err := writer.Write(TStdout, payload); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		var next [writers]int
		for range writers * frames {
			typ, payload, err := reader.Read()
			if err != nil || typ != TStdout || len(payload) != 4 || payload[0] >= writers {
				t.Fatalf("interleaved frame: type=%d payload=%v err=%v", typ, payload, err)
			}
			id := payload[0]
			if int(payload[1]) != next[id] || payload[2] != 0 || payload[3] != 255 {
				t.Fatalf("frame ordering/data corruption: %v, next=%v", payload, next)
			}
			next[id]++
		}
		done.Wait()
	})
}

func TestConnCoalescedFramesOwnPayload(t *testing.T) {
	var b bytes.Buffer
	c := NewConn(&b)
	for _, payload := range [][]byte{nil, []byte("first"), []byte("second")} {
		if err := c.Write(TStdout, payload); err != nil {
			t.Fatal(err)
		}
	}
	var received [][]byte
	for range 3 {
		_, payload, err := c.Read()
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, payload)
	}
	if len(received[0]) != 0 || string(received[1]) != "first" || string(received[2]) != "second" {
		t.Fatalf("coalesced data changed: %q", received)
	}
}

func FuzzConnRead(f *testing.F) {
	f.Add([]byte{byte(TStdin), 0, 0, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{byte(TFreeze), 255, 255, 255, 255})
	f.Add([]byte{byte(TStdin), 0, 0, 0, 1, '{'})
	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConn(fragmentedStream{bytes.NewReader(input), io.Discard, 3})
		_, payload, err := c.Read()
		if err == nil && (len(input) < 5 || len(payload) > MaxFrame || !bytes.Equal(payload, input[5:5+len(payload)])) {
			t.Fatal("decoder accepted inconsistent frame")
		}
	})
}
