package stream

import (
	"bytes"
	"errors"
	"testing"
)

func newTest(t *testing.T, size int64) (*Writer, *Reader, *memFile) {
	t.Helper()
	f := &memFile{buf: make([]byte, int(size))}
	w, err := NewWriter(f, 0, size, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(f, 0, size)
	if err != nil {
		t.Fatal(err)
	}
	return w, r, f
}

type memFile struct{ buf []byte }

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(m.buf)) {
		return 0, errors.New("out of range")
	}
	copy(m.buf[off:], p)
	return len(p), nil
}

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(m.buf)) {
		return 0, errors.New("out of range")
	}
	copy(p, m.buf[off:])
	return len(p), nil
}

func TestAppendRead(t *testing.T) {
	w, r, _ := newTest(t, MinSize)
	for i, s := range []string{"hello ", "world"} {
		typ := TypeIn
		if i == 1 {
			typ = TypeOut
		}
		if _, err := w.Append(typ, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	recs, head, err := r.Read(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if head != 0 || len(recs) != 2 {
		t.Fatalf("head=%d recs=%d", head, len(recs))
	}
	if string(recs[0].Data) != "hello " || recs[0].Type != TypeIn || recs[1].Type != TypeOut {
		t.Fatalf("unexpected records: %+v", recs)
	}
	if recs[1].Offset <= recs[0].Offset {
		t.Fatal("offsets must increase")
	}
	if got := recs[0].Gen; got != 1 {
		t.Fatalf("gen=%d", got)
	}
}

func TestTrimDropsOldestWholeRecords(t *testing.T) {
	size := MinSize
	w, r, _ := newTest(t, size)
	payload := bytes.Repeat([]byte("x"), 1024)
	var appended int
	for {
		if _, err := w.Append(TypeOut, payload); err != nil {
			t.Fatal(err)
		}
		appended++
		head, _ := w.Head()
		if head > 0 {
			break
		}
		if appended > int(size) {
			t.Fatal("ring never trimmed")
		}
	}
	head, _ := w.Head()
	recs, gotHead, err := r.Read(0, 0)
	if !errors.Is(err, ErrGap) || gotHead != head {
		t.Fatalf("expected gap at %d, got %d %v", head, gotHead, err)
	}
	if len(recs) != 0 {
		t.Fatalf("gap read returned records")
	}
	recs, _, err = r.Read(head, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 || recs[0].Offset != head {
		t.Fatalf("no record at head %d", head)
	}
}

func TestRecoverAfterRestart(t *testing.T) {
	w, _, f := newTest(t, MinSize)
	_, _ = w.Append(TypeIn, []byte("before"))
	if _, err := w.Append(TypeOut, []byte("kept")); err != nil {
		t.Fatal(err)
	}
	w2, err := NewWriter(f, 0, MinSize, 2)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewReader(f, 0, MinSize)
	recs, _, err := r.Read(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || string(recs[1].Data) != "kept" {
		t.Fatalf("recovered %+v", recs)
	}
	if _, err := w2.Append(TypeIn, []byte("after")); err != nil {
		t.Fatal(err)
	}
	recs, _, _ = r.Read(0, 0)
	if len(recs) != 3 || recs[2].Gen != 2 {
		t.Fatalf("after append: %+v", recs)
	}
}

func TestTornTailIgnored(t *testing.T) {
	w, _, f := newTest(t, MinSize)
	_, _ = w.Append(TypeOut, []byte("good"))
	head, tail := w.Head()
	// Corrupt the record header at tail.
	f.buf[int(dataStart)+int(tail)+4] ^= 0xff
	w2, err := NewWriter(f, 0, MinSize, 2)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := w2.Head(); h != head {
		t.Fatalf("head=%d want %d", h, head)
	}
}
