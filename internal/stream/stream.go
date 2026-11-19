// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package stream implements the append-only record ring that carries a
// blip's stdin, stdout, stderr and lifecycle events.
//
// The ring lives at a fixed offset inside a state's volume, after the ext4
// filesystem. The node agent is its only writer; readers may be on any node.
// When the ring fills, the writer drops the oldest whole records so a chatty
// agent never blocks.
package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
)

const (
	// Offset is where the ring starts inside a state volume. It equals the
	// largest accepted state filesystem, so no filesystem ever reaches it.
	Offset int64 = 1 << 40
	// HeaderSize is the space reserved for the two header slots.
	HeaderSize int64 = 8 << 10
	// SlotSize is the size of one header slot.
	SlotSize int64 = 4 << 10
	// MinSize and MaxSize bound BlipState.spec.streamSize.
	MinSize int64 = 1 << 20
	MaxSize int64 = 1 << 30
	// RecordHeader is the encoded size of a record header.
	RecordHeader = 32
	// MaxRecord is the largest payload a caller may append. Larger writes
	// are split by the caller.
	MaxRecord = 256 << 10
)

// RecordType identifies what a record carries.
type RecordType byte

const (
	// TypeOut is primary stdout.
	TypeOut RecordType = 1
	// TypeErr is primary stderr.
	TypeErr RecordType = 2
	// TypeIn is stdin written by a client.
	TypeIn RecordType = 3
	// TypeStart marks the start of a new blip generation.
	TypeStart RecordType = 4
	// TypeEnd marks the command's exit or the blip stopping.
	TypeEnd RecordType = 5
	// TypeGap marks records the ring dropped before Offset.
	TypeGap RecordType = 6
)

const (
	magic     = 0x424c5053 // "BLPS"
	version   = 1
	dataStart = HeaderSize
	// maxLogical is a sanity bound for recovered headers.
	maxLogical = 1 << 62
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// ReadWriterAt is the subset of *os.File the ring needs.
type ReadWriterAt interface {
	io.ReaderAt
	io.WriterAt
}

// Record is one decoded record.
type Record struct {
	// Offset is the logical byte offset of the record in the ring history.
	Offset uint64
	// Gen is the blip generation that wrote the record.
	Gen  uint64
	Type RecordType
	Data []byte
}

// ErrGap is returned by Reader.Read when the requested offset is older than
// the ring retains. The caller should emit a gap marker and continue from
// Head.
var ErrGap = errors.New("stream: records were trimmed")

// Writer appends records. It is safe for concurrent use.
type Writer struct {
	rw   ReadWriterAt
	base int64
	size int64
	gen  uint64

	mu     sync.Mutex
	head   uint64
	tail   uint64
	seq    uint64
	closed bool
}

// NewWriter opens (or formats) a ring of size bytes at base. gen stamps
// records from this writer.
func NewWriter(rw ReadWriterAt, base, size int64, gen uint64) (*Writer, error) {
	if size < MinSize || size > MaxSize || size%SlotSize != 0 {
		return nil, fmt.Errorf("stream: invalid size %d", size)
	}
	w := &Writer{rw: rw, base: base, size: size, gen: gen}
	if err := w.recover(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) ringLen() uint64 { return uint64(w.size - dataStart) }

func (w *Writer) end() int64 { return w.base + dataStart }

func (w *Writer) writeAt(logical uint64, p []byte) error {
	ring := w.ringLen()
	for len(p) > 0 {
		pos := logical % ring
		n := uint64(len(p))
		if n > ring-pos {
			n = ring - pos
		}
		if _, err := w.rw.WriteAt(p[:n], w.end()+int64(pos)); err != nil {
			return err
		}
		logical += n
		p = p[n:]
	}
	return nil
}

func (w *Writer) readAt(logical uint64, p []byte) error {
	ring := w.ringLen()
	for len(p) > 0 {
		pos := logical % ring
		n := uint64(len(p))
		if n > ring-pos {
			n = ring - pos
		}
		if _, err := w.rw.ReadAt(p[:n], w.end()+int64(pos)); err != nil {
			return err
		}
		logical += n
		p = p[n:]
	}
	return nil
}

type header struct {
	seq  uint64
	head uint64
	tail uint64
}

func (h header) encode() []byte {
	b := make([]byte, SlotSize)
	binary.LittleEndian.PutUint32(b[0:], magic)
	binary.LittleEndian.PutUint32(b[4:], version)
	binary.LittleEndian.PutUint64(b[8:], h.seq)
	binary.LittleEndian.PutUint64(b[16:], h.head)
	binary.LittleEndian.PutUint64(b[24:], h.tail)
	binary.LittleEndian.PutUint32(b[SlotSize-4:], crc32.Checksum(b[:SlotSize-4], castagnoli))
	return b
}

func decodeHeader(b []byte, capacity uint64) (header, bool) {
	if len(b) < int(SlotSize) || binary.LittleEndian.Uint32(b[0:]) != magic || binary.LittleEndian.Uint32(b[4:]) != version {
		return header{}, false
	}
	if crc32.Checksum(b[:SlotSize-4], castagnoli) != binary.LittleEndian.Uint32(b[SlotSize-4:]) {
		return header{}, false
	}
	h := header{
		seq:  binary.LittleEndian.Uint64(b[8:]),
		head: binary.LittleEndian.Uint64(b[16:]),
		tail: binary.LittleEndian.Uint64(b[24:]),
	}
	if h.head > h.tail || h.tail-h.head > capacity || h.tail > maxLogical {
		return header{}, false
	}
	return h, true
}

func (w *Writer) persist() error {
	w.seq++
	b := header{seq: w.seq, head: w.head, tail: w.tail}.encode()
	slot := int64(0)
	if w.seq%2 == 0 {
		slot = SlotSize
	}
	_, err := w.rw.WriteAt(b, w.base+slot)
	return err
}

// recover loads the newest valid header and drops a torn tail.
func (w *Writer) recover() error {
	var best header
	found := false
	for slot := int64(0); slot < HeaderSize; slot += SlotSize {
		b := make([]byte, SlotSize)
		if _, err := w.rw.ReadAt(b, w.base+slot); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		h, ok := decodeHeader(b, w.ringLen())
		if !ok {
			continue
		}
		if !found || h.seq > best.seq {
			best, found = h, true
		}
	}
	if !found {
		w.head, w.tail, w.seq = 0, 0, 0
		return w.persist()
	}
	w.head, w.tail, w.seq = best.head, best.tail, best.seq
	// Records beyond the persisted tail may be fully written (the header is
	// updated lazily after a crash). Advance over them.
	for {
		_, n, err := w.recordAt(w.tail)
		if err != nil || n == 0 {
			break
		}
		w.tail += uint64(n)
	}
	if w.tail-w.head > w.ringLen() {
		w.head = w.tail - w.ringLen()
	}
	return w.persist()
}

// recordAt reads and validates the record at logical offset.
func (w *Writer) recordAt(off uint64) (Record, int, error) {
	hdr := make([]byte, RecordHeader)
	if err := w.readAt(off, hdr); err != nil {
		return Record{}, 0, err
	}
	if binary.LittleEndian.Uint32(hdr[0:]) != magic {
		return Record{}, 0, nil
	}
	logical := binary.LittleEndian.Uint64(hdr[4:])
	gen := binary.LittleEndian.Uint64(hdr[12:])
	n := binary.LittleEndian.Uint32(hdr[20:])
	typ := RecordType(hdr[24])
	sum := binary.LittleEndian.Uint32(hdr[28:])
	if logical != off || n > MaxRecord || typ < TypeOut || typ > TypeGap {
		return Record{}, 0, nil
	}
	data := make([]byte, n)
	if err := w.readAt(off+RecordHeader, data); err != nil {
		return Record{}, 0, err
	}
	check := crc32.New(castagnoli)
	_, _ = check.Write(hdr[:28])
	_, _ = check.Write(data)
	if check.Sum32() != sum {
		return Record{}, 0, nil
	}
	return Record{Offset: off, Gen: gen, Type: typ, Data: data}, RecordHeader + int(n), nil
}

// Append writes one record, dropping the oldest records if the ring is full.
// It returns the record's logical offset.
func (w *Writer) Append(typ RecordType, data []byte) (uint64, error) {
	if len(data) > MaxRecord {
		return 0, fmt.Errorf("stream: record too large: %d", len(data))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("stream: writer closed")
	}
	total := uint64(RecordHeader + len(data))
	ring := w.ringLen()
	if total > ring {
		return 0, fmt.Errorf("stream: record %d exceeds ring %d", total, ring)
	}
	for w.tail+total-w.head > ring {
		_, n, err := w.recordAt(w.head)
		if err != nil || n == 0 {
			// Cannot find the next boundary: drop everything.
			w.head = w.tail
			break
		}
		w.head += uint64(n)
	}
	off := w.tail
	hdr := make([]byte, RecordHeader)
	binary.LittleEndian.PutUint32(hdr[0:], magic)
	binary.LittleEndian.PutUint64(hdr[4:], off)
	binary.LittleEndian.PutUint64(hdr[12:], w.gen)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(data)))
	hdr[24] = byte(typ)
	check := crc32.New(castagnoli)
	_, _ = check.Write(hdr[:28])
	_, _ = check.Write(data)
	binary.LittleEndian.PutUint32(hdr[28:], check.Sum32())
	if err := w.writeAt(off, hdr); err != nil {
		return 0, err
	}
	if len(data) > 0 {
		if err := w.writeAt(off+RecordHeader, data); err != nil {
			return 0, err
		}
	}
	w.tail += total
	if err := w.persist(); err != nil {
		return 0, err
	}
	return off, nil
}

// Head returns the oldest retained offset and the next write offset.
func (w *Writer) Head() (head, tail uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.tail
}

// Gen returns the generation stamped on records from this writer.
func (w *Writer) Gen() uint64 { return w.gen }

// Close persists the header and refuses further appends. The underlying
// file is owned by the caller.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.persist()
}

// Reader reads records from an independent handle.
type Reader struct {
	rw   ReadWriterAt
	base int64
	size int64
}

// NewReader opens a ring for reading. It does not format: a missing header
// reads as an empty ring.
func NewReader(rw ReadWriterAt, base, size int64) (*Reader, error) {
	if size < MinSize || size > MaxSize || size%SlotSize != 0 {
		return nil, fmt.Errorf("stream: invalid size %d", size)
	}
	return &Reader{rw: rw, base: base, size: size}, nil
}

func (r *Reader) ringLen() uint64 { return uint64(r.size - dataStart) }

func (r *Reader) readAt(logical uint64, p []byte) error {
	ring := r.ringLen()
	for len(p) > 0 {
		pos := logical % ring
		n := uint64(len(p))
		if n > ring-pos {
			n = ring - pos
		}
		if _, err := r.rw.ReadAt(p[:n], r.base+dataStart+int64(pos)); err != nil {
			return err
		}
		logical += n
		p = p[n:]
	}
	return nil
}

// Head returns the retained window. A zero tail with no valid header means
// the ring has never been written.
func (r *Reader) Head() (head, tail uint64) {
	var best header
	found := false
	for slot := int64(0); slot < HeaderSize; slot += SlotSize {
		b := make([]byte, SlotSize)
		if _, err := r.rw.ReadAt(b, r.base+slot); err != nil && !errors.Is(err, io.EOF) {
			return 0, 0
		}
		h, ok := decodeHeader(b, r.ringLen())
		if ok && (!found || h.seq > best.seq) {
			best, found = h, true
		}
	}
	if !found {
		return 0, 0
	}
	return best.head, best.tail
}

// Read returns up to max records starting at from. If from predates the
// retained window it returns ErrGap and the current head.
func (r *Reader) Read(from uint64, max int) ([]Record, uint64, error) {
	head, tail := r.Head()
	if from < head {
		return nil, head, ErrGap
	}
	if from > tail {
		from = tail
	}
	var out []Record
	for from < tail && (max <= 0 || len(out) < max) {
		rec, n, err := readRecord(r, from)
		if err != nil {
			return out, head, err
		}
		if n == 0 {
			break
		}
		out = append(out, rec)
		from += uint64(n)
	}
	return out, head, nil
}

func readRecord(r *Reader, off uint64) (Record, int, error) {
	hdr := make([]byte, RecordHeader)
	if err := r.readAt(off, hdr); err != nil {
		return Record{}, 0, err
	}
	if binary.LittleEndian.Uint32(hdr[0:]) != magic {
		return Record{}, 0, nil
	}
	logical := binary.LittleEndian.Uint64(hdr[4:])
	gen := binary.LittleEndian.Uint64(hdr[12:])
	n := binary.LittleEndian.Uint32(hdr[20:])
	typ := RecordType(hdr[24])
	sum := binary.LittleEndian.Uint32(hdr[28:])
	if logical != off || n > MaxRecord || typ < TypeOut || typ > TypeGap {
		return Record{}, 0, nil
	}
	data := make([]byte, n)
	if err := r.readAt(off+RecordHeader, data); err != nil {
		return Record{}, 0, err
	}
	check := crc32.New(castagnoli)
	_, _ = check.Write(hdr[:28])
	_, _ = check.Write(data)
	if check.Sum32() != sum {
		return Record{}, 0, nil
	}
	return Record{Offset: off, Gen: gen, Type: typ, Data: data}, RecordHeader + int(n), nil
}
