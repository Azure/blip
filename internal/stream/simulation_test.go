// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package stream

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simtest"
)

// The simulation uses the smallest legal ring so that the byte-for-byte disk
// model and exhaustive state exploration stay bounded.
const (
	simBase        int64 = 0
	simRingSize          = MinSize
	simLargeRecord       = 60 << 10
	// simBudget bounds each path. The real ring never reaches a terminal
	// state (there is always another append), so a finite budget is what lets
	// Explore terminate with Complete instead of truncating at a depth limit.
	simBudget = 4
)

var errSimWrite = errors.New("simulation disk: injected write failure")

// faultMode selects what a single WriteAt does when the current append's fault
// plan names its write index.
type faultMode uint8

const (
	faultNone   faultMode = iota // perform the write normally
	faultBefore                  // return an error without changing the disk
	faultTorn                    // write a prefix, then return an error
	faultLost                    // write everything, then report an error
)

func (f faultMode) String() string {
	switch f {
	case faultNone:
		return "ok"
	case faultBefore:
		return "fail"
	case faultTorn:
		return "torn"
	case faultLost:
		return "lost"
	default:
		return "unknown"
	}
}

// faultPlan names the zero-based WriteAt call of the next append that faults.
// Append calls WriteAt for the record header (possibly split at the ring
// boundary), the record payload (also possibly split), and finally the
// persisted header slot. index is -1 when no call faults.
type faultPlan struct {
	index int
	mode  faultMode
}

// simDisk is the crashable byte-addressed ring backing store. It implements
// ReadWriterAt exactly as the production code sees an *os.File. There is no
// fsync in this package, so the disk has no separate durable image: a
// completed WriteAt survives a restart, and a torn WriteAt leaves its prefix.
type simDisk struct {
	buf []byte

	// Transient fault plan and write counter for one Append call.
	plan      faultPlan
	writes    int
	triggered int
}

func newSimDisk() *simDisk {
	return &simDisk{
		buf:       make([]byte, simRingSize),
		plan:      faultPlan{index: -1},
		triggered: -1,
	}
}

func (d *simDisk) Clone() *simDisk {
	c := *d
	c.buf = slices.Clone(d.buf)
	return &c
}

func (d *simDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(d.buf)) {
		return 0, fmt.Errorf("simulation disk read out of range: off=%d len=%d", off, len(p))
	}
	return copy(p, d.buf[off:]), nil
}

func (d *simDisk) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(d.buf)) {
		return 0, fmt.Errorf("simulation disk write out of range: off=%d len=%d", off, len(p))
	}
	index := d.writes
	d.writes++
	if d.plan.mode != faultNone && index == d.plan.index {
		d.triggered = index
		switch d.plan.mode {
		case faultBefore:
			return 0, errSimWrite
		case faultTorn:
			n := len(p) / 2
			copy(d.buf[off:], p[:n])
			return n, errSimWrite
		case faultLost:
			copy(d.buf[off:], p)
			return len(p), errSimWrite
		}
	}
	copy(d.buf[off:], p)
	return len(p), nil
}

// appendAttempt is the part of the append history Check needs in order to
// recognize records that may still be visible. dataSum stands in for the
// payload so that preloaded 60 KiB records keep model clones small.
type appendAttempt struct {
	off     uint64
	gen     uint64
	typ     RecordType
	dataLen int
	dataSum [sha256.Size]byte
	plan    faultPlan
	ok      bool
}

func newAttempt(off, gen uint64, typ RecordType, data []byte, plan faultPlan, ok bool) appendAttempt {
	return appendAttempt{
		off:     off,
		gen:     gen,
		typ:     typ,
		dataLen: len(data),
		dataSum: sha256.Sum256(data),
		plan:    plan,
		ok:      ok,
	}
}

// streamModel drives the production Writer and Reader over simDisk. The model
// never reimplements ring logic: every disk mutation comes from Append,
// persist, or NewWriter. A crash discards only the process-local Writer
// (including its mutex); the disk bytes remain.
type streamModel struct {
	disk    *simDisk
	w       *Writer // nil after a crash, until restart
	gen     uint64  // generation for the next Writer
	history []appendAttempt
	synced  bool // the last completed operation persisted head/tail
	budget  int  // remaining actions; makes the infinite ring model finite

	// plan is the fault plan for the Append currently executing inside Step.
	// Step clears it before returning; the plan of every past attempt is kept
	// in history.
	plan faultPlan
}

func newStreamModel() *streamModel {
	d := newSimDisk()
	w, err := NewWriter(d, simBase, simRingSize, 1)
	if err != nil {
		panic(err)
	}
	m := &streamModel{
		disk:   d,
		w:      w,
		gen:    1,
		synced: true,
		budget: simBudget,
		plan:   faultPlan{index: -1},
	}
	ring := uint64(simRingSize - HeaderSize)
	largeTotal := uint64(RecordHeader + simLargeRecord)
	// Fill with large records until one more would not fit. This leaves the
	// ring nearly full without trimming yet, so the first modeled small
	// append has to drop the oldest whole record.
	for i := 0; i < 64; i++ {
		head, tail := w.Head()
		free := ring - (tail - head)
		if free <= largeTotal {
			break
		}
		data := preloadData(i, simLargeRecord)
		off, err := w.Append(TypeOut, data)
		if err != nil {
			panic(err)
		}
		m.history = append(m.history, newAttempt(off, 1, TypeOut, data, faultPlan{index: -1}, true))
	}
	head, tail := w.Head()
	if head != 0 {
		panic("preload trimmed before the filler record")
	}
	free := ring - (tail - head)
	if free <= 16 {
		panic("preload left too little room for a filler record")
	}
	// Pad the last free slot down to 8 bytes, so even the smallest modeled
	// append has to trim the oldest whole record. Because head is zero, this
	// also puts the write position 8 bytes before the physical end of the
	// ring, exercising a record header split across the wrap.
	fillerTotal := free - 8
	if fillerTotal < uint64(RecordHeader) || fillerTotal-uint64(RecordHeader) > uint64(MaxRecord) {
		panic("preload filler is not a legal record")
	}
	filler := preloadData(1<<20, int(fillerTotal)-RecordHeader)
	off, err := w.Append(TypeOut, filler)
	if err != nil {
		panic(err)
	}
	m.history = append(m.history, newAttempt(off, 1, TypeOut, filler, faultPlan{index: -1}, true))
	head, tail = w.Head()
	if head != 0 {
		panic("filler append trimmed records")
	}
	if got := ring - (tail - head); got != 8 {
		panic(fmt.Sprintf("preload left %d free bytes, want 8", got))
	}
	if pos := tail % ring; pos != ring-8 {
		panic(fmt.Sprintf("preload write position %d, want %d", pos, ring-8))
	}
	return m
}

// preloadData builds a deterministic, unique large payload.
func preloadData(tag, n int) []byte {
	prefix := fmt.Sprintf("preload-%06d:", tag)
	b := make([]byte, n)
	copy(b, prefix)
	for i := len(prefix); i < n; i++ {
		b[i] = byte('a' + (tag+i)%26)
	}
	return b
}

func (m *streamModel) Clone() sim.Model {
	c := *m
	c.disk = m.disk.Clone()
	c.w = cloneWriter(m.w, c.disk)
	c.history = slices.Clone(m.history)
	return &c
}

// cloneWriter rebuilds the production Writer explicitly. Copying the struct
// would copy its sync.Mutex, which is forbidden.
func cloneWriter(w *Writer, rw ReadWriterAt) *Writer {
	if w == nil {
		return nil
	}
	return &Writer{
		rw:     rw,
		base:   w.base,
		size:   w.size,
		gen:    w.gen,
		head:   w.head,
		tail:   w.tail,
		seq:    w.seq,
		closed: w.closed,
	}
}

// Key includes a digest of the whole disk because the ring is MinSize and the
// preload records are large; embedding the bytes would make every explored
// state and trace enormous. SHA-256 is collision-resistant for this purpose.
// The current fault plan and every attempt's recorded plan are included too;
// Step consumes a plan completely, so the current plan is idle between steps.
func (m *streamModel) Key() string {
	var b strings.Builder
	diskSum := sha256.Sum256(m.disk.buf)
	fmt.Fprintf(&b, "disk=%x;gen=%d;synced=%t;budget=%d;plan=%s@%d;", diskSum, m.gen, m.synced, m.budget, m.plan.mode, m.plan.index)
	if m.w == nil {
		b.WriteString("writer=nil;")
	} else {
		head, tail := m.w.Head()
		fmt.Fprintf(&b, "writer=%d/%d/%d/%d/%d/%d/%t;", m.w.base, m.w.size, m.w.gen, head, tail, m.w.seq, m.w.closed)
	}
	b.WriteString("history=")
	for _, a := range m.history {
		fmt.Fprintf(&b, "%d/%d/%d/%d/%x/%s@%d/%t;", a.off, a.gen, a.typ, a.dataLen, a.dataSum, a.plan.mode, a.plan.index, a.ok)
	}
	return b.String()
}

// nextAppend chooses a deterministic, history-unique record for the next
// production Append.
func (m *streamModel) nextAppend() (RecordType, []byte) {
	n := len(m.history)
	typ := RecordType(int(TypeOut) + n%3)
	size := 24 + (n%7)*11
	prefix := fmt.Sprintf("rec-%06d:", n)
	b := make([]byte, size)
	copy(b, prefix)
	for i := len(prefix); i < size; i++ {
		b[i] = byte('a' + (n+i)%26)
	}
	return typ, b
}

// appendCalls counts the WriteAt calls a successful append would make. The
// first headerSegs+payloadSegs calls write the record; the final call persists
// the header slot. This only predicts fault-injection call boundaries; all
// ring arithmetic and data movement remain in the production code.
func (m *streamModel) appendCalls(off uint64, payload int) int {
	ring := m.w.ringLen()
	headerSegs := simSegments(off, RecordHeader, ring)
	payloadSegs := simSegments(off+RecordHeader, payload, ring)
	return headerSegs + payloadSegs + 1
}

func simSegments(off uint64, n int, ring uint64) int {
	count := 0
	for n > 0 {
		pos := off % ring
		chunk := ring - pos
		if chunk > uint64(n) {
			chunk = uint64(n)
		}
		off += chunk
		n -= int(chunk)
		count++
	}
	return count
}

func (m *streamModel) Enabled() []string {
	if m.budget == 0 {
		return nil
	}
	if m.w == nil {
		return []string{"restart"}
	}
	var actions []string
	if !m.w.closed {
		actions = append(actions, "append/ok")
		_, data := m.nextAppend()
		calls := m.appendCalls(m.w.tail, len(data))
		for i := 0; i < calls; i++ {
			actions = append(actions,
				fmt.Sprintf("append/fail@%d", i),
				fmt.Sprintf("append/torn@%d", i),
				fmt.Sprintf("append/lost@%d", i),
			)
		}
		actions = append(actions, "close")
	}
	actions = append(actions, "crash")
	return actions
}

func parsePlan(action string) (faultPlan, error) {
	if action == "append/ok" {
		return faultPlan{index: -1}, nil
	}
	rest, ok := strings.CutPrefix(action, "append/")
	if !ok {
		return faultPlan{}, fmt.Errorf("unknown action %q", action)
	}
	name, indexText, ok := strings.Cut(rest, "@")
	if !ok {
		return faultPlan{}, fmt.Errorf("malformed fault action %q", action)
	}
	index, err := strconv.Atoi(indexText)
	if err != nil || index < 0 {
		return faultPlan{}, fmt.Errorf("malformed fault index in %q", action)
	}
	var mode faultMode
	switch name {
	case "fail":
		mode = faultBefore
	case "torn":
		mode = faultTorn
	case "lost":
		mode = faultLost
	default:
		return faultPlan{}, fmt.Errorf("unknown fault mode %q", name)
	}
	return faultPlan{index: index, mode: mode}, nil
}

func (m *streamModel) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond model budget")
	}
	m.budget--
	switch action {
	case "crash":
		if m.w == nil {
			return errors.New("crash without a live writer")
		}
		// The process's Writer, including head/tail/seq, disappears. Disk
		// bytes written by completed WriteAt calls remain.
		m.w = nil
		m.synced = false
		return nil
	case "restart":
		if m.w != nil {
			return errors.New("restart with a live writer")
		}
		m.gen++
		w, err := NewWriter(m.disk, simBase, simRingSize, m.gen)
		if err != nil {
			return fmt.Errorf("restart: %w", err)
		}
		m.w = w
		m.synced = true
		return m.probeAfterRestart()
	case "close":
		if m.w == nil || m.w.closed {
			return errors.New("close without an open writer")
		}
		if err := m.w.Close(); err != nil {
			return fmt.Errorf("close: %w", err)
		}
		m.synced = true
		return nil
	}

	plan, err := parsePlan(action)
	if err != nil {
		return err
	}
	if m.w == nil || m.w.closed {
		return fmt.Errorf("%s: no open writer", action)
	}
	return m.doAppend(plan)
}

// probeAfterRestart proves that recovery is usable: it appends one fault-free
// record through the recovered Writer and reads it back through a fresh
// Reader.
func (m *streamModel) probeAfterRestart() error {
	if err := m.doAppend(faultPlan{index: -1}); err != nil {
		return fmt.Errorf("restart probe append: %w", err)
	}
	r, err := NewReader(m.disk, simBase, simRingSize)
	if err != nil {
		return err
	}
	head, _ := r.Head()
	recs, _, err := r.Read(head, 0)
	if err != nil {
		return fmt.Errorf("restart probe read: %w", err)
	}
	if len(recs) == 0 {
		return errors.New("restart probe read returned no records")
	}
	last, want := recs[len(recs)-1], m.history[len(m.history)-1]
	if last.Offset != want.off || last.Gen != want.gen || last.Type != want.typ ||
		len(last.Data) != want.dataLen || sha256.Sum256(last.Data) != want.dataSum {
		return fmt.Errorf("restart probe record does not match the append: %+v", last)
	}
	return nil
}

func (m *streamModel) doAppend(plan faultPlan) error {
	typ, data := m.nextAppend()
	gen := m.w.Gen()
	_, tail := m.w.Head()
	off := tail
	calls := m.appendCalls(off, len(data))
	if plan.mode != faultNone && (plan.index < 0 || plan.index >= calls) {
		return fmt.Errorf("fault plan %s@%d outside append's %d writes", plan.mode, plan.index, calls)
	}

	m.plan = plan
	m.disk.plan = plan
	m.disk.writes = 0
	m.disk.triggered = -1
	got, err := m.w.Append(typ, data)
	writes, triggered := m.disk.writes, m.disk.triggered
	m.disk.plan = faultPlan{index: -1}
	m.disk.writes = 0
	m.disk.triggered = -1
	m.plan = faultPlan{index: -1}

	if err == nil && got != off {
		return fmt.Errorf("append returned offset %d, want %d", got, off)
	}
	if plan.mode == faultNone {
		if writes != calls {
			return fmt.Errorf("fault-free append made %d writes, want %d", writes, calls)
		}
		if triggered != -1 {
			return fmt.Errorf("fault-free append fired plan at %d", triggered)
		}
	} else {
		if triggered != plan.index || writes != plan.index+1 {
			return fmt.Errorf("plan %s@%d fired at %d after %d writes", plan.mode, plan.index, triggered, writes)
		}
	}

	recordCalls := calls - 1 // the persisted header slot is the final call
	complete := plan.mode == faultNone ||
		plan.index == recordCalls ||
		(plan.mode == faultLost && plan.index == recordCalls-1)
	if complete {
		m.history = append(m.history, newAttempt(off, gen, typ, data, plan, err == nil))
	}
	m.synced = err == nil
	return nil
}

func (m *streamModel) Check() error {
	r, err := NewReader(m.disk, simBase, simRingSize)
	if err != nil {
		return err
	}
	head, tail := r.Head()
	if head > tail {
		return fmt.Errorf("reader head %d > tail %d", head, tail)
	}

	// A fresh reader starting at the retained head must never return corrupt
	// data or an error. A read from zero may legitimately return ErrGap.
	recs, readHead, err := r.Read(head, 0)
	if err != nil {
		return fmt.Errorf("fresh read at head %d: %w", head, err)
	}
	if readHead != head {
		return fmt.Errorf("read reported head %d, want %d", readHead, head)
	}
	fromZero, gapHead, err := r.Read(0, 0)
	if err != nil {
		if !errors.Is(err, ErrGap) {
			return fmt.Errorf("read from zero: %w", err)
		}
		if len(fromZero) != 0 {
			return fmt.Errorf("gap read returned %d records", len(fromZero))
		}
		if gapHead != head {
			return fmt.Errorf("gap reported head %d, want %d", gapHead, head)
		}
	} else if head == 0 && len(fromZero) != len(recs) {
		return fmt.Errorf("read from zero returned %d records, read at head returned %d", len(fromZero), len(recs))
	}

	if err := m.checkRecords(recs, head, tail); err != nil {
		return err
	}

	if m.w != nil {
		writerHead, writerTail := m.w.Head()
		if writerHead > writerTail {
			return fmt.Errorf("writer head %d > tail %d", writerHead, writerTail)
		}
		// The persisted header can lag in-memory writer state after a failed
		// append, but it can never be ahead of it.
		if head > writerHead || tail > writerTail {
			return fmt.Errorf("reader window %d..%d ahead of writer %d..%d", head, tail, writerHead, writerTail)
		}
		if m.synced && (head != writerHead || tail != writerTail) {
			return fmt.Errorf("persisted window %d..%d differs from writer %d..%d", head, tail, writerHead, writerTail)
		}
	}
	return nil
}

func (m *streamModel) checkRecords(recs []Record, head, tail uint64) error {
	nextHistory := 0
	for i, rec := range recs {
		if rec.Offset < head || rec.Offset >= tail {
			return fmt.Errorf("record offset %d outside window %d..%d", rec.Offset, head, tail)
		}
		if i > 0 && rec.Offset <= recs[i-1].Offset {
			return fmt.Errorf("record offsets not strictly increasing: %d after %d", rec.Offset, recs[i-1].Offset)
		}
		if end := rec.Offset + uint64(RecordHeader+len(rec.Data)); end > tail {
			return fmt.Errorf("record at %d ends at %d, past tail %d", rec.Offset, end, tail)
		}
		sum := sha256.Sum256(rec.Data)
		matched := false
		for ; nextHistory < len(m.history); nextHistory++ {
			a := m.history[nextHistory]
			if a.off == rec.Offset && a.gen == rec.Gen && a.typ == rec.Type && a.dataLen == len(rec.Data) && a.dataSum == sum {
				nextHistory++
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("record at %d (gen=%d type=%d len=%d) is not in append history", rec.Offset, rec.Gen, rec.Type, len(rec.Data))
		}
	}
	return nil
}

func TestStreamSimulation(t *testing.T) {
	initial := newStreamModel()
	report := simtest.Explore(t, initial, sim.Limits{States: 3000, Depth: simBudget})
	if !report.Complete {
		t.Fatalf("incomplete exploration: %+v", report)
	}
	t.Logf("explored %d states, %d transitions", report.States, report.Transitions)

	simtest.Run(t, initial, simtest.Seeds(0, 8), 14)
}

func TestStreamRealFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "ring-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	path := f.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if err := f.Truncate(simRingSize); err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(f, simBase, simRingSize, 7)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("real-file-first")
	firstOff, err := w.Append(TypeOut, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	w2, err := NewWriter(reopened, simBase, simRingSize, 8)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(reopened, simBase, simRingSize)
	if err != nil {
		t.Fatal(err)
	}
	second := []byte("real-file-second")
	secondOff, err := w2.Append(TypeIn, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Sync(); err != nil {
		t.Fatal(err)
	}

	recs, head, err := r.Read(firstOff, 0)
	if err != nil {
		t.Fatal(err)
	}
	if head != 0 {
		t.Fatalf("head=%d", head)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Offset != firstOff || string(recs[0].Data) != string(first) || recs[0].Type != TypeOut || recs[0].Gen != 7 {
		t.Fatalf("first record: %+v", recs[0])
	}
	if recs[1].Offset != secondOff || secondOff <= firstOff || recs[1].Offset != firstOff+uint64(RecordHeader+len(first)) {
		t.Fatalf("second offset %d after first %d", recs[1].Offset, firstOff)
	}
	if string(recs[1].Data) != string(second) || recs[1].Type != TypeIn || recs[1].Gen != 8 {
		t.Fatalf("second record: %+v", recs[1])
	}
}
