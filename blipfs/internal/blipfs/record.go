package blipfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"sync"
)

const (
	recMagic   = 0xb11bf5a1
	recVersion = 1
	spillFlag  = 0x80
)

// Record types. The ops in the payload define the semantics; the type is
// informational except that JUNK and STAGE records are never applied.
const (
	RecJunk   = 1
	RecCommit = 2
	RecStage  = 3
	RecBranch = 4
	RecMerge  = 5
	RecGC     = 6
)

var recTypeNames = map[uint8]string{RecJunk: "junk", RecCommit: "commit", RecStage: "stage", RecBranch: "branch", RecMerge: "merge", RecGC: "gc"}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Record is one WAL slot:
// magic|ver|epoch|lsn|type|streams[]|backptrs[]|node|len|payload|crc32c
type Record struct {
	Epoch    uint64
	LSN      uint64
	Type     uint8
	Streams  []string
	Backptrs []uint64
	Node     string
	Payload  []byte
}

func (r *Record) Back(stream string) (uint64, bool) {
	for i, s := range r.Streams {
		if s == stream {
			return r.Backptrs[i], true
		}
	}
	return 0, false
}

func (r *Record) Encode() []byte {
	b := binary.BigEndian.AppendUint32(nil, recMagic)
	b = append(b, recVersion)
	b = binary.BigEndian.AppendUint64(b, r.Epoch)
	b = binary.BigEndian.AppendUint64(b, r.LSN)
	b = append(b, r.Type)
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.Streams)))
	for _, s := range r.Streams {
		b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
		b = append(b, s...)
	}
	for _, p := range r.Backptrs {
		b = binary.BigEndian.AppendUint64(b, p)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.Node)))
	b = append(b, r.Node...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(r.Payload)))
	b = append(b, r.Payload...)
	return binary.BigEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
}

var errShort = errors.New("short record")

// DecodeRecord parses a slot. It returns errShort with the needed total
// length when b holds only a prefix of the record.
func DecodeRecord(b []byte) (*Record, int, error) {
	r := &Record{}
	p := 0
	need := func(n int) bool { return p+n <= len(b) }
	if !need(22) || binary.BigEndian.Uint32(b) != recMagic || b[4] != recVersion {
		return nil, 0, errors.New("bad magic")
	}
	r.Epoch = binary.BigEndian.Uint64(b[5:])
	r.LSN = binary.BigEndian.Uint64(b[13:])
	r.Type = b[21]
	p = 22
	if !need(2) {
		return nil, 0, errShort
	}
	ns := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if ns > 64 {
		return nil, 0, errors.New("bad stream count")
	}
	for i := 0; i < ns; i++ {
		if !need(2) {
			return nil, 0, errShort
		}
		l := int(binary.BigEndian.Uint16(b[p:]))
		p += 2
		if !need(l) {
			return nil, 0, errShort
		}
		r.Streams = append(r.Streams, string(b[p:p+l]))
		p += l
	}
	for i := 0; i < ns; i++ {
		if !need(8) {
			return nil, 0, errShort
		}
		r.Backptrs = append(r.Backptrs, binary.BigEndian.Uint64(b[p:]))
		p += 8
	}
	if !need(2) {
		return nil, 0, errShort
	}
	l := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if !need(l) {
		return nil, 0, errShort
	}
	r.Node = string(b[p : p+l])
	p += l
	if !need(4) {
		return nil, 0, errShort
	}
	pl := int(binary.BigEndian.Uint32(b[p:]))
	p += 4
	total := p + pl + 4
	if pl > 1<<30 {
		return nil, 0, errors.New("bad length")
	}
	if total > len(b) {
		return nil, total, errShort
	}
	if crc32.Checksum(b[:p+pl], castagnoli) != binary.BigEndian.Uint32(b[p+pl:]) {
		return nil, 0, errors.New("bad crc")
	}
	r.Payload = append([]byte(nil), b[p:p+pl]...)
	return r, total, nil
}

// WAL is the striped, ring-addressed log on page blobs wal-0..wal-N-1.
type WAL struct {
	st       *Store
	stripes  int
	slotSize int
	slots    int // per stripe
}

func walName(i int) string { return fmt.Sprintf("wal-%d", i) }

// Capacity is the number of LSNs the ring holds before slots are reused.
func (w *WAL) Capacity() uint64 { return uint64(w.stripes * w.slots) }

func (w *WAL) loc(lsn uint64) (string, int64) {
	s := lsn % uint64(w.stripes)
	idx := (lsn / uint64(w.stripes)) % uint64(w.slots)
	return walName(int(s)), int64(idx) * int64(w.slotSize)
}

func (w *WAL) Create(ctx context.Context, epoch uint64) error {
	for i := 0; i < w.stripes; i++ {
		if _, err := w.st.CreatePage(ctx, walName(i), int64(w.slots)*int64(w.slotSize), int64(epoch), nil); err != nil {
			return err
		}
	}
	return nil
}

// Write puts rec into its slot, fenced on rec.Epoch. Payloads too large for a
// slot are spilled to a block blob that the record references.
func (w *WAL) Write(ctx context.Context, rec *Record) error {
	b := rec.Encode()
	if len(b) > w.slotSize {
		name := fmt.Sprintf("spill/%016x-%08x", rec.LSN, rand.Uint32())
		if err := w.st.PutBlob(ctx, name, rec.Payload); err != nil {
			return err
		}
		r2 := *rec
		r2.Type |= spillFlag
		r2.Payload = []byte(name)
		b = r2.Encode()
		if len(b) > w.slotSize {
			return errors.New("record header too large")
		}
	}
	blob, off := w.loc(rec.LSN)
	return w.st.WritePages(ctx, blob, off, b, int64(rec.Epoch), "")
}

// Read returns the record at lsn, or nil if the slot holds no valid record
// for this lsn (empty, torn, or an older lap of the ring).
func (w *WAL) Read(ctx context.Context, lsn uint64) (*Record, error) {
	blob, off := w.loc(lsn)
	b, err := w.st.Read(ctx, blob, off, 4096)
	if err != nil {
		return nil, err
	}
	return w.decodeSlot(ctx, lsn, b)
}

// decodeSlot decodes the (possibly partial) slot contents b read for lsn.
func (w *WAL) decodeSlot(ctx context.Context, lsn uint64, b []byte) (*Record, error) {
	r, total, err := DecodeRecord(b)
	if errors.Is(err, errShort) && total > len(b) && total <= w.slotSize {
		blob, off := w.loc(lsn)
		if b, err = w.st.Read(ctx, blob, off, int64(total)); err != nil {
			return nil, err
		}
		r, _, err = DecodeRecord(b)
	}
	if err != nil || r.LSN != lsn {
		return nil, nil
	}
	if r.Type&spillFlag != 0 {
		p, err := w.st.ReadAll(ctx, string(r.Payload))
		if err != nil {
			return nil, err
		}
		r.Type &^= spillFlag
		r.Payload = p
	}
	return r, nil
}

// ReadMany reads lsns in parallel; missing/invalid slots map to nil.
func (w *WAL) ReadMany(ctx context.Context, lsns []uint64) (map[uint64]*Record, error) {
	out := make(map[uint64]*Record, len(lsns))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, l := range lsns {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			r, err := w.Read(ctx, l)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			out[l] = r
		}()
	}
	wg.Wait()
	return out, firstErr
}

// ReadRange reads every slot in [lo, hi] using large contiguous reads per
// stripe; invalid slots map to nil.
func (w *WAL) ReadRange(ctx context.Context, lo, hi uint64) (map[uint64]*Record, error) {
	out := map[uint64]*Record{}
	if hi < lo {
		return out, nil
	}
	const run = 64
	type job struct{ first, n uint64 } // lsns first, first+N, ... (n of them)
	var jobs []job
	n := uint64(w.stripes)
	for s := uint64(0); s < n; s++ {
		first := lo + (s+n-lo%n)%n
		for l := first; l <= hi; {
			_, off := w.loc(l)
			k := uint64(0)
			// stop a run at the end of the stripe (ring wrap) or after run slots
			for l+k*n <= hi && k < run && off+int64(k)*int64(w.slotSize) < int64(w.slots)*int64(w.slotSize) {
				k++
			}
			jobs = append(jobs, job{l, k})
			l += k * n
		}
	}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			blob, off := w.loc(j.first)
			b, err := w.st.Read(ctx, blob, off, int64(j.n)*int64(w.slotSize))
			recs := map[uint64]*Record{}
			for i := uint64(0); err == nil && i < j.n; i++ {
				l := j.first + i*n
				s := b[min(len(b), int(i)*w.slotSize):min(len(b), int(i+1)*w.slotSize)]
				recs[l], err = w.decodeSlot(ctx, l, s)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for l, r := range recs {
				out[l] = r
			}
		}()
	}
	wg.Wait()
	return out, firstErr
}

// Seal raises every stripe's sequence number to epoch so that writes
// carrying an older epoch fail with 412.
func (w *WAL) Seal(ctx context.Context, epoch uint64) error {
	errs := make(chan error, w.stripes)
	for i := 0; i < w.stripes; i++ {
		go func() { errs <- w.st.Seal(ctx, walName(i), int64(epoch)) }()
	}
	var err error
	for i := 0; i < w.stripes; i++ {
		if e := <-errs; e != nil {
			err = e
		}
	}
	return err
}
