package blipfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jotfs/fastcdc-go"
	"github.com/zeebo/blake3"
)

const (
	packMax    = 64 << 20         // rotate packs at this size
	packBlocks = 4000             // ... or this many blocks
	blockSize  = 4 << 20          // stage blocks of this size
	readRun    = 8 << 20          // max bytes per coalesced ranged GET
	packIdle   = 10 * time.Minute // GC may reclaim packs idle much longer
)

var cdcOpts = fastcdc.Options{MinSize: 16 << 10, AverageSize: 64 << 10, MaxSize: 256 << 10}

func hashOf(b []byte) []byte { h := blake3.Sum256(b); return h[:] }

// chunkSplit calls fn for each content-defined chunk of r. Data passed to fn
// is only valid during the call.
func chunkSplit(r io.Reader, fn func(off int64, data []byte) error) error {
	c, err := fastcdc.NewChunker(r, cdcOpts)
	if err != nil {
		return err
	}
	for {
		ch, err := c.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(int64(ch.Offset), ch.Data); err != nil {
			return err
		}
	}
}

// ChunkVal is a chunk index entry: where a chunk lives, and the LSN of the
// record that last put (or re-asserted) it.
type ChunkVal struct {
	Pack string `cbor:"1,keyasint"`
	Off  int64  `cbor:"2,keyasint"`
	Len  int32  `cbor:"3,keyasint"`
	LSN  uint64 `cbor:"4,keyasint"`
}

type chunkEntry struct {
	ChunkVal
	mod       uint64 // LSN of the last change; drives checkpointing
	deleted   bool
	confirmed bool // applied from the !chunks stream (vs. our own not-yet-replayed put)
}

type packBlock struct {
	id   string
	done chan struct{}
	err  error
}

type pack struct {
	name      string
	size      int64
	buf       []byte
	blocks    []*packBlock
	committed int
	err       error
	at        time.Time // last append
	commitMu  sync.Mutex
}

// Chunks is the content-addressed chunk store: an append-only set of pack
// block blobs plus the global dedup index replicated through !chunks.
type Chunks struct {
	v      *Vol
	stream *stream

	mu sync.Mutex
	m  map[[32]byte]*chunkEntry

	pmu   sync.Mutex
	cur   *pack
	packs map[string]*pack // packs with uncommitted blocks
	sem   chan struct{}
}

func newChunks(v *Vol) *Chunks {
	c := &Chunks{v: v, m: map[[32]byte]*chunkEntry{}, packs: map[string]*pack{}, sem: make(chan struct{}, 16)}
	c.stream = &stream{v: v, name: chunksStream, apply: c.applyRecord}
	return c
}

func key32(h []byte) (k [32]byte) { copy(k[:], h); return }

func chunkShard(h []byte, shards int) int { return int(binary.BigEndian.Uint32(h) % uint32(shards)) }

// applyRecord replays the chunk ops of one !chunks record. First put wins;
// later puts of the same hash only refresh the entry's LSN.
func (c *Chunks) applyRecord(rec *Record, body *Body) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, op := range body.Ops {
		for _, ce := range op.Chunks {
			k := key32(ce.Hash)
			e := c.m[k]
			switch op.Kind {
			case OpChunkPut:
				if e == nil || !e.confirmed || e.deleted {
					if e == nil || !e.confirmed {
						if cur, ok := c.snapLookup(ce.Hash); ok {
							e = &chunkEntry{ChunkVal: cur, confirmed: true}
							c.m[k] = e
						}
					}
					if e == nil || !e.confirmed || e.deleted {
						e = &chunkEntry{ChunkVal: ChunkVal{Pack: ce.Pack, Off: ce.Off, Len: ce.Len}, confirmed: true}
						c.m[k] = e
					}
				}
				e.LSN, e.mod = max(e.LSN, rec.LSN), rec.LSN
			case OpChunkDel:
				if e == nil || !e.confirmed {
					cur, ok := c.snapLookup(ce.Hash)
					if !ok {
						continue
					}
					e = &chunkEntry{ChunkVal: cur, confirmed: true}
					c.m[k] = e
				}
				if !e.deleted && e.LSN <= op.Before {
					e.deleted, e.mod = true, rec.LSN
				}
			case OpChunkMove:
				if e == nil || !e.confirmed {
					cur, ok := c.snapLookup(ce.Hash)
					if !ok {
						continue
					}
					e = &chunkEntry{ChunkVal: cur, confirmed: true}
					c.m[k] = e
				}
				if !e.deleted && e.Pack == ce.OldPack && e.Off == ce.OldOff {
					e.Pack, e.Off, e.Len, e.mod = ce.Pack, ce.Off, ce.Len, rec.LSN
				}
			}
		}
	}
	return nil
}

// snapLookup reads the checkpointed index entry (caller may hold c.mu).
func (c *Chunks) snapLookup(h []byte) (ChunkVal, bool) {
	t := c.v.snap.tree(chunkShard(h, c.v.shards))
	v, ok, err := t.Get(append([]byte{'X'}, h...))
	if err != nil || !ok {
		return ChunkVal{}, false
	}
	var cv ChunkVal
	if cbor.Unmarshal(v, &cv) != nil {
		return ChunkVal{}, false
	}
	return cv, true
}

// Lookup returns the location of a chunk if the index knows it.
func (c *Chunks) Lookup(h []byte) (ChunkVal, bool) {
	c.mu.Lock()
	e := c.m[key32(h)]
	if e != nil {
		v, del := e.ChunkVal, e.deleted
		c.mu.Unlock()
		return v, !del
	}
	c.mu.Unlock()
	return c.snapLookup(h)
}

// noteOwn records our own puts right after their record is written so that
// reads work before we replay !chunks; the stream replay confirms them.
func (c *Chunks) noteOwn(lsn uint64, ents []ChunkEnt) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ce := range ents {
		k := key32(ce.Hash)
		if e := c.m[k]; e == nil || e.deleted && !e.confirmed {
			c.m[k] = &chunkEntry{ChunkVal: ChunkVal{Pack: ce.Pack, Off: ce.Off, Len: ce.Len, LSN: lsn}, mod: lsn}
		}
	}
}

// prune drops confirmed entries of shard k that a checkpoint up to lsn covers.
func (c *Chunks) prune(k int, lsn uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for h, e := range c.m {
		if e.confirmed && e.mod <= lsn && chunkShard(h[:], c.v.shards) == k {
			delete(c.m, h)
		}
	}
}

// --- writing ---

func newPackName() string {
	var b [8]byte
	rand.Read(b[:])
	return "pack/" + hex.EncodeToString(b[:])
}

func blockID(i int) string { return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%08d", i)) }

// put appends a chunk to the active pack and returns its location. The data
// is durable only after flush of that pack.
func (c *Chunks) put(data []byte) (string, int64) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	p := c.cur
	if p == nil || p.err != nil || p.size+int64(len(data)) > packMax || len(p.blocks) >= packBlocks || time.Since(p.at) > packIdle {
		if p != nil {
			c.cut(p)
		}
		p = &pack{name: newPackName()}
		c.cur = p
		c.packs[p.name] = p
	}
	off := p.size
	p.at = time.Now()
	p.buf = append(p.buf, data...)
	p.size += int64(len(data))
	if len(p.buf) >= blockSize {
		c.cut(p)
	}
	return p.name, off
}

// cut stages p's buffered bytes as a new block in the background (c.pmu held).
func (c *Chunks) cut(p *pack) {
	if len(p.buf) == 0 {
		return
	}
	b := &packBlock{id: blockID(len(p.blocks)), done: make(chan struct{})}
	p.blocks = append(p.blocks, b)
	data := p.buf
	p.buf = nil
	go func() {
		c.sem <- struct{}{}
		defer func() { <-c.sem }()
		b.err = c.v.st.StageBlock(context.Background(), p.name, b.id, data)
		close(b.done)
	}()
}

// flush makes everything appended so far to the named packs durable.
func (c *Chunks) flush(ctx context.Context, names map[string]bool) error {
	for name := range names {
		c.pmu.Lock()
		p := c.packs[name]
		if p == nil { // already fully committed
			c.pmu.Unlock()
			continue
		}
		c.cut(p)
		blocks := append([]*packBlock(nil), p.blocks...)
		c.pmu.Unlock()

		ids := make([]string, len(blocks))
		for i, b := range blocks {
			select {
			case <-b.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			if b.err != nil {
				c.pmu.Lock()
				p.err = b.err
				c.pmu.Unlock()
				return fmt.Errorf("upload pack block: %w", b.err)
			}
			ids[i] = b.id
		}
		p.commitMu.Lock()
		var err error
		if p.committed < len(ids) {
			if err = c.v.st.CommitBlocks(ctx, p.name, ids); err == nil {
				p.committed = len(ids)
			}
		}
		p.commitMu.Unlock()
		if err != nil {
			return err
		}
		c.pmu.Lock()
		if p != c.cur && p.committed == len(p.blocks) && len(p.buf) == 0 {
			delete(c.packs, p.name)
		}
		c.pmu.Unlock()
	}
	return nil
}

// upload stores the chunk unless the index already has it, and returns the
// entry to (re-)assert in the commit record.
func (c *Chunks) upload(data []byte, packs map[string]bool) ChunkEnt {
	h := hashOf(data)
	if v, ok := c.Lookup(h); ok {
		return ChunkEnt{Hash: h, Pack: v.Pack, Off: v.Off, Len: v.Len}
	}
	name, off := c.put(data)
	packs[name] = true
	return ChunkEnt{Hash: h, Pack: name, Off: off, Len: int32(len(data))}
}

// --- reading ---

// piece is a request for n bytes at skip within chunk hash.
type piece struct {
	hash []byte
	skip uint64
	n    uint64
	dst  []byte
}

var errChunkMissing = errors.New("chunk not found")

// read fills every piece's dst from Azure. Contiguous chunks in one pack are
// fetched with one ranged GET and verified against their hashes.
func (c *Chunks) read(ctx context.Context, ps []piece) error {
	err := c.readOnce(ctx, ps)
	if err == nil {
		return nil
	}
	// The chunk may have moved (compaction) or be known only via !chunks.
	if cerr := c.stream.catchUp(ctx, 0); cerr != nil {
		return cerr
	}
	return c.readOnce(ctx, ps)
}

func (c *Chunks) readOnce(ctx context.Context, ps []piece) error {
	type want struct {
		ChunkVal
		ps []*piece
	}
	byHash := map[[32]byte]*want{}
	var ws []*want
	for i := range ps {
		k := key32(ps[i].hash)
		w := byHash[k]
		if w == nil {
			v, ok := c.Lookup(ps[i].hash)
			if !ok {
				return fmt.Errorf("%w: %x", errChunkMissing, ps[i].hash)
			}
			w = &want{ChunkVal: v}
			byHash[k] = w
			ws = append(ws, w)
		}
		w.ps = append(w.ps, &ps[i])
	}
	sort.Slice(ws, func(i, j int) bool {
		if ws[i].Pack != ws[j].Pack {
			return ws[i].Pack < ws[j].Pack
		}
		return ws[i].Off < ws[j].Off
	})
	var runs [][]*want
	for i, w := range ws {
		if i > 0 {
			r := runs[len(runs)-1]
			l := r[len(r)-1]
			if l.Pack == w.Pack && l.Off+int64(l.Len) == w.Off && w.Off+int64(w.Len)-r[0].Off <= readRun {
				runs[len(runs)-1] = append(r, w)
				continue
			}
		}
		runs = append(runs, []*want{w})
	}
	errs := make(chan error, len(runs))
	sem := make(chan struct{}, 16)
	for _, r := range runs {
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			last := r[len(r)-1]
			b, err := c.v.st.Read(ctx, r[0].Pack, r[0].Off, last.Off+int64(last.Len)-r[0].Off)
			if err != nil {
				errs <- err
				return
			}
			for _, w := range r {
				data := b[w.Off-r[0].Off : w.Off-r[0].Off+int64(w.Len)]
				h := blake3.Sum256(data)
				if !bytes.Equal(h[:], w.ps[0].hash) {
					errs <- fmt.Errorf("chunk %x: hash mismatch in %s", w.ps[0].hash, w.Pack)
					return
				}
				for _, p := range w.ps {
					copy(p.dst, data[p.skip:p.skip+p.n])
				}
			}
			errs <- nil
		}()
	}
	var first error
	for range runs {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return first
}
