package blipfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	snapSize  = 1 << 40 // sparse; only written pages are billed
	snapData  = 8192    // tree nodes start here; superblocks live below
	rootEvery = 64      // materialise a full root every this many commits
	sbMagic   = 0xb11b5b10
	ckptEvery = 30 * time.Second
	snapTick  = 15 * time.Second
)

// RootRef is a persisted tree root.
type RootRef struct {
	Hash []byte `cbor:"1,keyasint,omitempty"`
	Loc  Loc    `cbor:"2,keyasint"`
}

type superblock struct {
	Seq   uint64  `cbor:"1,keyasint"`
	Ckpt  uint64  `cbor:"2,keyasint"` // every stream of the shard is captured at >= Ckpt
	Root  RootRef `cbor:"3,keyasint"`
	Alloc int64   `cbor:"4,keyasint"`
	Time  int64   `cbor:"5,keyasint"`
}

// branchEnt is the checkpointed state of one branch ('B'+name).
type branchEnt struct {
	Meta  BranchMeta `cbor:"1,keyasint"`
	Known uint64     `cbor:"2,keyasint"` // stream watermark the entry reflects
	Last  uint64     `cbor:"3,keyasint"` // newest record of the stream
	Root  RootRef    `cbor:"4,keyasint"`
}

// commitEnt is one checkpointed commit ('C'+stream+0+lsn).
type commitEnt struct {
	Type       uint8  `cbor:"1,keyasint"`
	Node       string `cbor:"2,keyasint"`
	Time       int64  `cbor:"3,keyasint"`
	Ops        []Op   `cbor:"4,keyasint"`
	Concurrent bool   `cbor:"5,keyasint,omitempty"`
	Count      uint64 `cbor:"6,keyasint"`
}

type shard struct {
	k     int
	mu    sync.Mutex
	sb    superblock
	tree  Tree
	lease *Lease
	last  time.Time // last checkpoint by this node
}

// Snap holds the checkpointed state: one page blob per shard, each with two
// alternating superblocks and an append-only area of tree nodes.
type Snap struct {
	v      *Vol
	shards []*shard
}

func snapName(k int) string { return fmt.Sprintf("snap-%d", k) }

func lsn8(l uint64) []byte { return binary.BigEndian.AppendUint64(nil, l) }

func skey(p byte, parts ...[]byte) []byte {
	k := []byte{p}
	for _, x := range parts {
		k = append(k, x...)
	}
	return k
}

func bKey(name string) []byte              { return skey('B', []byte(name)) }
func tKey(stream string) []byte            { return skey('T', []byte(stream)) }
func kKey(stream string) []byte            { return skey('K', []byte(stream)) }
func nKey(name string) []byte              { return skey('N', []byte(name)) }
func xKey(h []byte) []byte                 { return skey('X', h) }
func streamPrefix(p byte, s string) []byte { return skey(p, []byte(s), []byte{0}) }
func cKey(s string, l uint64) []byte       { return append(streamPrefix('C', s), lsn8(l)...) }
func rKey(s string, l uint64) []byte       { return append(streamPrefix('R', s), lsn8(l)...) }
func hKey(ino, l uint64, s string) []byte {
	return skey('H', lsn8(ino), lsn8(l), []byte(s))
}

func newSnap(v *Vol, shards int) *Snap {
	s := &Snap{v: v}
	for k := range shards {
		s.shards = append(s.shards, &shard{k: k, sb: superblock{Alloc: snapData}})
	}
	return s
}

func (s *Snap) readNode(l Loc) ([]byte, error) {
	return s.v.st.Read(context.Background(), snapName(int(l.Shard)), l.Off, int64(l.Len))
}

func (s *Snap) ref(r RootRef) *Ref {
	if len(r.Hash) == 0 {
		return nil
	}
	return RefAt(r.Hash, r.Loc, s)
}

func (s *Snap) branchShard(name string) int {
	h := fnv.New32a()
	h.Write([]byte(name))
	return int(h.Sum32() % uint32(len(s.shards)))
}

func encodeSB(sb superblock) []byte {
	body := mustCBOR(sb)
	b := make([]byte, 512)
	binary.BigEndian.PutUint32(b, sbMagic)
	binary.BigEndian.PutUint32(b[4:], uint32(len(body)))
	copy(b[8:], body)
	binary.BigEndian.PutUint32(b[8+len(body):], crc32.Checksum(b[:8+len(body)], castagnoli))
	return b
}

func decodeSB(b []byte) (superblock, bool) {
	var sb superblock
	if len(b) < 12 || binary.BigEndian.Uint32(b) != sbMagic {
		return sb, false
	}
	n := int(binary.BigEndian.Uint32(b[4:]))
	if 12+n > len(b) || binary.BigEndian.Uint32(b[8+n:]) != crc32.Checksum(b[:8+n], castagnoli) {
		return sb, false
	}
	return sb, cbor.Unmarshal(b[8:8+n], &sb) == nil
}

// create makes the shard blobs of a new volume.
func (s *Snap) create(ctx context.Context) error {
	for k := range s.shards {
		if _, err := s.v.st.CreatePage(ctx, snapName(k), snapSize, 0, nil); err != nil {
			return err
		}
	}
	return nil
}

// load reads the newest valid superblock of shard k and, when it moved,
// lets in-memory state drop what the checkpoint now covers.
func (s *Snap) load(ctx context.Context, k int) error {
	b, err := s.v.st.Read(ctx, snapName(k), 0, 1024)
	if err != nil {
		return err
	}
	best, ok := superblock{Alloc: snapData}, false
	for i := 0; i+512 <= len(b); i += 512 {
		if sb, valid := decodeSB(b[i : i+512]); valid && (!ok || sb.Seq > best.Seq) {
			best, ok = sb, true
		}
	}
	sh := s.shards[k]
	sh.mu.Lock()
	moved := best.Seq > sh.sb.Seq || (ok && sh.tree.Root == nil && len(best.Root.Hash) > 0)
	if moved {
		sh.sb, sh.tree = best, Tree{Root: s.ref(best.Root)}
	}
	sh.mu.Unlock()
	if moved {
		s.covered(k)
	}
	return nil
}

// covered trims in-memory history that shard k's checkpoint now holds.
func (s *Snap) covered(k int) {
	sh := s.shards[k]
	sh.mu.Lock()
	ckpt, t := sh.sb.Ckpt, sh.tree
	sh.mu.Unlock()
	if s.v.chunks != nil {
		s.v.chunks.prune(k, getU64(t, kKey(chunksStream)))
	}
	s.v.mu.Lock()
	var bs []*Branch
	for name, b := range s.v.branches {
		if s.branchShard(name) == k {
			bs = append(bs, b)
		}
	}
	s.v.mu.Unlock()
	for _, b := range bs {
		b.trim(ckpt)
	}
}

func getU64(t Tree, key []byte) uint64 {
	v, ok, err := t.Get(key)
	if err != nil || !ok || len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (s *Snap) tree(k int) Tree {
	sh := s.shards[k]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.tree
}

func (s *Snap) ckpt(k int) uint64 {
	sh := s.shards[k]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.sb.Ckpt
}

// minCkpt is the WAL trim point: everything at or below it is checkpointed.
func (s *Snap) minCkpt() uint64 {
	m := uint64(0)
	for k := range s.shards {
		if c := s.ckpt(k); k == 0 || c < m {
			m = c
		}
	}
	return m
}

func (s *Snap) loadAll(ctx context.Context) error {
	for k := range s.shards {
		if err := s.load(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

func (s *Snap) branchEntry(name string) (uint64, *branchEnt, error) {
	k := s.branchShard(name)
	sh := s.shards[k]
	sh.mu.Lock()
	ckpt, t := sh.sb.Ckpt, sh.tree
	sh.mu.Unlock()
	v, ok, err := t.Get(bKey(name))
	if err != nil || !ok {
		return ckpt, nil, err
	}
	var e branchEnt
	if err := cbor.Unmarshal(v, &e); err != nil {
		return 0, nil, err
	}
	return ckpt, &e, nil
}

// historicalTree rebuilds a branch tree at lsn from the nearest
// materialised root at or below lsn plus the checkpointed commits after it.
func (s *Snap) historicalTree(ctx context.Context, b *Branch, lsn uint64) (Tree, error) {
	t := s.tree(s.branchShard(b.name))
	st := branchStream(b.name)
	k, v, ok, err := t.Floor(rKey(st, lsn))
	if err != nil {
		return Tree{}, err
	}
	pre := streamPrefix('R', st)
	if !ok || !bytes.HasPrefix(k, pre) {
		return Tree{}, fmt.Errorf("%s@%d: no checkpointed history: %w", b.name, lsn, syscall.ENOENT)
	}
	var rr RootRef
	if err := cbor.Unmarshal(v, &rr); err != nil {
		return Tree{}, err
	}
	tree := Tree{Root: s.ref(rr)}
	from := binary.BigEndian.Uint64(k[len(pre):]) + 1
	cpre := streamPrefix('C', st)
	var ferr error
	err = t.Ascend(cKey(st, from), func(k, v []byte) bool {
		if !bytes.HasPrefix(k, cpre) {
			return false
		}
		l := binary.BigEndian.Uint64(k[len(cpre):])
		if l > lsn {
			return false
		}
		var ce commitEnt
		if ferr = cbor.Unmarshal(v, &ce); ferr != nil {
			return false
		}
		if ce.Type == RecStage {
			return true
		}
		tree, ferr = replayOps(tree, l, ce.Node, ce.Ops)
		return ferr == nil
	})
	if err == nil {
		err = ferr
	}
	return tree, err
}

// snapTails returns the WAL trim point and each stream's newest record as
// of the checkpoints, for leader recovery.
func (v *Vol) snapTails(ctx context.Context) (uint64, map[string]uint64, error) {
	if err := v.snap.loadAll(ctx); err != nil {
		return 0, nil, err
	}
	tails := map[string]uint64{}
	for k := range v.snap.shards {
		err := v.snap.tree(k).AscendPrefix([]byte{'T'}, func(key, val []byte) bool {
			if len(val) == 8 {
				s := string(key[1:])
				tails[s] = max(tails[s], binary.BigEndian.Uint64(val))
			}
			return true
		})
		if err != nil {
			return 0, nil, err
		}
	}
	return v.snap.minCkpt(), tails, nil
}

func (v *Vol) snapTrim(ctx context.Context) (uint64, error) {
	if err := v.snap.loadAll(ctx); err != nil {
		return 0, err
	}
	return v.snap.minCkpt(), nil
}

// loadState seeds the branch table and chunk stream from the checkpoints.
func (s *Snap) loadState() error {
	t0 := s.tree(0)
	tb := s.v.table
	err := t0.AscendPrefix([]byte{'N'}, func(k, v []byte) bool {
		var e tableEnt
		if cbor.Unmarshal(v, &e) == nil {
			tb.m[string(k[1:])] = &e
		}
		return true
	})
	if err != nil {
		return err
	}
	tb.s.known.Store(getU64(t0, kKey(branchesStream)))
	tb.s.last.Store(getU64(t0, tKey(branchesStream)))
	cs := s.v.chunks.stream
	var known, last uint64
	for k := range s.shards {
		t := s.tree(k)
		if c := getU64(t, kKey(chunksStream)); k == 0 || c < known {
			known = c
		}
		last = max(last, getU64(t, tKey(chunksStream)))
	}
	cs.known.Store(known)
	cs.last.Store(last)
	return nil
}

// --- checkpointing ---

// run keeps shard leases and checkpoints the shards this node holds.
func (s *Snap) run(ctx context.Context) {
	t := time.NewTicker(snapTick)
	defer t.Stop()
	for {
		for k, sh := range s.shards {
			s.tend(ctx, k, sh)
		}
		// Keep the dedup index fresh so writers never reuse deleted chunks.
		if err := s.v.chunks.stream.catchUp(ctx, 0); err != nil && ctx.Err() == nil {
			log.Printf("!chunks: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (sh *shard) setLease(l *Lease) {
	sh.mu.Lock()
	sh.lease = l
	sh.mu.Unlock()
}

func (s *Snap) tend(ctx context.Context, k int, sh *shard) {
	if sh.lease != nil {
		if err := sh.lease.Renew(ctx); err != nil {
			log.Printf("snap-%d: lost lease: %v", k, err)
			sh.setLease(nil)
		}
	}
	if sh.lease == nil {
		l, err := s.v.st.AcquireLease(ctx, snapName(k), s.v.leaseID, leaseSeconds)
		if err != nil {
			log.Printf("snap-%d: lease: %v", k, err)
		}
		sh.setLease(l)
	}
	if sh.lease == nil {
		if err := s.load(ctx, k); err != nil {
			log.Printf("snap-%d: refresh: %v", k, err)
		}
		return
	}
	if time.Since(sh.last) >= ckptEvery {
		if err := s.checkpoint(ctx, k); err != nil {
			log.Printf("snap-%d: checkpoint: %v", k, err)
			if isFenced(err) {
				sh.setLease(nil)
			}
			return
		}
		sh.last = time.Now()
	}
}

// close writes a final checkpoint of the shards we hold and releases them.
func (s *Snap) close(ctx context.Context) {
	for k, sh := range s.shards {
		if sh.lease == nil {
			continue
		}
		if err := s.checkpoint(ctx, k); err != nil {
			log.Printf("snap-%d: final checkpoint: %v", k, err)
		}
		sh.lease.Release(ctx)
		sh.setLease(nil)
	}
}

// ckptWriter accumulates one checkpoint: shard tree edits plus new nodes.
type ckptWriter struct {
	t     Tree
	edits map[string]Edit
	p     *persistBatch
}

func (w *ckptWriter) put(k, v []byte) { w.edits[string(k)] = Edit{Key: k, Val: v} }
func (w *ckptWriter) del(k []byte)    { w.edits[string(k)] = Edit{Key: k, Del: true} }
func (w *ckptWriter) putU64(k []byte, v uint64) {
	w.put(k, lsn8(v))
}

func (w *ckptWriter) root(t Tree) RootRef {
	if t.Root == nil {
		return RootRef{}
	}
	w.p.add(t.Root)
	l := t.Root.Loc()
	if l == nil {
		ll := w.p.locs[t.Root]
		l = &ll
	}
	return RootRef{Hash: t.Root.Hash[:], Loc: *l}
}

// checkpoint captures every stream owned by shard k at or beyond the
// current WAL tail and publishes it with a superblock flip.
func (s *Snap) checkpoint(ctx context.Context, k int) error {
	sh := s.shards[k]
	if err := s.load(ctx, k); err != nil {
		return err
	}
	sh.mu.Lock()
	sb, tree, lease := sh.sb, sh.tree, sh.lease
	sh.mu.Unlock()
	if lease == nil {
		return errors.New("not holding the shard lease")
	}
	next, _, err := s.v.seq.Tail(ctx)
	if err != nil {
		return err
	}
	target := next - 1
	if target <= sb.Ckpt {
		return nil
	}
	w := &ckptWriter{t: tree, edits: map[string]Edit{}, p: &persistBatch{shard: int32(k), base: sb.Alloc, locs: map[*Ref]Loc{}}}

	tb := s.v.table
	if err := tb.s.catchUp(ctx, 0); err != nil {
		return err
	}
	if k == 0 {
		s.ckptTable(w)
	}
	if err := s.v.chunks.stream.catchUp(ctx, 0); err != nil {
		return err
	}
	s.ckptChunks(w, k)
	for _, name := range tb.list(true) {
		if s.branchShard(name) != k {
			continue
		}
		b, err := s.v.branch(name)
		if err != nil {
			return err
		}
		if err := b.s.catchUp(ctx, 0); err != nil {
			return err
		}
		if err := s.ckptBranch(w, b); err != nil {
			return fmt.Errorf("branch %s: %w", name, err)
		}
	}

	nt, err := tree.Mutate(sortEdits(w.edits))
	if err != nil {
		return err
	}
	rr := w.root(nt)
	data := pad512(w.p.buf)
	if len(data) > 0 {
		if err := s.v.st.WritePages(ctx, snapName(k), sb.Alloc, data, -1, lease.ID); err != nil {
			return err
		}
	}
	w.p.commit()
	nsb := superblock{Seq: sb.Seq + 1, Ckpt: target, Root: rr, Alloc: sb.Alloc + int64(len(data)), Time: time.Now().Unix()}
	if err := s.v.st.WritePages(ctx, snapName(k), int64(nsb.Seq%2)*512, encodeSB(nsb), -1, lease.ID); err != nil {
		return err
	}
	sh.mu.Lock()
	sh.sb, sh.tree = nsb, nt
	sh.mu.Unlock()
	s.covered(k)
	return nil
}

func (s *Snap) ckptTable(w *ckptWriter) {
	tb := s.v.table
	tb.s.mu.Lock()
	defer tb.s.mu.Unlock()
	prev := getU64(w.t, kKey(branchesStream))
	tb.mu.Lock()
	for name, e := range tb.m {
		if e.mod > prev {
			w.put(nKey(name), mustCBOR(e))
		}
	}
	tb.mu.Unlock()
	w.putU64(kKey(branchesStream), tb.s.known.Load())
	w.putU64(tKey(branchesStream), tb.s.last.Load())
}

func (s *Snap) ckptChunks(w *ckptWriter, k int) {
	c := s.v.chunks
	c.stream.mu.Lock()
	defer c.stream.mu.Unlock()
	prev := getU64(w.t, kKey(chunksStream))
	c.mu.Lock()
	for h, e := range c.m {
		if !e.confirmed || e.mod <= prev || chunkShard(h[:], len(s.shards)) != k {
			continue
		}
		if e.deleted {
			w.del(xKey(h[:]))
		} else {
			w.put(xKey(h[:]), mustCBOR(&e.ChunkVal))
		}
	}
	c.mu.Unlock()
	w.putU64(kKey(chunksStream), c.stream.known.Load())
	w.putU64(tKey(chunksStream), c.stream.last.Load())
}

func isCreate(ops []Op) bool {
	for _, op := range ops {
		if op.Kind == OpBranchCreate || op.Kind == OpMergeStart {
			return true
		}
	}
	return false
}

func (s *Snap) ckptBranch(w *ckptWriter, b *Branch) error {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.exists {
		return nil
	}
	st := branchStream(b.name)
	known, last := b.s.known.Load(), b.s.last.Load()
	var prevKnown uint64
	if v, ok, err := w.t.Get(bKey(b.name)); err != nil {
		return err
	} else if ok {
		var old branchEnt
		if err := cbor.Unmarshal(v, &old); err != nil {
			return err
		}
		if old.Known >= known {
			return nil
		}
		prevKnown = old.Known
	}
	prev := b.baseRoot
	var head *commitRec
	for _, c := range b.commits {
		if c.LSN <= prevKnown {
			prev = c.Root
			continue
		}
		head = c
		w.put(cKey(st, c.LSN), mustCBOR(&commitEnt{Type: c.Type, Node: c.Node, Time: c.Time, Ops: c.Ops, Concurrent: c.Concurrent, Count: c.Count}))
		if c.Type == RecStage {
			continue
		}
		if isCreate(c.Ops) || c.Count%rootEvery == 0 {
			w.put(rKey(st, c.LSN), mustCBOR(w.root(c.Root)))
		}
		if !isCreate(c.Ops) {
			inos := map[uint64]bool{}
			err := Diff(prev, c.Root, func(k, _, _ []byte) error {
				if len(k) >= 9 {
					inos[keyIno(k)] = true
				}
				return nil
			})
			if err != nil {
				return err
			}
			for ino := range inos {
				w.put(hKey(ino, c.LSN, st), []byte{})
			}
		}
		prev = c.Root
	}
	if head != nil {
		w.put(rKey(st, head.LSN), mustCBOR(w.root(head.Root)))
	}
	w.put(bKey(b.name), mustCBOR(&branchEnt{Meta: b.meta.clone(), Known: known, Last: last, Root: w.root(b.root)}))
	w.putU64(tKey(st), last)
	return nil
}
