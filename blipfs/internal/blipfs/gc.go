package blipfs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/zeebo/blake3"
)

const (
	gcStateBlob = "gc-state"
	gcEvery     = time.Hour
	gcBatch     = 512 // chunk entries per GC record
	compactLive = 0.5 // compact packs with less than this fraction live
	gcRuns      = 16  // runs remembered in gc-state
)

// gcGrace protects in-flight uploads, idle readers of superseded snap pages
// and nodes with a slightly stale chunk index. Tests shorten it.
var gcGrace = time.Hour

var gcMu sync.Mutex

type gcRun struct {
	Time  int64
	Alloc []int64 // per-shard snap alloc pointers seen by this run
}

// gcState is persisted between runs so destructive steps only touch things
// that were already garbage a grace period ago.
type gcState struct {
	Runs []gcRun
	Dead map[string]int64 // pack -> first run that found it unreferenced
}

type gcStats struct {
	chunks, orphans, moved, compacted, packsDeleted, spills int
	packBytes, snapBytes                                    int64
}

func (v *Vol) gcLoop(ctx context.Context) {
	t := time.NewTicker(gcEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if v.leader.Load() == nil {
			continue
		}
		if out, err := v.gc(ctx); err != nil {
			log.Printf("gc: %v", err)
		} else {
			log.Print(out)
		}
	}
}

// gc runs one mark-and-sweep pass. History is never deleted: every revision
// of every branch (including closed branches and merge workspaces) stays
// reachable, so only storage no revision refers to is reclaimed.
func (v *Vol) gc(ctx context.Context) (string, error) {
	gcMu.Lock()
	defer gcMu.Unlock()
	now := time.Now()
	st, err := v.gcLoad(ctx)
	if err != nil {
		return "", err
	}

	// Everything at or below g is reflected in the state we mark.
	next, _, err := v.seq.Tail(ctx)
	if err != nil {
		return "", err
	}
	g := next - 1
	if err := v.snap.loadAll(ctx); err != nil {
		return "", err
	}
	if err := v.table.s.catchUp(ctx, 0); err != nil {
		return "", err
	}
	if err := v.chunks.stream.catchUp(ctx, 0); err != nil {
		return "", err
	}
	var bs []*Branch
	for _, name := range v.table.list(true) {
		b, err := v.branch(name)
		if err != nil {
			return "", err
		}
		if err := b.s.catchUp(ctx, 0); err != nil {
			return "", err
		}
		bs = append(bs, b)
	}

	m := &marker{nodes: map[Loc]bool{}, mem: map[*Ref]bool{}, chunks: map[[32]byte]bool{}}
	allocs := make([]int64, len(v.snap.shards))
	for k, sh := range v.snap.shards {
		sh.mu.Lock()
		t, alloc := sh.tree, sh.sb.Alloc
		sh.mu.Unlock()
		allocs[k] = alloc
		if err := m.shardTree(v.snap, t); err != nil {
			return "", fmt.Errorf("mark snap-%d: %w", k, err)
		}
	}
	for _, b := range bs {
		if err := m.branch(b); err != nil {
			return "", fmt.Errorf("mark %s: %w", b.name, err)
		}
	}

	var s gcStats
	s.chunks = len(m.chunks)
	index, err := v.chunkIndex()
	if err != nil {
		return "", err
	}
	if err := v.gcOrphans(ctx, index, m.chunks, g, &s); err != nil {
		return "", err
	}
	if err := v.gcPacks(ctx, st, now, &s); err != nil {
		return "", err
	}
	if err := v.gcSnap(ctx, st, m.nodes, now, &s); err != nil {
		return "", err
	}
	if err := v.gcSpills(ctx, &s); err != nil {
		return "", err
	}

	st.Runs = append(st.Runs, gcRun{Time: now.Unix(), Alloc: allocs})
	if len(st.Runs) > gcRuns {
		st.Runs = st.Runs[len(st.Runs)-gcRuns:]
	}
	if err := v.gcSave(ctx, st); err != nil {
		return "", err
	}
	return fmt.Sprintf("gc: %d live chunks; removed %d orphan chunks; compacted %d packs (%d chunks moved); deleted %d packs (%s); cleared %s of snap pages; deleted %d spill blobs",
		s.chunks, s.orphans, s.compacted, s.moved, s.packsDeleted, mib(s.packBytes), mib(s.snapBytes), s.spills), nil
}

func mib(n int64) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }

func (v *Vol) gcLoad(ctx context.Context) (*gcState, error) {
	st := &gcState{Dead: map[string]int64{}}
	b, err := v.st.ReadAll(ctx, gcStateBlob)
	if isNotFound(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", gcStateBlob, err)
	}
	if st.Dead == nil {
		st.Dead = map[string]int64{}
	}
	return st, nil
}

func (v *Vol) gcSave(ctx context.Context, st *gcState) error {
	b, _ := json.Marshal(st)
	return v.st.PutBlob(ctx, gcStateBlob, b)
}

// --- mark ---

type marker struct {
	nodes  map[Loc]bool  // persisted tree nodes
	mem    map[*Ref]bool // in-memory tree nodes
	chunks map[[32]byte]bool
}

// walk visits every node of a tree once; leaf calls fn for leaf entries.
func (m *marker) walk(r *Ref, leaf func(k, v []byte) error) error {
	if r == nil {
		return nil
	}
	if l := r.Loc(); l != nil {
		if m.nodes[*l] {
			return nil
		}
		m.nodes[*l] = true
	} else {
		if m.mem[r] {
			return nil
		}
		m.mem[r] = true
	}
	n, err := r.load()
	if err != nil {
		return err
	}
	if n.Level > 0 {
		for _, k := range n.Kids {
			if err := m.walk(k, leaf); err != nil {
				return err
			}
		}
		return nil
	}
	if leaf == nil {
		return nil
	}
	for i := range n.Keys {
		if err := leaf(n.Keys[i], n.Vals[i]); err != nil {
			return err
		}
	}
	return nil
}

// fsTree marks a filesystem tree's nodes and the chunks its extents use.
func (m *marker) fsTree(t Tree) error {
	return m.walk(t.Root, func(k, v []byte) error {
		if len(k) > 0 && k[0] == kExtent {
			m.extent(v)
		}
		return nil
	})
}

func (m *marker) extent(v []byte) {
	if e, err := decodeExtent(v); err == nil && len(e.Hash) == 32 {
		m.chunks[key32(e.Hash)] = true
	}
}

// ops marks chunks that commit deltas reference; historical revisions
// between materialised roots are rebuilt from these.
func (m *marker) ops(ops []Op) {
	for _, op := range ops {
		for _, r := range op.Ranges {
			if len(r.Ext.Hash) == 32 {
				m.chunks[key32(r.Ext.Hash)] = true
			}
		}
		for _, e := range op.Edits {
			if len(e.Key) > 0 && e.Key[0] == kExtent && !e.Del {
				m.extent(e.Val)
			}
		}
	}
}

func (m *marker) shardTree(s *Snap, t Tree) error {
	var roots []RootRef
	err := m.walk(t.Root, func(k, v []byte) error {
		switch k[0] {
		case 'B':
			var e branchEnt
			if err := cbor.Unmarshal(v, &e); err != nil {
				return err
			}
			roots = append(roots, e.Root)
		case 'R':
			var r RootRef
			if err := cbor.Unmarshal(v, &r); err != nil {
				return err
			}
			roots = append(roots, r)
		case 'C':
			var c commitEnt
			if err := cbor.Unmarshal(v, &c); err != nil {
				return err
			}
			m.ops(c.Ops)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, r := range roots {
		if err := m.fsTree(Tree{Root: s.ref(r)}); err != nil {
			return err
		}
	}
	return nil
}

// branch marks the state a replica holds beyond the checkpoints.
func (m *marker) branch(b *Branch) error {
	b.mu.Lock()
	trees := []Tree{b.root, b.baseRoot}
	var ops [][]Op
	for _, c := range b.commits {
		trees = append(trees, c.Root)
		ops = append(ops, c.Ops)
	}
	for _, st := range b.meta.Stages {
		ops = append(ops, st.Ops)
	}
	b.mu.Unlock()
	for _, o := range ops {
		m.ops(o)
	}
	for _, t := range trees {
		if err := m.fsTree(t); err != nil {
			return err
		}
	}
	return nil
}

// --- chunks and packs ---

// chunkIndex returns the full current chunk index.
func (v *Vol) chunkIndex() (map[[32]byte]ChunkVal, error) {
	out := map[[32]byte]ChunkVal{}
	for k := range v.snap.shards {
		err := v.snap.tree(k).AscendPrefix([]byte{'X'}, func(key, val []byte) bool {
			var cv ChunkVal
			if len(key) == 33 && cbor.Unmarshal(val, &cv) == nil {
				out[key32(key[1:])] = cv
			}
			return true
		})
		if err != nil {
			return nil, err
		}
	}
	c := v.chunks
	c.mu.Lock()
	for h, e := range c.m {
		if e.deleted {
			delete(out, h)
		} else {
			out[h] = e.ChunkVal
		}
	}
	c.mu.Unlock()
	return out, nil
}

// gcRecord writes chunk ops in batches on !chunks and applies them locally.
func (v *Vol) gcRecord(ctx context.Context, kind uint8, before uint64, ents []ChunkEnt) error {
	for len(ents) > 0 {
		n := min(len(ents), gcBatch)
		op := Op{Kind: kind, Before: before, Chunks: ents[:n], Node: v.node, Time: time.Now().UnixNano()}
		lsn, err := v.writeRecord(ctx, RecGC, []string{chunksStream}, []Op{op})
		if err != nil {
			return err
		}
		if err := v.chunks.stream.catchUp(ctx, lsn); err != nil {
			return err
		}
		ents = ents[n:]
	}
	return nil
}

// gcOrphans removes index entries no revision references. Entries
// (re-)asserted after g survive, since ChunkDel only applies to entries
// last put at or below Before.
func (v *Vol) gcOrphans(ctx context.Context, index map[[32]byte]ChunkVal, live map[[32]byte]bool, g uint64, s *gcStats) error {
	var dead []ChunkEnt
	for h, cv := range index {
		if !live[h] && cv.LSN <= g {
			dead = append(dead, ChunkEnt{Hash: append([]byte(nil), h[:]...), Pack: cv.Pack, Off: cv.Off, Len: cv.Len})
		}
	}
	sort.Slice(dead, func(i, j int) bool { return bytes.Compare(dead[i].Hash, dead[j].Hash) < 0 })
	s.orphans = len(dead)
	return v.gcRecord(ctx, OpChunkDel, g, dead)
}

// gcPacks compacts mostly-dead packs and deletes packs no index entry uses.
func (v *Vol) gcPacks(ctx context.Context, st *gcState, now time.Time, s *gcStats) error {
	blobs, err := v.st.List(ctx, "pack/")
	if err != nil {
		return err
	}
	index, err := v.chunkIndex()
	if err != nil {
		return err
	}
	type use struct {
		live int64
		ents []ChunkEnt
	}
	uses := map[string]*use{}
	for h, cv := range index {
		u := uses[cv.Pack]
		if u == nil {
			u = &use{}
			uses[cv.Pack] = u
		}
		u.live += int64(cv.Len)
		u.ents = append(u.ents, ChunkEnt{Hash: append([]byte(nil), h[:]...), Pack: cv.Pack, Off: cv.Off, Len: cv.Len})
	}
	old := now.Add(-gcGrace)
	compacted := map[string]bool{}
	for _, b := range blobs {
		u := uses[b.Name]
		if u == nil || b.Size == 0 || !b.Modified.Before(old) || float64(u.live)/float64(b.Size) >= compactLive {
			continue
		}
		n, err := v.compact(ctx, b.Name, u.ents)
		if err != nil {
			return fmt.Errorf("compact %s: %w", b.Name, err)
		}
		s.compacted++
		s.moved += n
		compacted[b.Name] = true
	}

	// A pack is deleted once it has had no index entries for a grace period
	// (two runs), so in-flight writers that deduplicated against it are seen.
	dead := map[string]int64{}
	for _, b := range blobs {
		if uses[b.Name] != nil && !compacted[b.Name] || !b.Modified.Before(old) {
			continue
		}
		if compacted[b.Name] {
			dead[b.Name] = now.Unix()
			continue
		}
		since, ok := st.Dead[b.Name]
		if !ok {
			dead[b.Name] = now.Unix()
			continue
		}
		if time.Unix(since, 0).After(old) {
			dead[b.Name] = since
			continue
		}
		if err := v.st.Delete(ctx, b.Name); err != nil {
			return err
		}
		s.packsDeleted++
		s.packBytes += b.Size
	}
	st.Dead = dead
	return nil
}

// compact copies the live chunks of a pack into the active pack and moves
// their index entries; the old pack is deleted by a later run.
func (v *Vol) compact(ctx context.Context, name string, ents []ChunkEnt) (int, error) {
	sort.Slice(ents, func(i, j int) bool { return ents[i].Off < ents[j].Off })
	data, err := v.st.ReadAll(ctx, name)
	if err != nil {
		return 0, err
	}
	packs := map[string]bool{}
	var moves []ChunkEnt
	for _, e := range ents {
		end := e.Off + int64(e.Len)
		if end > int64(len(data)) {
			return 0, fmt.Errorf("chunk %x beyond end of pack", e.Hash)
		}
		chunk := data[e.Off:end]
		if h := blake3.Sum256(chunk); !bytes.Equal(h[:], e.Hash) {
			return 0, fmt.Errorf("chunk %x: hash mismatch", e.Hash)
		}
		p, off := v.chunks.put(chunk)
		packs[p] = true
		moves = append(moves, ChunkEnt{Hash: e.Hash, Pack: p, Off: off, Len: e.Len, OldPack: name, OldOff: e.Off})
	}
	if err := v.chunks.flush(ctx, packs); err != nil {
		return 0, err
	}
	return len(moves), v.gcRecord(ctx, OpChunkMove, 0, moves)
}

// --- snap pages ---

// gcSnap clears pages of the shards this node checkpoints that no tree
// reaches. Only pages below the alloc pointer of a run at least a grace
// period old are touched, so readers of recently superseded trees are safe.
func (v *Vol) gcSnap(ctx context.Context, st *gcState, live map[Loc]bool, now time.Time, s *gcStats) error {
	var limit []int64
	for _, r := range st.Runs {
		if time.Unix(r.Time, 0).Before(now.Add(-gcGrace)) {
			limit = r.Alloc
		}
	}
	byShard := map[int32][][2]int64{}
	for l := range live {
		byShard[l.Shard] = append(byShard[l.Shard], [2]int64{l.Off, l.Off + int64(l.Len)})
	}
	for k, sh := range v.snap.shards {
		sh.mu.Lock()
		lease := sh.lease
		sh.mu.Unlock()
		if lease == nil || k >= len(limit) || limit[k] <= snapData {
			continue
		}
		used := byShard[int32(k)]
		sort.Slice(used, func(i, j int) bool { return used[i][0] < used[j][0] })
		written, err := v.st.PageRanges(ctx, snapName(k), snapData, limit[k]-snapData)
		if err != nil {
			return err
		}
		for _, w := range written {
			for _, gap := range gaps(w[0], min(w[1], limit[k]), used) {
				lo, hi := (gap[0]+511)&^511, gap[1]&^511
				if hi <= lo {
					continue
				}
				if err := v.st.ClearPages(ctx, snapName(k), lo, hi-lo, lease.ID); err != nil {
					return err
				}
				s.snapBytes += hi - lo
			}
		}
	}
	return nil
}

// gaps returns the parts of [lo, hi) not covered by the sorted ranges.
func gaps(lo, hi int64, used [][2]int64) [][2]int64 {
	var out [][2]int64
	i := sort.Search(len(used), func(i int) bool { return used[i][1] > lo })
	for ; i < len(used) && lo < hi; i++ {
		u := used[i]
		if u[0] >= hi {
			break
		}
		if u[0] > lo {
			out = append(out, [2]int64{lo, u[0]})
		}
		lo = max(lo, u[1])
	}
	if lo < hi {
		out = append(out, [2]int64{lo, hi})
	}
	return out
}

// --- spilled records ---

// gcSpills deletes spill blobs of records below the WAL trim point.
func (v *Vol) gcSpills(ctx context.Context, s *gcStats) error {
	trim := v.snap.minCkpt()
	blobs, err := v.st.List(ctx, "spill/")
	if err != nil {
		return err
	}
	for _, b := range blobs {
		lsn, ok := spillLSN(b.Name)
		if !ok || lsn > trim {
			continue
		}
		if err := v.st.Delete(ctx, b.Name); err != nil {
			return err
		}
		s.spills++
	}
	return nil
}

func spillLSN(name string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, "spill/")
	if !ok {
		return 0, false
	}
	hexLSN, _, _ := strings.Cut(rest, "-")
	l, err := strconv.ParseUint(hexLSN, 16, 64)
	return l, err == nil
}
