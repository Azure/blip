package blipfs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	chunksStream   = "!chunks"
	branchesStream = "!branches"
	walkLimit      = 256 // backpointer steps before switching to a range scan
	holeWait       = 30 * time.Second
)

func branchStream(name string) string { return "b/" + name }

// stream follows one WAL stream: it walks backpointers from the stream tail
// down to what it has already applied, then applies records in LSN order.
type stream struct {
	v     *Vol
	name  string
	mu    sync.Mutex    // serializes catch-up
	known atomic.Uint64 // every record of the stream <= known is applied
	last  atomic.Uint64 // newest applied record
	apply func(rec *Record, body *Body) error
}

// catchUp applies every record of the stream up to target, which must be an
// LSN of a record in this stream; target 0 means "the current tail".
func (s *stream) catchUp(ctx context.Context, target uint64) error {
	if target != 0 && target <= s.known.Load() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if target != 0 && target <= s.known.Load() {
		return nil
	}
	top, settle := target, target
	if target == 0 {
		next, tails, err := s.v.seq.Tail(ctx, s.name)
		if err != nil {
			return err
		}
		top, settle = tails[0], next-1
	}
	if known := s.known.Load(); top > known {
		recs, err := s.collect(ctx, known, top)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if r.Type != RecJunk {
				body, err := decodeBody(r.Payload)
				if err != nil {
					return fmt.Errorf("%s: decode record %d: %w", s.name, r.LSN, err)
				}
				if err := s.apply(r, body); err != nil {
					return err
				}
				s.last.Store(r.LSN)
			}
			s.known.Store(r.LSN)
		}
	}
	if settle > s.known.Load() {
		s.known.Store(settle)
	}
	return nil
}

// collect returns the stream's records in (known, top], ascending.
func (s *stream) collect(ctx context.Context, known, top uint64) ([]*Record, error) {
	var out []*Record
	l := top
	for steps := 0; l > known; steps++ {
		if steps >= walkLimit {
			recs, err := s.scan(ctx, known+1, l)
			out = append(out, recs...)
			if err != nil {
				return nil, err
			}
			break
		}
		r := s.v.ownRecord(l)
		if r == nil {
			var err error
			if r, err = s.readWait(ctx, l); err != nil {
				return nil, err
			}
		}
		b, ok := r.Back(s.name)
		if !ok {
			if r.Type != RecJunk || len(r.Streams) > 0 {
				return nil, fmt.Errorf("%s: record %d is not in the stream", s.name, l)
			}
			// junk written during leader recovery carries no backpointers
			recs, err := s.scan(ctx, known+1, l-1)
			out = append(out, recs...)
			if err != nil {
				return nil, err
			}
			break
		}
		out = append(out, r)
		l = b
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LSN < out[j].LSN })
	return out, nil
}

// scan range-reads [lo, hi] and keeps this stream's records, waiting for
// slots that are not written yet.
func (s *stream) scan(ctx context.Context, lo, hi uint64) ([]*Record, error) {
	recs, err := s.v.wal.ReadRange(ctx, lo, hi)
	if err != nil {
		return nil, err
	}
	var out []*Record
	for l := lo; l <= hi && l >= lo; l++ {
		r := recs[l]
		if r == nil {
			if r, err = s.readWait(ctx, l); err != nil {
				return nil, err
			}
		}
		if _, ok := r.Back(s.name); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// readWait reads the record at l, waiting for an in-flight write or for
// the sequencer to fill the hole.
func (s *stream) readWait(ctx context.Context, l uint64) (*Record, error) {
	deadline := time.Now().Add(holeWait)
	wait := 2 * time.Millisecond
	for {
		r, err := s.v.wal.Read(ctx, l)
		if err != nil {
			return nil, err
		}
		if r != nil {
			return r, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("wal: lsn %d is still unwritten after %v", l, holeWait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 250*time.Millisecond)
	}
}

// --- branches ---

type Edge struct {
	LSN uint64 `cbor:"1,keyasint"`
	Src Rev    `cbor:"2,keyasint"`
}

type Stage struct {
	LSN  uint64 `cbor:"1,keyasint"`
	Node string `cbor:"2,keyasint"`
	Ops  []Op   `cbor:"3,keyasint"`
}

// BranchMeta is per-branch state that lives beside the tree.
type BranchMeta struct {
	Created uint64      `cbor:"1,keyasint"`
	Src     Rev         `cbor:"2,keyasint,omitempty"`
	Edges   []Edge      `cbor:"3,keyasint,omitempty"`
	Closed  bool        `cbor:"4,keyasint,omitempty"`
	Active  string      `cbor:"5,keyasint,omitempty"` // id of the merge in progress into this branch
	Merge   *MergeState `cbor:"6,keyasint,omitempty"` // set on merge workspaces
	Stages  []Stage     `cbor:"7,keyasint,omitempty"`
	Count   uint64      `cbor:"8,keyasint,omitempty"` // commits so far
}

// commitRec is one applied record, kept in memory until checkpointed.
type commitRec struct {
	LSN        uint64
	Type       uint8
	Node       string
	Time       int64
	Ops        []Op
	Root       Tree
	Concurrent bool
	Count      uint64
	Meta       BranchMeta // branch metadata after this record
}

func (m BranchMeta) clone() BranchMeta {
	m.Edges = slices.Clone(m.Edges)
	m.Stages = slices.Clone(m.Stages)
	if m.Merge != nil {
		mm := *m.Merge
		mm.Conflicts = slices.Clone(mm.Conflicts)
		m.Merge = &mm
	}
	return m
}

type Branch struct {
	v    *Vol
	name string
	s    *stream

	mu       sync.Mutex
	exists   bool
	meta     BranchMeta
	root     Tree
	baseLSN  uint64 // state below this comes from the snapshot
	baseRoot Tree
	commits  []*commitRec
	results  map[uint64][]opResult

	cmu      sync.Mutex // group commit queue
	queue    []*commitReq
	flushing bool
}

func (b *Branch) Name() string { return b.name }

// branch returns the (lazily loaded) state of a branch.
func (v *Vol) branch(name string) (*Branch, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if b := v.branches[name]; b != nil {
		return b, nil
	}
	b := &Branch{v: v, name: name, results: map[uint64][]opResult{}}
	b.s = &stream{v: v, name: branchStream(name), apply: b.applyRecord}
	known, ent, err := v.snap.branchEntry(name)
	if err != nil {
		return nil, err
	}
	if ent != nil {
		known = ent.Known
		b.exists, b.meta = true, ent.Meta
		b.root = Tree{Root: v.snap.ref(ent.Root)}
		b.baseRoot = b.root
		b.s.last.Store(ent.Last)
	}
	b.baseLSN = known
	b.s.known.Store(known)
	v.branches[name] = b
	return b, nil
}

// head catches up and returns the newest state.
func (b *Branch) head(ctx context.Context) (uint64, Tree, error) {
	if err := b.s.catchUp(ctx, 0); err != nil {
		return 0, Tree{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.exists {
		return 0, Tree{}, fmt.Errorf("branch %q: %w", b.name, syscall.ENOENT)
	}
	return b.s.known.Load(), b.root, nil
}

// local returns the state this node already knows without catching up.
func (b *Branch) local() (Tree, BranchMeta, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.root, b.meta, b.exists
}

func (b *Branch) Meta() BranchMeta {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.meta
}

// TreeAt returns the tree as of lsn (after all records <= lsn).
func (b *Branch) TreeAt(ctx context.Context, lsn uint64) (Tree, error) {
	if lsn == 0 {
		_, t, err := b.head(ctx)
		return t, err
	}
	if lsn > b.s.known.Load() {
		if err := b.s.catchUp(ctx, 0); err != nil {
			return Tree{}, err
		}
		if lsn > b.s.known.Load() {
			return Tree{}, fmt.Errorf("%s@%d is in the future: %w", b.name, lsn, syscall.ENOENT)
		}
	}
	b.mu.Lock()
	if !b.exists || lsn < b.meta.Created {
		b.mu.Unlock()
		return Tree{}, fmt.Errorf("branch %q did not exist at %d: %w", b.name, lsn, syscall.ENOENT)
	}
	if lsn >= b.baseLSN {
		t := b.baseRoot
		for _, c := range b.commits {
			if c.LSN > lsn {
				break
			}
			t = c.Root
		}
		b.mu.Unlock()
		return t, nil
	}
	b.mu.Unlock()
	return b.v.snap.historicalTree(ctx, b, lsn)
}

func (v *Vol) treeAt(ctx context.Context, r Rev) (Tree, error) {
	b, err := v.branch(r.Branch)
	if err != nil {
		return Tree{}, err
	}
	return b.TreeAt(ctx, r.LSN)
}

// takeResults returns the per-op outcomes of our own record lsn.
func (b *Branch) takeResults(lsn uint64) []opResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.results[lsn]
	delete(b.results, lsn)
	return r
}

// trim drops in-memory history covered by a checkpoint at lsn.
func (b *Branch) trim(lsn uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lsn <= b.baseLSN || lsn > b.s.known.Load() {
		return
	}
	i := 0
	for i < len(b.commits) && b.commits[i].LSN <= lsn {
		b.baseRoot = b.commits[i].Root
		i++
	}
	b.commits = slices.Clone(b.commits[i:])
	b.baseLSN = lsn
	for l := range b.results {
		if l <= lsn {
			delete(b.results, l)
		}
	}
}

func (b *Branch) applyRecord(rec *Record, body *Body) error {
	ctx := context.Background()
	b.mu.Lock()
	defer b.mu.Unlock()
	var mine []Op
	for _, op := range body.Ops {
		if op.Branch == b.name && !isChunkOp(op.Kind) {
			mine = append(mine, op)
		}
	}
	if len(mine) == 0 {
		return nil
	}
	if rec.Type == RecStage {
		// staged (fsynced) writes are not visible; they live in the
		// branch metadata until their writer commits or recovers them
		if b.exists {
			b.meta.Stages = append(b.meta.Stages, Stage{LSN: rec.LSN, Node: rec.Node, Ops: mine})
			b.commits = append(b.commits, &commitRec{LSN: rec.LSN, Type: rec.Type, Node: rec.Node, Time: mine[0].Time,
				Ops: mine, Root: b.root, Count: b.meta.Count, Meta: b.meta.clone()})
		}
		return nil
	}
	res := make([]opResult, len(body.Ops))
	x := newTxn(b.root)
	c := &applyCtx{lsn: rec.LSN, node: rec.Node}
	for i := range body.Ops {
		op := &body.Ops[i]
		if op.Branch != b.name || isChunkOp(op.Kind) {
			continue
		}
		r, nx, err := b.applyOp(ctx, x, c, op)
		if err != nil {
			return fmt.Errorf("%s: apply %d: %w", b.name, rec.LSN, err)
		}
		x, res[i] = nx, r
	}
	root, err := x.commit()
	if err != nil {
		return err
	}
	b.root = root
	if b.exists {
		b.meta.Count++
		b.commits = append(b.commits, &commitRec{LSN: rec.LSN, Type: rec.Type, Node: rec.Node, Time: mine[0].Time,
			Ops: mine, Root: root, Concurrent: c.concurrent, Count: b.meta.Count, Meta: b.meta.clone()})
	}
	if rec.Node == b.v.node {
		b.results[rec.LSN] = res
	}
	return nil
}

// applyOp applies one op of this branch; branch-creating ops replace the txn.
func (b *Branch) applyOp(ctx context.Context, x *txn, c *applyCtx, op *Op) (opResult, *txn, error) {
	switch op.Kind {
	case OpBranchCreate, OpMergeStart:
		if b.exists {
			return opResult{Errno: syscall.EEXIST}, x, nil
		}
		var root Tree
		var err error
		if op.Src.Branch == "" {
			root, err = initTree(op.Time, op.Uid, op.Gid)
		} else {
			root, err = b.v.treeAt(ctx, op.Src)
		}
		if errors.Is(err, syscall.ENOENT) {
			return opResult{Errno: syscall.ENOENT}, x, nil
		}
		if err != nil {
			return opResult{}, x, err
		}
		nx := newTxn(root)
		if op.Kind == OpMergeStart {
			if r, err := applyFS(nx, c, op); err != nil || r.Errno != 0 {
				return r, x, err
			}
		}
		b.exists = true
		b.meta = BranchMeta{Created: c.lsn, Src: op.Src, Merge: op.Merge}
		return opResult{}, nx, nil
	}
	if !b.exists || b.meta.Closed {
		return opResult{Errno: syscall.ENOENT}, x, nil
	}
	switch op.Kind {
	case OpBranchClose:
		b.meta.Closed = true
	case OpMergeLock:
		if b.meta.Active != "" && b.meta.Active != op.Name {
			return opResult{Errno: syscall.EBUSY}, x, nil
		}
		b.meta.Active = op.Name
	case OpMergeUnlock:
		if b.meta.Active == op.Name {
			b.meta.Active = ""
		}
	case OpResolve:
		if b.meta.Merge == nil {
			return opResult{Errno: syscall.EINVAL}, x, nil
		}
		b.meta.Merge.Conflicts = slices.DeleteFunc(b.meta.Merge.Conflicts, func(p string) bool { return slices.Contains(op.Paths, p) })
	case OpStageDone:
		b.meta.Stages = slices.DeleteFunc(b.meta.Stages, func(s Stage) bool { return s.LSN == op.Before })
	case OpMergeDone, OpMergeUpdate:
		r, err := applyFS(x, c, op)
		if err != nil || r.Errno != 0 {
			return r, x, err
		}
		if op.Kind == OpMergeUpdate {
			b.meta.Merge = op.Merge
		} else if op.Merge != nil {
			if op.Merge.Edge {
				b.meta.Edges = append(b.meta.Edges, Edge{LSN: c.lsn, Src: op.Merge.Theirs})
			}
			if b.meta.Active == op.Merge.ID {
				b.meta.Active = ""
			}
		}
		return r, x, nil
	default:
		r, err := applyFS(x, c, op)
		return r, x, err
	}
	return opResult{}, x, nil
}

// replayOps re-applies checkpointed commit ops (FS and raw edits only) on t.
func replayOps(t Tree, lsn uint64, node string, ops []Op) (Tree, error) {
	x := newTxn(t)
	c := &applyCtx{lsn: lsn, node: node}
	for i := range ops {
		switch ops[i].Kind {
		case OpBranchCreate, OpMergeStart, OpBranchClose, OpMergeLock, OpMergeUnlock, OpResolve, OpStageDone:
			continue
		}
		if _, err := applyFS(x, c, &ops[i]); err != nil {
			return Tree{}, err
		}
	}
	return x.commit()
}

// --- the branch table (!branches) ---

type tableEnt struct {
	Created uint64 `cbor:"1,keyasint"`
	Closed  bool   `cbor:"2,keyasint,omitempty"`
	mod     uint64
}

type branchTable struct {
	s  *stream
	mu sync.Mutex
	m  map[string]*tableEnt
}

func (t *branchTable) applyRecord(rec *Record, body *Body) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, op := range body.Ops {
		e := t.m[op.Branch]
		switch op.Kind {
		case OpBranchCreate, OpMergeStart:
			if e == nil {
				t.m[op.Branch] = &tableEnt{Created: rec.LSN, mod: rec.LSN}
			}
		case OpBranchClose:
			if e != nil && !e.Closed {
				e.Closed, e.mod = true, rec.LSN
			}
		}
	}
	return nil
}

// list returns branch names; closed ones only if all is set.
func (t *branchTable) list(all bool) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for n, e := range t.m {
		if all || !e.Closed {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (t *branchTable) get(name string) (tableEnt, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[name]
	if e == nil {
		return tableEnt{}, false
	}
	return *e, true
}
