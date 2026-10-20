package blipfs

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/zeebo/blake3"
)

// Loc is where a persisted tree node lives: byte range in snap-<Shard>.
type Loc struct {
	Shard int32 `cbor:"1,keyasint"`
	Off   int64 `cbor:"2,keyasint"`
	Len   int32 `cbor:"3,keyasint"`
}

type nodeLoader interface {
	readNode(Loc) ([]byte, error)
}

// Ref points at a tree node by hash. The node is either in memory or
// loaded lazily from its persisted location.
type Ref struct {
	Hash [32]byte
	loc  atomic.Pointer[Loc]
	node atomic.Pointer[Node]
	ld   nodeLoader
}

func (r *Ref) Loc() *Loc { return r.loc.Load() }

// Node is a prolly tree node. Leaves hold Vals; internal nodes hold Kids,
// keyed by each child's last key.
type Node struct {
	Level int
	Keys  [][]byte
	Vals  [][]byte
	Kids  []*Ref
}

type nodeWire struct {
	L int      `cbor:"1,keyasint"`
	K [][]byte `cbor:"2,keyasint"`
	V [][]byte `cbor:"3,keyasint,omitempty"`
	H [][]byte `cbor:"4,keyasint,omitempty"`
	O []Loc    `cbor:"5,keyasint,omitempty"`
}

var cborEnc, _ = cbor.CanonicalEncOptions().EncMode()

func mustCBOR(v any) []byte {
	b, err := cborEnc.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (n *Node) wire() *nodeWire {
	w := &nodeWire{L: n.Level, K: n.Keys, V: n.Vals}
	for _, k := range n.Kids {
		w.H = append(w.H, k.Hash[:])
	}
	return w
}

// newRef seals a node: its hash covers keys, values and child hashes only,
// so identical trees hash identically on every replica.
func newRef(n *Node) *Ref {
	r := &Ref{Hash: blake3.Sum256(mustCBOR(n.wire()))}
	r.node.Store(n)
	return r
}

func (r *Ref) load() (*Node, error) {
	if n := r.node.Load(); n != nil {
		return n, nil
	}
	l := r.loc.Load()
	if l == nil || r.ld == nil {
		return nil, errors.New("tree node not loaded and not persisted")
	}
	b, err := r.ld.readNode(*l)
	if err != nil {
		return nil, err
	}
	var w nodeWire
	if err := cbor.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("decode node at %v: %w", *l, err)
	}
	n := &Node{Level: w.L, Keys: w.K, Vals: w.V}
	if w.L > 0 {
		if len(w.H) != len(w.K) || len(w.O) != len(w.K) {
			return nil, errors.New("corrupt tree node")
		}
		for i := range w.H {
			k := &Ref{ld: r.ld}
			copy(k.Hash[:], w.H[i])
			o := w.O[i]
			k.loc.Store(&o)
			n.Kids = append(n.Kids, k)
		}
	}
	r.node.CompareAndSwap(nil, n)
	return r.node.Load(), nil
}

// RefAt builds a lazily loaded reference to a persisted node.
func RefAt(hash []byte, loc Loc, ld nodeLoader) *Ref {
	r := &Ref{ld: ld}
	copy(r.Hash[:], hash)
	r.loc.Store(&loc)
	return r
}

// Tree is an immutable prolly tree; Root nil means empty.
type Tree struct {
	Root *Ref
}

func (t Tree) Equal(o Tree) bool {
	if t.Root == nil || o.Root == nil {
		return t.Root == o.Root
	}
	return t.Root.Hash == o.Root.Hash
}

const fanoutMask = 63 // ~1/64 entries end a node

func boundary(level int, key []byte) bool {
	h := uint64(14695981039346656037)
	h = (h ^ uint64(level+1)) * 1099511628211
	for _, c := range key {
		h = (h ^ uint64(c)) * 1099511628211
	}
	h ^= h >> 29
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 32
	return h&fanoutMask == 0
}

func (n *Node) search(key []byte) int {
	return sort.Search(len(n.Keys), func(i int) bool { return bytes.Compare(n.Keys[i], key) >= 0 })
}

func (t Tree) Get(key []byte) ([]byte, bool, error) {
	if t.Root == nil {
		return nil, false, nil
	}
	n, err := t.Root.load()
	for err == nil && n.Level > 0 {
		i := n.search(key)
		if i == len(n.Keys) {
			return nil, false, nil
		}
		n, err = n.Kids[i].load()
	}
	if err != nil {
		return nil, false, err
	}
	i := n.search(key)
	if i < len(n.Keys) && bytes.Equal(n.Keys[i], key) {
		return n.Vals[i], true, nil
	}
	return nil, false, nil
}

// Floor returns the greatest entry with key <= key.
func (t Tree) Floor(key []byte) ([]byte, []byte, bool, error) {
	if t.Root == nil {
		return nil, nil, false, nil
	}
	return floor(t.Root, key)
}

func floor(r *Ref, key []byte) ([]byte, []byte, bool, error) {
	n, err := r.load()
	if err != nil {
		return nil, nil, false, err
	}
	i := n.search(key)
	if n.Level == 0 {
		if i < len(n.Keys) && bytes.Equal(n.Keys[i], key) {
			return n.Keys[i], n.Vals[i], true, nil
		}
		if i == 0 {
			return nil, nil, false, nil
		}
		return n.Keys[i-1], n.Vals[i-1], true, nil
	}
	if i == len(n.Kids) {
		i--
	}
	k, v, ok, err := floor(n.Kids[i], key)
	if ok || err != nil || i == 0 {
		return k, v, ok, err
	}
	return last(n.Kids[i-1])
}

func last(r *Ref) ([]byte, []byte, bool, error) {
	n, err := r.load()
	for err == nil && n.Level > 0 {
		n, err = n.Kids[len(n.Kids)-1].load()
	}
	if err != nil || len(n.Keys) == 0 {
		return nil, nil, false, err
	}
	return n.Keys[len(n.Keys)-1], n.Vals[len(n.Vals)-1], true, nil
}

// Ascend calls fn for entries with key >= from in order until fn returns false.
func (t Tree) Ascend(from []byte, fn func(k, v []byte) bool) error {
	if t.Root == nil {
		return nil
	}
	_, err := ascend(t.Root, from, fn)
	return err
}

func ascend(r *Ref, from []byte, fn func(k, v []byte) bool) (bool, error) {
	n, err := r.load()
	if err != nil {
		return false, err
	}
	for i := n.search(from); i < len(n.Keys); i++ {
		if n.Level == 0 {
			if !fn(n.Keys[i], n.Vals[i]) {
				return false, nil
			}
			continue
		}
		if ok, err := ascend(n.Kids[i], from, fn); !ok || err != nil {
			return false, err
		}
	}
	return true, nil
}

// AscendPrefix visits all entries starting with prefix.
func (t Tree) AscendPrefix(prefix []byte, fn func(k, v []byte) bool) error {
	return t.Ascend(prefix, func(k, v []byte) bool {
		if !bytes.HasPrefix(k, prefix) {
			return false
		}
		return fn(k, v)
	})
}

// Edit is a put (Val, or Kid for internal levels) or a delete.
type Edit struct {
	Key []byte
	Val []byte
	Kid *Ref
	Del bool
}

type entry struct {
	key, val []byte
	kid      *Ref
}

func (n *Node) entries() []entry {
	es := make([]entry, len(n.Keys))
	for i := range n.Keys {
		es[i].key = n.Keys[i]
		if n.Level == 0 {
			es[i].val = n.Vals[i]
		} else {
			es[i].kid = n.Kids[i]
		}
	}
	return es
}

func mkNode(level int, es []entry) *Ref {
	n := &Node{Level: level, Keys: make([][]byte, len(es))}
	for i, e := range es {
		n.Keys[i] = e.key
		if level == 0 {
			n.Vals = append(n.Vals, e.val)
		} else {
			n.Kids = append(n.Kids, e.kid)
		}
	}
	return newRef(n)
}

func chunk(level int, es []entry) []*Ref {
	var out []*Ref
	start := 0
	for i, e := range es {
		if i == len(es)-1 || boundary(level, e.key) {
			out = append(out, mkNode(level, es[start:i+1]))
			start = i + 1
		}
	}
	return out
}

type frame struct {
	n *Node
	i int
}

// cursor walks the nodes of one level in key order.
type cursor struct{ path []frame }

func seek(root *Ref, level int, key []byte) (*cursor, error) {
	n, err := root.load()
	if err != nil {
		return nil, err
	}
	c := &cursor{path: []frame{{n: n}}}
	for n.Level > level {
		i := n.search(key)
		if i == len(n.Kids) {
			i--
		}
		c.path[len(c.path)-1].i = i
		if n, err = n.Kids[i].load(); err != nil {
			return nil, err
		}
		c.path = append(c.path, frame{n: n})
	}
	return c, nil
}

func (c *cursor) node() *Node { return c.path[len(c.path)-1].n }

func (c *cursor) hasNext() bool {
	for j := len(c.path) - 2; j >= 0; j-- {
		if c.path[j].i+1 < len(c.path[j].n.Kids) {
			return true
		}
	}
	return false
}

func (c *cursor) next() error {
	j := len(c.path) - 2
	for j >= 0 && c.path[j].i+1 >= len(c.path[j].n.Kids) {
		j--
	}
	if j < 0 {
		return errors.New("cursor at end")
	}
	c.path[j].i++
	for k := j; k < len(c.path)-1; k++ {
		n, err := c.path[k].n.Kids[c.path[k].i].load()
		if err != nil {
			return err
		}
		c.path[k+1] = frame{n: n}
	}
	return nil
}

func sortEdits(m map[string]Edit) []Edit {
	out := make([]Edit, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Key, out[j].Key) < 0 })
	return out
}

// Mutate applies edits (any order; last edit per key wins) and returns the
// new tree. Unchanged subtrees are shared with t.
func (t Tree) Mutate(edits []Edit) (Tree, error) {
	if len(edits) == 0 {
		return t, nil
	}
	m := make(map[string]Edit, len(edits))
	for _, e := range edits {
		m[string(e.Key)] = e
	}
	es := sortEdits(m)
	if t.Root == nil {
		var run []entry
		for _, e := range es {
			if !e.Del {
				run = append(run, entry{key: e.Key, val: e.Val})
			}
		}
		return grow(0, chunk(0, run))
	}
	root, err := t.Root.load()
	if err != nil {
		return t, err
	}
	for h := 0; ; h++ {
		up, nodes, err := mutateLevel(t.Root, h, es)
		if err != nil {
			return t, err
		}
		if h == root.Level {
			return grow(h, nodes)
		}
		es = up
	}
}

func grow(level int, nodes []*Ref) (Tree, error) {
	if len(nodes) == 0 {
		return Tree{}, nil
	}
	for len(nodes) > 1 {
		level++
		es := make([]entry, len(nodes))
		for i, r := range nodes {
			n := r.node.Load()
			es[i] = entry{key: n.Keys[len(n.Keys)-1], kid: r}
		}
		if level > 60 {
			nodes = []*Ref{mkNode(level, es)}
		} else {
			nodes = chunk(level, es)
		}
	}
	r := nodes[0]
	for {
		n, err := r.load()
		if err != nil {
			return Tree{}, err
		}
		if n.Level == 0 || len(n.Kids) > 1 {
			return Tree{Root: r}, nil
		}
		r = n.Kids[0]
	}
}

// mutateLevel applies sorted edits to the nodes of one level. It returns the
// edits for the parent level and every new node produced at this level.
func mutateLevel(root *Ref, h int, es []Edit) ([]Edit, []*Ref, error) {
	up := map[string]Edit{}
	var made []*Ref
	i := 0
	for i < len(es) {
		c, err := seek(root, h, es[i].Key)
		if err != nil {
			return nil, nil, err
		}
		var run []entry
		var gone [][]byte
		for {
			n := c.node()
			isLast := !c.hasNext()
			hi := n.Keys[len(n.Keys)-1]
			gone = append(gone, hi)
			old := n.entries()
			j := 0
			for j < len(old) || (i < len(es) && (isLast || bytes.Compare(es[i].Key, hi) <= 0)) {
				if i < len(es) && (isLast || bytes.Compare(es[i].Key, hi) <= 0) && (j == len(old) || bytes.Compare(es[i].Key, old[j].key) <= 0) {
					e := es[i]
					if j < len(old) && bytes.Equal(e.Key, old[j].key) {
						j++
					}
					if !e.Del {
						run = append(run, entry{key: e.Key, val: e.Val, kid: e.Kid})
					}
					i++
					continue
				}
				run = append(run, old[j])
				j++
			}
			if len(run) == 0 || isLast || boundary(h, run[len(run)-1].key) {
				break
			}
			if err := c.next(); err != nil {
				return nil, nil, err
			}
		}
		for _, k := range gone {
			up[string(k)] = Edit{Key: k, Del: true}
		}
		for _, r := range chunk(h, run) {
			n := r.node.Load()
			k := n.Keys[len(n.Keys)-1]
			up[string(k)] = Edit{Key: k, Kid: r}
			made = append(made, r)
		}
	}
	return sortEdits(up), made, nil
}

// Diff calls fn for every key whose value differs between a and b (nil
// means absent), skipping subtrees with equal hashes.
func Diff(a, b Tree, fn func(k, av, bv []byte) error) error {
	var la, lb []*Ref
	ha, hb := -1, -1
	if a.Root != nil {
		la = []*Ref{a.Root}
		n, err := a.Root.load()
		if err != nil {
			return err
		}
		ha = n.Level
	}
	if b.Root != nil {
		lb = []*Ref{b.Root}
		n, err := b.Root.load()
		if err != nil {
			return err
		}
		hb = n.Level
	}
	var err error
	for ha > hb && ha > 0 {
		la, err = expand(la)
		ha--
	}
	for hb > ha && hb > 0 {
		lb, err = expand(lb)
		hb--
	}
	if err != nil {
		return err
	}
	for {
		hs := map[[32]byte]int{}
		for _, r := range la {
			hs[r.Hash]++
		}
		for _, r := range lb {
			if hs[r.Hash] > 0 {
				hs[r.Hash] = -1
			}
		}
		la, lb = dropShared(la, hs), dropShared(lb, hs)
		level := max(ha, hb)
		if level <= 0 {
			break
		}
		if la, err = expand(la); err != nil {
			return err
		}
		if lb, err = expand(lb); err != nil {
			return err
		}
		ha, hb = level-1, level-1
	}
	ea, err := leafEntries(la)
	if err != nil {
		return err
	}
	eb, err := leafEntries(lb)
	if err != nil {
		return err
	}
	i, j := 0, 0
	for i < len(ea) || j < len(eb) {
		var c int
		switch {
		case i == len(ea):
			c = 1
		case j == len(eb):
			c = -1
		default:
			c = bytes.Compare(ea[i].key, eb[j].key)
		}
		var err error
		switch {
		case c < 0:
			err = fn(ea[i].key, present(ea[i].val), nil)
			i++
		case c > 0:
			err = fn(eb[j].key, nil, present(eb[j].val))
			j++
		default:
			if !bytes.Equal(ea[i].val, eb[j].val) {
				err = fn(ea[i].key, present(ea[i].val), present(eb[j].val))
			}
			i++
			j++
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// present makes empty values distinguishable from absent (nil) ones.
func present(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

func dropShared(l []*Ref, hs map[[32]byte]int) []*Ref {
	out := l[:0:0]
	for _, r := range l {
		if hs[r.Hash] != -1 {
			out = append(out, r)
		}
	}
	return out
}

func expand(l []*Ref) ([]*Ref, error) {
	var out []*Ref
	for _, r := range l {
		n, err := r.load()
		if err != nil {
			return nil, err
		}
		out = append(out, n.Kids...)
	}
	return out, nil
}

func leafEntries(l []*Ref) ([]entry, error) {
	var out []entry
	for _, r := range l {
		n, err := r.load()
		if err != nil {
			return nil, err
		}
		out = append(out, n.entries()...)
	}
	return out, nil
}

// persistBatch serializes every node under the given roots that has no
// location yet, children first, as one contiguous region starting at base.
type persistBatch struct {
	shard int32
	base  int64
	buf   []byte
	locs  map[*Ref]Loc
}

func (p *persistBatch) add(r *Ref) {
	if r == nil || r.loc.Load() != nil {
		return
	}
	if _, ok := p.locs[r]; ok {
		return
	}
	n := r.node.Load()
	w := n.wire()
	for _, k := range n.Kids {
		p.add(k)
		if l := k.loc.Load(); l != nil {
			w.O = append(w.O, *l)
		} else {
			w.O = append(w.O, p.locs[k])
		}
	}
	b := mustCBOR(w)
	p.locs[r] = Loc{Shard: p.shard, Off: p.base + int64(len(p.buf)), Len: int32(len(b))}
	p.buf = append(p.buf, b...)
}

// commit publishes the locations after the batch has been written.
func (p *persistBatch) commit() {
	for r, l := range p.locs {
		r.loc.CompareAndSwap(nil, &l)
	}
}
