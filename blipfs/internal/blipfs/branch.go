package blipfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/epiclabs-io/diff3"
	"github.com/fxamacker/cbor/v2"
)

var errBadRev = errors.New("bad revision")

const (
	mergePrefix = "merge/"
	maxMergeIn  = 64 << 20 // larger files merge as binary
	binarySniff = 8 << 10
)

func mergeBranch(id string) string { return mergePrefix + id }

func validBranchName(n string) error {
	if n == "" || strings.ContainsAny(n, "@\x00") || strings.HasPrefix(n, "-") || strings.HasPrefix(n, mergePrefix) ||
		strings.Contains(n, "..") || strings.HasPrefix(n, "/") || strings.HasSuffix(n, "/") {
		return fmt.Errorf("invalid branch name %q", n)
	}
	return nil
}

// existing returns a branch that exists (catching up the table if needed).
func (v *Vol) existing(ctx context.Context, name string) (*Branch, error) {
	if _, ok := v.table.get(name); !ok {
		if err := v.table.s.catchUp(ctx, 0); err != nil {
			return nil, err
		}
		if _, ok := v.table.get(name); !ok {
			return nil, fmt.Errorf("no such branch %q", name)
		}
	}
	return v.branch(name)
}

// parseRev resolves "branch", "branch@lsn", "@lsn" or "lsn" (the latter two
// on def) to an explicit revision.
func (v *Vol) parseRev(ctx context.Context, s, def string) (Rev, error) {
	name, at, has := strings.Cut(s, "@")
	if !has {
		if _, err := strconv.ParseUint(s, 10, 64); err == nil {
			name, at, has = "", s, true
		}
	}
	if name == "" {
		name = def
	}
	if name == "" {
		return Rev{}, fmt.Errorf("%w %q: no branch given", errBadRev, s)
	}
	b, err := v.existing(ctx, name)
	if err != nil {
		return Rev{}, err
	}
	if !has {
		l, _, err := b.head(ctx)
		return Rev{Branch: name, LSN: l}, err
	}
	l, err := strconv.ParseUint(at, 10, 64)
	if err != nil || l == 0 {
		return Rev{}, fmt.Errorf("%w %q", errBadRev, s)
	}
	if _, err := b.TreeAt(ctx, l); err != nil {
		return Rev{}, err
	}
	return Rev{Branch: name, LSN: l}, nil
}

func (r Rev) String() string { return fmt.Sprintf("%s@%d", r.Branch, r.LSN) }

// --- history ---

type commitInfo struct {
	LSN        uint64
	Type       uint8
	Node       string
	Time       int64
	Ops        []Op
	Concurrent bool
}

// history lists a branch's records (oldest first): checkpointed ones from
// the snapshot, newer ones from memory.
func (b *Branch) history(ctx context.Context) ([]commitInfo, error) {
	if _, _, err := b.head(ctx); err != nil {
		return nil, err
	}
	b.mu.Lock()
	base := b.baseLSN
	var mem []commitInfo
	for _, c := range b.commits {
		mem = append(mem, commitInfo{c.LSN, c.Type, c.Node, c.Time, c.Ops, c.Concurrent})
	}
	b.mu.Unlock()
	t := b.v.snap.tree(b.v.snap.branchShard(b.name))
	pre := streamPrefix('C', branchStream(b.name))
	var out []commitInfo
	var ferr error
	err := t.AscendPrefix(pre, func(k, v []byte) bool {
		l := binary.BigEndian.Uint64(k[len(pre):])
		if l > base {
			return false
		}
		var ce commitEnt
		if ferr = cbor.Unmarshal(v, &ce); ferr != nil {
			return false
		}
		out = append(out, commitInfo{l, ce.Type, ce.Node, ce.Time, ce.Ops, ce.Concurrent})
		return true
	})
	if err == nil {
		err = ferr
	}
	for _, c := range mem {
		if len(out) == 0 || c.LSN > out[len(out)-1].LSN {
			out = append(out, c)
		}
	}
	return out, err
}

// findCommit returns the newest visible commit at or below lsn.
func (b *Branch) findCommit(ctx context.Context, lsn uint64) (commitInfo, error) {
	h, err := b.history(ctx)
	if err != nil {
		return commitInfo{}, err
	}
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].LSN <= lsn && h[i].Type != RecStage {
			return h[i], nil
		}
	}
	return commitInfo{}, fmt.Errorf("no commit at or before %s@%d", b.name, lsn)
}

// touched returns the commits of b that changed ino.
func (b *Branch) touched(ctx context.Context, ino uint64) (map[uint64]bool, error) {
	out := map[uint64]bool{}
	st := branchStream(b.name)
	pre := u64([]byte{'H'}, ino)
	err := b.v.snap.tree(b.v.snap.branchShard(b.name)).AscendPrefix(pre, func(k, _ []byte) bool {
		if len(k) > 17 && string(k[17:]) == st {
			out[binary.BigEndian.Uint64(k[9:17])] = true
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	prev, commits := b.baseRoot, slices.Clone(b.commits)
	b.mu.Unlock()
	for _, c := range commits {
		if c.Type == RecStage {
			continue
		}
		err := Diff(prev, c.Root, func(k, _, _ []byte) error {
			if len(k) >= 9 && keyIno(k) == ino {
				out[c.LSN] = true
				return io.EOF
			}
			return nil
		})
		if err != nil && err != io.EOF {
			return nil, err
		}
		prev = c.Root
	}
	return out, nil
}

// --- merge bases ---

// frontier records, per stream, the newest LSN whose state is contained in r.
func (v *Vol) frontier(ctx context.Context, r Rev, f map[string]uint64) error {
	if f[r.Branch] >= r.LSN {
		return nil
	}
	f[r.Branch] = r.LSN
	b, err := v.branch(r.Branch)
	if err != nil {
		return err
	}
	if r.LSN > b.s.known.Load() {
		if err := b.s.catchUp(ctx, 0); err != nil {
			return err
		}
	}
	m := b.Meta()
	if m.Src.Branch != "" {
		if err := v.frontier(ctx, m.Src, f); err != nil {
			return err
		}
	}
	for _, e := range m.Edges {
		if e.LSN <= r.LSN {
			if err := v.frontier(ctx, e.Src, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// lca picks the newest revision contained in both a and b.
func (v *Vol) lca(ctx context.Context, a, b Rev) (Rev, error) {
	fa, fb := map[string]uint64{}, map[string]uint64{}
	if err := v.frontier(ctx, a, fa); err != nil {
		return Rev{}, err
	}
	if err := v.frontier(ctx, b, fb); err != nil {
		return Rev{}, err
	}
	var best Rev
	for s, la := range fa {
		if lb, ok := fb[s]; ok {
			if l := min(la, lb); l > best.LSN {
				best = Rev{Branch: s, LSN: l}
			}
		}
	}
	if best.Branch == "" {
		return Rev{}, fmt.Errorf("%s and %s have no common ancestor", a, b)
	}
	return best, nil
}

// --- three-way merge ---

type merger struct {
	v                  *Vol
	ctx                context.Context
	base, ours, theirs Tree
	x                  *txn // ours plus the merge result
	conflicts          map[uint64]bool
	alive              map[uint64]bool // inodes kept by a modify/delete conflict
	inos               map[uint64]bool // inodes whose links may have changed
	packs              map[string]bool
	ents               []ChunkEnt
}

func isMetaKey(k []byte) bool {
	return len(k) >= 9 && (k[0] == kInode || k[0] == kExtent || k[0] == kXattr)
}

func changes(a, b Tree) (map[string][]byte, error) {
	m := map[string][]byte{}
	err := Diff(a, b, func(k, _, bv []byte) error {
		if len(k) > 0 && k[0] != kBackref {
			m[string(k)] = bv
		}
		return nil
	})
	return m, err
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// merge3 merges the changes base->theirs into ours. It returns the merged
// tree, the conflicting paths and the chunks it uploaded.
func (v *Vol) merge3(ctx context.Context, base, ours, theirs Tree) (Tree, []string, []ChunkEnt, error) {
	m := &merger{v: v, ctx: ctx, base: base, ours: ours, theirs: theirs, x: newTxn(ours),
		conflicts: map[uint64]bool{}, alive: map[uint64]bool{}, inos: map[uint64]bool{}, packs: map[string]bool{}}
	dO, err := changes(base, ours)
	if err != nil {
		return Tree{}, nil, nil, err
	}
	dT, err := changes(base, theirs)
	if err != nil {
		return Tree{}, nil, nil, err
	}
	contentO := map[uint64]bool{}
	for k := range dO {
		if isMetaKey([]byte(k)) {
			contentO[keyIno([]byte(k))] = true
		}
	}
	// inodes ours renamed or unlinked: theirs must not add names for them
	moved := map[uint64]bool{}
	for k, ov := range dO {
		if k[0] != kDirent {
			continue
		}
		if bv, ok, _ := base.Get([]byte(k)); ok && !bytes.Equal(bv, ov) {
			moved[binary.BigEndian.Uint64(bv)] = true
		}
	}
	// 1. inode content
	done := map[uint64]bool{}
	for _, k := range sortedKeys(dT) {
		kb := []byte(k)
		if !isMetaKey(kb) {
			continue
		}
		ino := keyIno(kb)
		if !contentO[ino] {
			m.set(kb, dT[k])
			continue
		}
		if !done[ino] {
			done[ino] = true
			if err := m.mergeInode(ino); err != nil {
				return Tree{}, nil, nil, err
			}
		}
	}
	// 2. directory entries
	for _, k := range sortedKeys(dT) {
		kb := []byte(k)
		if kb[0] != kDirent {
			continue
		}
		tv := dT[k]
		ov, oChanged := dO[k]
		bv, inBase, err := base.Get(kb)
		if err != nil {
			return Tree{}, nil, nil, err
		}
		if tv != nil && !(inBase && bytes.Equal(bv, tv)) {
			// rename/rename of one inode: ours wins
			if ino := binary.BigEndian.Uint64(tv); moved[ino] && m.renamedBy(theirs, ino) {
				continue
			}
		}
		switch {
		case !oChanged:
			m.setDirent(kb, tv)
		case bytes.Equal(ov, tv):
		case tv == nil:
			// theirs removed a name ours changed: keep ours
		case ov == nil:
			m.setDirent(kb, tv)
		default:
			if err := m.clash(kb, binary.BigEndian.Uint64(ov), binary.BigEndian.Uint64(tv), !inBase); err != nil {
				return Tree{}, nil, nil, err
			}
		}
	}
	if err := m.fixLinks(); err != nil {
		return Tree{}, nil, nil, err
	}
	if err := v.chunks.flush(ctx, m.packs); err != nil {
		return Tree{}, nil, nil, err
	}
	res, err := m.x.commit()
	if err != nil {
		return Tree{}, nil, nil, err
	}
	var paths []string
	for ino := range m.conflicts {
		if p, err := pathOf(res, ino); err == nil && p != "" {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	return res, slices.Compact(paths), m.ents, nil
}

// renamedBy reports whether t dropped one of ino's base names.
func (m *merger) renamedBy(t Tree, ino uint64) bool {
	gone := false
	m.base.AscendPrefix(backrefPrefix(ino), func(k, _ []byte) bool {
		if _, ok, _ := t.Get(k); !ok {
			gone = true
		}
		return !gone
	})
	return gone
}

func (m *merger) set(k, v []byte) {
	if v == nil {
		m.x.del(k)
	} else {
		m.x.put(k, v)
	}
	m.inos[keyIno(k)] = true
}

// setDirent changes one name, keeping the reverse index in step.
func (m *merger) setDirent(k, v []byte) {
	parent, name := keyIno(k), string(k[9:])
	if old, ok, _ := m.x.get(k); ok {
		m.x.del(backrefKey(binary.BigEndian.Uint64(old), parent, name))
		m.inos[binary.BigEndian.Uint64(old)] = true
	}
	if v == nil {
		m.x.del(k)
		return
	}
	ino := binary.BigEndian.Uint64(v)
	m.x.put(k, v)
	m.x.put(backrefKey(ino, parent, name), nil)
	m.inos[ino] = true
}

func (m *merger) keys(t Tree, prefix []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := t.AscendPrefix(prefix, func(k, v []byte) bool {
		out[string(k)] = v
		return true
	})
	return out, err
}

func sameKeys(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// copyPrefix replaces x's keys under prefix(dst) with t's keys under prefix(src).
func (m *merger) copyPrefix(t Tree, prefix func(uint64) []byte, src, dst uint64) error {
	if err := m.x.scanPrefix(prefix(dst), func(k, _ []byte) bool { m.x.del(k); return true }); err != nil {
		return err
	}
	sp, dp := prefix(src), prefix(dst)
	return t.AscendPrefix(sp, func(k, v []byte) bool {
		m.x.put(append(slices.Clone(dp), k[len(sp):]...), v)
		return true
	})
}

func treeAttrOf(t Tree, ino uint64) (*Attr, error) {
	a, err := treeAttr(t, ino)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	return a, err
}

// mergeInode merges an inode both sides changed.
func (m *merger) mergeInode(ino uint64) error {
	ba, err := treeAttrOf(m.base, ino)
	if err != nil {
		return err
	}
	oa, err := treeAttrOf(m.ours, ino)
	if err != nil {
		return err
	}
	ta, err := treeAttrOf(m.theirs, ino)
	if err != nil {
		return err
	}
	switch {
	case oa == nil && ta == nil:
		return nil
	case oa == nil:
		// deleted by ours, modified by theirs: keep theirs
		m.conflicts[ino], m.alive[ino] = true, true
		m.x.put(inodeKey(ino), mustCBOR(ta))
		if err := m.copyPrefix(m.theirs, extentPrefix, ino, ino); err != nil {
			return err
		}
		return m.copyPrefix(m.theirs, xattrPrefix, ino, ino)
	case ta == nil:
		m.conflicts[ino], m.alive[ino] = true, true
		return nil
	}
	if err := m.mergeXattrs(ino); err != nil {
		return err
	}
	a := *oa
	if ba != nil {
		if a.Mode == ba.Mode {
			a.Mode = ta.Mode
		}
		if a.Uid == ba.Uid {
			a.Uid = ta.Uid
		}
		if a.Gid == ba.Gid {
			a.Gid = ta.Gid
		}
	}
	a.Mtime, a.Ctime, a.Atime = max(oa.Mtime, ta.Mtime), max(oa.Ctime, ta.Ctime), max(oa.Atime, ta.Atime)
	a.Ver = max(oa.Ver, ta.Ver) + 1
	if oa.IsDir() || ta.IsDir() || oa.Mode&syscall.S_IFMT != ta.Mode&syscall.S_IFMT {
		m.x.putAttr(ino, &a)
		return nil
	}
	be, err := m.keys(m.base, extentPrefix(ino))
	if err != nil {
		return err
	}
	oe, err := m.keys(m.ours, extentPrefix(ino))
	if err != nil {
		return err
	}
	te, err := m.keys(m.theirs, extentPrefix(ino))
	if err != nil {
		return err
	}
	switch {
	case sameKeys(oe, te) && oa.Size == ta.Size && oa.Target == ta.Target:
	case sameKeys(be, oe) && ba != nil && ba.Size == oa.Size && ba.Target == oa.Target:
		a.Size, a.Target = ta.Size, ta.Target
		if err := m.copyPrefix(m.theirs, extentPrefix, ino, ino); err != nil {
			return err
		}
	case sameKeys(be, te) && ba != nil && ba.Size == ta.Size && ba.Target == ta.Target:
	case !oa.IsReg():
		m.conflicts[ino] = true // e.g. a symlink retargeted on both sides: ours wins
	default:
		m.x.putAttr(ino, &a)
		return m.mergeData(ino, m.base, ino, m.theirs, ino)
	}
	a.Writer = ""
	m.x.putAttr(ino, &a)
	return nil
}

func (m *merger) mergeXattrs(ino uint64) error {
	bx, err := m.keys(m.base, xattrPrefix(ino))
	if err != nil {
		return err
	}
	tx, err := m.keys(m.theirs, xattrPrefix(ino))
	if err != nil {
		return err
	}
	ox, err := m.keys(m.ours, xattrPrefix(ino))
	if err != nil {
		return err
	}
	for k, tv := range tx {
		bv, inB := bx[k]
		if inB && bytes.Equal(bv, tv) {
			continue
		}
		if ov, ok := ox[k]; ok == inB && (!ok || bytes.Equal(ov, bv)) {
			m.x.put([]byte(k), tv)
		}
	}
	for k, bv := range bx {
		if _, ok := tx[k]; !ok {
			if ov, ok := ox[k]; ok && bytes.Equal(ov, bv) {
				m.x.del([]byte(k))
			}
		}
	}
	return nil
}

func (m *merger) readFile(t Tree, ino uint64) ([]byte, bool, error) {
	if t.Root == nil || ino == 0 {
		return nil, true, nil
	}
	a, err := treeAttrOf(t, ino)
	if err != nil || a == nil {
		return nil, true, err
	}
	if a.Size > maxMergeIn {
		return nil, false, nil
	}
	buf := make([]byte, a.Size)
	if err := readExtents(m.ctx, m.v.chunks, t, ino, 0, buf); err != nil {
		return nil, false, err
	}
	return buf, true, nil
}

func isBinary(b []byte) bool { return bytes.IndexByte(b[:min(len(b), binarySniff)], 0) >= 0 }

// mergeData three-way merges file contents into ours' ino: text merges
// with diff3 (conflict markers on overlap); binary keeps ours and adds
// theirs beside it as name~theirs.
func (m *merger) mergeData(ino uint64, base Tree, bino uint64, theirs Tree, tino uint64) error {
	bd, okb, err := m.readFile(base, bino)
	if err != nil {
		return err
	}
	od, oko, err := m.readFile(m.ours, ino)
	if err != nil {
		return err
	}
	td, okt, err := m.readFile(theirs, tino)
	if err != nil {
		return err
	}
	if bytes.Equal(od, td) && oko && okt {
		return nil
	}
	if !okb || !oko || !okt || isBinary(bd) || isBinary(od) || isBinary(td) {
		return m.addTheirs(ino, theirs, tino)
	}
	r, err := diff3.Merge(bytes.NewReader(od), bytes.NewReader(bd), bytes.NewReader(td), true, "ours", "theirs")
	if err != nil {
		return err
	}
	out, err := io.ReadAll(r.Result)
	if err != nil {
		return err
	}
	if r.Conflicts {
		m.conflicts[ino] = true
		out = gitMarkers(out)
	}
	if len(out) > 0 && (bytes.HasSuffix(od, []byte("\n")) || bytes.HasSuffix(td, []byte("\n"))) {
		out = append(out, '\n') // diff3 drops the final newline
	}
	return m.writeData(ino, out)
}

// gitMarkers rewrites diff3's 9-character conflict markers to the
// 7-character ones that git and editors recognise.
func gitMarkers(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	in := false
	for i, l := range lines {
		switch {
		case !in && l == "<<<<<<<<< ours":
			lines[i], in = "<<<<<<< ours", true
		case in && l == "=========":
			lines[i] = "======="
		case in && l == ">>>>>>>>> theirs":
			lines[i], in = ">>>>>>> theirs", false
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// writeData replaces the content of ino in the merge result.
func (m *merger) writeData(ino uint64, data []byte) error {
	a, err := m.x.attr(ino)
	if err != nil || a == nil {
		return err
	}
	if err := m.x.scanPrefix(extentPrefix(ino), func(k, _ []byte) bool { m.x.del(k); return true }); err != nil {
		return err
	}
	if len(data) <= inlineMax {
		if len(data) > 0 {
			m.x.put(extentKey(ino, 0), mustCBOR(Extent{Len: uint64(len(data)), Data: data}))
		}
	} else {
		err := chunkSplit(bytes.NewReader(data), func(off int64, d []byte) error {
			e := m.v.chunks.upload(d, m.packs)
			m.ents = append(m.ents, e)
			m.x.put(extentKey(ino, uint64(off)), mustCBOR(Extent{Hash: e.Hash, Len: uint64(len(d))}))
			return nil
		})
		if err != nil {
			return err
		}
	}
	a.Size, a.Writer = uint64(len(data)), ""
	a.Mtime = max(a.Mtime, time.Now().UnixNano())
	a.Ver++
	m.x.putAttr(ino, a)
	return nil
}

func newMergeIno() uint64 { return 1<<62 | rand.Uint64()&(1<<62-1) }

// addTheirs copies theirs' tino to a new inode named <name>~theirs next to
// each of ours' names of ino.
func (m *merger) addTheirs(ino uint64, theirs Tree, tino uint64) error {
	ta, err := treeAttrOf(theirs, tino)
	if err != nil || ta == nil {
		return err
	}
	var names [][]byte
	if err := m.x.scanPrefix(backrefPrefix(ino), func(k, _ []byte) bool {
		names = append(names, slices.Clone(k))
		return true
	}); err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	n := newMergeIno()
	a := *ta
	a.Nlink = 0
	m.x.putAttr(n, &a)
	if err := m.copyPrefix(theirs, extentPrefix, tino, n); err != nil {
		return err
	}
	if err := m.copyPrefix(theirs, xattrPrefix, tino, n); err != nil {
		return err
	}
	for _, k := range names {
		parent := binary.BigEndian.Uint64(k[9:17])
		m.setDirent(direntKey(parent, m.freeName(parent, string(k[17:])+"~theirs")), u64(nil, n))
	}
	m.conflicts[ino], m.conflicts[n] = true, true
	return nil
}

func (m *merger) freeName(parent uint64, name string) string {
	for i := 1; ; i++ {
		n := name
		if i > 1 {
			n = fmt.Sprintf("%s%d", name, i)
		}
		if _, ok, _ := m.x.lookup(parent, n); !ok {
			return n
		}
	}
}

// clash handles a name both sides point at different inodes.
func (m *merger) clash(k []byte, oino, tino uint64, added bool) error {
	oa, err := m.x.attr(oino)
	if err != nil || oa == nil {
		return err
	}
	ta, err := treeAttrOf(m.theirs, tino)
	if err != nil || ta == nil {
		return err
	}
	if added && oa.IsReg() && ta.IsReg() {
		// add/add of two files: merge their contents with an empty base
		if err := m.mergeData(oino, Tree{}, 0, m.theirs, tino); err != nil {
			return err
		}
		m.dropIno(tino)
		return nil
	}
	parent, name := keyIno(k), string(k[9:])
	m.setDirent(direntKey(parent, m.freeName(parent, name+"~theirs")), u64(nil, tino))
	m.conflicts[oino], m.conflicts[tino] = true, true
	return nil
}

// dropIno removes an inode step 1 copied from theirs.
func (m *merger) dropIno(ino uint64) {
	if _, ok, _ := m.ours.Get(inodeKey(ino)); ok {
		return
	}
	m.x.del(inodeKey(ino))
	for _, p := range [][]byte{extentPrefix(ino), xattrPrefix(ino), direntPrefix(ino)} {
		m.x.scanPrefix(p, func(k, _ []byte) bool { m.x.del(k); return true })
	}
	delete(m.inos, ino)
}

// fixLinks reattaches inodes kept by modify/delete conflicts and recomputes
// link counts.
func (m *merger) fixLinks() error {
	for ino := range m.alive {
		has := false
		m.x.scanPrefix(backrefPrefix(ino), func(k, _ []byte) bool { has = true; return false })
		if has {
			continue
		}
		var names [][]byte
		m.base.AscendPrefix(backrefPrefix(ino), func(k, _ []byte) bool {
			names = append(names, slices.Clone(k))
			return true
		})
		for _, k := range names {
			parent, name := binary.BigEndian.Uint64(k[9:17]), string(k[17:])
			if pa, err := m.x.attr(parent); err != nil || pa == nil || !pa.IsDir() {
				parent = rootIno
			}
			m.setDirent(direntKey(parent, m.freeName(parent, name)), u64(nil, ino))
		}
	}
	for ino := range m.inos {
		a, err := m.x.attr(ino)
		if err != nil {
			return err
		}
		if a == nil || a.IsDir() {
			continue
		}
		n := uint32(0)
		m.x.scanPrefix(backrefPrefix(ino), func(k, _ []byte) bool { n++; return true })
		if n == 0 {
			m.x.del(inodeKey(ino))
			for _, p := range [][]byte{extentPrefix(ino), xattrPrefix(ino)} {
				m.x.scanPrefix(p, func(k, _ []byte) bool { m.x.del(k); return true })
			}
			continue
		}
		if a.Nlink != n {
			a.Nlink = n
			m.x.putAttr(ino, a)
		}
	}
	return nil
}

// editsBetween turns from into to as raw edits checked against from.
func editsBetween(from, to Tree) ([]RawEdit, error) {
	var es []RawEdit
	err := Diff(from, to, func(k, a, b []byte) error {
		e := RawEdit{Key: k, Check: true, Pre: a, Absent: a == nil}
		if b == nil {
			e.Del = true
		} else {
			e.Val = b
		}
		es = append(es, e)
		return nil
	})
	return es, err
}

// --- merge, cherry-pick, revert ---

type mergeReq struct {
	kind   string // merge, cherry-pick, revert
	dst    string
	base   Rev
	theirs Rev
	edge   bool // record a merge edge (merge only)
	info   string
}

// apply3 applies base->theirs onto dst: one MERGE record when clean,
// otherwise a workspace branch holding the conflicts.
func (v *Vol) apply3(ctx context.Context, r mergeReq) (string, error) {
	db, err := v.existing(ctx, r.dst)
	if err != nil {
		return "", err
	}
	bt, err := v.treeAt(ctx, r.base)
	if err != nil {
		return "", err
	}
	tt, err := v.treeAt(ctx, r.theirs)
	if err != nil {
		return "", err
	}
	for try := 0; try < writeTries; try++ {
		dstLSN, ours, err := db.head(ctx)
		if err != nil {
			return "", err
		}
		meta := db.Meta()
		if meta.Merge != nil {
			return "", fmt.Errorf("%s is a merge workspace", r.dst)
		}
		if meta.Active != "" {
			return "", fmt.Errorf("a merge into %s is in progress (%s); use merge --continue or --abort", r.dst, meta.Active)
		}
		res, conflicts, ents, err := v.merge3(ctx, bt, ours, tt)
		if err != nil {
			return "", err
		}
		ms := &MergeState{ID: randHex(4), Kind: r.kind, Dst: r.dst, DstLSN: dstLSN, Base: r.base, Theirs: r.theirs,
			Conflicts: conflicts, Edge: r.edge, Info: r.info}
		var ops []Op
		if len(ents) > 0 {
			ops = append(ops, Op{Kind: OpChunkPut, Chunks: ents})
		}
		edits, err := editsBetween(ours, res)
		if err != nil {
			return "", err
		}
		now := time.Now().UnixNano()
		if len(conflicts) == 0 {
			if len(edits) == 0 && !r.edge {
				return "nothing to " + r.kind + "\n", nil
			}
			ops = append(ops, Op{Kind: OpMergeDone, Branch: r.dst, Edits: edits, Merge: ms, Info: r.info, Time: now, Node: v.node})
			lsn, res, err := v.write(ctx, RecMerge, db, ops)
			if err != nil {
				return "", err
			}
			if e := res[len(res)-1].Errno; e == syscall.ESTALE {
				continue
			} else if e != 0 {
				return "", e
			}
			return fmt.Sprintf("%s -> %s@%d\n", r.info, r.dst, lsn), nil
		}
		ws := mergeBranch(ms.ID)
		wb, err := v.branch(ws)
		if err != nil {
			return "", err
		}
		ops = append(ops,
			Op{Kind: OpMergeLock, Branch: r.dst, Name: ms.ID, Time: now},
			Op{Kind: OpMergeStart, Branch: ws, Src: Rev{Branch: r.dst, LSN: dstLSN}, Edits: edits, Merge: ms, Info: r.info, Time: now, Node: v.node})
		lsn, wres, err := v.write(ctx, RecMerge, wb, ops)
		if err != nil {
			return "", err
		}
		if e := wres[len(wres)-1].Errno; e != 0 {
			return "", e
		}
		if err := db.s.catchUp(ctx, lsn); err != nil {
			return "", err
		}
		if dres := db.takeResults(lsn); len(dres) >= 2 && dres[len(dres)-2].Errno != 0 {
			v.write(ctx, RecBranch, wb, []Op{{Kind: OpBranchClose, Branch: ws, Time: now}})
			if dres[len(dres)-2].Errno == syscall.EBUSY {
				return "", fmt.Errorf("another merge into %s started meanwhile", r.dst)
			}
			return "", dres[len(dres)-2].Errno
		}
		return conflictReport(v, r.dst, ms.ID, conflicts), nil
	}
	return "", fmt.Errorf("%s kept changing; giving up", r.dst)
}

func conflictReport(v *Vol, dst, id string, conflicts []string) string {
	var sb strings.Builder
	for _, p := range conflicts {
		fmt.Fprintf(&sb, "CONFLICT: %s\n", p)
	}
	where := ".blipfs/merge/" + id + "/work"
	for _, m := range v.mountsOf(dst) {
		where = m + "/" + where
		break
	}
	fmt.Fprintf(&sb, "resolve the conflicts in %s, mark them with `blipfs resolve <path>...`, then run `blipfs merge --continue`\n", where)
	return sb.String()
}

// mountsOf returns the mount points of a branch.
func (v *Vol) mountsOf(branch string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for p, m := range v.mounts {
		if m.b.name == branch {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// activeMerge returns the workspace of the merge in progress into dst.
func (v *Vol) activeMerge(ctx context.Context, dst string) (*Branch, *Branch, *MergeState, error) {
	db, err := v.existing(ctx, dst)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, err := db.head(ctx); err != nil {
		return nil, nil, nil, err
	}
	id := db.Meta().Active
	if id == "" {
		return nil, nil, nil, fmt.Errorf("no merge in progress into %s", dst)
	}
	wb, err := v.branch(mergeBranch(id))
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, err := wb.head(ctx); err != nil {
		return nil, nil, nil, err
	}
	ms := wb.Meta().Merge
	if ms == nil {
		return nil, nil, nil, fmt.Errorf("merge %s has no state", id)
	}
	return db, wb, ms, nil
}

// mergeContinue lands a resolved workspace on its destination.
func (v *Vol) mergeContinue(ctx context.Context, dst string) (string, error) {
	db, wb, ms, err := v.activeMerge(ctx, dst)
	if err != nil {
		return "", err
	}
	if len(ms.Conflicts) > 0 {
		return "", fmt.Errorf("unresolved conflicts:\n  %s\nmark them with `blipfs resolve <path>...`", strings.Join(ms.Conflicts, "\n  "))
	}
	start, err := v.treeAt(ctx, Rev{Branch: dst, LSN: ms.DstLSN})
	if err != nil {
		return "", err
	}
	for try := 0; try < writeTries; try++ {
		_, work, err := wb.head(ctx)
		if err != nil {
			return "", err
		}
		dstLSN, ours, err := db.head(ctx)
		if err != nil {
			return "", err
		}
		res := work
		var ents []ChunkEnt
		now := time.Now().UnixNano()
		if !ours.Equal(start) {
			// dst moved on: rebase the workspace result onto it
			var conflicts []string
			res, conflicts, ents, err = v.merge3(ctx, start, ours, work)
			if err != nil {
				return "", err
			}
			if len(conflicts) > 0 {
				edits, err := editsBetween(work, res)
				if err != nil {
					return "", err
				}
				nm := *ms
				nm.DstLSN, nm.Conflicts = dstLSN, conflicts
				ops := []Op{{Kind: OpMergeUpdate, Branch: wb.name, Edits: edits, Merge: &nm, Time: now, Node: v.node}}
				if len(ents) > 0 {
					ops = append([]Op{{Kind: OpChunkPut, Chunks: ents}}, ops...)
				}
				_, r, err := v.write(ctx, RecMerge, wb, ops)
				if err != nil {
					return "", err
				}
				if e := r[len(r)-1].Errno; e == syscall.ESTALE {
					continue
				} else if e != 0 {
					return "", e
				}
				return "", errors.New(dst + " changed meanwhile and conflicts again:\n" + conflictReport(v, dst, ms.ID, conflicts))
			}
		}
		edits, err := editsBetween(ours, res)
		if err != nil {
			return "", err
		}
		var ops []Op
		if len(ents) > 0 {
			ops = append(ops, Op{Kind: OpChunkPut, Chunks: ents})
		}
		ops = append(ops,
			Op{Kind: OpMergeDone, Branch: dst, Edits: edits, Merge: ms, Info: ms.Info, Time: now, Node: v.node},
			Op{Kind: OpBranchClose, Branch: wb.name, Time: now})
		lsn, r, err := v.write(ctx, RecMerge, db, ops)
		if err != nil {
			return "", err
		}
		if e := r[len(r)-2].Errno; e == syscall.ESTALE {
			continue
		} else if e != 0 {
			return "", e
		}
		return fmt.Sprintf("%s -> %s@%d\n", ms.Info, dst, lsn), nil
	}
	return "", fmt.Errorf("%s kept changing; giving up", dst)
}

func (v *Vol) mergeAbort(ctx context.Context, dst string) (string, error) {
	db, wb, ms, err := v.activeMerge(ctx, dst)
	if err != nil {
		return "", err
	}
	now := time.Now().UnixNano()
	_, _, err = v.write(ctx, RecMerge, db, []Op{
		{Kind: OpMergeUnlock, Branch: dst, Name: ms.ID, Time: now},
		{Kind: OpBranchClose, Branch: wb.name, Time: now}})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("aborted %s of %s into %s\n", ms.Kind, ms.Theirs, dst), nil
}
