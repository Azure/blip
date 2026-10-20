package blipfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const (
	fuseTTL    = time.Second
	viewIDBase = 1 << 63 // node ids of .blipfs entries and non-main views
	followTick = time.Second
)

// view is a tree shown in a mount: the mounted branch, a merge workspace
// (both writable), or a fixed revision (read-only).
type view struct {
	b *Branch
	t Tree
}

func (w *view) tree() Tree {
	if w.b != nil {
		t, _, _ := w.b.local()
		return t
	}
	return w.t
}

// vnode is a node id outside the main view.
type vnode struct {
	w    *view
	ino  uint64
	virt string // virtual directory under .blipfs ("" for tree nodes)
}

type vkey struct {
	w    *view
	ino  uint64
	virt string
}

type handle struct {
	w     *view
	ino   uint64
	t     Tree // tree at open, to keep reading unlinked files
	write bool
	dir   []fuse.DirEntry
}

type dkey struct {
	b   *Branch
	ino uint64
}

// dirtyFile holds data written since the last commit in a temp file at the
// same offsets; iv lists the dirty intervals.
type dirtyFile struct {
	mu     sync.Mutex
	f      *os.File
	iv     [][2]uint64
	size   uint64
	base   uint64 // inode version the writes are based on
	mtime  int64
	stages []uint64
}

// Mount serves one branch at one path.
type Mount struct {
	fuse.RawFileSystem
	v    *Vol
	b    *Branch
	main *view
	path string
	srv  *fuse.Server
	stop chan struct{}

	mu      sync.Mutex
	ids     map[vkey]uint64
	nodes   map[uint64]*vnode
	nextID  uint64
	revs    map[string]*view
	handles map[uint64]*handle
	nextFh  uint64
	dirty   map[dkey]*dirtyFile
	writers map[dkey]int
	opened  map[uint64]uint64 // ino -> version at last open (page cache validity)
}

func (v *Vol) mount(branch, path string) (*Mount, error) {
	b, err := v.branch(branch)
	if err != nil {
		return nil, err
	}
	if _, _, err := b.head(context.Background()); err != nil {
		return nil, err
	}
	m := &Mount{
		RawFileSystem: fuse.NewDefaultRawFileSystem(),
		v:             v, b: b, main: &view{b: b}, path: path, stop: make(chan struct{}),
		ids: map[vkey]uint64{}, nodes: map[uint64]*vnode{}, nextID: viewIDBase,
		revs: map[string]*view{}, handles: map[uint64]*handle{}, nextFh: 1,
		dirty: map[dkey]*dirtyFile{}, writers: map[dkey]int{}, opened: map[uint64]uint64{},
	}
	opts := &fuse.MountOptions{
		FsName:             "blipfs:" + branch,
		Name:               "blipfs",
		Options:            []string{"default_permissions"},
		AllowOther:         os.Geteuid() == 0,
		MaxWrite:           1 << 20,
		MaxReadAhead:       1 << 20,
		MaxBackground:      64,
		DisableReadDirPlus: true,
		// No CAP_WRITEBACK_CACHE: with it the kernel owns i_size and ignores
		// sizes reported by the daemon, hiding appends made on other hosts.
	}
	srv, err := fuse.NewServer(m, path, opts)
	if err != nil {
		return nil, err
	}
	m.srv = srv
	go srv.Serve()
	if err := srv.WaitMount(); err != nil {
		srv.Unmount()
		return nil, err
	}
	go m.follow()
	setReadAhead(path)
	return m, nil
}

// readAheadKB is the kernel readahead window for mounts. There is no read
// cache, so a large window is what turns sequential reads into many parallel
// ranged GETs instead of one 128KiB GET at a time.
const readAheadKB = 16 << 10

// setReadAhead raises the mount's readahead; it needs root and is skipped
// otherwise.
func setReadAhead(path string) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return
	}
	f := fmt.Sprintf("/sys/class/bdi/%d:%d/read_ahead_kb", unix.Major(st.Dev), unix.Minor(st.Dev))
	if err := os.WriteFile(f, []byte(fmt.Sprint(readAheadKB)), 0); err != nil && os.Geteuid() == 0 {
		log.Printf("mount %s: set readahead: %v", path, err)
	}
}

// unmount commits outstanding dirty data and detaches the mount.
func (m *Mount) unmount() error {
	m.mu.Lock()
	var ds []dkey
	for k := range m.dirty {
		ds = append(ds, k)
	}
	m.mu.Unlock()
	for _, k := range ds {
		if err := m.commitDirty(context.Background(), k); err != nil {
			log.Printf("unmount %s: commit inode %d: %v", m.path, k.ino, err)
		}
	}
	if err := m.srv.Unmount(); err != nil {
		return err
	}
	close(m.stop)
	return nil
}

// follow tails the branch so changes made elsewhere invalidate the kernel's caches.
func (m *Mount) follow() {
	t := time.NewTicker(followTick)
	defer t.Stop()
	prev, _, _ := m.b.local()
	seen := m.b.s.known.Load()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := m.b.s.catchUp(ctx, 0)
		cancel()
		if err != nil {
			continue
		}
		cur, _, _ := m.b.local()
		m.b.mu.Lock()
		foreign := seen < m.b.baseLSN // commits since seen were checkpointed away
		for _, c := range m.b.commits {
			// merges, picks and reverts come from the CLI, not this mount
			if c.LSN > seen && (c.Node != m.v.node || c.Type != RecCommit) {
				foreign = true
			}
		}
		m.b.mu.Unlock()
		seen = m.b.s.known.Load()
		if foreign && !cur.Equal(prev) {
			var inos []uint64
			var ents [][2]any
			Diff(prev, cur, func(k, av, bv []byte) error {
				switch k[0] {
				case kInode:
					inos = append(inos, keyIno(k))
				case kDirent:
					ents = append(ents, [2]any{keyIno(k), string(k[9:])})
				}
				return nil
			})
			for _, ino := range inos {
				m.srv.InodeNotify(ino, 0, 0)
			}
			for _, e := range ents {
				m.srv.EntryNotify(e[0].(uint64), e[1].(string))
			}
		}
		prev = cur
	}
}

// --- node ids ---

func (m *Mount) idFor(w *view, ino uint64, virt string) uint64 {
	if w == m.main {
		return ino
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := vkey{w, ino, virt}
	if id, ok := m.ids[k]; ok {
		return id
	}
	m.nextID++
	m.ids[k] = m.nextID
	m.nodes[m.nextID] = &vnode{w: w, ino: ino, virt: virt}
	return m.nextID
}

func (m *Mount) node(id uint64) (*view, uint64, string, fuse.Status) {
	if id < viewIDBase {
		return m.main, id, "", fuse.OK
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[id]
	if n == nil {
		return nil, 0, "", fuse.ENOENT
	}
	return n.w, n.ino, n.virt, fuse.OK
}

// wnode resolves a node that must be writable.
func (m *Mount) wnode(id uint64) (*view, uint64, fuse.Status) {
	w, ino, virt, st := m.node(id)
	if !st.Ok() {
		return nil, 0, st
	}
	if virt != "" || w.b == nil {
		return nil, 0, fuse.Status(syscall.EROFS)
	}
	return w, ino, fuse.OK
}

func errStatus(err error) fuse.Status {
	var e syscall.Errno
	if errors.As(err, &e) {
		return fuse.Status(e)
	}
	if errors.Is(err, context.Canceled) {
		return fuse.EINTR
	}
	log.Printf("fuse: %v", err)
	return fuse.EIO
}

// --- attributes ---

func fillAttr(out *fuse.Attr, id uint64, a *Attr) {
	*out = fuse.Attr{}
	out.Ino = id
	out.Size = a.Size
	out.Blocks = (a.Size + 511) / 512
	out.Mode = a.Mode
	out.Nlink = a.Nlink
	out.Uid, out.Gid = a.Uid, a.Gid
	out.Rdev = a.Rdev
	out.Blksize = 64 << 10
	out.Atime, out.Atimensec = uint64(a.Atime/1e9), uint32(a.Atime%1e9)
	out.Mtime, out.Mtimensec = uint64(a.Mtime/1e9), uint32(a.Mtime%1e9)
	out.Ctime, out.Ctimensec = uint64(a.Ctime/1e9), uint32(a.Ctime%1e9)
}

func virtAttr() *Attr {
	t := time.Now().UnixNano()
	return &Attr{Mode: syscall.S_IFDIR | 0o555, Nlink: 2, Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid()), Atime: t, Mtime: t, Ctime: t}
}

// attr returns the attributes of ino in w including uncommitted writes.
func (m *Mount) attr(w *view, ino uint64) (*Attr, fuse.Status) {
	a, err := treeAttr(w.tree(), ino)
	if err != nil {
		return nil, errStatus(err)
	}
	if a == nil {
		return nil, fuse.ENOENT
	}
	if a.IsDir() {
		a.Nlink = 1 // not tracked; 1 tells tools not to count subdirectories
	}
	if w.b != nil {
		m.mu.Lock()
		d := m.dirty[dkey{w.b, ino}]
		m.mu.Unlock()
		if d != nil {
			d.mu.Lock()
			if len(d.iv) > 0 {
				a.Size, a.Mtime = d.size, max(a.Mtime, d.mtime)
			}
			d.mu.Unlock()
		}
	}
	return a, fuse.OK
}

func (m *Mount) entry(w *view, ino uint64, out *fuse.EntryOut) fuse.Status {
	a, st := m.attr(w, ino)
	if !st.Ok() {
		return st
	}
	id := m.idFor(w, ino, "")
	out.NodeId, out.Generation = id, a.Gen
	fillAttr(&out.Attr, id, a)
	out.SetEntryTimeout(fuseTTL)
	out.SetAttrTimeout(fuseTTL)
	return fuse.OK
}

func (m *Mount) virtEntry(virt string, out *fuse.EntryOut) fuse.Status {
	id := m.idFor(nil, 0, virt)
	out.NodeId = id
	fillAttr(&out.Attr, id, virtAttr())
	out.SetEntryTimeout(fuseTTL)
	out.SetAttrTimeout(fuseTTL)
	return fuse.OK
}

// --- .blipfs ---

// revView returns the read-only view of a revision name like "main@42",
// "42" (on the mounted branch) or "main" (its head).
func (m *Mount) revView(ctx context.Context, name string) (*view, error) {
	r, err := m.v.parseRev(ctx, name, m.b.name)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, syscall.ENOENT // not a revision name
	}
	key := fmt.Sprintf("%s@%d", r.Branch, r.LSN)
	m.mu.Lock()
	w := m.revs[key]
	m.mu.Unlock()
	if w != nil {
		return w, nil
	}
	t, err := m.v.treeAt(ctx, r)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revs[key] == nil {
		m.revs[key] = &view{t: t}
	}
	return m.revs[key], nil
}

// mergeView returns a view of merge workspace id: "work" is the writable
// workspace branch; base, ours and theirs are the merge inputs.
func (m *Mount) mergeView(ctx context.Context, id, part string) (*view, error) {
	ws, err := m.v.branch(mergeBranch(id))
	if err != nil {
		return nil, err
	}
	if _, _, err := ws.head(ctx); err != nil {
		return nil, err
	}
	meta := ws.Meta()
	if meta.Merge == nil || meta.Closed {
		return nil, syscall.ENOENT
	}
	var r Rev
	switch part {
	case "work":
		m.mu.Lock()
		defer m.mu.Unlock()
		key := "merge/" + id
		if m.revs[key] == nil {
			m.revs[key] = &view{b: ws}
		}
		return m.revs[key], nil
	case "base":
		r = meta.Merge.Base
	case "ours":
		r = Rev{meta.Merge.Dst, meta.Merge.DstLSN}
	case "theirs":
		r = meta.Merge.Theirs
	default:
		return nil, syscall.ENOENT
	}
	return m.revView(ctx, fmt.Sprintf("%s@%d", r.Branch, r.LSN))
}

func (m *Mount) virtLookup(ctx context.Context, virt, name string, out *fuse.EntryOut) fuse.Status {
	var w *view
	var err error
	switch {
	case virt == ".blipfs":
		if name != "rev" && name != "merge" {
			return fuse.ENOENT
		}
		return m.virtEntry(".blipfs/"+name, out)
	case virt == ".blipfs/rev":
		w, err = m.revView(ctx, name)
	case virt == ".blipfs/merge":
		e, ok := m.v.table.get(mergeBranch(name))
		if !ok {
			if err := m.v.table.s.catchUp(ctx, 0); err != nil {
				return errStatus(err)
			}
			e, ok = m.v.table.get(mergeBranch(name))
		}
		if !ok || e.Closed {
			return fuse.ENOENT
		}
		return m.virtEntry(".blipfs/merge/"+name, out)
	case strings.HasPrefix(virt, ".blipfs/merge/"):
		w, err = m.mergeView(ctx, strings.TrimPrefix(virt, ".blipfs/merge/"), name)
	default:
		return fuse.ENOENT
	}
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, errBadRev) {
			return fuse.ENOENT
		}
		return errStatus(err)
	}
	return m.entry(w, rootIno, out)
}

func (m *Mount) virtList(virt string) []fuse.DirEntry {
	dir := func(names ...string) []fuse.DirEntry {
		var out []fuse.DirEntry
		for _, n := range names {
			out = append(out, fuse.DirEntry{Name: n, Mode: syscall.S_IFDIR})
		}
		return out
	}
	if virt == ".blipfs/rev" || virt == ".blipfs/merge" {
		if err := m.v.table.s.catchUp(context.Background(), 0); err != nil {
			log.Printf("fuse: listing %s: %v", virt, err)
		}
	}
	switch {
	case virt == ".blipfs":
		return dir("rev", "merge")
	case virt == ".blipfs/rev":
		var names []string
		for _, n := range m.v.table.list(false) {
			if !strings.HasPrefix(n, "merge/") {
				names = append(names, n)
			}
		}
		return dir(names...)
	case virt == ".blipfs/merge":
		var names []string
		for _, n := range m.v.table.list(false) {
			if id, ok := strings.CutPrefix(n, "merge/"); ok {
				names = append(names, id)
			}
		}
		return dir(names...)
	default:
		return dir("work", "base", "ours", "theirs")
	}
}

// --- lookups ---

func (m *Mount) Lookup(cancel <-chan struct{}, h *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	w, ino, virt, st := m.node(h.NodeId)
	if !st.Ok() {
		return st
	}
	if virt != "" {
		return m.virtLookup(context.Background(), virt, name, out)
	}
	if w == m.main && ino == rootIno && name == ".blipfs" {
		return m.virtEntry(".blipfs", out)
	}
	c, ok, err := treeLookup(w.tree(), ino, name)
	if err == nil && !ok && w.b != nil {
		// the name may have been created elsewhere: catch up before saying no
		if err = w.b.s.catchUp(context.Background(), 0); err == nil {
			c, ok, err = treeLookup(w.tree(), ino, name)
		}
	}
	if err != nil {
		return errStatus(err)
	}
	if !ok {
		return fuse.ENOENT
	}
	return m.entry(w, c, out)
}

func (m *Mount) GetAttr(cancel <-chan struct{}, in *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	w, ino, virt, st := m.node(in.NodeId)
	if !st.Ok() {
		return st
	}
	a := virtAttr()
	if virt == "" {
		if a, st = m.attr(w, ino); !st.Ok() {
			return st
		}
	}
	fillAttr(&out.Attr, in.NodeId, a)
	out.SetTimeout(fuseTTL)
	return fuse.OK
}

func (m *Mount) Readlink(cancel <-chan struct{}, h *fuse.InHeader) ([]byte, fuse.Status) {
	w, ino, virt, st := m.node(h.NodeId)
	if !st.Ok() || virt != "" {
		return nil, fuse.EINVAL
	}
	a, st := m.attr(w, ino)
	if !st.Ok() {
		return nil, st
	}
	if a.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		return nil, fuse.EINVAL
	}
	return []byte(a.Target), fuse.OK
}

func (m *Mount) Access(cancel <-chan struct{}, in *fuse.AccessIn) fuse.Status { return fuse.OK }

func (m *Mount) StatFs(cancel <-chan struct{}, h *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	*out = fuse.StatfsOut{Blocks: 1 << 40, Bfree: 1 << 40, Bavail: 1 << 40, Files: 1 << 40, Ffree: 1 << 40, Bsize: 64 << 10, NameLen: 255, Frsize: 64 << 10}
	return fuse.OK
}

// --- namespace ops: each commits on its own ---

func (m *Mount) do(w *view, op Op) (opResult, fuse.Status) {
	op.Branch, op.Node = w.b.name, m.v.node
	if op.Time == 0 {
		op.Time = time.Now().UnixNano()
	}
	_, res, err := w.b.commit(context.Background(), op)
	if err != nil {
		return opResult{}, errStatus(err)
	}
	if res[0].Errno != 0 {
		return res[0], fuse.Status(res[0].Errno)
	}
	return res[0], fuse.OK
}

func (m *Mount) create(h *fuse.InHeader, name string, mode, rdev uint32, target string, out *fuse.EntryOut) fuse.Status {
	w, ino, st := m.wnode(h.NodeId)
	if !st.Ok() {
		return st
	}
	if w == m.main && ino == rootIno && name == ".blipfs" {
		return fuse.Status(syscall.EEXIST)
	}
	r, st := m.do(w, Op{Kind: OpCreate, Parent: ino, Name: name, Mode: mode, Rdev: rdev, Target: target, Uid: h.Uid, Gid: h.Gid})
	if !st.Ok() {
		return st
	}
	return m.entry(w, r.Ino, out)
}

func (m *Mount) Mknod(cancel <-chan struct{}, in *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	return m.create(&in.InHeader, name, in.Mode, in.Rdev, "", out)
}

func (m *Mount) Mkdir(cancel <-chan struct{}, in *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	return m.create(&in.InHeader, name, in.Mode|syscall.S_IFDIR, 0, "", out)
}

func (m *Mount) Symlink(cancel <-chan struct{}, h *fuse.InHeader, target, name string, out *fuse.EntryOut) fuse.Status {
	return m.create(h, name, syscall.S_IFLNK|0o777, 0, target, out)
}

func (m *Mount) Link(cancel <-chan struct{}, in *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	w, parent, st := m.wnode(in.NodeId)
	if !st.Ok() {
		return st
	}
	w2, ino, _, st := m.node(in.Oldnodeid)
	if !st.Ok() {
		return st
	}
	if w2 != w {
		return fuse.EXDEV
	}
	if _, st := m.do(w, Op{Kind: OpLink, Ino: ino, NewParent: parent, NewName: name}); !st.Ok() {
		return st
	}
	return m.entry(w, ino, out)
}

func (m *Mount) Unlink(cancel <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	w, ino, st := m.wnode(h.NodeId)
	if !st.Ok() {
		return st
	}
	_, st = m.do(w, Op{Kind: OpUnlink, Parent: ino, Name: name})
	return st
}

func (m *Mount) Rmdir(cancel <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	w, ino, st := m.wnode(h.NodeId)
	if !st.Ok() {
		return st
	}
	_, st = m.do(w, Op{Kind: OpRmdir, Parent: ino, Name: name})
	return st
}

func (m *Mount) Rename(cancel <-chan struct{}, in *fuse.RenameIn, oldName, newName string) fuse.Status {
	w, parent, st := m.wnode(in.NodeId)
	if !st.Ok() {
		return st
	}
	w2, newParent, st := m.wnode(in.Newdir)
	if !st.Ok() {
		return st
	}
	if w2 != w {
		return fuse.EXDEV
	}
	_, st = m.do(w, Op{Kind: OpRename, Parent: parent, Name: oldName, NewParent: newParent, NewName: newName, Flags: in.Flags})
	return st
}

func (m *Mount) SetAttr(cancel <-chan struct{}, in *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	w, ino, st := m.wnode(in.NodeId)
	if !st.Ok() {
		return st
	}
	now := time.Now().UnixNano()
	op := Op{Kind: OpSetAttr, Ino: ino, Time: now}
	if in.Valid&fuse.FATTR_MODE != 0 {
		op.Valid |= SetMode
		op.Mode = in.Mode
	}
	if in.Valid&fuse.FATTR_UID != 0 {
		op.Valid |= SetUid
		op.Uid = in.Uid
	}
	if in.Valid&fuse.FATTR_GID != 0 {
		op.Valid |= SetGid
		op.Gid = in.Gid
	}
	if in.Valid&(fuse.FATTR_ATIME|fuse.FATTR_ATIME_NOW) != 0 {
		op.Valid |= SetAtime
		op.Atime = int64(in.Atime)*1e9 + int64(in.Atimensec)
		if in.Valid&fuse.FATTR_ATIME_NOW != 0 {
			op.Atime = now
		}
	}
	if in.Valid&(fuse.FATTR_MTIME|fuse.FATTR_MTIME_NOW) != 0 {
		op.Valid |= SetMtime
		op.Mtime = int64(in.Mtime)*1e9 + int64(in.Mtimensec)
		if in.Valid&fuse.FATTR_MTIME_NOW != 0 {
			op.Mtime = now
		}
	}
	if in.Valid&fuse.FATTR_SIZE != 0 {
		op.Valid |= SetSize
		op.Size = in.Size
		// truncation applies on top of the data written so far
		if err := m.commitDirty(context.Background(), dkey{w.b, ino}); err != nil {
			return errStatus(err)
		}
	}
	if op.Valid != 0 {
		if _, st := m.do(w, op); !st.Ok() {
			return st
		}
	}
	a, st := m.attr(w, ino)
	if !st.Ok() {
		return st
	}
	fillAttr(&out.Attr, in.NodeId, a)
	out.SetTimeout(fuseTTL)
	return fuse.OK
}

// --- xattrs ---

func (m *Mount) GetXAttr(cancel <-chan struct{}, h *fuse.InHeader, name string, dest []byte) (uint32, fuse.Status) {
	w, ino, virt, st := m.node(h.NodeId)
	if !st.Ok() || virt != "" {
		return 0, fuse.ENODATA
	}
	v, ok, err := w.tree().Get(xattrKey(ino, name))
	if err != nil {
		return 0, errStatus(err)
	}
	if !ok {
		return 0, fuse.ENODATA
	}
	if len(dest) == 0 {
		return uint32(len(v)), fuse.OK
	}
	if len(dest) < len(v) {
		return uint32(len(v)), fuse.ERANGE
	}
	return uint32(copy(dest, v)), fuse.OK
}

func (m *Mount) ListXAttr(cancel <-chan struct{}, h *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	w, ino, virt, st := m.node(h.NodeId)
	if !st.Ok() || virt != "" {
		return 0, fuse.OK
	}
	var b []byte
	p := xattrPrefix(ino)
	err := w.tree().AscendPrefix(p, func(k, v []byte) bool {
		b = append(append(b, k[len(p):]...), 0)
		return true
	})
	if err != nil {
		return 0, errStatus(err)
	}
	if len(dest) == 0 {
		return uint32(len(b)), fuse.OK
	}
	if len(dest) < len(b) {
		return uint32(len(b)), fuse.ERANGE
	}
	return uint32(copy(dest, b)), fuse.OK
}

func (m *Mount) SetXAttr(cancel <-chan struct{}, in *fuse.SetXAttrIn, name string, data []byte) fuse.Status {
	w, ino, st := m.wnode(in.NodeId)
	if !st.Ok() {
		return st
	}
	_, st = m.do(w, Op{Kind: OpSetXattr, Ino: ino, Name: name, XVal: slices.Clone(data), Flags: in.Flags})
	return st
}

func (m *Mount) RemoveXAttr(cancel <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	w, ino, st := m.wnode(h.NodeId)
	if !st.Ok() {
		return st
	}
	_, st = m.do(w, Op{Kind: OpRmXattr, Ino: ino, Name: name})
	return st
}

// --- directories ---

func (m *Mount) OpenDir(cancel <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	w, ino, virt, st := m.node(in.NodeId)
	if !st.Ok() {
		return st
	}
	ents := []fuse.DirEntry{{Name: ".", Mode: syscall.S_IFDIR, Ino: in.NodeId}, {Name: "..", Mode: syscall.S_IFDIR}}
	if virt != "" {
		ents = append(ents, m.virtList(virt)...)
	} else {
		if w.b != nil {
			// close-to-open applies to directory listings too
			if err := w.b.s.catchUp(context.Background(), 0); err != nil {
				return errStatus(err)
			}
		}
		t := w.tree()
		if w == m.main && ino == rootIno {
			ents = append(ents, fuse.DirEntry{Name: ".blipfs", Mode: syscall.S_IFDIR})
		}
		p := direntPrefix(ino)
		var kids []uint64
		var names []string
		err := t.AscendPrefix(p, func(k, v []byte) bool {
			names = append(names, string(k[len(p):]))
			kids = append(kids, binary.BigEndian.Uint64(v))
			return true
		})
		if err != nil {
			return errStatus(err)
		}
		for i, c := range kids {
			a, err := treeAttr(t, c)
			if err != nil {
				return errStatus(err)
			}
			mode := uint32(syscall.S_IFREG)
			if a != nil {
				mode = a.Mode
			}
			ents = append(ents, fuse.DirEntry{Name: names[i], Mode: mode, Ino: m.idFor(w, c, "")})
		}
	}
	m.mu.Lock()
	out.Fh = m.nextFh
	m.handles[m.nextFh] = &handle{w: w, ino: ino, dir: ents}
	m.nextFh++
	m.mu.Unlock()
	return fuse.OK
}

func (m *Mount) ReadDir(cancel <-chan struct{}, in *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	m.mu.Lock()
	h := m.handles[in.Fh]
	m.mu.Unlock()
	if h == nil {
		return fuse.EBADF
	}
	for i := in.Offset; i < uint64(len(h.dir)); i++ {
		e := h.dir[i]
		e.Off = i + 1
		if !out.AddDirEntry(e) {
			break
		}
	}
	return fuse.OK
}

func (m *Mount) ReleaseDir(in *fuse.ReleaseIn) {
	m.mu.Lock()
	delete(m.handles, in.Fh)
	m.mu.Unlock()
}

func (m *Mount) FsyncDir(cancel <-chan struct{}, in *fuse.FsyncIn) fuse.Status { return fuse.OK }

// --- files ---

func (m *Mount) open(w *view, ino uint64, flags uint32, out *fuse.OpenOut) fuse.Status {
	write := flags&syscall.O_ACCMODE != syscall.O_RDONLY
	if write && w.b == nil {
		return fuse.Status(syscall.EROFS)
	}
	if w.b != nil {
		// close-to-open: see every revision closed before this open
		if err := w.b.s.catchUp(context.Background(), 0); err != nil {
			return errStatus(err)
		}
	}
	a, st := m.attr(w, ino)
	if !st.Ok() {
		return st
	}
	if a.IsDir() && write {
		return fuse.Status(syscall.EISDIR)
	}
	if flags&syscall.O_TRUNC != 0 && write && a.Size > 0 {
		m.dropDirty(dkey{w.b, ino})
		if _, st := m.do(w, Op{Kind: OpSetAttr, Ino: ino, Valid: SetSize}); !st.Ok() {
			return st
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if w == m.main {
		if m.opened[ino] == a.Ver {
			out.OpenFlags |= fuse.FOPEN_KEEP_CACHE
		}
		m.opened[ino] = a.Ver
	} else if w.b == nil {
		out.OpenFlags |= fuse.FOPEN_KEEP_CACHE
	}
	out.Fh = m.nextFh
	m.handles[m.nextFh] = &handle{w: w, ino: ino, t: w.tree(), write: write}
	m.nextFh++
	if write {
		m.writers[dkey{w.b, ino}]++
	}
	return fuse.OK
}

func (m *Mount) Open(cancel <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	w, ino, virt, st := m.node(in.NodeId)
	if !st.Ok() {
		return st
	}
	if virt != "" {
		return fuse.Status(syscall.EISDIR)
	}
	return m.open(w, ino, in.Flags, out)
}

func (m *Mount) Create(cancel <-chan struct{}, in *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	if st := m.create(&in.InHeader, name, in.Mode, 0, "", &out.EntryOut); !st.Ok() {
		return st
	}
	w, ino, _, _ := m.node(out.NodeId)
	return m.open(w, ino, in.Flags&^syscall.O_TRUNC, &out.OpenOut)
}

func (m *Mount) handle(fh uint64) *handle {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handles[fh]
}

func (m *Mount) Read(cancel <-chan struct{}, in *fuse.ReadIn, buf []byte) (fuse.ReadResult, fuse.Status) {
	h := m.handle(in.Fh)
	if h == nil {
		return nil, fuse.EBADF
	}
	b, err := m.readAt(context.Background(), h, in.Offset, uint64(in.Size))
	if err != nil {
		return nil, errStatus(err)
	}
	return fuse.ReadResultData(b), fuse.OK
}

// readAt reads committed extents and overlays uncommitted writes.
func (m *Mount) readAt(ctx context.Context, h *handle, off, n uint64) ([]byte, error) {
	t := h.w.tree()
	a, err := treeAttr(t, h.ino)
	if err != nil {
		return nil, err
	}
	if a == nil {
		t = h.t // unlinked while open
		if a, err = treeAttr(t, h.ino); err != nil || a == nil {
			return nil, syscall.ESTALE
		}
	}
	size := a.Size
	var d *dirtyFile
	if h.w.b != nil {
		m.mu.Lock()
		d = m.dirty[dkey{h.w.b, h.ino}]
		m.mu.Unlock()
	}
	if d != nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.iv) > 0 {
			size = d.size
		}
	}
	if off >= size {
		return nil, nil
	}
	n = min(n, size-off)
	buf := make([]byte, n)
	if err := readExtents(ctx, m.v.chunks, t, h.ino, off, buf); err != nil {
		return nil, err
	}
	if d != nil {
		for _, iv := range d.iv {
			lo, hi := max(iv[0], off), min(iv[1], off+n)
			if lo < hi {
				if _, err := d.f.ReadAt(buf[lo-off:hi-off], int64(lo)); err != nil && err != io.EOF {
					return nil, err
				}
			}
		}
	}
	return buf, nil
}

// fileExtents calls fn for every extent of ino overlapping [off, end).
func fileExtents(t Tree, ino, off, end uint64, fn func(eoff uint64, e Extent) error) error {
	from := extentKey(ino, off)
	if k, _, ok, err := t.Floor(from); err != nil {
		return err
	} else if ok && len(k) == 17 && k[0] == kExtent && keyIno(k) == ino {
		from = k
	}
	var ferr error
	err := t.Ascend(from, func(k, v []byte) bool {
		if len(k) != 17 || k[0] != kExtent || keyIno(k) != ino {
			return false
		}
		eoff := binary.BigEndian.Uint64(k[9:])
		if eoff >= end {
			return false
		}
		e, err := decodeExtent(v)
		if err != nil {
			ferr = err
			return false
		}
		if eoff+e.Len > off {
			if ferr = fn(eoff, e); ferr != nil {
				return false
			}
		}
		return true
	})
	if err != nil {
		return err
	}
	return ferr
}

// readExtents fills buf with file bytes at off; holes read as zeros.
func readExtents(ctx context.Context, c *Chunks, t Tree, ino, off uint64, buf []byte) error {
	end := off + uint64(len(buf))
	var ps []piece
	err := fileExtents(t, ino, off, end, func(eoff uint64, e Extent) error {
		lo, hi := max(eoff, off), min(eoff+e.Len, end)
		dst := buf[lo-off : hi-off]
		rel := lo - eoff
		if e.Hash == nil {
			copy(dst, e.Data[e.Skip+rel:])
			return nil
		}
		ps = append(ps, piece{hash: e.Hash, skip: e.Skip + rel, n: hi - lo, dst: dst})
		return nil
	})
	if err != nil || len(ps) == 0 {
		return err
	}
	return c.read(ctx, ps)
}

// --- writes ---

func (m *Mount) Write(cancel <-chan struct{}, in *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	w, ino, st := m.wnode(in.NodeId)
	if !st.Ok() {
		return 0, st
	}
	k := dkey{w.b, ino}
	m.mu.Lock()
	d := m.dirty[k]
	idle := m.writers[k] == 0
	m.mu.Unlock()
	if d == nil {
		a, st := m.attr(w, ino)
		if !st.Ok() {
			return 0, st
		}
		f, err := os.CreateTemp(m.v.cfg.TmpDir, "dirty-")
		if err != nil {
			return 0, errStatus(err)
		}
		os.Remove(f.Name())
		m.mu.Lock()
		if d = m.dirty[k]; d == nil {
			d = &dirtyFile{f: f, size: a.Size, base: a.Ver}
			m.dirty[k] = d
		} else {
			f.Close()
		}
		m.mu.Unlock()
	}
	d.mu.Lock()
	if len(d.iv) == 0 {
		// size may have changed since the last commit
		if a, err := treeAttr(w.tree(), ino); err == nil && a != nil {
			d.size = a.Size
		}
	}
	_, err := d.f.WriteAt(data, int64(in.Offset))
	if err == nil {
		d.iv = addInterval(d.iv, in.Offset, in.Offset+uint64(len(data)))
		d.size = max(d.size, in.Offset+uint64(len(data)))
		d.mtime = time.Now().UnixNano()
	}
	d.mu.Unlock()
	if err != nil {
		return 0, errStatus(err)
	}
	if idle {
		// writeback after the last close (e.g. mmap): commit on our own
		go func() {
			time.Sleep(time.Second)
			if err := m.commitDirty(context.Background(), k); err != nil {
				log.Printf("background commit of inode %d: %v", ino, err)
			}
		}()
	}
	return uint32(len(data)), fuse.OK
}

// addInterval inserts [lo, hi) into a sorted list of disjoint intervals.
func addInterval(iv [][2]uint64, lo, hi uint64) [][2]uint64 {
	var out [][2]uint64
	for _, x := range iv {
		switch {
		case x[1] < lo:
			out = append(out, x)
		case x[0] > hi:
			if lo < hi {
				out = append(out, [2]uint64{lo, hi})
				lo, hi = 0, 0
			}
			out = append(out, x)
		default:
			lo, hi = min(lo, x[0]), max(hi, x[1])
		}
	}
	if lo < hi {
		out = append(out, [2]uint64{lo, hi})
	}
	return out
}

// dirtyOps chunks and uploads the dirty ranges and returns the ops that
// make them a revision.
func (m *Mount) dirtyOps(ctx context.Context, b *Branch, ino uint64, d *dirtyFile) ([]Op, error) {
	packs := map[string]bool{}
	var ents []ChunkEnt
	var ranges []Range
	for _, iv := range d.iv {
		r := io.NewSectionReader(d.f, int64(iv[0]), int64(iv[1]-iv[0]))
		err := chunkSplit(r, func(off int64, data []byte) error {
			o := iv[0] + uint64(off)
			if d.size <= inlineMax {
				ranges = append(ranges, Range{Off: o, Ext: Extent{Len: uint64(len(data)), Data: slices.Clone(data)}})
				return nil
			}
			e := m.v.chunks.upload(data, packs)
			ents = append(ents, e)
			ranges = append(ranges, Range{Off: o, Ext: Extent{Hash: e.Hash, Len: uint64(len(data))}})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := m.v.chunks.flush(ctx, packs); err != nil {
		return nil, err
	}
	var ops []Op
	if len(ents) > 0 {
		ops = append(ops, Op{Kind: OpChunkPut, Chunks: ents})
	}
	now := time.Now().UnixNano()
	ops = append(ops, Op{Kind: OpWrite, Branch: b.name, Ino: ino, BaseRev: d.base, Ranges: ranges, Time: now, Node: m.v.node})
	return ops, nil
}

// commitDirty turns the dirty ranges of an inode into one revision.
func (m *Mount) commitDirty(ctx context.Context, k dkey) error {
	m.mu.Lock()
	d := m.dirty[k]
	m.mu.Unlock()
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.iv) > 0 {
		ops, err := m.dirtyOps(ctx, k.b, k.ino, d)
		if err != nil {
			return err
		}
		for _, l := range d.stages {
			ops = append(ops, Op{Kind: OpStageDone, Branch: k.b.name, Before: l})
		}
		lsn, res, err := k.b.commit(ctx, ops...)
		if err != nil {
			return err
		}
		if e := res[len(res)-1-len(d.stages)].Errno; e != 0 && e != syscall.ENOENT {
			// ENOENT: the file was unlinked meanwhile; its data goes with it
			return e
		}
		d.iv, d.stages, d.base = nil, nil, lsn
		d.f.Truncate(0)
	}
	m.mu.Lock()
	if m.writers[k] == 0 && m.dirty[k] == d {
		delete(m.dirty, k)
		d.f.Close()
	}
	m.mu.Unlock()
	return nil
}

func (m *Mount) dropDirty(k dkey) {
	m.mu.Lock()
	d := m.dirty[k]
	delete(m.dirty, k)
	m.mu.Unlock()
	if d != nil {
		d.mu.Lock()
		d.f.Close()
		d.iv = nil
		d.mu.Unlock()
	}
}

func (m *Mount) Flush(cancel <-chan struct{}, in *fuse.FlushIn) fuse.Status {
	h := m.handle(in.Fh)
	if h == nil || h.w.b == nil {
		return fuse.OK
	}
	if err := m.commitDirty(context.Background(), dkey{h.w.b, h.ino}); err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

// Fsync makes dirty data durable as a STAGE record without making it visible.
func (m *Mount) Fsync(cancel <-chan struct{}, in *fuse.FsyncIn) fuse.Status {
	h := m.handle(in.Fh)
	if h == nil || h.w.b == nil {
		return fuse.OK
	}
	m.mu.Lock()
	d := m.dirty[dkey{h.w.b, h.ino}]
	m.mu.Unlock()
	if d == nil {
		return fuse.OK
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.iv) == 0 {
		return fuse.OK
	}
	ctx := context.Background()
	ops, err := m.dirtyOps(ctx, h.w.b, h.ino, d)
	if err != nil {
		return errStatus(err)
	}
	lsn, _, err := m.v.write(ctx, RecStage, h.w.b, ops)
	if err != nil {
		return errStatus(err)
	}
	d.stages = append(d.stages, lsn)
	return fuse.OK
}

func (m *Mount) Release(cancel <-chan struct{}, in *fuse.ReleaseIn) {
	m.mu.Lock()
	h := m.handles[in.Fh]
	delete(m.handles, in.Fh)
	if h != nil && h.write {
		m.writers[dkey{h.w.b, h.ino}]--
	}
	m.mu.Unlock()
	if h != nil && h.write {
		if err := m.commitDirty(context.Background(), dkey{h.w.b, h.ino}); err != nil {
			log.Printf("release: commit inode %d: %v", h.ino, err)
		}
	}
}
