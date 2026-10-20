package blipfs

import (
	"bytes"
	"encoding/binary"
	"sort"
	"syscall"

	"github.com/fxamacker/cbor/v2"
)

// Metadata key spaces inside a branch tree.
const (
	kInode   = 0x01 // ino -> Attr
	kDirent  = 0x02 // parent|name -> child ino
	kExtent  = 0x03 // ino|off -> Extent
	kXattr   = 0x04 // ino|name -> value
	kBackref = 0x05 // ino|parent|name -> "" (reverse dirent index)
)

const (
	rootIno     = 1
	inlineMax   = 4096
	maxExtent   = 256 << 10 // largest extent; bounds overlap scans
	createsPerL = 256       // ino = lsn<<8 | i
)

func u64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

func inodeKey(ino uint64) []byte           { return u64([]byte{kInode}, ino) }
func direntPrefix(parent uint64) []byte    { return u64([]byte{kDirent}, parent) }
func extentPrefix(ino uint64) []byte       { return u64([]byte{kExtent}, ino) }
func xattrPrefix(ino uint64) []byte        { return u64([]byte{kXattr}, ino) }
func backrefPrefix(ino uint64) []byte      { return u64([]byte{kBackref}, ino) }
func extentKey(ino, off uint64) []byte     { return u64(extentPrefix(ino), off) }
func xattrKey(ino uint64, n string) []byte { return append(xattrPrefix(ino), n...) }
func direntKey(parent uint64, name string) []byte {
	return append(direntPrefix(parent), name...)
}
func backrefKey(ino, parent uint64, name string) []byte {
	return append(u64(backrefPrefix(ino), parent), name...)
}

// keyIno returns the inode a key belongs to (for dirents: the parent).
func keyIno(k []byte) uint64 {
	if len(k) < 9 {
		return 0
	}
	return binary.BigEndian.Uint64(k[1:9])
}

// Attr is an inode. Ver is the LSN of the last change; Writer the node
// that last wrote content (for the concurrent-writer flag).
type Attr struct {
	Mode   uint32 `cbor:"1,keyasint"`
	Uid    uint32 `cbor:"2,keyasint,omitempty"`
	Gid    uint32 `cbor:"3,keyasint,omitempty"`
	Size   uint64 `cbor:"4,keyasint,omitempty"`
	Nlink  uint32 `cbor:"5,keyasint"`
	Atime  int64  `cbor:"6,keyasint,omitempty"`
	Mtime  int64  `cbor:"7,keyasint,omitempty"`
	Ctime  int64  `cbor:"8,keyasint,omitempty"`
	Rdev   uint32 `cbor:"9,keyasint,omitempty"`
	Gen    uint64 `cbor:"10,keyasint,omitempty"`
	Target string `cbor:"11,keyasint,omitempty"`
	Ver    uint64 `cbor:"12,keyasint,omitempty"`
	Writer string `cbor:"13,keyasint,omitempty"`
}

func (a *Attr) IsDir() bool { return a.Mode&syscall.S_IFMT == syscall.S_IFDIR }
func (a *Attr) IsReg() bool { return a.Mode&syscall.S_IFMT == syscall.S_IFREG }

// Extent maps file bytes [off, off+Len) to chunk Hash at Skip, or to inline Data.
type Extent struct {
	Hash []byte `cbor:"1,keyasint,omitempty"`
	Skip uint64 `cbor:"2,keyasint,omitempty"`
	Len  uint64 `cbor:"3,keyasint"`
	Data []byte `cbor:"4,keyasint,omitempty"`
}

func (e Extent) slice(skip, n uint64) Extent {
	o := Extent{Hash: e.Hash, Skip: e.Skip + skip, Len: n}
	if e.Hash == nil {
		o.Skip = 0
		o.Data = e.Data[e.Skip+skip : e.Skip+skip+n]
	}
	return o
}

// Op kinds. FS ops target Op.Branch; chunk ops target the !chunks stream.
const (
	OpCreate = iota + 1
	OpLink
	OpUnlink
	OpRmdir
	OpRename
	OpSetAttr
	OpWrite
	OpSetXattr
	OpRmXattr
	OpRaw
	OpBranchCreate
	OpBranchClose
	OpMergeStart
	OpMergeUpdate
	OpMergeLock
	OpMergeUnlock
	OpMergeDone
	OpResolve
	OpStageDone
	OpChunkPut
	OpChunkDel
	OpChunkMove
)

var opNames = map[uint8]string{
	OpCreate: "create", OpLink: "link", OpUnlink: "unlink", OpRmdir: "rmdir", OpRename: "rename",
	OpSetAttr: "setattr", OpWrite: "write", OpSetXattr: "setxattr", OpRmXattr: "rmxattr", OpRaw: "edit",
	OpBranchCreate: "branch-create", OpBranchClose: "branch-close", OpMergeStart: "merge-start",
	OpMergeUpdate: "merge-update", OpMergeLock: "merge-lock", OpMergeUnlock: "merge-unlock",
	OpMergeDone: "merge", OpResolve: "resolve", OpStageDone: "stage-done",
	OpChunkPut: "chunk-put", OpChunkDel: "chunk-del", OpChunkMove: "chunk-move",
}

// SetAttr valid bits (same values as FUSE FATTR_*).
const (
	SetMode  = 1 << 0
	SetUid   = 1 << 1
	SetGid   = 1 << 2
	SetSize  = 1 << 3
	SetAtime = 1 << 4
	SetMtime = 1 << 5
)

const (
	renameNoreplace = 1
	renameExchange  = 2
	xattrCreate     = 1
	xattrReplace    = 2
)

type Range struct {
	Off uint64 `cbor:"1,keyasint"`
	Ext Extent `cbor:"2,keyasint"`
}

// RawEdit is a key-level edit with an optional precondition on the current
// value: with Check set the key must hold Pre, or be missing if Absent.
type RawEdit struct {
	Key    []byte `cbor:"1,keyasint"`
	Val    []byte `cbor:"2,keyasint,omitempty"`
	Del    bool   `cbor:"3,keyasint,omitempty"`
	Check  bool   `cbor:"4,keyasint,omitempty"`
	Pre    []byte `cbor:"5,keyasint,omitempty"`
	Absent bool   `cbor:"6,keyasint,omitempty"`
}

type ChunkEnt struct {
	Hash []byte `cbor:"1,keyasint"`
	Pack string `cbor:"2,keyasint,omitempty"`
	Off  int64  `cbor:"3,keyasint,omitempty"`
	Len  int32  `cbor:"4,keyasint,omitempty"`
	// for ChunkMove: the location being replaced
	OldPack string `cbor:"5,keyasint,omitempty"`
	OldOff  int64  `cbor:"6,keyasint,omitempty"`
}

// MergeState describes an in-progress merge, cherry-pick or revert whose
// conflicts live in a workspace branch.
type MergeState struct {
	ID        string   `cbor:"1,keyasint"`
	Kind      string   `cbor:"2,keyasint"`
	Dst       string   `cbor:"3,keyasint"`
	DstLSN    uint64   `cbor:"4,keyasint"`
	Base      Rev      `cbor:"5,keyasint"`
	Theirs    Rev      `cbor:"6,keyasint"`
	Conflicts []string `cbor:"7,keyasint,omitempty"`
	Edge      bool     `cbor:"8,keyasint,omitempty"`
	Info      string   `cbor:"9,keyasint,omitempty"`
}

// Rev names a point in a stream's history.
type Rev struct {
	Branch string `cbor:"1,keyasint"`
	LSN    uint64 `cbor:"2,keyasint"`
}

type Op struct {
	Kind      uint8       `cbor:"1,keyasint"`
	Branch    string      `cbor:"2,keyasint,omitempty"`
	Time      int64       `cbor:"3,keyasint,omitempty"`
	Parent    uint64      `cbor:"4,keyasint,omitempty"`
	Name      string      `cbor:"5,keyasint,omitempty"`
	Ino       uint64      `cbor:"6,keyasint,omitempty"`
	NewParent uint64      `cbor:"7,keyasint,omitempty"`
	NewName   string      `cbor:"8,keyasint,omitempty"`
	Mode      uint32      `cbor:"9,keyasint,omitempty"`
	Uid       uint32      `cbor:"10,keyasint,omitempty"`
	Gid       uint32      `cbor:"11,keyasint,omitempty"`
	Rdev      uint32      `cbor:"12,keyasint,omitempty"`
	Target    string      `cbor:"13,keyasint,omitempty"`
	Flags     uint32      `cbor:"14,keyasint,omitempty"`
	Valid     uint32      `cbor:"15,keyasint,omitempty"`
	Size      uint64      `cbor:"16,keyasint,omitempty"`
	Atime     int64       `cbor:"17,keyasint,omitempty"`
	Mtime     int64       `cbor:"18,keyasint,omitempty"`
	BaseRev   uint64      `cbor:"19,keyasint,omitempty"`
	Ranges    []Range     `cbor:"20,keyasint,omitempty"`
	XVal      []byte      `cbor:"21,keyasint,omitempty"`
	Edits     []RawEdit   `cbor:"22,keyasint,omitempty"`
	Src       Rev         `cbor:"23,keyasint,omitempty"`
	Merge     *MergeState `cbor:"24,keyasint,omitempty"`
	Paths     []string    `cbor:"25,keyasint,omitempty"`
	Chunks    []ChunkEnt  `cbor:"26,keyasint,omitempty"`
	Before    uint64      `cbor:"27,keyasint,omitempty"`
	Info      string      `cbor:"28,keyasint,omitempty"`
	Node      string      `cbor:"29,keyasint,omitempty"`
}

// Body is the CBOR payload of a WAL record.
type Body struct {
	Ops []Op `cbor:"1,keyasint"`
}

func decodeBody(p []byte) (*Body, error) {
	var b Body
	if len(p) == 0 {
		return &b, nil
	}
	return &b, cbor.Unmarshal(p, &b)
}

func isChunkOp(k uint8) bool { return k == OpChunkPut || k == OpChunkDel || k == OpChunkMove }

// txn overlays pending edits on a tree while one record is applied.
type txn struct {
	base Tree
	over map[string]*[]byte // nil pointer = deleted
}

func newTxn(t Tree) *txn { return &txn{base: t, over: map[string]*[]byte{}} }

func (x *txn) get(k []byte) ([]byte, bool, error) {
	if v, ok := x.over[string(k)]; ok {
		if v == nil {
			return nil, false, nil
		}
		return *v, true, nil
	}
	return x.base.Get(k)
}

func (x *txn) put(k, v []byte) { x.over[string(k)] = &v }
func (x *txn) del(k []byte)    { x.over[string(k)] = nil }

// scan visits keys in [from, to) in order, overlay included.
func (x *txn) scan(from, to []byte, fn func(k, v []byte) bool) error {
	var ov []string
	for k := range x.over {
		if k >= string(from) && k < string(to) {
			ov = append(ov, k)
		}
	}
	sort.Strings(ov)
	stop := false
	emit := func(k string) bool {
		if v := x.over[k]; v != nil {
			return fn([]byte(k), *v)
		}
		return true
	}
	err := x.base.Ascend(from, func(k, v []byte) bool {
		if bytes.Compare(k, to) >= 0 {
			return false
		}
		for len(ov) > 0 && ov[0] < string(k) {
			if !emit(ov[0]) {
				stop = true
				return false
			}
			ov = ov[1:]
		}
		if len(ov) > 0 && ov[0] == string(k) {
			ov = ov[1:]
			if !emit(string(k)) {
				stop = true
				return false
			}
			return true
		}
		if !fn(k, v) {
			stop = true
			return false
		}
		return true
	})
	if err != nil || stop {
		return err
	}
	for _, k := range ov {
		if !emit(k) {
			break
		}
	}
	return nil
}

func prefixEnd(p []byte) []byte {
	e := append([]byte(nil), p...)
	for i := len(e) - 1; i >= 0; i-- {
		if e[i] < 0xff {
			e[i]++
			return e[:i+1]
		}
	}
	return append(p, 0xff)
}

func (x *txn) scanPrefix(p []byte, fn func(k, v []byte) bool) error {
	return x.scan(p, prefixEnd(p), fn)
}

func (x *txn) commit() (Tree, error) {
	es := make([]Edit, 0, len(x.over))
	for k, v := range x.over {
		if v == nil {
			es = append(es, Edit{Key: []byte(k), Del: true})
		} else {
			es = append(es, Edit{Key: []byte(k), Val: *v})
		}
	}
	return x.base.Mutate(es)
}

func (x *txn) attr(ino uint64) (*Attr, error) {
	v, ok, err := x.get(inodeKey(ino))
	if err != nil || !ok {
		return nil, err
	}
	var a Attr
	return &a, cbor.Unmarshal(v, &a)
}

func (x *txn) putAttr(ino uint64, a *Attr) { x.put(inodeKey(ino), mustCBOR(a)) }

func (x *txn) lookup(parent uint64, name string) (uint64, bool, error) {
	v, ok, err := x.get(direntKey(parent, name))
	if err != nil || !ok {
		return 0, false, err
	}
	return binary.BigEndian.Uint64(v), true, nil
}

func (x *txn) hasChildren(ino uint64) (bool, error) {
	found := false
	err := x.scanPrefix(direntPrefix(ino), func(k, v []byte) bool { found = true; return false })
	return found, err
}

// opResult is what replay decided for one op; identical on every replica.
type opResult struct {
	Errno syscall.Errno
	Ino   uint64
}

type applyCtx struct {
	lsn        uint64
	node       string
	creates    int
	concurrent bool
}

func errnoOf(err error) syscall.Errno {
	if e, ok := err.(syscall.Errno); ok {
		return e
	}
	return syscall.EIO
}

// applyFS applies one filesystem op. All checks happen before any edit so a
// failed op leaves the txn untouched.
func applyFS(x *txn, c *applyCtx, op *Op) (opResult, error) {
	switch op.Kind {
	case OpCreate:
		pa, err := x.attr(op.Parent)
		if err != nil {
			return opResult{}, err
		}
		if pa == nil {
			return opResult{Errno: syscall.ENOENT}, nil
		}
		if !pa.IsDir() {
			return opResult{Errno: syscall.ENOTDIR}, nil
		}
		if _, ok, err := x.lookup(op.Parent, op.Name); err != nil || ok {
			return opResult{Errno: syscall.EEXIST}, err
		}
		if c.creates >= createsPerL {
			return opResult{Errno: syscall.EAGAIN}, nil
		}
		ino := c.lsn<<8 | uint64(c.creates)
		c.creates++
		a := &Attr{Mode: op.Mode, Uid: op.Uid, Gid: op.Gid, Nlink: 1, Atime: op.Time, Mtime: op.Time, Ctime: op.Time, Rdev: op.Rdev, Target: op.Target, Gen: c.lsn, Ver: c.lsn}
		if op.Target != "" {
			a.Size = uint64(len(op.Target))
		}
		x.putAttr(ino, a)
		x.put(direntKey(op.Parent, op.Name), u64(nil, ino))
		x.put(backrefKey(ino, op.Parent, op.Name), nil)
		touchDir(x, op.Parent, pa, op.Time, c.lsn)
		return opResult{Ino: ino}, nil

	case OpLink:
		a, err := x.attr(op.Ino)
		if err != nil || a == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		if a.IsDir() {
			return opResult{Errno: syscall.EPERM}, nil
		}
		pa, err := x.attr(op.NewParent)
		if err != nil || pa == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		if !pa.IsDir() {
			return opResult{Errno: syscall.ENOTDIR}, nil
		}
		if _, ok, err := x.lookup(op.NewParent, op.NewName); err != nil || ok {
			return opResult{Errno: syscall.EEXIST}, err
		}
		a.Nlink++
		a.Ctime, a.Ver = op.Time, c.lsn
		x.putAttr(op.Ino, a)
		x.put(direntKey(op.NewParent, op.NewName), u64(nil, op.Ino))
		x.put(backrefKey(op.Ino, op.NewParent, op.NewName), nil)
		touchDir(x, op.NewParent, pa, op.Time, c.lsn)
		return opResult{Ino: op.Ino}, nil

	case OpUnlink, OpRmdir:
		ino, ok, err := x.lookup(op.Parent, op.Name)
		if err != nil || !ok {
			return opResult{Errno: syscall.ENOENT}, err
		}
		a, err := x.attr(ino)
		if err != nil || a == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		if op.Kind == OpUnlink && a.IsDir() {
			return opResult{Errno: syscall.EISDIR}, nil
		}
		if op.Kind == OpRmdir {
			if !a.IsDir() {
				return opResult{Errno: syscall.ENOTDIR}, nil
			}
			if has, err := x.hasChildren(ino); err != nil || has {
				return opResult{Errno: syscall.ENOTEMPTY}, err
			}
		}
		if err := unlinkIno(x, ino, a, op.Parent, op.Name, op.Time, c.lsn); err != nil {
			return opResult{}, err
		}
		if pa, err := x.attr(op.Parent); err == nil && pa != nil {
			touchDir(x, op.Parent, pa, op.Time, c.lsn)
		}
		return opResult{Ino: ino}, nil

	case OpRename:
		return applyRename(x, c, op)

	case OpSetAttr:
		a, err := x.attr(op.Ino)
		if err != nil || a == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		if op.Valid&SetSize != 0 {
			if !a.IsReg() {
				return opResult{Errno: syscall.EINVAL}, nil
			}
			if err := truncateExtents(x, op.Ino, op.Size); err != nil {
				return opResult{}, err
			}
			a.Size = op.Size
			a.Mtime = op.Time
		}
		if op.Valid&SetMode != 0 {
			a.Mode = a.Mode&syscall.S_IFMT | op.Mode&^uint32(syscall.S_IFMT)
		}
		if op.Valid&SetUid != 0 {
			a.Uid = op.Uid
		}
		if op.Valid&SetGid != 0 {
			a.Gid = op.Gid
		}
		if op.Valid&SetAtime != 0 {
			a.Atime = op.Atime
		}
		if op.Valid&SetMtime != 0 {
			a.Mtime = op.Mtime
		}
		a.Ctime = op.Time
		if op.Valid&SetSize != 0 {
			// Ver tracks content only, so metadata updates (e.g. the kernel
			// setting mtime before a flush) don't look like concurrent writes.
			a.Ver, a.Writer = c.lsn, op.Node
		}
		x.putAttr(op.Ino, a)
		return opResult{Ino: op.Ino}, nil

	case OpWrite:
		a, err := x.attr(op.Ino)
		if err != nil || a == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		if !a.IsReg() {
			return opResult{Errno: syscall.EINVAL}, nil
		}
		if op.BaseRev < a.Ver && a.Writer != "" && a.Writer != op.Node {
			c.concurrent = true
		}
		for _, r := range op.Ranges {
			if err := trimExtents(x, op.Ino, r.Off, r.Off+r.Ext.Len); err != nil {
				return opResult{}, err
			}
			x.put(extentKey(op.Ino, r.Off), mustCBOR(r.Ext))
			a.Size = max(a.Size, r.Off+r.Ext.Len)
		}
		if op.Valid&SetSize != 0 {
			if err := truncateExtents(x, op.Ino, op.Size); err != nil {
				return opResult{}, err
			}
			a.Size = op.Size
		}
		a.Mtime, a.Ctime, a.Ver, a.Writer = op.Time, op.Time, c.lsn, op.Node
		x.putAttr(op.Ino, a)
		return opResult{Ino: op.Ino}, nil

	case OpSetXattr, OpRmXattr:
		a, err := x.attr(op.Ino)
		if err != nil || a == nil {
			return opResult{Errno: syscall.ENOENT}, err
		}
		k := xattrKey(op.Ino, op.Name)
		_, exists, err := x.get(k)
		if err != nil {
			return opResult{}, err
		}
		if op.Kind == OpRmXattr {
			if !exists {
				return opResult{Errno: syscall.ENODATA}, nil
			}
			x.del(k)
		} else {
			if op.Flags&xattrCreate != 0 && exists {
				return opResult{Errno: syscall.EEXIST}, nil
			}
			if op.Flags&xattrReplace != 0 && !exists {
				return opResult{Errno: syscall.ENODATA}, nil
			}
			x.put(k, op.XVal)
		}
		a.Ctime, a.Ver = op.Time, c.lsn
		x.putAttr(op.Ino, a)
		return opResult{Ino: op.Ino}, nil

	case OpRaw, OpMergeDone, OpMergeStart, OpMergeUpdate:
		for _, e := range op.Edits {
			if !e.Check {
				continue
			}
			v, ok, err := x.get(e.Key)
			if err != nil {
				return opResult{}, err
			}
			if ok == e.Absent || ok && !bytes.Equal(v, e.Pre) {
				return opResult{Errno: syscall.ESTALE}, nil
			}
		}
		for _, e := range op.Edits {
			if e.Del {
				x.del(e.Key)
			} else {
				x.put(e.Key, e.Val)
			}
		}
		return opResult{}, nil
	}
	return opResult{Errno: syscall.ENOSYS}, nil
}

func touchDir(x *txn, ino uint64, a *Attr, t int64, lsn uint64) {
	a.Mtime, a.Ctime, a.Ver = t, t, lsn
	x.putAttr(ino, a)
}

// unlinkIno removes one name of ino and frees the inode when unreferenced.
func unlinkIno(x *txn, ino uint64, a *Attr, parent uint64, name string, t int64, lsn uint64) error {
	x.del(direntKey(parent, name))
	x.del(backrefKey(ino, parent, name))
	if a.Nlink > 0 {
		a.Nlink--
	}
	if !a.IsDir() && a.Nlink > 0 {
		a.Ctime, a.Ver = t, lsn
		x.putAttr(ino, a)
		return nil
	}
	x.del(inodeKey(ino))
	for _, p := range [][]byte{extentPrefix(ino), xattrPrefix(ino), backrefPrefix(ino)} {
		var ks [][]byte
		if err := x.scanPrefix(p, func(k, v []byte) bool { ks = append(ks, k); return true }); err != nil {
			return err
		}
		for _, k := range ks {
			x.del(k)
		}
	}
	return nil
}

func applyRename(x *txn, c *applyCtx, op *Op) (opResult, error) {
	if op.Flags&renameExchange != 0 {
		return opResult{Errno: syscall.EINVAL}, nil
	}
	src, ok, err := x.lookup(op.Parent, op.Name)
	if err != nil || !ok {
		return opResult{Errno: syscall.ENOENT}, err
	}
	sa, err := x.attr(src)
	if err != nil || sa == nil {
		return opResult{Errno: syscall.ENOENT}, err
	}
	npa, err := x.attr(op.NewParent)
	if err != nil || npa == nil {
		return opResult{Errno: syscall.ENOENT}, err
	}
	if !npa.IsDir() {
		return opResult{Errno: syscall.ENOTDIR}, nil
	}
	if op.Parent == op.NewParent && op.Name == op.NewName {
		return opResult{Ino: src}, nil
	}
	dst, exists, err := x.lookup(op.NewParent, op.NewName)
	if err != nil {
		return opResult{}, err
	}
	var da *Attr
	if exists {
		if op.Flags&renameNoreplace != 0 {
			return opResult{Errno: syscall.EEXIST}, nil
		}
		if dst == src {
			return opResult{Ino: src}, nil
		}
		if da, err = x.attr(dst); err != nil || da == nil {
			return opResult{Errno: syscall.EIO}, err
		}
		if sa.IsDir() && !da.IsDir() {
			return opResult{Errno: syscall.ENOTDIR}, nil
		}
		if !sa.IsDir() && da.IsDir() {
			return opResult{Errno: syscall.EISDIR}, nil
		}
		if da.IsDir() {
			if has, err := x.hasChildren(dst); err != nil || has {
				return opResult{Errno: syscall.ENOTEMPTY}, err
			}
		}
	}
	if sa.IsDir() {
		// refuse to move a directory under itself
		for p := op.NewParent; p != rootIno; {
			if p == src {
				return opResult{Errno: syscall.EINVAL}, nil
			}
			var next uint64
			found := false
			if err := x.scanPrefix(backrefPrefix(p), func(k, v []byte) bool {
				next, found = binary.BigEndian.Uint64(k[9:17]), true
				return false
			}); err != nil {
				return opResult{}, err
			}
			if !found {
				break
			}
			p = next
		}
	}
	if exists {
		if err := unlinkIno(x, dst, da, op.NewParent, op.NewName, op.Time, c.lsn); err != nil {
			return opResult{}, err
		}
	}
	x.del(direntKey(op.Parent, op.Name))
	x.del(backrefKey(src, op.Parent, op.Name))
	x.put(direntKey(op.NewParent, op.NewName), u64(nil, src))
	x.put(backrefKey(src, op.NewParent, op.NewName), nil)
	sa.Ctime, sa.Ver = op.Time, c.lsn
	x.putAttr(src, sa)
	if pa, err := x.attr(op.Parent); err == nil && pa != nil {
		touchDir(x, op.Parent, pa, op.Time, c.lsn)
	}
	if npa, err = x.attr(op.NewParent); err == nil && npa != nil {
		touchDir(x, op.NewParent, npa, op.Time, c.lsn)
	}
	return opResult{Ino: src}, nil
}

func decodeExtent(v []byte) (Extent, error) {
	var e Extent
	return e, cbor.Unmarshal(v, &e)
}

// trimExtents cuts [lo, hi) out of the file's extents.
func trimExtents(x *txn, ino, lo, hi uint64) error {
	from := uint64(0)
	if lo > maxExtent {
		from = lo - maxExtent
	}
	type ent struct {
		off uint64
		e   Extent
	}
	var hits []ent
	err := x.scan(extentKey(ino, from), extentKey(ino, hi), func(k, v []byte) bool {
		off := binary.BigEndian.Uint64(k[9:])
		e, err := decodeExtent(v)
		if err == nil && off+e.Len > lo {
			hits = append(hits, ent{off, e})
		}
		return true
	})
	if err != nil {
		return err
	}
	for _, h := range hits {
		x.del(extentKey(ino, h.off))
		if h.off < lo {
			x.put(extentKey(ino, h.off), mustCBOR(h.e.slice(0, lo-h.off)))
		}
		if end := h.off + h.e.Len; end > hi {
			x.put(extentKey(ino, hi), mustCBOR(h.e.slice(hi-h.off, end-hi)))
		}
	}
	return nil
}

func truncateExtents(x *txn, ino, size uint64) error {
	return trimExtents(x, ino, size, 1<<63)
}

// initTree builds the tree of a brand-new volume: an empty root directory.
// The root belongs to the user that created the volume.
func initTree(t int64, uid, gid uint32) (Tree, error) {
	a := &Attr{Mode: syscall.S_IFDIR | 0o755, Uid: uid, Gid: gid, Nlink: 1, Atime: t, Mtime: t, Ctime: t}
	return Tree{}.Mutate([]Edit{{Key: inodeKey(rootIno), Val: mustCBOR(a)}})
}

// Path helpers over a txn view of a tree.

func treeAttr(t Tree, ino uint64) (*Attr, error) { return newTxn(t).attr(ino) }

func treeLookup(t Tree, parent uint64, name string) (uint64, bool, error) {
	return newTxn(t).lookup(parent, name)
}

// pathOf returns one path of ino ("" if unreachable).
func pathOf(t Tree, ino uint64) (string, error) {
	var parts []string
	for ino != rootIno {
		var parent uint64
		var name string
		found := false
		err := t.AscendPrefix(backrefPrefix(ino), func(k, v []byte) bool {
			parent, name, found = binary.BigEndian.Uint64(k[9:17]), string(k[17:]), true
			return false
		})
		if err != nil {
			return "", err
		}
		if !found || len(parts) > 4096 {
			return "", nil
		}
		parts = append(parts, name)
		ino = parent
	}
	p := ""
	for i := len(parts) - 1; i >= 0; i-- {
		p += "/" + parts[i]
	}
	if p == "" {
		p = "/"
	}
	return p, nil
}

// resolvePath walks a slash-separated path from the root.
func resolvePath(t Tree, p string) (uint64, error) {
	ino := uint64(rootIno)
	for _, part := range bytes.Split([]byte(p), []byte("/")) {
		if len(part) == 0 || string(part) == "." {
			continue
		}
		c, ok, err := treeLookup(t, ino, string(part))
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, syscall.ENOENT
		}
		ino = c
	}
	return ino, nil
}
