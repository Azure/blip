package blipfs

import (
	"bytes"
	"syscall"
	"testing"
)

func TestRecordRoundTrip(t *testing.T) {
	r := &Record{Epoch: 3, LSN: 77, Type: RecCommit, Streams: []string{"b/main", "!chunks"}, Backptrs: []uint64{70, 12}, Node: "h/1", Payload: []byte("hello")}
	b := r.Encode()
	got, n, err := DecodeRecord(append(b, make([]byte, 100)...))
	if err != nil || n != len(b) {
		t.Fatalf("decode: %v n=%d", err, n)
	}
	if got.Epoch != 3 || got.LSN != 77 || got.Type != RecCommit || got.Node != "h/1" || !bytes.Equal(got.Payload, r.Payload) {
		t.Fatalf("mismatch: %+v", got)
	}
	if l, ok := got.Back("!chunks"); !ok || l != 12 {
		t.Fatal("backptr")
	}
	b[len(b)-6] ^= 1
	if _, _, err := DecodeRecord(b); err == nil {
		t.Fatal("corruption not detected")
	}
}

type fsT struct {
	t    *testing.T
	tree Tree
	lsn  uint64
}

func (f *fsT) do(op Op) opResult {
	f.t.Helper()
	f.lsn++
	x := newTxn(f.tree)
	op.Time = int64(f.lsn)
	op.Node = "n"
	res, err := applyFS(x, &applyCtx{lsn: f.lsn, node: "n"}, &op)
	if err != nil {
		f.t.Fatal(err)
	}
	if f.tree, err = x.commit(); err != nil {
		f.t.Fatal(err)
	}
	return res
}

func (f *fsT) ok(op Op) uint64 {
	f.t.Helper()
	r := f.do(op)
	if r.Errno != 0 {
		f.t.Fatalf("op %s: %v", opNames[op.Kind], r.Errno)
	}
	return r.Ino
}

func TestApplyFS(t *testing.T) {
	tr, err := initTree(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := &fsT{t: t, tree: tr, lsn: 1}
	dir := f.ok(Op{Kind: OpCreate, Parent: rootIno, Name: "d", Mode: syscall.S_IFDIR | 0o755})
	file := f.ok(Op{Kind: OpCreate, Parent: dir, Name: "f", Mode: syscall.S_IFREG | 0o644})
	if r := f.do(Op{Kind: OpCreate, Parent: dir, Name: "f", Mode: syscall.S_IFREG | 0o644}); r.Errno != syscall.EEXIST {
		t.Fatalf("duplicate create: %v", r.Errno)
	}
	f.ok(Op{Kind: OpWrite, Ino: file, Ranges: []Range{{Off: 0, Ext: Extent{Len: 5, Data: []byte("hello")}}}})
	f.ok(Op{Kind: OpWrite, Ino: file, Ranges: []Range{{Off: 3, Ext: Extent{Len: 4, Data: []byte("p me")}}}})
	a, _ := treeAttr(f.tree, file)
	if a.Size != 7 {
		t.Fatalf("size %d", a.Size)
	}
	buf := make([]byte, 7)
	if err := readExtents(t.Context(), nil, f.tree, file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "help me" {
		t.Fatalf("content %q", buf)
	}
	if p, _ := pathOf(f.tree, file); p != "d/f" && p != "/d/f" {
		t.Fatalf("path %q", p)
	}
	f.ok(Op{Kind: OpLink, Ino: file, NewParent: rootIno, NewName: "g"})
	if a, _ := treeAttr(f.tree, file); a.Nlink != 2 {
		t.Fatalf("nlink %d", a.Nlink)
	}
	if r := f.do(Op{Kind: OpRmdir, Parent: rootIno, Name: "d"}); r.Errno != syscall.ENOTEMPTY {
		t.Fatalf("rmdir non-empty: %v", r.Errno)
	}
	f.ok(Op{Kind: OpRename, Parent: dir, Name: "f", NewParent: rootIno, NewName: "h"})
	if r := f.do(Op{Kind: OpRename, Parent: rootIno, Name: "h", NewParent: rootIno, NewName: "g", Flags: renameNoreplace}); r.Errno != syscall.EEXIST {
		t.Fatalf("noreplace: %v", r.Errno)
	}
	if r := f.do(Op{Kind: OpRename, Parent: rootIno, Name: "d", NewParent: dir, NewName: "x"}); r.Errno != syscall.EINVAL {
		t.Fatalf("rename into self: %v", r.Errno)
	}
	f.ok(Op{Kind: OpRmdir, Parent: rootIno, Name: "d"})
	f.ok(Op{Kind: OpUnlink, Parent: rootIno, Name: "g"})
	f.ok(Op{Kind: OpSetAttr, Ino: file, Valid: SetSize, Size: 2})
	if a, _ := treeAttr(f.tree, file); a.Size != 2 || a.Nlink != 1 {
		t.Fatalf("after truncate: %+v", a)
	}
	f.ok(Op{Kind: OpUnlink, Parent: rootIno, Name: "h"})
	if a, _ := treeAttr(f.tree, file); a != nil {
		t.Fatal("inode should be gone")
	}
	// Only the root inode remains.
	n := 0
	f.tree.Ascend(nil, func(k, v []byte) bool { n++; return true })
	if n != 1 {
		t.Fatalf("%d keys left", n)
	}
}

func TestGaps(t *testing.T) {
	used := [][2]int64{{10, 20}, {15, 30}, {40, 50}}
	got := gaps(0, 60, used)
	want := [][2]int64{{0, 10}, {30, 40}, {50, 60}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
	if g := gaps(12, 18, used); len(g) != 0 {
		t.Fatalf("%v", g)
	}
}
