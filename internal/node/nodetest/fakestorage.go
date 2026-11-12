// Package nodetest has test doubles for the node daemon (internal/node).
// It does not import the node package, so the node's own tests can use
// it.
package nodetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/example/blip/internal/api"
	ns "github.com/example/blip/internal/node/nodestorage"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
	"github.com/example/blip/internal/storage/extent"
)

// FakeStorage is an in-memory nodestorage.Storage. It keeps contents,
// exports and compute attachments in maps and creates no devices. Slot
// disks are empty regular files under Dir, or /dev/null when Dir is
// empty. Local snapshots and received contents are files of at most
// 1 MiB under Dir (a temporary directory when Dir is empty), so
// WriteSnapshot between fake nodes in one process moves real bytes: a
// local snapshot of seq s has its first 4 KiB filled with byte s and its
// delta is the first 64 KiB. Read-write exports are found through a
// process-wide registry by subsystem NQN. Scrub hashes depend only on
// the content ID and the chunks marked with Corrupt, so replicas agree
// unless a test corrupts one.
type FakeStorage struct {
	Node    string
	Address string
	Port    uint32
	Dir     string
	// DisksPerSlot is the number of slot disks. Default 8.
	DisksPerSlot int

	mu       sync.Mutex
	HostNQN  string
	HostPSK  []byte
	contents map[string]*pb.ContentInfo
	exports  map[string]fakeExport          // key content/host
	allocs   map[string]map[string]*fakeAtt // allocation -> attachment
	slots    map[string][]string            // slot -> disk -> "alloc/att" or ""
	tmp      string
	Calls    []string
	// unknown are thin IDs reported as StorageState.UnknownThins until
	// DeleteThins removes them. deleted lists the removed ones.
	unknown []uint32
	deleted []uint32
	// FailNext makes the next call of the named method fail with this
	// error. Set it with FailNextCall while the storage is in use.
	FailNext map[string]error

	origins    map[string]string         // content -> base or parent content
	corrupt    map[string]map[int64]byte // content -> chunk -> value
	failWrites map[string]bool           // target node -> fail WriteSnapshot
	capacity   *pb.StorageCapacity
}

type fakeAtt struct {
	spec  ns.VolumeSpec
	snaps map[int64]string // seq -> file
}

// NewFakeStorage returns an empty FakeStorage.
func NewFakeStorage(node, dir string) *FakeStorage {
	return &FakeStorage{
		Node: node, Address: "127.0.0.1", Port: 4420, Dir: dir, DisksPerSlot: storage.DefaultDisksPerSlot,
		contents: map[string]*pb.ContentInfo{},
		exports:  map[string]fakeExport{},
		allocs:   map[string]map[string]*fakeAtt{},
		slots:    map[string][]string{},
		FailNext: map[string]error{},
		origins:  map[string]string{}, corrupt: map[string]map[int64]byte{}, failWrites: map[string]bool{},
	}
}

// SetUnknownThins sets the thin IDs State reports as unknown.
func (f *FakeStorage) SetUnknownThins(ids ...uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unknown = ids
}

// DeletedThins returns the thin IDs DeleteThins removed, in order.
func (f *FakeStorage) DeletedThins() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.deleted...)
}

// FailNextCall makes the next call of the named method fail with err.
func (f *FakeStorage) FailNextCall(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.FailNext[name] = err
}

// FailWritesTo makes WriteSnapshot fail for targets on node.
func (f *FakeStorage) FailWritesTo(node string, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fail {
		f.failWrites[node] = true
	} else {
		delete(f.failWrites, node)
	}
}

// Content returns a copy of a content, or nil.
func (f *FakeStorage) Content(id string) *pb.ContentInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.contents[id]; c != nil {
		return proto.Clone(c).(*pb.ContentInfo)
	}
	return nil
}

// Origin returns the content a content was made from (the base of a
// received snapshot or the parent of a clone), or "".
func (f *FakeStorage) Origin(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.origins[id]
}

// PutContent adds a content as is (test setup, for example orphans).
func (f *FakeStorage) PutContent(ci *pb.ContentInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contents[ci.ContentId] = proto.Clone(ci).(*pb.ContentInfo)
}

// DropContent removes a content (a lost replica).
func (f *FakeStorage) DropContent(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.contents, id)
}

// Corrupt changes the scrub hash of a chunk of a content.
func (f *FakeStorage) Corrupt(id string, chunk int64) { f.CorruptWith(id, chunk, 1) }

// CorruptWith changes the scrub hash of a chunk; replicas with different
// values disagree.
func (f *FakeStorage) CorruptWith(id string, chunk int64, v byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.corrupt[id] == nil {
		f.corrupt[id] = map[int64]byte{}
	}
	f.corrupt[id][chunk] = v
}

// Repaired clears the corruption of a content.
func (f *FakeStorage) Repaired(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.corrupt, id)
}

// SetCapacity sets the storage capacity Capacity reports. LvCount is
// always the number of contents.
func (f *FakeStorage) SetCapacity(c *pb.StorageCapacity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.capacity = proto.Clone(c).(*pb.StorageCapacity)
}

// Reboot drops the compute state (attachments, local snapshots, slot
// disk mappings), as a host reboot does. Contents stay.
func (f *FakeStorage) Reboot() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, atts := range f.allocs {
		for att := range atts {
			f.releaseLocked(id, att)
		}
	}
	f.slots = map[string][]string{}
}

// fileDir is where snapshot and content files go. f.mu is held.
func (f *FakeStorage) fileDir() (string, error) {
	if f.Dir != "" {
		return f.Dir, nil
	}
	if f.tmp == "" {
		d, err := os.MkdirTemp("", "blip-fake-storage-")
		if err != nil {
			return "", err
		}
		f.tmp = d
	}
	return f.tmp, nil
}

func (f *FakeStorage) call(name string) error {
	f.Calls = append(f.Calls, name)
	if err, ok := f.FailNext[name]; ok {
		delete(f.FailNext, name)
		return err
	}
	return nil
}

// CallCount returns how often the named method was called.
func (f *FakeStorage) CallCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == name {
			n++
		}
	}
	return n
}

// AddContent adds a sealed content, for tests.
func (f *FakeStorage) AddContent(id string, size int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contents[id] = &pb.ContentInfo{ContentId: id, Kind: pb.ContentKind_CONTENT_KIND_ROOT, Sealed: true, SizeBytes: size}
}

func (f *FakeStorage) SetHostKey(_ context.Context, hostNQN string, psk []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("SetHostKey"); err != nil {
		return err
	}
	f.HostNQN, f.HostPSK = hostNQN, append([]byte(nil), psk...)
	return nil
}

func (f *FakeStorage) Export(_ context.Context, c *pb.Export) (*pb.ExportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Export"); err != nil {
		return nil, err
	}
	ci, ok := f.contents[c.ContentId]
	if !ok {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "content %s not found", c.ContentId)
	}
	if c.Mode == pb.ExportMode_EXPORT_MODE_READ_WRITE && ci.Sealed && !c.RepairSealed {
		return nil, fmt.Errorf("content %s is sealed", c.ContentId)
	}
	path := &pb.Path{Node: f.Node, SubsystemNqn: api.SubsystemNQN(f.Node, api.LVName(c.ContentId)), Address: f.Address, Port: f.Port}
	f.exports[c.ContentId+"/"+c.HostNqn] = fakeExport{ContentId: c.ContentId, HostNqn: c.HostNqn}
	if c.Mode == pb.ExportMode_EXPORT_MODE_READ_WRITE {
		dir, err := f.fileDir()
		if err != nil {
			return nil, err
		}
		fakeTargets.Store(path.SubsystemNqn, filepath.Join(dir, "content-"+c.ContentId))
	}
	return &pb.ExportResult{Path: path}, nil
}

// fakeTargets maps the subsystem NQN of fake read-write exports to the
// content file, for WriteSnapshot.
var fakeTargets sync.Map

// fakeExport is one export of a content to a host.
type fakeExport struct{ ContentId, HostNqn string }

func (f *FakeStorage) Unexport(_ context.Context, c *pb.Unexport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Unexport"); err != nil {
		return err
	}
	for k, e := range f.exports {
		if e.ContentId == c.ContentId && (c.HostNqn == "" || c.HostNqn == e.HostNqn) {
			delete(f.exports, k)
			fakeTargets.Delete(api.SubsystemNQN(f.Node, api.LVName(c.ContentId)))
		}
	}
	return nil
}

func (f *FakeStorage) Seal(_ context.Context, c *pb.Seal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Seal"); err != nil {
		return err
	}
	ci, ok := f.contents[c.ContentId]
	if !ok {
		return ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "content %s not found", c.ContentId)
	}
	for _, e := range f.exports {
		if e.ContentId == c.ContentId {
			return fmt.Errorf("content %s is exported", c.ContentId)
		}
	}
	ci.Sealed = true
	return nil
}

func (f *FakeStorage) DeleteContent(_ context.Context, c *pb.DeleteContent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("DeleteContent"); err != nil {
		return err
	}
	dir, _ := f.fileDir()
	for _, id := range c.ContentIds {
		os.Remove(filepath.Join(dir, "content-"+id))
		fakeTargets.Delete(api.SubsystemNQN(f.Node, api.LVName(id)))
		for k, e := range f.exports {
			if e.ContentId == id {
				delete(f.exports, k)
			}
		}
		delete(f.contents, id)
		delete(f.origins, id)
	}
	return nil
}

func (f *FakeStorage) CreateContent(_ context.Context, c *pb.CreateContent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("CreateContent"); err != nil {
		return err
	}
	if _, ok := f.contents[c.ContentId]; !ok {
		f.contents[c.ContentId] = &pb.ContentInfo{ContentId: c.ContentId, Kind: c.Kind, SizeBytes: c.SizeBytes}
	}
	return nil
}

func targetsOK(ts []*pb.Path) []*pb.TargetResult {
	var r []*pb.TargetResult
	for _, t := range ts {
		r = append(r, &pb.TargetResult{Node: t.Node, Ok: true})
	}
	return r
}

func (f *FakeStorage) Import(_ context.Context, c *pb.Import) (*pb.ImportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Import"); err != nil {
		return nil, err
	}
	if _, ok := f.contents[c.ContentId]; !ok {
		f.contents[c.ContentId] = &pb.ContentInfo{ContentId: c.ContentId, Kind: pb.ContentKind_CONTENT_KIND_ROOT, SizeBytes: c.SizeBytes}
	}
	digest := ""
	if c.ImageReference != "" {
		digest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(c.ImageReference)))
	}
	return &pb.ImportResult{ImageDigest: digest, SizeBytes: c.SizeBytes, Targets: targetsOK(c.Targets)}, nil
}

func (f *FakeStorage) Clone(_ context.Context, c *pb.Clone) (*pb.CopyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Clone"); err != nil {
		return nil, err
	}
	p, ok := f.contents[c.ParentContentId]
	if !ok {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "parent %s not found", c.ParentContentId)
	}
	if c.Mode == pb.CloneMode_CLONE_MODE_SNAPSHOT {
		if _, ok := f.contents[c.ContentId]; !ok {
			f.contents[c.ContentId] = &pb.ContentInfo{ContentId: c.ContentId, Kind: pb.ContentKind_CONTENT_KIND_CLONE, SizeBytes: p.SizeBytes}
			f.origins[c.ContentId] = c.ParentContentId
		}
		return &pb.CopyResult{}, nil
	}
	return &pb.CopyResult{BytesCopied: p.SizeBytes, Targets: targetsOK(c.Targets)}, nil
}

func (f *FakeStorage) Repair(_ context.Context, c *pb.Repair) (*pb.CopyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Repair"); err != nil {
		return nil, err
	}
	if _, ok := f.contents[c.ContentId]; !ok {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "content %s not found", c.ContentId)
	}
	return &pb.CopyResult{Targets: targetsOK([]*pb.Path{c.Target})}, nil
}

func (f *FakeStorage) Scrub(_ context.Context, c *pb.Scrub) (*pb.ScrubResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("Scrub"); err != nil {
		return nil, err
	}
	ci, ok := f.contents[c.ContentId]
	if !ok {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "content %s not found", c.ContentId)
	}
	per := max(c.BlocksPerHash, 1)
	end := (ci.SizeBytes + api.DefaultChunkBytes - 1) / api.DefaultChunkBytes
	if c.ChunkCount > 0 && c.StartChunk+c.ChunkCount < end {
		end = c.StartChunk + c.ChunkCount
	}
	res := &pb.ScrubResult{StartChunk: c.StartChunk, BlocksPerHash: c.BlocksPerHash}
	for start := c.StartChunk; start < end; start += per {
		h := sha256.New()
		h.Write([]byte(c.ContentId))
		for ch := start; ch < min(start+per, end); ch++ {
			var b [9]byte
			binary.LittleEndian.PutUint64(b[:], uint64(ch))
			b[8] = f.corrupt[c.ContentId][ch]
			h.Write(b[:])
		}
		res.Hashes = append(res.Hashes, h.Sum(nil))
	}
	return res, nil
}

func (f *FakeStorage) PrepareReceive(_ context.Context, r ns.ReceiveSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("PrepareReceive"); err != nil {
		return err
	}
	if c, ok := f.contents[r.ContentID]; ok && c.Sealed {
		return fmt.Errorf("receive %s: %w", r.ContentID, storage.ErrSealed)
	}
	dir, err := f.fileDir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, "content-"+r.ContentID)
	if _, ok := f.contents[r.ContentID]; ok && exists(p) {
		return nil
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return err
	}
	if r.BaseContentID != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "content-"+r.BaseContentID)); err == nil {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				return err
			}
		}
	}
	if err := os.Truncate(p, fileSize(r.SizeBytes)); err != nil {
		return err
	}
	f.contents[r.ContentID] = &pb.ContentInfo{ContentId: r.ContentID, Kind: pb.ContentKind_CONTENT_KIND_SNAPSHOT, SizeBytes: r.SizeBytes}
	f.origins[r.ContentID] = r.BaseContentID
	return nil
}

// ContentPath returns the file of a received content, for tests.
func (f *FakeStorage) ContentPath(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, _ := f.fileDir()
	return filepath.Join(dir, "content-"+id)
}

func (f *FakeStorage) disks() int {
	if f.DisksPerSlot == 0 {
		return storage.DefaultDisksPerSlot
	}
	return f.DisksPerSlot
}

func (f *FakeStorage) SlotDisks(_ context.Context, slotID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.slots[slotID] == nil {
		f.slots[slotID] = make([]string, f.disks())
	}
	out := make([]string, f.disks())
	for i := range out {
		if f.Dir == "" {
			out[i] = "/dev/null"
			continue
		}
		p := filepath.Join(f.Dir, fmt.Sprintf("slot-dev-%s-d%d", slotID, i))
		if !exists(p) {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				return nil, err
			}
		}
		out[i] = p
	}
	return out, nil
}

func (f *FakeStorage) ResetSlot(_ context.Context, slotID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ResetSlot"); err != nil {
		return err
	}
	f.slots[slotID] = make([]string, f.disks())
	return nil
}

func (f *FakeStorage) ResetSlotDisk(_ context.Context, slotID string, n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ResetSlotDisk"); err != nil {
		return err
	}
	if d := f.slots[slotID]; n >= 0 && n < len(d) {
		d[n] = ""
	}
	return nil
}

// SlotDiskMapping returns what disk n of a slot maps ("alloc/att"), for
// tests.
func (f *FakeStorage) SlotDiskMapping(slotID string, n int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d := f.slots[slotID]; n >= 0 && n < len(d) {
		return d[n]
	}
	return ""
}

func (f *FakeStorage) att(allocID, attID string) *fakeAtt {
	return f.allocs[allocID][attID]
}

func (f *FakeStorage) AttachVolume(_ context.Context, v ns.VolumeSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("AttachVolume"); err != nil {
		return "", err
	}
	if len(v.Paths) == 0 {
		return "", ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_ENOUGH_REPLICAS, "no paths")
	}
	if f.allocs[v.AllocationID] == nil {
		f.allocs[v.AllocationID] = map[string]*fakeAtt{}
	}
	at := f.allocs[v.AllocationID][v.AttachmentID]
	if at == nil {
		at = &fakeAtt{spec: v, snaps: map[int64]string{}}
		f.allocs[v.AllocationID][v.AttachmentID] = at
	}
	if v.SlotID != "" {
		if f.slots[v.SlotID] == nil {
			f.slots[v.SlotID] = make([]string, f.disks())
		}
		d := f.slots[v.SlotID]
		key := v.AllocationID + "/" + v.AttachmentID
		if v.SlotDisk < 0 || v.SlotDisk >= len(d) {
			return "", fmt.Errorf("slot disk %d out of range", v.SlotDisk)
		}
		if d[v.SlotDisk] != "" && d[v.SlotDisk] != key {
			return "", storage.ErrSlotDiskBusy
		}
		d[v.SlotDisk] = key
	}
	return "/dev/blip/volumes/" + v.UID, nil
}

// fileSize bounds the size of snapshot and content files to 1 MiB.
func fileSize(size int64) int64 {
	if size <= 0 {
		return 1 << 20
	}
	return min(size, 1<<20)
}

func (f *FakeStorage) CaptureLocal(_ context.Context, allocID string, attIDs []string, seq int64) (*ns.CaptureResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("CaptureLocal"); err != nil {
		return nil, err
	}
	dir, err := f.fileDir()
	if err != nil {
		return nil, err
	}
	for _, attID := range attIDs {
		if f.att(allocID, attID) == nil {
			return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "attachment %s not found", attID)
		}
	}
	res := &ns.CaptureResult{}
	for _, attID := range attIDs {
		at := f.att(allocID, attID)
		if _, ok := at.snaps[seq]; ok {
			continue
		}
		p := filepath.Join(dir, fmt.Sprintf("snap-%s-%s-%d", allocID, attID, seq))
		if err := os.WriteFile(p, bytes.Repeat([]byte{byte(seq)}, 4096), 0o600); err != nil {
			return nil, err
		}
		if err := os.Truncate(p, fileSize(at.spec.SizeBytes)); err != nil {
			return nil, err
		}
		at.snaps[seq] = p
		res.Suspended = time.Millisecond
	}
	return res, nil
}

func (f *FakeStorage) DropLocalSnapshot(_ context.Context, allocID, attID string, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("DropLocalSnapshot"); err != nil {
		return err
	}
	if at := f.att(allocID, attID); at != nil {
		if p, ok := at.snaps[seq]; ok {
			os.Remove(p)
			delete(at.snaps, seq)
		}
	}
	return nil
}

func (f *FakeStorage) SnapshotSource(_ context.Context, allocID, attID string, seq, baseSeq int64, full bool) (*ns.SnapshotSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ns.SnapshotSource"); err != nil {
		return nil, err
	}
	at := f.att(allocID, attID)
	if at == nil || at.snaps[seq] == "" {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "local snapshot %d of %s not found", seq, attID)
	}
	if baseSeq != 0 && at.snaps[baseSeq] == "" {
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "local snapshot %d of %s not found", baseSeq, attID)
	}
	size := fileSize(at.spec.SizeBytes)
	src := &ns.SnapshotSource{Size: size, Ranges: []extent.Range{{Off: 0, Len: min(size, storage.BlockSize)}}}
	if full {
		src.Full, src.Ranges = true, []extent.Range{{Off: 0, Len: size}}
	}
	return src, nil
}

func (f *FakeStorage) WriteSnapshot(_ context.Context, allocID, attID string, seq int64, ranges []extent.Range, targets []*pb.Path) ([]error, error) {
	f.mu.Lock()
	if err := f.call("WriteSnapshot"); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	at := f.att(allocID, attID)
	if at == nil || at.snaps[seq] == "" {
		f.mu.Unlock()
		return nil, ns.Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "local snapshot %d of %s not found", seq, attID)
	}
	src := at.snaps[seq]
	fail := map[string]bool{}
	for k, v := range f.failWrites {
		fail[k] = v
	}
	f.mu.Unlock()
	errs := make([]error, len(targets))
	for i, t := range targets {
		if fail[t.Node] {
			errs[i] = fmt.Errorf("write to %s: injected failure", t.Node)
			continue
		}
		dst, ok := fakeTargets.Load(t.SubsystemNqn)
		if !ok {
			errs[i] = fmt.Errorf("connect to %s: %s is not exported", t.Node, t.SubsystemNqn)
			continue
		}
		errs[i] = copyRanges(src, dst.(string), ranges)
	}
	return errs, nil
}

// copyRanges copies ranges of file src into file dst.
func copyRanges(src, dst string, ranges []extent.Range) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer out.Close()
	for _, r := range ranges {
		b := make([]byte, r.Len)
		if _, err := in.ReadAt(b, r.Off); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if _, err := out.WriteAt(b, r.Off); err != nil {
			return err
		}
	}
	return out.Sync()
}

func (f *FakeStorage) ReleaseAttachment(_ context.Context, allocID, attID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ReleaseAttachment"); err != nil {
		return err
	}
	at := f.att(allocID, attID)
	if at == nil {
		return nil
	}
	f.releaseLocked(allocID, attID)
	return nil
}

func (f *FakeStorage) releaseLocked(allocID, attID string) {
	at := f.att(allocID, attID)
	for _, p := range at.snaps {
		os.Remove(p)
	}
	for _, d := range f.slots {
		for i, k := range d {
			if k == allocID+"/"+attID {
				d[i] = ""
			}
		}
	}
	delete(f.allocs[allocID], attID)
	if len(f.allocs[allocID]) == 0 {
		delete(f.allocs, allocID)
	}
}

func (f *FakeStorage) ReleaseAllocation(_ context.Context, allocID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ReleaseAllocation"); err != nil {
		return err
	}
	for id := range f.allocs[allocID] {
		f.releaseLocked(allocID, id)
	}
	return nil
}

func (f *FakeStorage) DeleteThins(_ context.Context, ids []uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("DeleteThins"); err != nil {
		return err
	}
	del := map[uint32]bool{}
	for _, id := range ids {
		del[id] = true
	}
	var keep []uint32
	for _, id := range f.unknown {
		if del[id] {
			f.deleted = append(f.deleted, id)
		} else {
			keep = append(keep, id)
		}
	}
	f.unknown = keep
	return nil
}

func (f *FakeStorage) State(context.Context) (*ns.StorageState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &ns.StorageState{Allocations: map[string]map[string]ns.AttachmentStorage{}, UnknownThins: append([]uint32(nil), f.unknown...)}
	for _, c := range f.contents {
		s.Contents = append(s.Contents, proto.Clone(c).(*pb.ContentInfo))
	}
	sort.Slice(s.Contents, func(i, j int) bool { return s.Contents[i].ContentId < s.Contents[j].ContentId })
	for id, atts := range f.allocs {
		m := map[string]ns.AttachmentStorage{}
		for attID, at := range atts {
			as := ns.AttachmentStorage{UID: at.spec.UID, Generation: at.spec.Generation, ContentID: at.spec.ContentID, Overlay: true, SlotDisk: -1}
			for _, d := range f.slots {
				for i, k := range d {
					if k == id+"/"+attID {
						as.SlotDisk = i
					}
				}
			}
			for seq := range at.snaps {
				as.Snaps = append(as.Snaps, ns.LocalSnapStorage{Seq: seq, State: pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_READY})
			}
			sort.Slice(as.Snaps, func(i, j int) bool { return as.Snaps[i].Seq < as.Snaps[j].Seq })
			m[attID] = as
		}
		s.Allocations[id] = m
	}
	return s, nil
}

func (f *FakeStorage) Capacity(context.Context) (*pb.StorageCapacity, *pb.ComputeCapacity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sc := &pb.StorageCapacity{}
	if f.capacity != nil {
		sc = proto.Clone(f.capacity).(*pb.StorageCapacity)
	}
	sc.LvCount = int32(len(f.contents))
	return sc, &pb.ComputeCapacity{}, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var _ ns.Storage = (*FakeStorage)(nil)
