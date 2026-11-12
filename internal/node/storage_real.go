package node

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/image"
	"github.com/example/blip/internal/storage/names"
)

// RealConfig configures RealStorage.
type RealConfig struct {
	Node string
	// Addr and Port are where this node's exports listen.
	Addr string
	Port int
	// Storage node settings; VG empty means this is not a storage node.
	VG      string
	Devices []string
	// ComputeDevice is the local disk for the compute pool; empty means
	// this is not a compute node.
	ComputeDevice string
	// DevDir holds device nodes. The device plugin passes slot device
	// paths from here to the kubelet, so it must be a host path.
	DevDir string
	// WorkDir is scratch space for image extraction.
	WorkDir string
	// DisksPerSlot is the number of disks per slot. Default
	// storage.DefaultDisksPerSlot.
	DisksPerSlot int
	Timeouts     storage.Timeouts
	// PathCheck is the period of the path health loop. Default 10s.
	PathCheck time.Duration
}

// RealStorage is the Storage backed by internal/storage.
type RealStorage struct {
	cfg RealConfig
	sn  *storage.StorageNode // nil if not a storage node
	cn  *storage.ComputeNode // nil if not a compute node

	mu      sync.Mutex
	hostPSK []byte

	// cmu serializes compute changes (thin IDs are picked from the
	// device list, so two attaches must not race).
	cmu sync.Mutex
}

// NewRealStorage opens the storage and compute sides that cfg asks for.
func NewRealStorage(cfg RealConfig) (*RealStorage, error) {
	if cfg.Port == 0 {
		cfg.Port = 4420
	}
	if cfg.PathCheck == 0 {
		cfg.PathCheck = 10 * time.Second
	}
	r := &RealStorage{cfg: cfg}
	if cfg.VG != "" {
		if len(cfg.Devices) == 0 {
			return nil, errors.New("storage.devices is required on storage nodes (LVM only looks at these devices)")
		}
		sn, err := storage.NewStorageNode(storage.StorageConfig{
			Node: cfg.Node, Addr: cfg.Addr, Port: cfg.Port, VG: cfg.VG, Devices: cfg.Devices,
			DevDir: cfg.DevDir, WorkDir: cfg.WorkDir, Timeouts: cfg.Timeouts,
		})
		if err != nil {
			return nil, err
		}
		r.sn = sn
	}
	if cfg.ComputeDevice != "" {
		cn, err := storage.NewComputeNode(storage.ComputeConfig{
			Node: cfg.Node, Device: cfg.ComputeDevice, DevDir: cfg.DevDir, Timeouts: cfg.Timeouts, DisksPerSlot: cfg.DisksPerSlot,
		})
		if err != nil {
			return nil, err
		}
		r.cn = cn
	}
	return r, nil
}

// StorageNode returns the storage side, or nil. For tests.
func (r *RealStorage) StorageNode() *storage.StorageNode { return r.sn }

// ComputeNode returns the compute side, or nil. For tests.
func (r *RealStorage) ComputeNode() *storage.ComputeNode { return r.cn }

// Prepare creates the compute pool if needed. Device-mapper state does
// not survive a reboot, so a missing pool means a new boot: the disk is
// wiped and the header gets the new boot ID.
func (r *RealStorage) Prepare(ctx context.Context) error {
	if r.cn == nil {
		return nil
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	old := r.cn.PoolBootID()
	created, err := r.cn.PreparePool(ctx)
	if err != nil {
		return fmt.Errorf("prepare compute pool: %w", err)
	}
	if created {
		log.Printf("storage: new compute pool on %s (header had boot ID %q, now %q)", r.cfg.ComputeDevice, old, r.cn.PoolBootID())
	}
	return nil
}

// Run checks origin paths of attachments until ctx ends. There is
// no multipathd: lost replicas are connected again and failed paths whose
// controller is live are reinstated.
func (r *RealStorage) Run(ctx context.Context) {
	if r.cn == nil {
		return
	}
	t := time.NewTicker(r.cfg.PathCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.CheckPaths(ctx)
		}
	}
}

// CheckPaths runs one round of the path health loop.
func (r *RealStorage) CheckPaths(ctx context.Context) {
	st, err := r.cn.Rescan(ctx)
	if err != nil {
		log.Printf("storage: rescan: %v", err)
		return
	}
	psk := r.psk()
	for allocID, a := range st.Allocations {
		for attID, at := range a.Attachments {
			if len(at.Origin) == 0 {
				continue
			}
			active := 0
			for _, p := range at.Origin {
				if p.Active {
					active++
				}
			}
			if active == len(at.Origin) && (len(at.Replicas) == 0 || len(at.Replicas) == len(at.Origin)) {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			var n int
			if len(at.Replicas) > 0 && psk != nil {
				r.cmu.Lock()
				n, err = r.cn.RefreshPaths(cctx, storage.AttachRequest{AllocID: allocID, AttachmentID: attID, Generation: at.Generation,
					UID: at.UID, ContentID: at.ContentID, Replicas: at.Replicas, PSK: psk})
				r.cmu.Unlock()
			} else {
				_, err = r.cn.ReinstatePaths(cctx, allocID, attID)
			}
			cancel()
			if err != nil {
				log.Printf("storage: refresh paths of %s/%s: %v", allocID, attID, err)
			} else if n > 0 && n != active {
				log.Printf("storage: attachment %s/%s now has %d active paths (was %d)", allocID, attID, n, active)
			}
		}
	}
}

func (r *RealStorage) psk() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostPSK
}

func (r *RealStorage) needPSK() ([]byte, error) {
	if p := r.psk(); p != nil {
		return p, nil
	}
	return nil, Codef(pb.ErrorCode_ERROR_CODE_TLS, "no host key yet")
}

func (r *RealStorage) storageNode() (*storage.StorageNode, error) {
	if r.sn == nil {
		return nil, errors.New("this node is not a storage node")
	}
	return r.sn, nil
}

func (r *RealStorage) computeNode() (*storage.ComputeNode, error) {
	if r.cn == nil {
		return nil, errors.New("this node is not a compute node")
	}
	return r.cn, nil
}

// codeOf adds an ErrorCode to errors of the storage library.
func codeOf(err error) error {
	if err == nil || ErrorCodeOf(err) != pb.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return err
	}
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return WithCode(pb.ErrorCode_ERROR_CODE_NOT_FOUND, err)
	case errors.Is(err, storage.ErrStaleGeneration):
		return WithCode(pb.ErrorCode_ERROR_CODE_STALE_GENERATION, err)
	case errors.Is(err, storage.ErrSuspendBudget):
		return WithCode(pb.ErrorCode_ERROR_CODE_SUSPEND_TIMEOUT, err)
	case errors.Is(err, image.ErrPull):
		return WithCode(pb.ErrorCode_ERROR_CODE_IMAGE_PULL, err)
	case errors.Is(err, syscall.ENOSPC) || isNoSpace(err.Error()):
		return WithCode(pb.ErrorCode_ERROR_CODE_NO_SPACE, err)
	}
	return err
}

func isNoSpace(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"no space left", "insufficient free space", "out of data space", "out_of_data_space", "free space in thin pool"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// SetHostKey keeps this node's PSK. Keys are inserted into the .nvme
// keyring per connection, with the identity of each subsystem.
func (r *RealStorage) SetHostKey(_ context.Context, hostNQN string, psk []byte) error {
	if want := names.HostNQN(r.cfg.Node); hostNQN != want {
		return Codef(pb.ErrorCode_ERROR_CODE_TLS, "host NQN %q from controller, expected %q", hostNQN, want)
	}
	if len(psk) != 32 {
		return Codef(pb.ErrorCode_ERROR_CODE_TLS, "host PSK has %d bytes, want 32", len(psk))
	}
	r.mu.Lock()
	r.hostPSK = append([]byte(nil), psk...)
	r.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// Storage node commands

// Kind tags of LVs. CreateRoot tags roots "content".
var kindTags = map[pb.ContentKind]string{
	pb.ContentKind_CONTENT_KIND_ROOT:     "root",
	pb.ContentKind_CONTENT_KIND_CLONE:    "clone",
	pb.ContentKind_CONTENT_KIND_SNAPSHOT: "snapshot",
	pb.ContentKind_CONTENT_KIND_REPAIR:   "repair",
}

func kindTag(k pb.ContentKind) string {
	if t, ok := kindTags[k]; ok {
		return t
	}
	return "content"
}

func kindOf(tag string) pb.ContentKind {
	for k, t := range kindTags {
		if t == tag {
			return k
		}
	}
	if tag == "content" {
		return pb.ContentKind_CONTENT_KIND_ROOT
	}
	return pb.ContentKind_CONTENT_KIND_UNSPECIFIED
}

// content returns one content, or a NOT_FOUND error.
func (r *RealStorage) content(ctx context.Context, sn *storage.StorageNode, id string) (storage.Content, error) {
	st, err := sn.State(ctx)
	if err != nil {
		return storage.Content{}, err
	}
	c, ok := st.Contents[id]
	if !ok {
		return storage.Content{}, Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "content %s not found", id)
	}
	return c, nil
}

func (r *RealStorage) path(sub string) *pb.Path {
	return &pb.Path{Node: r.cfg.Node, SubsystemNqn: sub, Address: r.cfg.Addr, Port: uint32(r.cfg.Port)}
}

func (r *RealStorage) Export(ctx context.Context, c *pb.Export) (*pb.ExportResult, error) {
	sn, err := r.storageNode()
	if err != nil {
		return nil, err
	}
	if err := names.Check("host node", c.HostNode); err != nil || c.HostNqn != names.HostNQN(c.HostNode) {
		return nil, Codef(pb.ErrorCode_ERROR_CODE_TLS, "host NQN %q does not match host node %q", c.HostNqn, c.HostNode)
	}
	if len(c.HostPsk) != 32 {
		return nil, Codef(pb.ErrorCode_ERROR_CODE_TLS, "host PSK has %d bytes, want 32", len(c.HostPsk))
	}
	var rem storage.Remote
	switch c.Mode {
	case pb.ExportMode_EXPORT_MODE_READ_ONLY:
		rem, err = sn.Export(ctx, c.ContentId, c.HostNode, c.HostPsk, false)
	case pb.ExportMode_EXPORT_MODE_READ_WRITE:
		if c.RepairSealed {
			rem, err = sn.ExportSealedRW(ctx, c.ContentId, c.HostNode, c.HostPsk)
		} else {
			rem, err = sn.Export(ctx, c.ContentId, c.HostNode, c.HostPsk, true)
		}
	default:
		return nil, fmt.Errorf("export: unknown mode %v", c.Mode)
	}
	if err != nil {
		return nil, codeOf(err)
	}
	return &pb.ExportResult{Path: r.path(rem.SubNQN)}, nil
}

func (r *RealStorage) Unexport(ctx context.Context, c *pb.Unexport) error {
	sn, err := r.storageNode()
	if err != nil {
		return err
	}
	if err := names.Check("content ID", c.ContentId); err != nil {
		return err
	}
	if c.HostNqn == "" {
		return sn.UnexportAll(c.ContentId)
	}
	host, ok := strings.CutPrefix(c.HostNqn, names.NQNPrefix+":host:")
	if !ok {
		return fmt.Errorf("unexport: bad host NQN %q", c.HostNqn)
	}
	return errors.Join(sn.Unexport(ctx, c.ContentId, host, false), sn.Unexport(ctx, c.ContentId, host, true))
}

func (r *RealStorage) Seal(ctx context.Context, c *pb.Seal) error {
	sn, err := r.storageNode()
	if err != nil {
		return err
	}
	if err := sn.Seal(ctx, c.ContentId); err != nil {
		return codeOf(err)
	}
	if uid := c.GetBlipvol().GetUid(); uid != "" {
		return codeOf(sn.SetOwner(ctx, c.ContentId, uid))
	}
	return nil
}

func (r *RealStorage) DeleteContent(ctx context.Context, c *pb.DeleteContent) error {
	sn, err := r.storageNode()
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range c.ContentIds {
		if err := sn.Delete(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (r *RealStorage) CreateContent(ctx context.Context, c *pb.CreateContent) error {
	sn, err := r.storageNode()
	if err != nil {
		return err
	}
	return codeOf(sn.CreateBlank(ctx, c.ContentId, c.SizeBytes, kindTag(c.Kind), c.GetBlipvol().GetUid()))
}

func remotes(ps []*pb.Path) []storage.Remote {
	out := make([]storage.Remote, 0, len(ps))
	for _, p := range ps {
		out = append(out, storage.Remote{Node: p.Node, Addr: p.Address, Port: int(p.Port), SubNQN: p.SubsystemNqn})
	}
	return out
}

func targetResults(ps []*pb.Path, errs []error) []*pb.TargetResult {
	out := make([]*pb.TargetResult, 0, len(ps))
	for i, p := range ps {
		t := &pb.TargetResult{Node: p.Node, Ok: true}
		if i < len(errs) && errs[i] != nil {
			t.Ok, t.Error = false, errs[i].Error()
		}
		out = append(out, t)
	}
	return out
}

// copyTo writes ranges of local content id to every target.
func (r *RealStorage) copyTo(ctx context.Context, sn *storage.StorageNode, id string, targets []*pb.Path, copy, zero []extent.Range) ([]*pb.TargetResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	psk, err := r.needPSK()
	if err != nil {
		return nil, err
	}
	errs := sn.WriteExtents(ctx, id, remotes(targets), psk, copy, zero)
	for i, e := range errs {
		if e != nil {
			log.Printf("storage: write %s to %s: %v", id, targets[i].Node, e)
		}
	}
	return targetResults(targets, errs), nil
}

func (r *RealStorage) Import(ctx context.Context, c *pb.Import) (*pb.ImportResult, error) {
	sn, err := r.storageNode()
	if err != nil {
		return nil, err
	}
	req := storage.RootRequest{ID: c.ContentId, Size: c.SizeBytes, Owner: c.GetBlipvol().GetUid()}
	if c.ImageReference != "" {
		auth, err := pullAuth(c.PullSecretDockerconfigjson, c.ImageReference)
		if err != nil {
			return nil, WithCode(pb.ErrorCode_ERROR_CODE_IMAGE_PULL, err)
		}
		req.Image = &storage.ImageSource{Ref: c.ImageReference, Auth: auth}
	}
	digest, err := sn.CreateRoot(ctx, req)
	if err != nil {
		return nil, codeOf(err)
	}
	rs, err := sn.MappedRanges(ctx, c.ContentId)
	if err != nil {
		return nil, codeOf(err)
	}
	ts, err := r.copyTo(ctx, sn, c.ContentId, c.Targets, rs, nil)
	if err != nil {
		return nil, err
	}
	return &pb.ImportResult{ImageDigest: digest, SizeBytes: c.SizeBytes, Targets: ts}, nil
}

func (r *RealStorage) Clone(ctx context.Context, c *pb.Clone) (*pb.CopyResult, error) {
	sn, err := r.storageNode()
	if err != nil {
		return nil, err
	}
	p, err := r.content(ctx, sn, c.ParentContentId)
	if err != nil {
		return nil, err
	}
	if !p.Sealed {
		return nil, Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "parent %s is not sealed", c.ParentContentId)
	}
	switch c.Mode {
	case pb.CloneMode_CLONE_MODE_SNAPSHOT:
		err := sn.Snapshot(ctx, c.ParentContentId, c.ContentId, kindTag(pb.ContentKind_CONTENT_KIND_CLONE), c.GetBlipvol().GetUid())
		return &pb.CopyResult{}, codeOf(err)
	case pb.CloneMode_CLONE_MODE_COPY:
		rs, err := sn.MappedRanges(ctx, c.ParentContentId)
		if err != nil {
			return nil, codeOf(err)
		}
		ts, err := r.copyTo(ctx, sn, c.ParentContentId, c.Targets, rs, nil)
		if err != nil {
			return nil, err
		}
		return &pb.CopyResult{BytesCopied: extent.Total(rs), Targets: ts}, nil
	}
	return nil, fmt.Errorf("clone: unknown mode %v", c.Mode)
}

func (r *RealStorage) Repair(ctx context.Context, c *pb.Repair) (*pb.CopyResult, error) {
	sn, err := r.storageNode()
	if err != nil {
		return nil, err
	}
	if c.Target == nil {
		return nil, errors.New("repair: no target")
	}
	if _, err := r.content(ctx, sn, c.ContentId); err != nil {
		return nil, err
	}
	var copy, zero []extent.Range
	switch {
	case len(c.Extents) > 0:
		for _, e := range c.Extents {
			copy = append(copy, extent.Range{Off: e.OffsetBytes, Len: e.LengthBytes})
		}
	case c.BaseContentId != "":
		if copy, zero, err = sn.ThinDelta(ctx, c.BaseContentId, c.ContentId); err != nil {
			return nil, codeOf(err)
		}
	default:
		if copy, err = sn.MappedRanges(ctx, c.ContentId); err != nil {
			return nil, codeOf(err)
		}
	}
	ts, err := r.copyTo(ctx, sn, c.ContentId, []*pb.Path{c.Target}, copy, zero)
	if err != nil {
		return nil, err
	}
	return &pb.CopyResult{BytesCopied: extent.Total(copy), Targets: ts}, nil
}

func (r *RealStorage) Scrub(ctx context.Context, c *pb.Scrub) (*pb.ScrubResult, error) {
	sn, err := r.storageNode()
	if err != nil {
		return nil, err
	}
	h, err := sn.Scrub(ctx, c.ContentId)
	if err != nil {
		return nil, codeOf(err)
	}
	return groupHashes(h.Sums, c.StartChunk, c.ChunkCount, c.BlocksPerHash), nil
}

// groupHashes turns per-chunk hashes into one hash per group of
// blocksPerHash chunks. A group of one chunk is that chunk's hash; a
// larger group is the SHA-256 of its chunk hashes.
func groupHashes(sums [][32]byte, start, count, per int64) *pb.ScrubResult {
	if per <= 0 {
		per = 1
	}
	if start < 0 {
		start = 0
	}
	end := int64(len(sums))
	if count > 0 && start+count < end {
		end = start + count
	}
	res := &pb.ScrubResult{StartChunk: start, BlocksPerHash: per}
	for i := start; i < end; i += per {
		j := min(i+per, end)
		if per == 1 {
			s := sums[i]
			res.Hashes = append(res.Hashes, s[:])
			continue
		}
		hh := sha256.New()
		for _, s := range sums[i:j] {
			hh.Write(s[:])
		}
		res.Hashes = append(res.Hashes, hh.Sum(nil))
	}
	return res
}

// ---------------------------------------------------------------------------
// Transfers (storage node side)

func (r *RealStorage) PrepareReceive(ctx context.Context, rs ReceiveSpec) error {
	sn, err := r.storageNode()
	if err != nil {
		return err
	}
	_, err = sn.PrepareReceive(ctx, storage.ReceiveRequest{
		ContentID: rs.ContentID, BaseContentID: rs.BaseContentID, SizeBytes: rs.SizeBytes, Owner: rs.Owner, Generation: rs.Generation,
	})
	return err
}

// ---------------------------------------------------------------------------
// Compute node commands

func (r *RealStorage) SlotDisks(ctx context.Context, slotID string) ([]string, error) {
	cn, err := r.computeNode()
	if err != nil {
		return nil, err
	}
	ds, err := cn.EnsureSlot(ctx, slotID)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ds))
	for i, d := range ds {
		if out[i], err = devnode.Ensure(r.cfg.DevDir, fmt.Sprintf("slot-%s-d%d", slotID, i), d); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *RealStorage) ResetSlot(ctx context.Context, slotID string) error {
	cn, err := r.computeNode()
	if err != nil {
		return err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	var errs []error
	for i := range cn.DisksPerSlot() {
		errs = append(errs, cn.ResetSlotDisk(ctx, slotID, i))
	}
	return errors.Join(errs...)
}

func (r *RealStorage) ResetSlotDisk(ctx context.Context, slotID string, n int) error {
	cn, err := r.computeNode()
	if err != nil {
		return err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return cn.ResetSlotDisk(ctx, slotID, n)
}

func (r *RealStorage) AttachVolume(ctx context.Context, v VolumeSpec) (string, error) {
	cn, err := r.computeNode()
	if err != nil {
		return "", err
	}
	psk, err := r.needPSK()
	if err != nil {
		return "", err
	}
	if len(v.Paths) == 0 {
		return "", Codef(pb.ErrorCode_ERROR_CODE_NOT_ENOUGH_REPLICAS, "attach %s: no paths", v.AttachmentID)
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	att, err := cn.Attach(ctx, storage.AttachRequest{
		AllocID: v.AllocationID, AttachmentID: v.AttachmentID, Generation: v.Generation, UID: v.UID, ContentID: v.ContentID,
		SizeBytes: v.SizeBytes, Slot: v.SlotID, SlotDisk: v.SlotDisk, Replicas: remotes(v.Paths), PSK: psk,
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "no replica of content"):
			return "", WithCode(pb.ErrorCode_ERROR_CODE_NOT_ENOUGH_REPLICAS, err)
		case errors.Is(err, storage.ErrSlotDiskBusy):
			return "", WithCode(pb.ErrorCode_ERROR_CODE_CONFLICT, err)
		}
		return "", codeOf(err)
	}
	return att.HostLink, nil
}

func (r *RealStorage) CaptureLocal(ctx context.Context, allocID string, attIDs []string, seq int64) (*CaptureResult, error) {
	cn, err := r.computeNode()
	if err != nil {
		return nil, err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	res, err := cn.CaptureLocal(ctx, allocID, attIDs, seq)
	if err != nil {
		return nil, codeOf(err)
	}
	return &CaptureResult{Suspended: res.Suspended}, nil
}

func (r *RealStorage) DropLocalSnapshot(ctx context.Context, allocID, attID string, seq int64) error {
	cn, err := r.computeNode()
	if err != nil {
		return err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return codeOf(cn.DropLocalSnapshot(ctx, allocID, attID, seq))
}

func (r *RealStorage) SnapshotSource(ctx context.Context, allocID, attID string, seq, baseSeq int64, full bool) (*SnapshotSource, error) {
	cn, err := r.computeNode()
	if err != nil {
		return nil, err
	}
	_, size, err := cn.LocalSnapshotPath(ctx, allocID, attID, seq)
	if err != nil {
		return nil, codeOf(err)
	}
	src := &SnapshotSource{Size: size}
	if !full {
		rs, err := cn.LocalDelta(ctx, allocID, attID, seq, baseSeq)
		switch {
		case errors.Is(err, storage.ErrLeftOnly):
			src.FullResend = true
		case err != nil:
			return nil, codeOf(err)
		default:
			src.Ranges = rs
			return src, nil
		}
	}
	src.Full = true
	src.Ranges = []extent.Range{{Off: 0, Len: size}}
	return src, nil
}

func (r *RealStorage) WriteSnapshot(ctx context.Context, allocID, attID string, seq int64, ranges []extent.Range, targets []*pb.Path) ([]error, error) {
	cn, err := r.computeNode()
	if err != nil {
		return nil, err
	}
	psk, err := r.needPSK()
	if err != nil {
		return nil, err
	}
	return cn.WriteLocalSnapshot(ctx, allocID, attID, seq, remotes(targets), psk, ranges), nil
}

func (r *RealStorage) ReleaseAttachment(ctx context.Context, allocID, attID string) error {
	cn, err := r.computeNode()
	if err != nil {
		return err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	if err := cn.ReleaseAttachment(ctx, allocID, attID); err != nil {
		return codeOf(err)
	}
	return nil
}

func (r *RealStorage) ReleaseAllocation(ctx context.Context, allocID string) error {
	cn, err := r.computeNode()
	if err != nil {
		return err
	}
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return cn.Cleanup(ctx, allocID)
}

// ---------------------------------------------------------------------------
// State and capacity

func snapState(s storage.SnapState) pb.LocalSnapshotState {
	switch s {
	case storage.SnapCreating:
		return pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_CREATING
	case storage.SnapReady, storage.SnapHidden:
		return pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_READY
	case storage.SnapDeleting:
		return pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_DELETING
	}
	return pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_UNSPECIFIED
}

func (r *RealStorage) DeleteThins(ctx context.Context, ids []uint32) error {
	if r.cn == nil || len(ids) == 0 {
		return nil
	}
	return r.cn.DeleteThins(ctx, ids)
}

func (r *RealStorage) State(ctx context.Context) (*StorageState, error) {
	s := &StorageState{Allocations: map[string]map[string]AttachmentStorage{}}
	if r.sn != nil {
		st, err := r.sn.State(ctx)
		if err != nil {
			return nil, err
		}
		s.Contents = contentInfos(st)
	}
	if r.cn != nil {
		st, err := r.cn.Rescan(ctx)
		if err != nil {
			return nil, err
		}
		s.UnknownThins = st.UnknownThins
		for id, a := range st.Allocations {
			m := map[string]AttachmentStorage{}
			for attID, at := range a.Attachments {
				as := AttachmentStorage{UID: at.UID, Generation: at.Generation, ContentID: at.ContentID,
					Overlay: at.ThinID != 0, SlotDisk: at.SlotDisk}
				for _, ls := range at.LocalSnaps {
					as.Snaps = append(as.Snaps, LocalSnapStorage{Seq: ls.Seq, State: snapState(ls.State)})
				}
				m[attID] = as
			}
			s.Allocations[id] = m
		}
	}
	return s, nil
}

func contentInfos(st storage.State) []*pb.ContentInfo {
	var out []*pb.ContentInfo
	for _, c := range st.Contents {
		ci := &pb.ContentInfo{ContentId: c.ID, Kind: kindOf(c.Kind), Sealed: c.Sealed, SizeBytes: c.Size}
		if c.Receiving {
			ci.Kind = pb.ContentKind_CONTENT_KIND_SNAPSHOT
		}
		if !c.Created.IsZero() {
			ci.Created = timestamppb.New(c.Created)
		}
		out = append(out, ci)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContentId < out[j].ContentId })
	return out
}

func (r *RealStorage) Capacity(ctx context.Context) (*pb.StorageCapacity, *pb.ComputeCapacity, error) {
	var sc *pb.StorageCapacity
	var cc *pb.ComputeCapacity
	var errs []error
	if r.sn != nil {
		u, err := r.sn.Usage(ctx)
		if err != nil {
			errs = append(errs, err)
		} else {
			sc = &pb.StorageCapacity{PoolSizeBytes: u.PoolSize, DataPercent: u.DataPercent, MetadataPercent: u.MetaPercent, LvCount: int32(u.LVCount)}
		}
	}
	if r.cn != nil {
		st, err := r.cn.Rescan(ctx)
		if err != nil {
			errs = append(errs, err)
		} else {
			cc = &pb.ComputeCapacity{}
			if st.PoolStatus.TotalData > 0 {
				cc.DataPercent = 100 * float64(st.PoolStatus.UsedData) / float64(st.PoolStatus.TotalData)
			}
		}
	}
	return sc, cc, errors.Join(errs...)
}
