package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/image"
	"github.com/example/blip/internal/storage/lvm"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmet"
	"github.com/example/blip/internal/storage/tlskeys"
)

// LV tags.
const (
	TagKind   = "blip.kind"
	TagOwner  = "blip.owner"
	TagSealed = "blip.sealed"
	TagDigest = "blip.digest"
)

// StorageConfig configures a StorageNode.
type StorageConfig struct {
	Node    string
	Addr    string   // listen address for exports
	Port    int      // default 4420
	VG      string   // volume group, for example "blip-<node>"
	Pool    string   // thin pool LV, default "pool"
	Devices []string // physical volumes of the VG
	DevDir  string   // private directory for device nodes
	WorkDir string   // scratch space for image extraction
	// NvmetRoot is the nvmet configfs directory (default
	// /sys/kernel/config/nvmet).
	NvmetRoot string
	Timeouts  Timeouts
}

// StorageNode runs storage operations on one storage node.
type StorageNode struct {
	cfg    StorageConfig
	lvm    *lvm.LVM
	target *nvmet.Target
	host   *host
	port   nvmet.Port
	mu     sync.Mutex // serializes export changes and Seal
}

// NewStorageNode checks the config and opens the VG and nvmet configfs.
func NewStorageNode(cfg StorageConfig) (*StorageNode, error) {
	if cfg.Port == 0 {
		cfg.Port = 4420
	}
	if cfg.Addr == "" {
		return nil, errors.New("storage: Addr is required")
	}
	h, err := newHost(cfg.Node, cfg.DevDir, cfg.Timeouts)
	if err != nil {
		return nil, err
	}
	l, err := lvm.New(lvm.Config{VG: cfg.VG, Pool: cfg.Pool, Devices: cfg.Devices})
	if err != nil {
		return nil, err
	}
	t, err := nvmet.New(cfg.NvmetRoot)
	if err != nil {
		return nil, err
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = os.TempDir()
	}
	return &StorageNode{
		cfg: cfg, lvm: l, target: t, host: h,
		port: nvmet.Port{ID: names.PortID(cfg.Node, cfg.Addr, cfg.Port), Addr: cfg.Addr, Svc: cfg.Port},
	}, nil
}

// LVM returns the LVM handle, for setup and tests.
func (s *StorageNode) LVM() *lvm.LVM { return s.lvm }

// Content is one LV as reported by State.
type Content struct {
	ID      string
	Kind    string
	Owner   string
	Sealed  bool
	Digest  string
	Size    int64
	Created time.Time
	Origin  string // content ID of the snapshot origin, if it still exists
	ThinID  uint32
	Active  bool
	// Receiving is set for content prepared by PrepareReceive and not
	// sealed yet.
	Receiving bool
}

// ExportState is one subsystem of this node.
type ExportState struct {
	ContentID string
	RW        bool
	Hosts     []string // host node names
}

// State is everything a storage node reports.
type State struct {
	Contents map[string]Content
	Exports  []ExportState
	Usage    Usage
}

// Usage is pool fullness.
type Usage struct {
	DataPercent float64
	MetaPercent float64
	LVCount     int
	PoolSize    int64
}

// sealed reports whether an LV is sealed. A sealed tag next to
// TagReceiving or TagCreating was copied from a snapshot parent.
func sealed(lv lvm.LV) bool {
	return lv.HasTag(TagSealed) && !lv.HasTag(TagReceiving) && !lv.HasTag(TagCreating)
}

func contentOf(lv lvm.LV) (Content, bool) {
	id, ok := names.ContentOfLV(lv.Name)
	if !ok {
		return Content{}, false
	}
	c := Content{ID: id, Kind: lv.TagValue(TagKind), Owner: lv.TagValue(TagOwner), Sealed: sealed(lv),
		Digest: lv.TagValue(TagDigest), Size: lv.Size, Created: lv.Created, ThinID: lv.ThinID, Active: lv.Active,
		Receiving: lv.HasTag(TagReceiving)}
	if o, ok := names.ContentOfLV(lv.Origin); ok {
		c.Origin = o
	}
	return c, true
}

// State lists contents with one lvs call, plus exports from configfs.
func (s *StorageNode) State(ctx context.Context) (State, error) {
	r, err := s.lvm.Report(ctx)
	if err != nil {
		return State{}, err
	}
	st := State{Contents: map[string]Content{}, Usage: usageOf(r)}
	for _, lv := range r.LVs {
		if c, ok := contentOf(lv); ok {
			st.Contents[c.ID] = c
		}
	}
	subs, err := s.target.List(func(n string) bool {
		node, _, _, ok := names.ParseSubsystemNQN(n)
		return ok && node == s.cfg.Node
	})
	if err != nil {
		return State{}, err
	}
	for _, sub := range subs {
		_, id, rw, _ := names.ParseSubsystemNQN(sub.NQN)
		e := ExportState{ContentID: id, RW: rw}
		for _, h := range sub.Hosts {
			if n, ok := strings.CutPrefix(h, names.NQNPrefix+":host:"); ok {
				e.Hosts = append(e.Hosts, n)
			}
		}
		st.Exports = append(st.Exports, e)
	}
	return st, nil
}

func usageOf(r lvm.Report) Usage {
	return Usage{DataPercent: r.DataPercent, MetaPercent: r.MetaPercent, LVCount: len(r.LVs), PoolSize: r.PoolSize}
}

// Usage returns pool fullness and the LV count.
func (s *StorageNode) Usage(ctx context.Context) (Usage, error) {
	r, err := s.lvm.Report(ctx)
	if err != nil {
		return Usage{}, err
	}
	return usageOf(r), nil
}

func (s *StorageNode) get(ctx context.Context, id string) (lvm.LV, error) {
	if err := names.Check("content ID", id); err != nil {
		return lvm.LV{}, err
	}
	lv, err := s.lvm.Get(ctx, names.LV(id))
	if errors.Is(err, lvm.ErrNotFound) {
		return lvm.LV{}, fmt.Errorf("content %s: %w", id, ErrNotFound)
	}
	return lv, err
}

// ErrNotFound is returned when a content does not exist.
var ErrNotFound = errors.New("not found")

// ErrSealed is returned when an operation would change sealed content.
var ErrSealed = errors.New("content is sealed")

// ErrInUse is returned for a read-write export of content that still has
// a read-only export (a compute node may read it as an origin).
var ErrInUse = errors.New("content has a read-only export")

// devPath activates the LV and returns a device node for it.
func (s *StorageNode) devPath(ctx context.Context, id string) (string, error) {
	lv, err := s.get(ctx, id)
	if err != nil {
		return "", err
	}
	d := lv.Dev
	if !lv.Active {
		if d, err = s.lvm.Activate(ctx, lv.Name); err != nil {
			return "", err
		}
	}
	return devnode.Ensure(s.cfg.DevDir, "lv-"+s.cfg.VG+"-"+lv.Name, d)
}

// ImageSource selects an OCI image for CreateRoot.
type ImageSource struct {
	Ref      string
	Auth     *image.Auth
	Platform string // default linux/<GOARCH>
}

// RootRequest asks for a new root content.
type RootRequest struct {
	ID    string
	Size  int64        // bytes, multiple of 4MiB
	Image *ImageSource // nil means a zero-filled raw device
	Owner string
}

// CreateRoot creates an unsealed root LV and returns the image digest.
// With an image, the LV holds an ext4 filesystem built from it; without
// one, it is a zero-filled raw device (no filesystem). The caller then copies
// MappedRanges to the other replicas and seals all of them. If the LV
// exists and is sealed, it returns its digest. An unsealed leftover from
// an earlier attempt is replaced.
func (s *StorageNode) CreateRoot(ctx context.Context, req RootRequest) (string, error) {
	lv, err := s.get(ctx, req.ID)
	switch {
	case err == nil && sealed(lv):
		return lv.TagValue(TagDigest), nil
	case err == nil:
		if err := s.Delete(ctx, req.ID); err != nil {
			return "", err
		}
	case !errors.Is(err, ErrNotFound):
		return "", err
	}
	src, digest := "", ""
	if req.Image != nil {
		dir := filepath.Join(s.cfg.WorkDir, "image-"+req.ID)
		if err := os.RemoveAll(dir); err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
		if digest, err = image.Pull(ctx, req.Image.Ref, req.Image.Auth, req.Image.Platform, dir); err != nil {
			return "", err
		}
		src = dir
	}
	tags := []string{TagKind + "=content"}
	if req.Owner != "" {
		tags = append(tags, TagOwner+"="+req.Owner)
	}
	if digest != "" {
		tags = append(tags, TagDigest+"="+digest)
	}
	if err := s.lvm.CreateThin(ctx, names.LV(req.ID), req.Size, tags); err != nil {
		return "", err
	}
	if req.Image == nil {
		return "", nil // a new thin LV reads as zeros
	}
	p, err := s.devPath(ctx, req.ID)
	if err != nil {
		return "", err
	}
	if err := image.MkfsExt4(ctx, p, src, image.MkfsOptions{}); err != nil {
		return "", err
	}
	return digest, nil
}

// CreateBlank creates an unsealed, all-zero LV, the target of a full copy
// or of a repair without a base. An existing LV is left as is.
func (s *StorageNode) CreateBlank(ctx context.Context, id string, size int64, kind, owner string) error {
	if err := names.Check("content ID", id); err != nil {
		return err
	}
	return s.lvm.CreateThin(ctx, names.LV(id), size, kindTags(kind, owner))
}

func kindTags(kind, owner string) []string {
	t := []string{TagKind + "=" + kind}
	if owner != "" {
		t = append(t, TagOwner+"="+owner)
	}
	return t
}

// Snapshot creates id as a thin snapshot of parent, unsealed, with the
// given kind and owner. It is used for clones and repair bases. If id
// exists it is left as is, unless an interrupted Snapshot left it with
// the parent's tags: then its tags are fixed.
func (s *StorageNode) Snapshot(ctx context.Context, parent, id, kind, owner string) error {
	if err := names.Check("content ID", id); err != nil {
		return err
	}
	if _, err := s.get(ctx, parent); err != nil {
		return err
	}
	if lv, err := s.get(ctx, id); err == nil {
		if lv.HasTag(TagCreating) {
			return s.setTags(ctx, id, kindTags(kind, owner))
		}
		return nil
	}
	// LVM copies the parent's tags (blip.sealed among them); TagCreating
	// marks them as not ours until setTags replaces them.
	if err := s.lvm.Snapshot(ctx, names.LV(parent), names.LV(id), append(kindTags(kind, owner), TagCreating)); err != nil {
		return err
	}
	return s.setTags(ctx, id, kindTags(kind, owner))
}

// setTags makes the tags of content id exactly tags, whatever LVM copied
// from a snapshot parent.
func (s *StorageNode) setTags(ctx context.Context, id string, tags []string) error {
	lv, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, t := range tags {
		want[t] = true
	}
	var add, del []string
	for _, t := range lv.Tags {
		if !want[t] {
			del = append(del, t)
		}
		delete(want, t)
	}
	for t := range want {
		add = append(add, t)
	}
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	return s.lvm.Tag(ctx, lv.Name, add, del)
}

// Seal tags the content sealed. Sealed content is never written again.
// It is refused while a read-write export exists.
func (s *StorageNode) Seal(ctx context.Context, id string) error {
	// Under the export lock, so a concurrent read-write Export cannot
	// slip in between the check and the tag.
	s.mu.Lock()
	defer s.mu.Unlock()
	lv, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	if sealed(lv) {
		return nil
	}
	if s.hasExport(id, true) {
		return errors.New("seal: a read-write export still exists")
	}
	var del []string
	if lv.HasTag(TagReceiving) {
		del = append(del, TagReceiving)
	}
	var add []string
	if !lv.HasTag(TagSealed) {
		add = append(add, TagSealed)
	}
	return s.lvm.Tag(ctx, lv.Name, add, del)
}

// SetOwner replaces the owner tag of the content. An empty owner removes it.
func (s *StorageNode) SetOwner(ctx context.Context, id, owner string) error {
	lv, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	want := TagOwner + "=" + owner
	var add, del []string
	found := false
	for _, t := range lv.Tags {
		switch {
		case owner != "" && t == want:
			found = true
		case strings.HasPrefix(t, TagOwner+"="):
			del = append(del, t)
		}
	}
	if owner != "" && !found {
		add = []string{want}
	}
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	return s.lvm.Tag(ctx, lv.Name, add, del)
}

func (s *StorageNode) hasExport(id string, rw bool) bool {
	n := names.SubsystemNQN(s.cfg.Node, id, rw)
	subs, _ := s.target.List(func(x string) bool { return x == n })
	return len(subs) > 0
}

// Export exports the content to hostNode and returns the address the host
// connects to. psk is the host's PSK. A read-write export is refused while
// a read-only export of the content exists or if the content is sealed.
func (s *StorageNode) Export(ctx context.Context, id, hostNode string, psk []byte, rw bool) (Remote, error) {
	return s.export(ctx, id, hostNode, psk, rw, false)
}

// ExportSealedRW exports sealed content read-write. It is only for
// repairing a replica after a scrub mismatch, and is refused with ErrInUse
// while the content has a read-only export: compute nodes may be reading
// it as the origin of an overlay.
func (s *StorageNode) ExportSealedRW(ctx context.Context, id, hostNode string, psk []byte) (Remote, error) {
	return s.export(ctx, id, hostNode, psk, true, true)
}

func (s *StorageNode) export(ctx context.Context, id, hostNode string, psk []byte, rw, allowSealed bool) (Remote, error) {
	if err := names.Check("host node", hostNode); err != nil {
		return Remote{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lv, err := s.get(ctx, id)
	if err != nil {
		return Remote{}, err
	}
	if rw {
		if sealed(lv) && !allowSealed {
			return Remote{}, fmt.Errorf("read-write export of %s: %w", id, ErrSealed)
		}
		if s.hasExport(id, false) {
			return Remote{}, fmt.Errorf("read-write export of %s: %w", id, ErrInUse)
		}
	}
	p, err := s.devPath(ctx, id)
	if err != nil {
		return Remote{}, err
	}
	if err := s.target.EnsurePort(s.port); err != nil {
		return Remote{}, err
	}
	sub := names.SubsystemNQN(s.cfg.Node, id, rw)
	hostNQN := names.HostNQN(hostNode)
	kr, err := keyring()
	if err != nil {
		return Remote{}, err
	}
	if _, err := tlskeys.Insert(kr, tlskeys.Identity(hostNQN, sub), tlskeys.Target, psk); err != nil {
		return Remote{}, err
	}
	if err := s.target.Export(nvmet.Export{SubNQN: sub, HostNQN: hostNQN, Device: p, PortID: s.port.ID}); err != nil {
		return Remote{}, err
	}
	return Remote{Node: s.cfg.Node, Addr: s.cfg.Addr, Port: s.cfg.Port, SubNQN: sub}, nil
}

// Unexport removes hostNode's access. When no host is left, the subsystem
// is removed.
func (s *StorageNode) Unexport(ctx context.Context, id, hostNode string, rw bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := names.SubsystemNQN(s.cfg.Node, id, rw)
	hostNQN := names.HostNQN(hostNode)
	if err := s.target.Unexport(sub, hostNQN); err != nil {
		return err
	}
	kr, err := keyring()
	if err != nil {
		return err
	}
	return tlskeys.Remove(kr, tlskeys.Identity(hostNQN, sub), tlskeys.Target)
}

// UnexportAll removes both subsystems of a content and their keys.
func (s *StorageNode) UnexportAll(id string) error { return s.unexportAll(id) }

func (s *StorageNode) unexportAll(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kr, err := keyring()
	if err != nil {
		return err
	}
	for _, rw := range []bool{false, true} {
		sub := names.SubsystemNQN(s.cfg.Node, id, rw)
		if err := s.target.RemoveSubsystem(sub); err != nil {
			return err
		}
		if err := tlskeys.RemoveMatching(kr, tlskeys.Target, func(ident string) bool {
			return strings.HasSuffix(ident, " "+sub)
		}); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes all exports of the content and the LV. Thin snapshots
// are independent, so children stay intact. A missing content is not an
// error.
func (s *StorageNode) Delete(ctx context.Context, id string) error {
	if err := names.Check("content ID", id); err != nil {
		return err
	}
	if err := s.unexportAll(id); err != nil {
		return err
	}
	if err := s.lvm.Remove(ctx, names.LV(id)); err != nil {
		return err
	}
	return devnode.Remove(s.cfg.DevDir, "lv-"+s.cfg.VG+"-"+names.LV(id))
}

func (s *StorageNode) poolMeta(ctx context.Context) (pool, meta string, err error) {
	r, err := s.lvm.ActivatePool(ctx)
	if err != nil {
		return "", "", err
	}
	if r.MetaDev == (devnode.Dev{}) {
		return "", "", errors.New("thin pool metadata device not active")
	}
	meta, err = devnode.Ensure(s.cfg.DevDir, "tmeta-"+s.cfg.VG, r.MetaDev)
	return r.PoolDM, meta, err
}

func blocksToRanges(rs []dm.BlockRange, blockSectors uint64) []extent.Range {
	bs := int64(blockSectors) * 512
	out := make([]extent.Range, 0, len(rs))
	for _, r := range rs {
		out = append(out, extent.Range{Off: int64(r.Begin) * bs, Len: int64(r.Length) * bs})
	}
	return out
}

// MappedRanges returns the byte ranges mapped in the content's thin LV,
// which is everything that differs from zeros.
func (s *StorageNode) MappedRanges(ctx context.Context, id string) ([]extent.Range, error) {
	lv, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	pool, meta, err := s.poolMeta(ctx)
	if err != nil {
		return nil, err
	}
	bs, rs, err := dm.MappedBlocks(ctx, pool, meta, lv.ThinID)
	if err != nil {
		return nil, err
	}
	return blocksToRanges(rs, bs), nil
}

// ThinDelta compares base and id on this node. To turn a copy of base
// into a copy of id, write copy from id and zero the zero ranges.
func (s *StorageNode) ThinDelta(ctx context.Context, base, id string) (copy, zero []extent.Range, err error) {
	b, err := s.get(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	pool, meta, err := s.poolMeta(ctx)
	if err != nil {
		return nil, nil, err
	}
	d, err := dm.ThinDelta(ctx, pool, meta, b.ThinID, c.ThinID)
	if err != nil {
		return nil, nil, err
	}
	return blocksToRanges(d.Copy, d.BlockSectors), blocksToRanges(d.Zero, d.BlockSectors), nil
}

// Scrub hashes the content per 64KiB block.
func (s *StorageNode) Scrub(ctx context.Context, id string) (extent.Hashes, error) {
	p, err := s.devPath(ctx, id)
	if err != nil {
		return extent.Hashes{}, err
	}
	return extent.Hash(ctx, p, BlockSize)
}

// WriteExtents copies ranges of local content id into each remote
// read-write export, and writes zeros over zero ranges. psk is this
// node's own PSK. It returns one error (or nil) per remote. Each remote
// gets a flush before its connection is closed.
func (s *StorageNode) WriteExtents(ctx context.Context, id string, dsts []Remote, psk []byte, copy, zero []extent.Range) []error {
	src, err := s.devPath(ctx, id)
	if err != nil {
		errs := make([]error, len(dsts))
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	return writeExtents(ctx, s.host, src, dsts, psk, copy, zero)
}

// writeExtents connects to each remote in parallel and copies.
func writeExtents(ctx context.Context, h *host, src string, dsts []Remote, psk []byte, copy, zero []extent.Range) []error {
	errs := make([]error, len(dsts))
	var wg sync.WaitGroup
	for i, r := range dsts {
		wg.Add(1)
		// The goroutine may run on another thread; network namespace
		// matters only for connect, which runs here.
		p, err := h.connect(ctx, r, psk)
		if err != nil {
			errs[i] = err
			wg.Done()
			continue
		}
		go func() {
			defer wg.Done()
			err := writeOne(ctx, src, p, copy, zero)
			errs[i] = errors.Join(err, h.disconnect(r.SubNQN))
		}()
	}
	wg.Wait()
	return errs
}

func writeOne(ctx context.Context, src string, p path, copy, zero []extent.Range) error {
	ssz, err := sizeOf(src)
	if err != nil {
		return err
	}
	if p.NS.Sectors*512 != ssz {
		return fmt.Errorf("size mismatch: source %d bytes, %s has %d", ssz, p.Remote.Node, p.NS.Sectors*512)
	}
	if len(zero) > 0 {
		if err := extent.Zero(ctx, p.Node, zero); err != nil {
			return fmt.Errorf("zero on %s: %w", p.Remote.Node, err)
		}
	}
	if err := extent.Copy(ctx, src, p.Node, copy); err != nil {
		return fmt.Errorf("copy to %s: %w", p.Remote.Node, err)
	}
	return nil
}

func sizeOf(dev string) (int64, error) {
	f, err := os.Open(dev)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Seek(0, 2)
}

// TagGeneration records the claim generation a received content was
// prepared for. TagReceiving marks content prepared by PrepareReceive and
// not sealed yet; Seal removes it in the same change that adds TagSealed,
// so a sealed tag copied from a snapshot parent is never mistaken for a
// sealed received snapshot.
const (
	TagGeneration = "blip.generation"
	TagReceiving  = "blip.receiving"
)

// TagCreating marks a Snapshot whose tags are not fixed yet.
const TagCreating = "blip.creating"

// ReceiveRequest prepares the destination of a captured snapshot.
type ReceiveRequest struct {
	ContentID     string // the new content
	BaseContentID string // local base; "" for a blank (all-zero) LV
	SizeBytes     int64  // size of the new content
	Owner         string
	Generation    int64
}

// PrepareReceive creates the destination LV of a captured snapshot: a thin
// snapshot of the base on this node, or a blank thin LV when there is no
// base. It is unsealed and not exported. It returns a device node the
// caller may use; the compute node writes the snapshot through a
// read-write export.
//
// It is idempotent: an unsealed LV of the same generation is reused. An
// unsealed LV prepared for an older generation is replaced (its write
// was abandoned); one prepared for a newer generation is refused with
// ErrStaleGeneration. Sealed content returns ErrSealed.
func (s *StorageNode) PrepareReceive(ctx context.Context, req ReceiveRequest) (string, error) {
	if err := names.Check("content ID", req.ContentID); err != nil {
		return "", err
	}
	if req.SizeBytes <= 0 {
		return "", fmt.Errorf("receive %s: bad size %d", req.ContentID, req.SizeBytes)
	}
	tags := append(kindTags("content", req.Owner), fmt.Sprintf("%s=%d", TagGeneration, req.Generation), TagReceiving)
	lv, err := s.get(ctx, req.ContentID)
	switch {
	case err == nil && sealed(lv):
		return "", fmt.Errorf("receive %s: %w", req.ContentID, ErrSealed)
	case err == nil:
		var have int64
		fmt.Sscan(lv.TagValue(TagGeneration), &have)
		switch {
		case have > req.Generation:
			return "", fmt.Errorf("receive %s prepared for generation %d, got %d: %w", req.ContentID, have, req.Generation, ErrStaleGeneration)
		case have == req.Generation && lv.Size == req.SizeBytes && lv.TagValue(TagGeneration) != "":
			// Fix tags an interrupted earlier call copied from the base.
			if err := s.setTags(ctx, req.ContentID, tags); err != nil {
				return "", err
			}
			return s.devPath(ctx, req.ContentID)
		}
		if err := s.Delete(ctx, req.ContentID); err != nil {
			return "", err
		}
	case !errors.Is(err, ErrNotFound):
		return "", err
	}
	if req.BaseContentID == "" {
		if err := s.lvm.CreateThin(ctx, names.LV(req.ContentID), req.SizeBytes, tags); err != nil {
			return "", err
		}
		return s.devPath(ctx, req.ContentID)
	}
	base, err := s.get(ctx, req.BaseContentID)
	if err != nil {
		return "", err
	}
	if base.Size != req.SizeBytes {
		return "", fmt.Errorf("receive %s: base %s has %d bytes, want %d", req.ContentID, req.BaseContentID, base.Size, req.SizeBytes)
	}
	if err := s.lvm.Snapshot(ctx, base.Name, names.LV(req.ContentID), tags); err != nil {
		return "", err
	}
	if err := s.setTags(ctx, req.ContentID, tags); err != nil {
		return "", err
	}
	return s.devPath(ctx, req.ContentID)
}

// DevicePath activates the content and returns a device node for it.
func (s *StorageNode) DevicePath(ctx context.Context, id string) (string, error) {
	return s.devPath(ctx, id)
}
