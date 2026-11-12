package node

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/example/blip/internal/meta"
	"github.com/example/blip/internal/storage/extent"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/example/blip/internal/api"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/slot/chapi"
	"github.com/example/blip/internal/storage"
)

// maxSerial is the length limit of a virtio-blk serial. The attachment
// name is the serial of the volume's disk.
const maxSerial = 20

// ---------------------------------------------------------------------------
// Generations
//
// The node daemon is the only layer that fences generations: it sees
// every command before any side effect (hot-plug, slot links, storage),
// and it knows each attachment's generation from the allocation record.
// For new attachments it also remembers, per BlipVol UID, the highest
// claim generation it has seen (node.json, boot-scoped like the overlays
// it protects). The storage layer records generations but does not
// check them.

// noteGen records gen for uid if it is the highest seen.
func (n *Node) noteGen(uid string, gen int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if gen <= n.gens[uid] {
		return nil
	}
	n.gens[uid] = gen
	return n.saveState()
}

func (n *Node) uidGen(uid string) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gens[uid]
}

func staleGen(what string, have, got int64) error {
	return rejectCode(pb.ErrorCode_ERROR_CODE_STALE_GENERATION, "%s has generation %d, command has %d", what, have, got)
}

// checkAttGen applies the generation rules to a known attachment.
func checkAttGen(at *attRecord, gen int64) error {
	switch {
	case gen < at.Generation:
		return staleGen("attachment "+at.ID, at.Generation, gen)
	case gen > at.Generation:
		return rejectCode(pb.ErrorCode_ERROR_CODE_CONFLICT, "attachment %s has generation %d, command has %d", at.ID, at.Generation, gen)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Slot links

func (n *Node) slotLinkPath(slotID, uid string) string {
	return slot.VolumePath(n.slotDir(slotID), uid)
}

// slotDiskPath is the path of slot disk i inside the slot container.
func (n *Node) slotDiskPath(slotID string, i int) string {
	if n.cfg.SlotDiskPath != nil {
		return n.cfg.SlotDiskPath(slotID, i)
	}
	return fmt.Sprintf("%s/%d", ContainerDiskDir, i)
}

// ensureSlotLink makes <slotDir>/volumes/<uid> point at slot disk i.
func (n *Node) ensureSlotLink(slotID, uid string, i int) error {
	p := n.slotLinkPath(slotID, uid)
	want := n.slotDiskPath(slotID, i)
	if cur, err := os.Readlink(p); err == nil && cur == want {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(want, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (n *Node) removeSlotLink(slotID, uid string) {
	if slotID == "" || uid == "" {
		return
	}
	if err := os.Remove(n.slotLinkPath(slotID, uid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("remove slot link %s: %v", n.slotLinkPath(slotID, uid), err)
	}
}

// containerVolumePath is what Cloud Hypervisor opens for a volume.
func (n *Node) containerVolumePath(slotID, uid string) string {
	return slot.VolumePath(n.cfg.ContainerRunDir, uid)
}

// slotDiskHostPath returns the host device of slot disk i.
func (n *Node) slotDiskHostPath(ctx context.Context, slotID string, i int) (string, error) {
	ds, err := n.st.SlotDisks(ctx, slotID)
	if err != nil {
		return "", err
	}
	if i < 0 || i >= len(ds) {
		return "", fmt.Errorf("slot %s has %d disks, no disk %d", slotID, len(ds), i)
	}
	return ds[i], nil
}

// ---------------------------------------------------------------------------
// Attach and detach

func attResult(at *attRecord) *pb.AttachVolumeResult {
	return &pb.AttachVolumeResult{GuestPath: at.GuestPath, HostPath: at.HostPath}
}

// uidOwner returns the attachment that uses uid on this node, if any.
func (n *Node) uidOwner(uid string) (allocID, attID string) {
	n.mu.Lock()
	as := make([]*alloc, 0, len(n.allocs))
	for _, a := range n.allocs {
		as = append(as, a)
	}
	n.mu.Unlock()
	for _, a := range as {
		a.mu.Lock()
		for id, at := range a.rec.Attachments {
			if at.UID == uid {
				allocID, attID = a.rec.ID, id
			}
		}
		a.mu.Unlock()
		if attID != "" {
			return
		}
	}
	return "", ""
}

// AttachVolume attaches a BlipVol to the VM of an allocation: storage
// (origin, overlay, slot disk, host link), slot link, Cloud Hypervisor
// hot-plug, and the metadata disk volume list once started. Every step
// is idempotent.
func (n *Node) AttachVolume(ctx context.Context, c *pb.AttachVolume) (*pb.AttachVolumeResult, error) {
	switch {
	case c.AllocationId == "" || c.AttachmentId == "" || c.Uid == "" || c.Name == "" || c.ContentId == "":
		return nil, rejectf("attach volume: allocation_id, attachment_id, uid, name and content_id are required")
	case len(c.Name) > maxSerial:
		return nil, rejectf("attach volume: name %q is longer than %d bytes (virtio-blk serial)", c.Name, maxSerial)
	case c.Name == meta.Serial:
		return nil, rejectf("attach volume: name %q is reserved for the metadata disk", c.Name)
	case c.SlotDisk < 0 || int(c.SlotDisk) >= n.disksPerSlot():
		return nil, rejectf("attach volume: slot_disk %d out of range [0,%d)", c.SlotDisk, n.disksPerSlot())
	case len(c.OriginPaths) == 0:
		return nil, Codef(pb.ErrorCode_ERROR_CODE_NOT_ENOUGH_REPLICAS, "attach volume %s: no origin paths", c.AttachmentId)
	}
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return nil, err
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	if !r.Assigned {
		return nil, rejectf("allocation %s has no slot assigned", r.ID)
	}
	if r.vmGone() {
		return nil, rejectf("allocation %s has ended", r.ID)
	}
	at := r.Attachments[c.AttachmentId]
	if at != nil {
		if err := checkAttGen(at, c.Generation); err != nil {
			return nil, err
		}
		if at.UID != c.Uid || at.SlotDisk != int(c.SlotDisk) || at.ContentID != c.ContentId || at.Name != c.Name {
			return nil, rejectCode(pb.ErrorCode_ERROR_CODE_CONFLICT, "attachment %s exists with uid %s, content %s, slot disk %d", at.ID, at.UID, at.ContentID, at.SlotDisk)
		}
		if at.State == pb.AttachmentState_ATTACHMENT_STATE_RELEASING {
			return nil, rejectf("attachment %s is being released", at.ID)
		}
		if at.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHED {
			return attResult(at), nil
		}
	} else {
		if have := n.uidGen(c.Uid); c.Generation < have {
			return nil, staleGen("BlipVol "+c.Uid, have, c.Generation)
		}
		for _, o := range r.Attachments {
			// A detached attachment no longer maps its slot disk.
			busy := o.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHING || o.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHED
			if busy && o.SlotDisk == int(c.SlotDisk) {
				return nil, rejectCode(pb.ErrorCode_ERROR_CODE_CONFLICT, "slot disk %d is used by attachment %s", c.SlotDisk, o.ID)
			}
		}
		if oa, oid := n.uidOwner(c.Uid); oid != "" {
			return nil, rejectCode(pb.ErrorCode_ERROR_CODE_CONFLICT, "BlipVol %s is attached as %s of allocation %s", c.Uid, oid, oa)
		}
		at = &attRecord{
			ID: c.AttachmentId, UID: c.Uid, Name: c.Name, Generation: c.Generation, ContentID: c.ContentId,
			SizeBytes: c.SizeBytes, SlotDisk: int(c.SlotDisk), State: pb.AttachmentState_ATTACHMENT_STATE_ATTACHING,
			BlipVol: PodRef{Namespace: c.GetBlipvol().GetNamespace(), Name: c.GetBlipvol().GetName(), UID: c.GetBlipvol().GetUid()},
		}
		if err := n.noteGen(c.Uid, c.Generation); err != nil {
			return nil, err
		}
	}
	at.Paths = c.OriginPaths
	a.update(func(r *allocRecord) { r.Attachments[at.ID] = at.clone() })
	if err := n.persist(a); err != nil {
		return nil, err
	}

	hostPath, err := n.st.AttachVolume(ctx, VolumeSpec{
		AllocationID: r.ID, AttachmentID: at.ID, Generation: at.Generation, UID: at.UID, ContentID: at.ContentID,
		SizeBytes: at.SizeBytes, SlotID: r.SlotID, SlotDisk: at.SlotDisk, Paths: c.OriginPaths,
	})
	if err != nil {
		return nil, fmt.Errorf("attach storage: %w", err)
	}
	if err := n.ensureSlotLink(r.SlotID, at.UID, at.SlotDisk); err != nil {
		return nil, fmt.Errorf("slot link: %w", err)
	}
	// The virtio serial is the volume name: the guest sees
	// /dev/disk/by-id/virtio-<name>.
	disk := chapi.VolumeDisk(n.containerVolumePath(r.SlotID, at.UID), at.ID, at.Name)
	if err := n.cfg.Hypervisor.AddDisk(ctx, n.slotDir(r.SlotID), disk); err != nil {
		return nil, WithCode(pb.ErrorCode_ERROR_CODE_HOTPLUG, fmt.Errorf("hot-plug: %w", err))
	}
	var res *pb.AttachVolumeResult
	a.update(func(r *allocRecord) {
		x := r.Attachments[at.ID]
		x.HostPath, x.GuestPath = hostPath, api.GuestVolumePath(at.Name)
		x.State = pb.AttachmentState_ATTACHMENT_STATE_ATTACHED
		res = attResult(x)
	})
	if err := n.persist(a); err != nil {
		return nil, err
	}
	if a.record().Started {
		// List it in the metadata disk host slot.
		if err := n.writeMeta(a); err != nil {
			return nil, fmt.Errorf("write metadata disk: %w", err)
		}
	}
	log.Printf("allocation %s: attached %s (BlipVol %s, %s) as slot disk %d", r.ID, at.ID, at.UID, at.Name, at.SlotDisk)
	return res, nil
}

// DetachVolume unplugs an attachment from the VM. The overlay stays for
// the final capture until ReleaseAttachment.
func (n *Node) DetachVolume(ctx context.Context, c *pb.DetachVolume) error {
	if c.AllocationId == "" || c.AttachmentId == "" {
		return rejectf("detach volume: allocation_id and attachment_id are required")
	}
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return err
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	at := r.Attachments[c.AttachmentId]
	if at == nil {
		return nil
	}
	if err := checkAttGen(at, c.Generation); err != nil {
		return err
	}
	switch at.State {
	case pb.AttachmentState_ATTACHMENT_STATE_DETACHED:
		return nil
	case pb.AttachmentState_ATTACHMENT_STATE_RELEASING:
		return rejectf("attachment %s is being released", at.ID)
	}
	if !r.vmGone() {
		if at.ID == r.RootAttachmentID {
			return rejectf("attachment %s is the root volume of a running VM", at.ID)
		}
		// Forced: the guest is not asked.
		dev, err := n.slotDiskHostPath(ctx, r.SlotID, at.SlotDisk)
		if err != nil {
			return err
		}
		if err := n.cfg.Hypervisor.RemoveDisk(ctx, n.slotDir(r.SlotID), chapi.VolumeDiskID(at.ID), dev); err != nil {
			// The VM may have gone meanwhile; then the unplug is moot.
			n.checkExit(a)
			if !a.record().vmGone() {
				return WithCode(pb.ErrorCode_ERROR_CODE_HOTPLUG, fmt.Errorf("unplug: %w", err))
			}
		}
	}
	n.removeSlotLink(r.SlotID, at.UID)
	if err := n.st.ResetSlotDisk(ctx, r.SlotID, at.SlotDisk); err != nil {
		return fmt.Errorf("reset slot disk %d: %w", at.SlotDisk, err)
	}
	a.update(func(r *allocRecord) {
		if x := r.Attachments[at.ID]; x != nil {
			x.State = pb.AttachmentState_ATTACHMENT_STATE_DETACHED
		}
	})
	log.Printf("allocation %s: detached %s (BlipVol %s)", r.ID, at.ID, at.UID)
	if err := n.persist(a); err != nil {
		return err
	}
	if rr := a.record(); rr.Started && !rr.vmGone() {
		if err := n.writeMeta(a); err != nil {
			log.Printf("allocation %s: write metadata disk: %v", r.ID, err)
		}
	}
	return nil
}

// finishedOrUnknown returns the allocation, or nil when it is finished
// or unknown (release-type commands then succeed).
func (n *Node) allocOrNil(id string) *alloc {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.finished[id]; ok {
		return nil
	}
	return n.allocs[id]
}

// ReleaseAttachment removes everything of a detached attachment.
func (n *Node) ReleaseAttachment(ctx context.Context, c *pb.ReleaseAttachment) error {
	if c.AllocationId == "" || c.AttachmentId == "" {
		return rejectf("release attachment: allocation_id and attachment_id are required")
	}
	if n.isFinished(c.AllocationId) {
		return nil // Release removed everything.
	}
	a := n.allocOrNil(c.AllocationId)
	if a == nil {
		return n.st.ReleaseAttachment(ctx, c.AllocationId, c.AttachmentId)
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	at := r.Attachments[c.AttachmentId]
	if at == nil {
		return n.st.ReleaseAttachment(ctx, c.AllocationId, c.AttachmentId)
	}
	if err := checkAttGen(at, c.Generation); err != nil {
		return err
	}
	if at.State != pb.AttachmentState_ATTACHMENT_STATE_DETACHED && at.State != pb.AttachmentState_ATTACHMENT_STATE_RELEASING && !r.vmGone() {
		return rejectf("attachment %s is %s; detach it or stop the VM first", at.ID, at.State)
	}
	a.update(func(r *allocRecord) { r.Attachments[at.ID].State = pb.AttachmentState_ATTACHMENT_STATE_RELEASING })
	if err := n.persist(a); err != nil {
		return err
	}
	n.removeSlotLink(r.SlotID, at.UID)
	if err := n.st.ReleaseAttachment(ctx, r.ID, at.ID); err != nil {
		return fmt.Errorf("release storage: %w", err)
	}
	a.update(func(r *allocRecord) {
		delete(r.Attachments, at.ID)
		r.pruneCaptures()
	})
	log.Printf("allocation %s: released attachment %s (BlipVol %s)", r.ID, at.ID, at.UID)
	return n.persist(a)
}

// pruneCaptures drops capture records no attachment has a snapshot of.
func (r *allocRecord) pruneCaptures() {
	for seq := range r.Captures {
		used := false
		for _, at := range r.Attachments {
			if _, ok := at.Snaps[seq]; ok {
				used = true
			}
		}
		if !used {
			delete(r.Captures, seq)
		}
	}
}

// ---------------------------------------------------------------------------
// Local snapshots

// maxLocalSnaps is the local retention per attachment: the last committed
// baseline plus one in-flight capture.
const maxLocalSnaps = 2

// CaptureLocal takes a crash-consistent local snapshot of a set of
// attachments.
func (n *Node) CaptureLocal(ctx context.Context, c *pb.CaptureLocal) (*pb.CaptureLocalResult, error) {
	if c.AllocationId == "" || c.Seq <= 0 || len(c.Attachments) == 0 {
		return nil, rejectf("capture: allocation_id, seq > 0 and attachments are required")
	}
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return nil, err
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	var ids []string
	for _, ref := range c.Attachments {
		at := r.Attachments[ref.AttachmentId]
		if at == nil {
			return nil, Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "attachment %s not found in allocation %s", ref.AttachmentId, r.ID)
		}
		if err := checkAttGen(at, ref.Generation); err != nil {
			return nil, err
		}
		if at.State == pb.AttachmentState_ATTACHMENT_STATE_RELEASING || at.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHING {
			return nil, rejectf("attachment %s is %s", at.ID, at.State)
		}
		if slices.Contains(ids, at.ID) {
			return nil, rejectf("capture: attachment %s listed twice", at.ID)
		}
		ids = append(ids, at.ID)
	}
	sort.Strings(ids)
	if prev, ok := r.Captures[c.Seq]; ok {
		if !slices.Equal(prev, ids) {
			return nil, rejectf("capture %d was taken of attachments %v, not %v", c.Seq, prev, ids)
		}
	} else {
		for _, id := range ids {
			at := r.Attachments[id]
			if len(at.Snaps) >= maxLocalSnaps {
				return nil, Codef(pb.ErrorCode_ERROR_CODE_CONFLICT, "attachment %s already has %d local snapshots", id, len(at.Snaps))
			}
			for s := range at.Snaps {
				if s > c.Seq {
					return nil, rejectf("attachment %s has a newer local snapshot %d than %d", id, s, c.Seq)
				}
			}
		}
		a.update(func(r *allocRecord) { r.Captures[c.Seq] = ids })
		if err := n.persist(a); err != nil {
			return nil, err
		}
	}
	res, err := n.st.CaptureLocal(ctx, r.ID, ids, c.Seq)
	if err != nil {
		if errors.Is(err, storage.ErrSuspendBudget) {
			err = WithCode(pb.ErrorCode_ERROR_CODE_SUSPEND_TIMEOUT, err)
		}
		a.update(func(r *allocRecord) {
			if !r.hasSnap(c.Seq) {
				delete(r.Captures, c.Seq)
			}
		})
		_ = n.persist(a)
		return nil, err
	}
	now := time.Now()
	out := &pb.CaptureLocalResult{Suspended: durationpb.New(res.Suspended)}
	a.update(func(r *allocRecord) {
		for _, id := range ids {
			at := r.Attachments[id]
			if at.Snaps == nil {
				at.Snaps = map[int64]time.Time{}
			}
			t, ok := at.Snaps[c.Seq]
			if !ok {
				t = now
				at.Snaps[c.Seq] = t
			}
			out.Snapshots = append(out.Snapshots, &pb.LocalSnapshotInfo{AttachmentId: id, Seq: c.Seq,
				State: pb.LocalSnapshotState_LOCAL_SNAPSHOT_STATE_READY, Created: timestamppb.New(t)})
		}
	})
	if err := n.persist(a); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *allocRecord) hasSnap(seq int64) bool {
	for _, at := range r.Attachments {
		if _, ok := at.Snaps[seq]; ok {
			return true
		}
	}
	return false
}

// DropLocalSnapshot deletes a local snapshot. Unknown ones succeed.
func (n *Node) DropLocalSnapshot(ctx context.Context, c *pb.DropLocalSnapshot) error {
	if c.AllocationId == "" || c.AttachmentId == "" || c.Seq <= 0 {
		return rejectf("drop local snapshot: allocation_id, attachment_id and seq are required")
	}
	if n.isFinished(c.AllocationId) {
		return nil
	}
	a := n.allocOrNil(c.AllocationId)
	if a == nil {
		return n.st.DropLocalSnapshot(ctx, c.AllocationId, c.AttachmentId, c.Seq)
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	at := r.Attachments[c.AttachmentId]
	if at == nil {
		return nil
	}
	if err := checkAttGen(at, c.Generation); err != nil {
		return err
	}
	if err := n.st.DropLocalSnapshot(ctx, r.ID, at.ID, c.Seq); err != nil {
		return err
	}
	a.update(func(r *allocRecord) {
		delete(r.Attachments[at.ID].Snaps, c.Seq)
		r.pruneCaptures()
	})
	return n.persist(a)
}

// ---------------------------------------------------------------------------
// Snapshot writes

// PrepareReceive creates the unsealed content that receives a captured
// snapshot (storage node).
func (n *Node) PrepareReceive(ctx context.Context, c *pb.PrepareReceive) (*pb.PrepareReceiveResult, error) {
	if n.cfg.NodeConfig.Storage == nil {
		return nil, rejectf("not a storage node")
	}
	if c.ContentId == "" || c.SizeBytes <= 0 {
		return nil, rejectf("prepare receive: content_id and size_bytes are required")
	}
	err := n.st.PrepareReceive(ctx, ReceiveSpec{
		ContentID: c.ContentId, BaseContentID: c.BaseContentId, SizeBytes: c.SizeBytes,
		Owner: c.GetOwner().GetUid(), Generation: c.Generation,
	})
	switch {
	case errors.Is(err, storage.ErrSealed):
		return nil, rejectf("prepare receive %s: %v", c.ContentId, err)
	case err != nil:
		return nil, codeOf(err)
	}
	log.Printf("receive %s (base %q, generation %d) from %s/%s prepared", c.ContentId, c.BaseContentId, c.Generation, c.AllocationId, c.AttachmentId)
	return &pb.PrepareReceiveResult{Ok: true}, nil
}

// WriteSnapshot writes a local snapshot to the read-write exports of the
// target replicas (compute node).
func (n *Node) WriteSnapshot(ctx context.Context, c *pb.WriteSnapshot) (*pb.WriteSnapshotResult, error) {
	if c.AllocationId == "" || c.AttachmentId == "" || c.Seq <= 0 || len(c.Targets) == 0 {
		return nil, rejectf("write snapshot: allocation_id, attachment_id, seq and targets are required")
	}
	if c.BaseSeq < 0 || c.BaseSeq >= c.Seq {
		return nil, rejectf("write snapshot: base_seq %d must be 0 or below seq %d", c.BaseSeq, c.Seq)
	}
	for _, t := range c.Targets {
		if t.Node == "" || t.Address == "" || t.SubsystemNqn == "" {
			return nil, rejectf("write snapshot: target %q needs node, address and subsystem_nqn", t.Node)
		}
	}
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return nil, err
	}
	// Validate under opMu, but do not hold it for the copy.
	a.opMu.Lock()
	r := a.record()
	at := r.Attachments[c.AttachmentId]
	if at == nil {
		a.opMu.Unlock()
		return nil, Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "attachment %s not found in allocation %s", c.AttachmentId, r.ID)
	}
	if err := checkAttGen(at, c.Generation); err != nil {
		a.opMu.Unlock()
		return nil, err
	}
	src, err := n.st.SnapshotSource(ctx, r.ID, at.ID, c.Seq, c.BaseSeq, c.Full)
	a.opMu.Unlock()
	if err != nil {
		return nil, err
	}
	if src.FullResend {
		log.Printf("allocation %s: attachment %s: delta %d..%d impossible; writing the whole device", r.ID, at.ID, c.BaseSeq, c.Seq)
	}
	start := time.Now()
	errs, err := n.st.WriteSnapshot(ctx, r.ID, at.ID, c.Seq, src.Ranges, c.Targets)
	if err != nil {
		return nil, err
	}
	res := &pb.WriteSnapshotResult{ChangedBytes: extent.Total(src.Ranges), FullResend: src.FullResend}
	okN := 0
	for i, t := range c.Targets {
		tr := &pb.TargetResult{Node: t.Node, Ok: true}
		if i < len(errs) && errs[i] != nil {
			tr.Ok, tr.Error = false, errs[i].Error()
			log.Printf("allocation %s: write %s seq %d to %s: %v", r.ID, at.ID, c.Seq, t.Node, errs[i])
		} else {
			okN++
		}
		res.Targets = append(res.Targets, tr)
	}
	n.metrics.snapshotWrite(res.ChangedBytes * int64(okN))
	log.Printf("allocation %s: wrote %s seq %d (base %d, full %v) as %s to %d/%d targets in %s: %d bytes each",
		r.ID, at.ID, c.Seq, c.BaseSeq, src.Full, c.ContentId, okN, len(c.Targets), time.Since(start).Round(time.Millisecond), res.ChangedBytes)
	if okN == 0 {
		return res, Codef(pb.ErrorCode_ERROR_CODE_TRANSFER, "no target written: %s", res.Targets[0].Error)
	}
	return res, nil
}
