package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmehost"
)

// AttachRequest attaches the sealed content of a BlipVol to an allocation.
type AttachRequest struct {
	AllocID      string
	AttachmentID string
	// Generation is the BlipVol claim generation. It is recorded and
	// reported, not checked: the node fences stale commands.
	Generation int64
	UID        string // BlipVol UID: name of the host link
	ContentID  string // sealed input content
	// SizeBytes, if not 0, must equal the size of the replica exports.
	SizeBytes int64
	// Slot and SlotDisk select the slot disk that maps the overlay. An
	// empty Slot maps no slot disk.
	Slot     string
	SlotDisk int
	Replicas []Remote // read-only exports of the content, one per replica
	PSK      []byte   // this node's PSK
}

// SnapState is the state of a local snapshot.
type SnapState string

const (
	SnapCreating SnapState = "Creating" // interrupted capture; removed by Rescan
	SnapReady    SnapState = "Ready"    // device active
	SnapHidden   SnapState = "Hidden"   // in the pool, without a device
	SnapDeleting SnapState = "Deleting"
)

// LocalSnap is a local snapshot of an overlay.
type LocalSnap struct {
	Seq    int64
	ThinID uint32
	Dev    devnode.Dev
	State  SnapState
}

// AttachmentState is one attachment of an allocation.
type AttachmentState struct {
	UID        string
	Generation int64
	ContentID  string // input content
	ThinID     uint32 // overlay; 0 if the overlay does not exist
	Dev        devnode.Dev
	Sectors    int64
	// Slot and SlotDisk are the slot disk mapping the overlay (SlotDisk
	// -1 if none).
	Slot     string
	SlotDisk int
	// OriginDev is the read-only multipath device; Origin its paths.
	OriginDev  devnode.Dev
	Origin     []dm.MultipathPath
	LocalSnaps []LocalSnap // by Seq
	// Replicas are the content exports recorded by the last Attach.
	Replicas []Remote
	// HostLink is the host link to the overlay device, if any.
	HostLink string
}

// AllocationState is one allocation with its attachments.
type AllocationState struct {
	Slot        string
	Attachments map[string]AttachmentState
}

// SlotDisk is one disk of a slot.
type SlotDisk struct {
	Dev devnode.Dev
	// AllocID and AttachmentID are the overlay the disk maps, empty for
	// the error target.
	AllocID, AttachmentID string
}

// ComputeState is everything Rescan finds.
type ComputeState struct {
	Pool bool
	// PoolStatus counts every block of the pool, local snapshots
	// included.
	PoolStatus  dm.PoolStatus
	Allocations map[string]AllocationState
	Slots       map[string][]SlotDisk // slot ID -> disks by index
	// LocalSnapshots is the number of local snapshots on the node.
	LocalSnapshots int
	// UnknownThins are thin IDs in the pool that have neither a device nor
	// a journal entry. They are kept until DeleteThins is called for them.
	UnknownThins []uint32
	// Resumed lists devices Rescan found suspended and resumed.
	Resumed []string
}

func checkAttNames(node, allocID, attID string) error {
	if err := names.Check("allocation ID", allocID); err != nil {
		return err
	}
	if err := names.Check("attachment ID", attID); err != nil {
		return err
	}
	// The longest name: a local snapshot with the largest thin ID and a
	// long sequence number.
	return names.CheckDM(names.LocalSnap(node, dm.MaxThinID, allocID, attID, 1<<40))
}

// Attach connects to every replica of the content, builds the read-only
// origin multipath device over them, creates the overlay (a local thin
// device with the origin as external origin), maps the slot disk onto it
// and creates the host link. At least one replica must connect. Attach is
// idempotent: an existing overlay is reused.
func (c *ComputeNode) Attach(ctx context.Context, req AttachRequest) (AttachmentState, error) {
	if err := checkAttNames(c.cfg.Node, req.AllocID, req.AttachmentID); err != nil {
		return AttachmentState{}, err
	}
	if err := names.Check("content ID", req.ContentID); err != nil {
		return AttachmentState{}, err
	}
	if req.UID != "" && (strings.ContainsAny(req.UID, "/\x00") || req.UID == "." || req.UID == "..") {
		return AttachmentState{}, fmt.Errorf("invalid UID %q", req.UID)
	}
	if req.Slot != "" {
		if err := names.Check("slot ID", req.Slot); err != nil {
			return AttachmentState{}, err
		}
		if req.SlotDisk < 0 || req.SlotDisk >= c.cfg.DisksPerSlot {
			return AttachmentState{}, fmt.Errorf("slot disk %d out of range", req.SlotDisk)
		}
	} else {
		req.SlotDisk = -1
	}
	k := attKey(req.AllocID, req.AttachmentID)

	// Record the attachment (and its generation) first, and reuse an
	// existing overlay.
	c.mu.Lock()
	st, done, err := c.attachRecord(ctx, req)
	c.mu.Unlock()
	if done || err != nil {
		return st, err
	}

	// Connect without the lock: it can take seconds.
	var paths []path
	var errs []error
	for _, r := range req.Replicas {
		p, err := c.host.connect(ctx, r, req.PSK)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		err := fmt.Errorf("no replica of content %s connected: %w", req.ContentID, errors.Join(errs...))
		c.mu.Lock()
		defer c.mu.Unlock()
		if j, jerr := c.journal(); jerr == nil && j.Attachments[k] == nil {
			// A release in between disconnected what we connected.
			err = fmt.Errorf("attachment %s was released during attach: %w", k, ErrNotFound)
		}
		return AttachmentState{}, err
	}
	sectors := paths[0].NS.Sectors
	var devs []devnode.Dev
	for _, p := range paths {
		if p.NS.Sectors != sectors {
			return AttachmentState{}, fmt.Errorf("replica sizes differ: %s has %d sectors, %s has %d",
				paths[0].Remote.Node, sectors, p.Remote.Node, p.NS.Sectors)
		}
		devs = append(devs, p.NS.Dev)
	}
	if req.SizeBytes != 0 && req.SizeBytes != sectors*512 {
		return AttachmentState{}, fmt.Errorf("content %s has %d bytes, want %d", req.ContentID, sectors*512, req.SizeBytes)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.journal()
	if err != nil {
		return AttachmentState{}, err
	}
	e := j.Attachments[k]
	if e == nil {
		// Released while connecting: the release may have disconnected
		// before our connects, so drop them again.
		return AttachmentState{}, errors.Join(fmt.Errorf("attachment %s was released during attach: %w", k, ErrNotFound),
			c.dropUnused(req.ContentID))
	}
	pool, err := c.poolInfo(ctx)
	if err != nil {
		return AttachmentState{}, err
	}
	d, err := c.list(ctx)
	if err != nil {
		return AttachmentState{}, err
	}
	ok, err := c.hasOverlay(ctx, d, k)
	if err != nil {
		return AttachmentState{}, err
	}
	if !ok {
		mpName := names.Origin(c.cfg.Node, req.AllocID, req.AttachmentID)
		table := dm.MultipathTable(sectors, devs)
		mp, err := dm.Create(ctx, mpName, names.DMUUID(mpName), table, true)
		if err != nil {
			return AttachmentState{}, err
		}
		// An origin left by an interrupted Attach may use other paths.
		if err := dm.Reload(ctx, mpName, table); err != nil {
			return AttachmentState{}, err
		}
		e.Sectors = sectors
		id, err := c.createThin(ctx, d, thinEntry{Kind: kindOverlay, AllocID: req.AllocID, AttID: req.AttachmentID},
			func(id uint32) error { return dm.CreateThinID(ctx, names.Pool(c.cfg.Node), id) })
		if err != nil {
			return AttachmentState{}, err
		}
		name := names.Overlay(c.cfg.Node, id, req.AllocID, req.AttachmentID)
		if _, err := dm.Create(ctx, name, names.DMUUID(name), dm.ThinTable(sectors, pool.Dev, id, &mp.Dev), false); err != nil {
			// A failed create may still have made the device.
			return AttachmentState{}, errors.Join(err, c.deleteThin(ctx, id, name))
		}
		if err := c.markLive(id); err != nil {
			return AttachmentState{}, err
		}
		if d, err = c.list(ctx); err != nil {
			return AttachmentState{}, err
		}
	}
	return c.finishAttach(ctx, d, e)
}

// attachRecord records the attachment in the journal. If the overlay
// exists, it finishes the attachment and returns done.
func (c *ComputeNode) attachRecord(ctx context.Context, req AttachRequest) (AttachmentState, bool, error) {
	j, err := c.journal()
	if err != nil {
		return AttachmentState{}, false, err
	}
	k := attKey(req.AllocID, req.AttachmentID)
	e := j.Attachments[k]
	if e == nil {
		e = &attEntry{AllocID: req.AllocID, AttID: req.AttachmentID, UID: req.UID, ContentID: req.ContentID, SlotDisk: -1}
		j.Attachments[k] = e
	}
	if e.ContentID != req.ContentID || e.UID != req.UID {
		return AttachmentState{}, false, fmt.Errorf("attachment %s exists for content %s (uid %q)", k, e.ContentID, e.UID)
	}
	e.Generation, e.Slot, e.SlotDisk, e.Replicas = req.Generation, req.Slot, req.SlotDisk, req.Replicas
	if err := j.save(); err != nil {
		return AttachmentState{}, false, err
	}
	d, err := c.list(ctx)
	if err != nil {
		return AttachmentState{}, false, err
	}
	if ok, err := c.hasOverlay(ctx, d, k); err != nil || !ok {
		return AttachmentState{}, false, err
	}
	st, err := c.finishAttach(ctx, d, e)
	return st, true, err
}

// hasOverlay reports whether attachment k has a usable overlay (see
// settled). c.mu must be held.
func (c *ComputeNode) hasOverlay(ctx context.Context, d *devices, k string) (bool, error) {
	ov, ok := d.overlays[k]
	if !ok {
		return false, nil
	}
	if ok, err := c.settled(ctx, d, ov); err != nil || !ok {
		delete(d.overlays, k)
		return false, err
	}
	return true, nil
}

// settled finishes an interrupted journaled operation on a thin device
// before it is used: a device whose ID is marked deleting is deleted (an
// earlier delete failed half way; Rescan would delete it later anyway),
// and one still marked creating gets marked live (its create got as far
// as making the device). It reports whether the device is usable. c.mu
// must be held.
func (c *ComputeNode) settled(ctx context.Context, d *devices, t thinDev) (bool, error) {
	e := c.j.Thins[t.ThinID]
	switch {
	case e == nil || e.State == thinLive:
		return true, nil
	case e.State == thinCreating:
		return true, c.markLive(t.ThinID)
	}
	if err := c.deleteThin(ctx, t.ThinID, t.Name); err != nil {
		return false, err
	}
	delete(d.thinIDs, t.ThinID)
	return false, nil
}

// finishAttach maps the slot disk and creates the host link.
func (c *ComputeNode) finishAttach(ctx context.Context, d *devices, e *attEntry) (AttachmentState, error) {
	ov := d.overlays[attKey(e.AllocID, e.AttID)]
	sectors, err := devnode.Sectors(ov.Dev)
	if err != nil {
		return AttachmentState{}, err
	}
	if e.Slot != "" && e.SlotDisk >= 0 {
		if err := c.pointSlotDisk(ctx, d, e.Slot, e.SlotDisk, ov.Dev, sectors); err != nil {
			return AttachmentState{}, err
		}
	}
	// An Attach with a new generation may move the overlay to another
	// slot disk (or to none): reset the disks that map it elsewhere.
	for slot, disks := range d.slotDisks {
		for n, i := range disks {
			if slot == e.Slot && n == e.SlotDisk {
				continue
			}
			t, err := slotDiskTarget(ctx, i.Name)
			if err != nil {
				return AttachmentState{}, err
			}
			if t == ov.Dev {
				if err := dm.Reload(ctx, i.Name, dm.ErrorTable(1)); err != nil {
					return AttachmentState{}, err
				}
			}
		}
	}
	if e.UID != "" {
		p, err := devnode.Ensure(c.cfg.DevDir, ov.Name, ov.Dev)
		if err != nil {
			return AttachmentState{}, err
		}
		if err := ensureLink(c.volumeLink(e.UID), p); err != nil {
			return AttachmentState{}, err
		}
	}
	return c.attachmentState(ctx, d, e), nil
}

// attachmentState builds the state of one attachment.
func (c *ComputeNode) attachmentState(ctx context.Context, d *devices, e *attEntry) AttachmentState {
	k := attKey(e.AllocID, e.AttID)
	a := AttachmentState{UID: e.UID, Generation: e.Generation, ContentID: e.ContentID, Sectors: e.Sectors, Slot: e.Slot, SlotDisk: -1,
		Replicas: e.Replicas}
	if ov, ok := d.overlays[k]; ok {
		a.ThinID, a.Dev = ov.ThinID, ov.Dev
		if sz, err := devnode.Sectors(ov.Dev); err == nil {
			a.Sectors = sz
		}
		for slot, disks := range d.slotDisks {
			for n, i := range disks {
				if t, err := slotDiskTarget(ctx, i.Name); err == nil && t == ov.Dev {
					a.Slot, a.SlotDisk = slot, n
				}
			}
		}
		if e.UID != "" {
			if p, err := filepath.EvalSymlinks(c.volumeLink(e.UID)); err == nil && p == filepath.Join(c.cfg.DevDir, ov.Name) {
				a.HostLink = c.volumeLink(e.UID)
			}
		}
	}
	if mp, ok := d.origins[k]; ok {
		a.OriginDev = mp.Dev
		if s, err := dm.Status(ctx, mp.Name); err == nil {
			a.Origin, _ = dm.ParseMultipathStatus(s)
		}
		if a.ContentID == "" {
			var devs []devnode.Dev
			for _, p := range a.Origin {
				devs = append(devs, p.Dev)
			}
			for _, sub := range subsystemsOfDevs(devs) {
				if _, id, _, ok := names.ParseSubsystemNQN(sub); ok {
					a.ContentID = id
				}
			}
		}
	}
	seen := map[int64]bool{}
	for seq, s := range d.snaps[k] {
		a.LocalSnaps = append(a.LocalSnaps, LocalSnap{Seq: seq, ThinID: s.ThinID, Dev: s.Dev, State: SnapReady})
		seen[seq] = true
	}
	if c.j != nil {
		for id, t := range c.j.Thins {
			if t.Kind != kindLocalSnap || t.AllocID != e.AllocID || t.AttID != e.AttID {
				continue
			}
			if _, mapped := d.thinIDs[id]; mapped || seen[t.Seq] {
				continue
			}
			st := SnapHidden
			switch t.State {
			case thinCreating:
				st = SnapCreating
			case thinDeleting:
				st = SnapDeleting
			}
			a.LocalSnaps = append(a.LocalSnaps, LocalSnap{Seq: t.Seq, ThinID: id, State: st})
		}
	}
	sort.Slice(a.LocalSnaps, func(i, j int) bool { return a.LocalSnaps[i].Seq < a.LocalSnaps[j].Seq })
	return a
}

// newThinID returns an ID that is not used anywhere: not in the journal,
// not by a device and not in the pool metadata. c.mu must be held.
func (c *ComputeNode) newThinID(ctx context.Context, d *devices) (uint32, error) {
	meta, err := c.metaPath(ctx)
	if err != nil {
		return 0, err
	}
	pool, err := dm.ThinIDs(ctx, names.Pool(c.cfg.Node), meta)
	if err != nil {
		return 0, err
	}
	used := map[uint32]bool{}
	var top uint32
	add := func(id uint32) {
		used[id] = true
		top = max(top, id)
	}
	for _, id := range pool {
		add(id)
	}
	for id := range d.thinIDs {
		add(id)
	}
	for id := range c.j.Thins {
		add(id)
	}
	if top < dm.MaxThinID {
		return top + 1, nil
	}
	for id := uint32(1); id <= dm.MaxThinID; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("compute pool has no free thin IDs")
}

// createThin records a new thin ID as creating, then calls create (the
// pool message). If create fails, the ID is deleted again. The caller
// makes the device and then calls markLive. c.mu must be held.
func (c *ComputeNode) createThin(ctx context.Context, d *devices, e thinEntry, create func(id uint32) error) (uint32, error) {
	id, err := c.newThinID(ctx, d)
	if err != nil {
		return 0, err
	}
	e.State = thinCreating
	c.j.Thins[id] = &e
	if err := c.j.save(); err != nil {
		delete(c.j.Thins, id)
		return 0, err
	}
	d.thinIDs[id] = "" // reserved for the next newThinID call
	if err := create(id); err != nil {
		return 0, errors.Join(err, c.deleteThin(context.WithoutCancel(ctx), id, ""))
	}
	return id, nil
}

// markLive marks a created thin ID live. c.mu must be held.
func (c *ComputeNode) markLive(ids ...uint32) error {
	for _, id := range ids {
		if e := c.j.Thins[id]; e != nil {
			e.State = thinLive
		}
	}
	return c.j.save()
}

// deleteThin removes the device name (if not empty) and deletes thin ID
// id from the pool, journaling the intent first. c.mu must be held.
func (c *ComputeNode) deleteThin(ctx context.Context, id uint32, name string) error {
	if e := c.j.Thins[id]; e != nil && e.State != thinDeleting {
		e.State = thinDeleting
		if err := c.j.save(); err != nil {
			return err
		}
	}
	if name != "" {
		if err := dm.Remove(ctx, name); err != nil {
			return err
		}
		if err := devnode.Remove(c.cfg.DevDir, name); err != nil {
			return err
		}
	}
	if err := dm.DeleteThinID(ctx, names.Pool(c.cfg.Node), id); err != nil {
		return err
	}
	delete(c.j.Thins, id)
	return c.j.save()
}

// ReleaseAttachment removes everything of an attachment: slot disk
// mappings (back to the error target), the host link, local snapshots,
// the overlay, the origin multipath device and, if no other attachment
// uses the content, the NVMe connections and keys. A missing attachment is
// not an error.
func (c *ComputeNode) ReleaseAttachment(ctx context.Context, allocID, attID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.journal(); err != nil {
		return err
	}
	d, err := c.list(ctx)
	if err != nil {
		return err
	}
	return c.release(ctx, d, allocID, attID)
}

// Cleanup releases every attachment of an allocation. A missing
// allocation is not an error.
func (c *ComputeNode) Cleanup(ctx context.Context, allocID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.journal()
	if err != nil {
		return err
	}
	d, err := c.list(ctx)
	if err != nil {
		return err
	}
	atts := map[string]bool{}
	for _, e := range j.Attachments {
		if e.AllocID == allocID {
			atts[e.AttID] = true
		}
	}
	for _, e := range j.Thins {
		if e.AllocID == allocID {
			atts[e.AttID] = true
		}
	}
	for _, i := range d.all {
		if n, ok := names.ParseDM(c.cfg.Node, i.Name); ok && n.AllocID == allocID {
			atts[n.AttID] = true
		}
	}
	var errs []error
	for _, att := range sortedKeys(atts) {
		errs = append(errs, c.release(ctx, d, allocID, att))
	}
	return errors.Join(errs...)
}

// release does the work of ReleaseAttachment. c.mu must be held.
func (c *ComputeNode) release(ctx context.Context, d *devices, allocID, attID string) error {
	k := attKey(allocID, attID)
	e := c.j.Attachments[k]
	devs := map[devnode.Dev]bool{}
	if ov, ok := d.overlays[k]; ok {
		devs[ov.Dev] = true
	}
	for _, s := range d.snaps[k] {
		devs[s.Dev] = true
	}
	if err := c.resetSlotDisks(ctx, d, devs); err != nil {
		return err
	}
	if e != nil && e.UID != "" {
		if ov, ok := d.overlays[k]; ok {
			if err := removeLinkTo(c.volumeLink(e.UID), filepath.Join(c.cfg.DevDir, ov.Name)); err != nil {
				return err
			}
		}
	}
	// Local snapshots first, then the overlay.
	var ids []uint32
	for id, t := range c.j.Thins {
		if t.AllocID == allocID && t.AttID == attID {
			ids = append(ids, id)
		}
	}
	for _, s := range d.snaps[k] {
		ids = append(ids, s.ThinID)
	}
	if ov, ok := d.overlays[k]; ok {
		ids = append(ids, ov.ThinID)
	}
	sort.Slice(ids, func(a, b int) bool {
		// snapshots before the overlay
		ka, kb := c.thinKind(d, ids[a]), c.thinKind(d, ids[b])
		if ka != kb {
			return ka == kindLocalSnap
		}
		return ids[a] < ids[b]
	})
	done := map[uint32]bool{}
	for _, id := range ids {
		if done[id] {
			continue
		}
		done[id] = true
		if err := c.deleteThin(ctx, id, d.thinIDs[id]); err != nil {
			return err
		}
	}
	contentID := ""
	if e != nil {
		contentID = e.ContentID
	}
	if mp, ok := d.origins[k]; ok {
		if contentID == "" {
			if s, err := dm.Status(ctx, mp.Name); err == nil {
				ps, _ := dm.ParseMultipathStatus(s)
				var pd []devnode.Dev
				for _, p := range ps {
					pd = append(pd, p.Dev)
				}
				for _, sub := range subsystemsOfDevs(pd) {
					if _, id, _, ok := names.ParseSubsystemNQN(sub); ok {
						contentID = id
					}
				}
			}
		}
		if err := dm.Remove(ctx, mp.Name); err != nil {
			return err
		}
		delete(d.origins, k)
	}
	delete(d.overlays, k)
	delete(d.snaps, k)
	// Disconnect before forgetting the attachment: its entry is the only
	// record of the content once the origin is gone, so a retry after a
	// failed disconnect must still find it.
	if contentID != "" && !c.contentInUse(contentID, k) {
		if err := c.disconnectContent(contentID); err != nil {
			return err
		}
	}
	delete(c.j.Attachments, k)
	return c.j.save()
}

// dropUnused disconnects a content that no attachment reads. c.mu must
// be held.
func (c *ComputeNode) dropUnused(contentID string) error {
	if contentID == "" || c.contentInUse(contentID, "") {
		return nil
	}
	return c.disconnectContent(contentID)
}

// contentInUse reports whether an attachment other than k reads the
// content. c.mu must be held.
func (c *ComputeNode) contentInUse(contentID, k string) bool {
	for ok, o := range c.j.Attachments {
		if ok != k && o.ContentID == contentID {
			return true
		}
	}
	return false
}

func (c *ComputeNode) thinKind(d *devices, id uint32) thinKind {
	if e := c.j.Thins[id]; e != nil {
		return e.Kind
	}
	if n, ok := names.ParseDM(c.cfg.Node, d.thinIDs[id]); ok && n.Kind == names.KindLocalSnap {
		return kindLocalSnap
	}
	return kindOverlay
}

// disconnectContent removes all read-only connections to a content and
// their keys.
func (c *ComputeNode) disconnectContent(contentID string) error {
	cs, err := nvmehost.Controllers()
	if err != nil {
		return err
	}
	var errs []error
	for _, x := range cs {
		if x.HostNQN != c.host.hostNQN {
			continue
		}
		if _, id, rw, ok := names.ParseSubsystemNQN(x.SubNQN); ok && id == contentID && !rw {
			errs = append(errs, c.host.disconnect(x.SubNQN))
		}
	}
	// Keys can outlive controllers (for example after ctrl_loss_tmo).
	kr, err := keyring()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	// Only read-only keys: a storage node with the same name may hold a
	// read-write connection (WriteExtents) to the content.
	errs = append(errs, removeHostKeys(kr, c.host.hostNQN, func(sub string) bool {
		_, id, rw, ok := names.ParseSubsystemNQN(sub)
		return ok && id == contentID && !rw
	}))
	return errors.Join(errs...)
}

// ReinstatePaths marks failed origin paths active again when their NVMe
// controller is live. Without multipathd nothing else does this.
func (c *ComputeNode) ReinstatePaths(ctx context.Context, allocID, attID string) (int, error) {
	name := names.Origin(c.cfg.Node, allocID, attID)
	s, err := dm.Status(ctx, name)
	if err != nil {
		return 0, err
	}
	ps, err := dm.ParseMultipathStatus(s)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range ps {
		if p.Active || !pathLive(p.Dev) {
			continue
		}
		if err := dm.ReinstatePath(ctx, name, p.Dev); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// pathLive reports whether an NVMe namespace has a live controller.
func pathLive(d devnode.Dev) bool {
	cs, err := nvmehost.Controllers()
	if err != nil {
		return false
	}
	subs := subsystemsOfDevs([]devnode.Dev{d})
	for _, c := range cs {
		for _, s := range subs {
			if c.SubNQN == s && c.State == "live" {
				return true
			}
		}
	}
	return false
}

// RefreshPaths repairs the origin of an attachment: it connects again to
// replicas whose controller is gone (after ctrl_loss_tmo), puts every
// connected path into the table, and reinstates failed paths whose
// controller is live. It uses AllocID, AttachmentID, ContentID, Replicas
// and PSK of req, and returns the number of active paths.
func (c *ComputeNode) RefreshPaths(ctx context.Context, req AttachRequest) (int, error) {
	name := names.Origin(c.cfg.Node, req.AllocID, req.AttachmentID)
	cur, err := dm.Table(ctx, name)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(cur)
	if len(f) < 2 {
		return 0, fmt.Errorf("bad multipath table %q", cur)
	}
	sectors, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0, err
	}
	var devs []devnode.Dev
	for _, r := range req.Replicas {
		p, err := c.host.connect(ctx, r, req.PSK)
		if err != nil || p.NS.Sectors != sectors {
			continue
		}
		devs = append(devs, p.NS.Dev)
	}
	// The attachment may have been released while we connected.
	c.mu.Lock()
	j, err := c.journal()
	if err == nil && j.Attachments[attKey(req.AllocID, req.AttachmentID)] == nil {
		err = errors.Join(fmt.Errorf("attachment %s/%s was released: %w", req.AllocID, req.AttachmentID, ErrNotFound),
			c.dropUnused(req.ContentID))
	}
	if err == nil && len(devs) > 0 {
		if t := dm.MultipathTable(sectors, devs); t != cur {
			err = dm.Reload(ctx, name, t)
		}
	}
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if _, err := c.ReinstatePaths(ctx, req.AllocID, req.AttachmentID); err != nil {
		return 0, err
	}
	s, err := dm.Status(ctx, name)
	if err != nil {
		return 0, err
	}
	ps, err := dm.ParseMultipathStatus(s)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range ps {
		if p.Active {
			n++
		}
	}
	return n, nil
}
