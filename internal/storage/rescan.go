package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/names"
)

// Rescan rebuilds the state from device-mapper devices and the journal,
// for example after a daemon restart. It also recovers from a crash:
//
//   - devices of this node found suspended (an interrupted CaptureLocal)
//     are resumed;
//   - thin IDs the journal marks creating without a device, or deleting,
//     are deleted (their operation did not finish; callers retry);
//   - live thin IDs whose device is gone get their device back if the
//     attachment's origin still exists (snapshots read-only).
//
// Thin IDs found only in the pool metadata are reported in UnknownThins
// and never deleted here.
func (c *ComputeNode) Rescan(ctx context.Context) (ComputeState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.journal()
	if err != nil {
		return ComputeState{}, err
	}
	d, err := c.list(ctx)
	if err != nil {
		return ComputeState{}, err
	}
	st := ComputeState{Allocations: map[string]AllocationState{}, Slots: map[string][]SlotDisk{}}
	var errs []error
	for _, i := range d.all {
		if i.Suspended {
			if err := dm.Resume(ctx, i.Name); err != nil {
				errs = append(errs, fmt.Errorf("resume %s: %w", i.Name, err))
				continue
			}
			st.Resumed = append(st.Resumed, i.Name)
		}
	}
	if d.pool != nil {
		st.Pool = true
		st.PoolStatus, _ = dm.GetPoolStatus(ctx, d.pool.Name)
		if err := c.recover(ctx, d); err != nil {
			errs = append(errs, err)
		}
		if d, err = c.list(ctx); err != nil {
			return ComputeState{}, err
		}
		if meta, err := c.metaPath(ctx); err == nil {
			ids, err := dm.ThinIDs(ctx, d.pool.Name, meta)
			if err != nil {
				errs = append(errs, err)
			}
			for _, id := range ids {
				if _, ok := d.thinIDs[id]; !ok && j.Thins[id] == nil {
					st.UnknownThins = append(st.UnknownThins, id)
				}
			}
		}
	}

	// Attachments: from the journal, plus devices the journal does not
	// know (for example after the journal was lost).
	entries := map[string]*attEntry{}
	for k, e := range j.Attachments {
		entries[k] = e
	}
	addDev := func(allocID, attID string) {
		if _, ok := entries[attKey(allocID, attID)]; !ok {
			entries[attKey(allocID, attID)] = &attEntry{AllocID: allocID, AttID: attID, SlotDisk: -1}
		}
	}
	for _, i := range d.all {
		if n, ok := names.ParseDM(c.cfg.Node, i.Name); ok && n.AllocID != "" {
			addDev(n.AllocID, n.AttID)
		}
	}
	for _, e := range j.Thins {
		addDev(e.AllocID, e.AttID)
	}
	byDev := map[devnode.Dev][2]string{}
	for _, k := range sortedKeys(entries) {
		e := entries[k]
		a := c.attachmentState(ctx, d, e)
		al := st.Allocations[e.AllocID]
		if al.Attachments == nil {
			al.Attachments = map[string]AttachmentState{}
		}
		if al.Slot == "" {
			al.Slot = a.Slot
		}
		al.Attachments[e.AttID] = a
		st.Allocations[e.AllocID] = al
		st.LocalSnapshots += len(a.LocalSnaps)
		if a.Dev != (devnode.Dev{}) {
			byDev[a.Dev] = [2]string{e.AllocID, e.AttID}
		}
	}
	for slot, disks := range d.slotDisks {
		n := 0
		for i := range disks {
			n = max(n, i+1)
		}
		out := make([]SlotDisk, n)
		for i, info := range disks {
			out[i].Dev = info.Dev
			if t, err := slotDiskTarget(ctx, info.Name); err == nil {
				if a, ok := byDev[t]; ok {
					out[i].AllocID, out[i].AttachmentID = a[0], a[1]
				}
			}
		}
		st.Slots[slot] = out
	}
	return st, errors.Join(errs...)
}

// recover finishes or rolls back journaled thin operations. c.mu must be
// held.
func (c *ComputeNode) recover(ctx context.Context, d *devices) error {
	pool, err := c.poolInfo(ctx)
	if err != nil {
		return err
	}
	ids := make([]uint32, 0, len(c.j.Thins))
	for id := range c.j.Thins {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	var errs []error
	for _, id := range ids {
		e := c.j.Thins[id]
		name, mapped := d.thinIDs[id]
		switch {
		case e.State == thinCreating && mapped:
			e.State = thinLive
			errs = append(errs, c.j.save())
		case e.State == thinCreating || e.State == thinDeleting:
			errs = append(errs, c.deleteThin(ctx, id, name))
		case e.State == thinLive && !mapped:
			errs = append(errs, c.reactivate(ctx, d, pool.Dev, id, e))
		}
	}
	return errors.Join(errs...)
}

// reactivate creates the device of a live thin whose device is gone, if
// its origin still exists.
func (c *ComputeNode) reactivate(ctx context.Context, d *devices, pool devnode.Dev, id uint32, e *thinEntry) error {
	mp, ok := d.origins[attKey(e.AllocID, e.AttID)]
	if !ok {
		return nil // reported as hidden; released with the attachment
	}
	sectors, err := devnode.Sectors(mp.Dev)
	if err != nil {
		return err
	}
	name := names.Overlay(c.cfg.Node, id, e.AllocID, e.AttID)
	ro := false
	if e.Kind == kindLocalSnap {
		name, ro = names.LocalSnap(c.cfg.Node, id, e.AllocID, e.AttID, e.Seq), true
	} else if _, ok := d.overlays[attKey(e.AllocID, e.AttID)]; ok {
		return fmt.Errorf("thin %d: attachment %s/%s has another overlay", id, e.AllocID, e.AttID)
	}
	_, err = dm.Create(ctx, name, names.DMUUID(name), dm.ThinTable(sectors, pool, id, &mp.Dev), ro)
	return err
}

// DeleteThins deletes pool thin IDs that have neither a device nor a
// journal entry, after the caller decided they belong to nobody (see
// ComputeState.UnknownThins). IDs in use are refused.
func (c *ComputeNode) DeleteThins(ctx context.Context, ids []uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.journal(); err != nil {
		return err
	}
	d, err := c.list(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if name, ok := d.thinIDs[id]; ok {
			errs = append(errs, fmt.Errorf("thin %d is in use by %s", id, name))
			continue
		}
		if e := c.j.Thins[id]; e != nil && e.State == thinLive {
			errs = append(errs, fmt.Errorf("thin %d belongs to %s/%s", id, e.AllocID, e.AttID))
			continue
		}
		errs = append(errs, c.deleteThin(ctx, id, ""))
	}
	return errors.Join(errs...)
}
