package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/names"
)

// CaptureResult is the outcome of CaptureLocal.
type CaptureResult struct {
	// Snaps maps attachment ID to its new local snapshot.
	Snaps map[string]LocalSnap
	// Suspended is how long the overlays were suspended; 0 if the
	// snapshots existed already.
	Suspended time.Duration
}

// CaptureLocal takes a crash-consistent local snapshot seq of a set of
// overlays of one allocation: it suspends all of them (which drains and
// flushes in-flight I/O), creates a thin snapshot of each, resumes all
// and activates the snapshots read-only with the overlay's external
// origin. The guest never pauses; its I/O waits while the overlays are
// suspended. If that takes longer than the suspend budget, everything is
// resumed, the new snapshots are deleted and ErrSuspendBudget is
// returned.
//
// CaptureLocal is idempotent per (allocation, seq): if every attachment
// has snapshot seq, it is returned. Snapshots of seq that exist for only
// some attachments (an interrupted capture) are deleted and taken again,
// so a set is always captured in one suspend window.
func (c *ComputeNode) CaptureLocal(ctx context.Context, allocID string, attIDs []string, seq int64) (CaptureResult, error) {
	if len(attIDs) == 0 {
		return CaptureResult{}, errors.New("capture: no attachments")
	}
	if seq <= 0 {
		return CaptureResult{}, fmt.Errorf("capture: bad sequence %d", seq)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.journal()
	if err != nil {
		return CaptureResult{}, err
	}
	pool, err := c.poolInfo(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	d, err := c.list(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	type member struct {
		att     string
		ov      thinDev
		origin  devnode.Dev
		sectors int64
		snapID  uint32
	}
	var ms []*member
	seen := map[string]bool{}
	complete := true
	for _, attID := range attIDs {
		if err := checkAttNames(c.cfg.Node, allocID, attID); err != nil {
			return CaptureResult{}, err
		}
		if seen[attID] {
			return CaptureResult{}, fmt.Errorf("capture: attachment %s listed twice", attID)
		}
		seen[attID] = true
		k := attKey(allocID, attID)
		ov, ok := d.overlays[k]
		if !ok {
			return CaptureResult{}, fmt.Errorf("overlay of %s: %w", k, ErrNotFound)
		}
		mp, ok := d.origins[k]
		if !ok {
			return CaptureResult{}, fmt.Errorf("origin of %s: %w", k, ErrNotFound)
		}
		sz, err := devnode.Sectors(ov.Dev)
		if err != nil {
			return CaptureResult{}, err
		}
		ms = append(ms, &member{att: attID, ov: ov, origin: mp.Dev, sectors: sz})
		s, ok := d.snaps[k][seq]
		if ok {
			if ok, err = c.settled(ctx, d, s); err != nil {
				return CaptureResult{}, err
			}
		}
		if !ok {
			delete(d.snaps[k], seq)
			complete = false
		}
	}
	res := CaptureResult{Snaps: map[string]LocalSnap{}}
	if complete {
		for _, m := range ms {
			s := d.snaps[attKey(allocID, m.att)][seq]
			res.Snaps[m.att] = LocalSnap{Seq: seq, ThinID: s.ThinID, Dev: s.Dev, State: SnapReady}
		}
		return res, nil
	}
	// Drop what an interrupted capture of seq left.
	for _, m := range ms {
		if err := c.dropSnap(ctx, d, allocID, m.att, seq); err != nil {
			return CaptureResult{}, err
		}
	}
	// Reserve the IDs before suspending anything.
	poolName := names.Pool(c.cfg.Node)
	for _, m := range ms {
		id, err := c.newThinID(ctx, d)
		if err != nil {
			return CaptureResult{}, err
		}
		j.Thins[id] = &thinEntry{State: thinCreating, Kind: kindLocalSnap, AllocID: allocID, AttID: m.att, Seq: seq}
		d.thinIDs[id] = ""
		m.snapID = id
	}
	if err := j.save(); err != nil {
		return CaptureResult{}, err
	}
	abort := func(cause error) (CaptureResult, error) {
		bg := context.WithoutCancel(ctx)
		errs := []error{cause}
		for _, m := range ms {
			errs = append(errs, c.deleteThin(bg, m.snapID, ""))
		}
		return CaptureResult{}, errors.Join(errs...)
	}

	suspended, err := c.snapshotSuspended(ctx, poolName, len(ms), func(i int) string { return ms[i].ov.Name },
		func(sctx context.Context, i int) error {
			return dm.CreateSnapID(sctx, poolName, ms[i].snapID, ms[i].ov.ThinID)
		})
	res.Suspended = suspended
	if err != nil {
		return abort(err)
	}
	var created []string
	for _, m := range ms {
		name := names.LocalSnap(c.cfg.Node, m.snapID, allocID, m.att, seq)
		// Recorded first: a failed create may still have made the device.
		created = append(created, name)
		i, err := dm.Create(ctx, name, names.DMUUID(name), dm.ThinTable(m.sectors, pool.Dev, m.snapID, &m.origin), true)
		if err != nil {
			// Remove the devices made so far; abort deletes the IDs.
			for _, n := range created {
				_ = dm.Remove(context.WithoutCancel(ctx), n)
			}
			return abort(err)
		}
		res.Snaps[m.att] = LocalSnap{Seq: seq, ThinID: m.snapID, Dev: i.Dev, State: SnapReady}
	}
	ids := make([]uint32, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.snapID)
	}
	if err := c.markLive(ids...); err != nil {
		return CaptureResult{}, err
	}
	return res, nil
}

// testSuspendHook, if set, runs while the overlays are suspended.
var testSuspendHook func()

// snapshotSuspended suspends n devices, calls snap for each, and resumes
// them. Resume always runs, also on errors and cancellation. It returns
// how long the first device was suspended, and ErrSuspendBudget if that
// exceeded the budget.
func (c *ComputeNode) snapshotSuspended(ctx context.Context, pool string, n int, name func(int) string, snap func(context.Context, int) error) (time.Duration, error) {
	budget := c.cfg.SuspendBudget
	sctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var suspended []string
	var start time.Time
	// resume resumes every suspended device, trying each a few times: a
	// device left suspended blocks the guest's I/O until a Rescan.
	resume := func() error {
		bg := context.WithoutCancel(ctx)
		var errs []error
		for _, s := range suspended {
			var err error
			for try := 0; try < 3; try++ {
				if err = dm.Resume(bg, s); err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("resume %s: %w", s, err))
			}
		}
		suspended = nil
		return errors.Join(errs...)
	}
	defer func() { _ = resume() }()
	var err error
	for i := range n {
		if i == 0 {
			start = time.Now()
		}
		// Record before suspending: a timed-out dmsetup may still have
		// suspended the device.
		suspended = append(suspended, name(i))
		if err = dm.Suspend(sctx, name(i), false); err != nil {
			break
		}
	}
	if err == nil {
		if testSuspendHook != nil {
			testSuspendHook()
		}
		for i := range n {
			if err = snap(sctx, i); err != nil {
				break
			}
		}
	}
	rerr := resume()
	took := time.Since(start)
	if took > budget {
		err = errors.Join(fmt.Errorf("overlays suspended for %v, budget %v: %w", took.Round(time.Millisecond), budget, ErrSuspendBudget), err)
	}
	return took, errors.Join(err, rerr)
}

// findSnap returns the device of local snapshot seq.
func (c *ComputeNode) findSnap(ctx context.Context, allocID, attID string, seq int64) (thinDev, error) {
	d, err := c.list(ctx)
	if err != nil {
		return thinDev{}, err
	}
	s, ok := d.snaps[attKey(allocID, attID)][seq]
	if !ok {
		return thinDev{}, fmt.Errorf("local snapshot %d of %s/%s: %w", seq, allocID, attID, ErrNotFound)
	}
	return s, nil
}

// LocalSnapshotPath returns a device node for reading local snapshot seq,
// and its size in bytes.
func (c *ComputeNode) LocalSnapshotPath(ctx context.Context, allocID, attID string, seq int64) (string, int64, error) {
	s, err := c.findSnap(ctx, allocID, attID, seq)
	if err != nil {
		return "", 0, err
	}
	sz, err := devnode.Sectors(s.Dev)
	if err != nil {
		return "", 0, err
	}
	p, err := devnode.Ensure(c.cfg.DevDir, s.Name, s.Dev)
	return p, sz * 512, err
}

// WriteLocalSnapshot writes ranges of local snapshot seq of an
// attachment to every remote: read-write exports of content prepared by
// PrepareReceive on the storage nodes. psk is this node's PSK. It
// connects to all remotes, copies in parallel with direct I/O, flushes
// and disconnects. It returns one error (or nil) per remote. Call it in
// the network namespace of the node; c.mu is not held while copying.
func (c *ComputeNode) WriteLocalSnapshot(ctx context.Context, allocID, attID string, seq int64, dsts []Remote, psk []byte, ranges []extent.Range) []error {
	src, _, err := c.LocalSnapshotPath(ctx, allocID, attID, seq)
	if err != nil {
		errs := make([]error, len(dsts))
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	return writeExtents(ctx, c.host, src, dsts, psk, ranges, nil)
}

// LocalDelta returns the byte ranges (64KiB blocks) that differ between
// local snapshots baseSeq and newSeq of an attachment. With baseSeq 0 it
// returns every block written since the origin (all mapped blocks of
// newSeq). If the base has blocks newSeq lacks, it returns ErrLeftOnly
// and the caller sends the whole device.
func (c *ComputeNode) LocalDelta(ctx context.Context, allocID, attID string, newSeq, baseSeq int64) ([]extent.Range, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.findSnap(ctx, allocID, attID, newSeq)
	if err != nil {
		return nil, err
	}
	meta, err := c.metaPath(ctx)
	if err != nil {
		return nil, err
	}
	pool := names.Pool(c.cfg.Node)
	if baseSeq == 0 {
		bs, rs, err := dm.MappedBlocks(ctx, pool, meta, n.ThinID)
		if err != nil {
			return nil, err
		}
		return blocksToRanges(rs, bs), nil
	}
	b, err := c.findSnap(ctx, allocID, attID, baseSeq)
	if err != nil {
		return nil, err
	}
	delta, err := dm.ThinDelta(ctx, pool, meta, b.ThinID, n.ThinID)
	if err != nil {
		return nil, err
	}
	if len(delta.Zero) > 0 {
		return nil, fmt.Errorf("local snapshots %d..%d of %s/%s: %w", baseSeq, newSeq, allocID, attID, ErrLeftOnly)
	}
	return blocksToRanges(delta.Copy, delta.BlockSectors), nil
}

// DropLocalSnapshot deletes local snapshot seq of an attachment: its
// device (if any) and its thin ID. A missing snapshot is not an error.
func (c *ComputeNode) DropLocalSnapshot(ctx context.Context, allocID, attID string, seq int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.journal(); err != nil {
		return err
	}
	d, err := c.list(ctx)
	if err != nil {
		return err
	}
	return c.dropSnap(ctx, d, allocID, attID, seq)
}

// dropSnap deletes every thin of local snapshot seq. c.mu must be held.
func (c *ComputeNode) dropSnap(ctx context.Context, d *devices, allocID, attID string, seq int64) error {
	k := attKey(allocID, attID)
	ids := map[uint32]string{}
	if s, ok := d.snaps[k][seq]; ok {
		ids[s.ThinID] = s.Name
	}
	for id, e := range c.j.Thins {
		if e.Kind == kindLocalSnap && e.AllocID == allocID && e.AttID == attID && e.Seq == seq {
			if _, ok := ids[id]; !ok {
				ids[id] = d.thinIDs[id]
			}
		}
	}
	keys := make([]uint32, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a] < keys[b] })
	for _, id := range keys {
		if err := c.deleteThin(ctx, id, ids[id]); err != nil {
			return err
		}
		delete(d.thinIDs, id)
	}
	delete(d.snaps[k], seq)
	return nil
}
