package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/names"
)

// makeVolume creates sealed content id on every storage node with some
// data, and exports it read-only to tc1.
func (e *env) makeVolume(t *testing.T, ctx context.Context, id string) []Remote {
	t.Helper()
	on(t, "ts1", func() error {
		if _, err := e.storage["ts1"].CreateRoot(ctx, RootRequest{ID: id, Size: itSize}); err != nil {
			return err
		}
		p, err := e.storage["ts1"].DevicePath(ctx, id)
		if err == nil {
			guestWrite(t, p, [][2]int64{{0, 1 << 20}, {32 << 20, 512 << 10}, {200 << 20, 4096}})
		}
		return err
	})
	e.replicate(t, ctx, "ts1", id, []string{"ts2", "ts3"})
	return e.exportRO(t, ctx, id)
}

// send writes local snapshot seq of att (delta against baseSeq) into
// new content id on dsts, prepared from baseContent and exported
// read-write to tc1, and seals it.
func (e *env) send(t *testing.T, ctx context.Context, att string, seq, baseSeq int64, baseContent, id string, dsts []string) {
	t.Helper()
	c := e.compute
	var size int64
	var ranges []extent.Range
	on(t, "tc1", func() (err error) {
		if _, size, err = c.LocalSnapshotPath(ctx, "alloc1", att, seq); err != nil {
			return err
		}
		ranges, err = c.LocalDelta(ctx, "alloc1", att, seq, baseSeq)
		return err
	})
	var remotes []Remote
	for _, n := range dsts {
		on(t, n, func() error {
			p, err := e.storage[n].PrepareReceive(ctx, ReceiveRequest{ContentID: id, BaseContentID: baseContent, SizeBytes: size, Owner: "o", Generation: 1})
			if err != nil {
				return err
			}
			// Again: idempotent.
			if p2, err := e.storage[n].PrepareReceive(ctx, ReceiveRequest{ContentID: id, BaseContentID: baseContent, SizeBytes: size, Owner: "o", Generation: 1}); err != nil || p2 != p {
				return fmt.Errorf("prepare again: %s %v", p2, err)
			}
			r, err := e.storage[n].Export(ctx, id, "tc1", e.psk("tc1"), true)
			remotes = append(remotes, r)
			return err
		})
	}
	on(t, "tc1", func() error {
		noErrs(t, "write snapshot", c.WriteLocalSnapshot(ctx, "alloc1", att, seq, remotes, e.psk("tc1"), ranges))
		return nil
	})
	for _, n := range dsts {
		on(t, n, func() error {
			if err := e.storage[n].Unexport(ctx, id, "tc1", true); err != nil {
				return err
			}
			return e.storage[n].Seal(ctx, id)
		})
	}
}

// writeLoad writes random 4KiB blocks to dev with O_DIRECT until stop is
// closed, and returns the number of writes.
func writeLoad(dev string, stop <-chan struct{}, n *atomic.Int64) error {
	f, err := os.OpenFile(dev, os.O_WRONLY|unix.O_DIRECT, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	defer unix.Munmap(buf)
	r := mrand.New(mrand.NewPCG(1, 2))
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		rand.Read(buf)
		if _, err := f.WriteAt(buf, r.Int64N(itSize/4096)*4096); err != nil {
			return err
		}
		n.Add(1)
	}
}

func TestCaptureAndTransfer(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := e.compute
	ro1 := e.makeVolume(t, ctx, "vol1")
	ro2 := e.makeVolume(t, ctx, "vol2")
	disk0 := e.slotDiskPath(t, ctx, "0", 0)
	disk1 := e.slotDiskPath(t, ctx, "0", 1)
	var ov1 string
	on(t, "tc1", func() error {
		if _, err := c.PreparePool(ctx); err != nil {
			return err
		}
		a1, err := c.Attach(ctx, AttachRequest{AllocID: "alloc1", AttachmentID: "att1", Generation: 1, UID: "u1", ContentID: "vol1",
			Slot: "0", SlotDisk: 0, Replicas: ro1, PSK: e.psk("tc1")})
		if err != nil {
			return err
		}
		if ov1, err = devnode.Ensure(c.cfg.DevDir, "ov1", a1.Dev); err != nil {
			return err
		}
		if _, err := c.Attach(ctx, AttachRequest{AllocID: "alloc1", AttachmentID: "att2", Generation: 1, UID: "u2", ContentID: "vol2",
			Slot: "0", SlotDisk: 1, Replicas: ro2, PSK: e.psk("tc1")}); err != nil {
			return err
		}
		// A second attachment of vol2 cannot take a used slot disk.
		_, err = c.Attach(ctx, AttachRequest{AllocID: "alloc1", AttachmentID: "att3", Generation: 1, ContentID: "vol2",
			Slot: "0", SlotDisk: 0, Replicas: ro2, PSK: e.psk("tc1")})
		if !errors.Is(err, ErrSlotDiskBusy) {
			return fmt.Errorf("busy slot disk: %v", err)
		}
		// Releasing it keeps vol2's connections for att2.
		return c.ReleaseAttachment(ctx, "alloc1", "att3")
	})
	if got := hashDev(t, ctx, disk1); got != e.scrubAll(t, ctx, "vol2", []string{"ts1"}) {
		t.Fatal("att2 lost its origin after releasing att3")
	}

	// 1. Deterministic writes on att1, random load on att2; capture both
	// under load a few times and check the suspend window.
	w1 := [][2]int64{{0, 4096}, {64 << 10, 128 << 10}, {10 << 20, 8192}, {100 << 20, 64 << 10}}
	blocks1 := guestWrite(t, disk0, w1)
	sum1 := hashDev(t, ctx, ov1)
	stop := make(chan struct{})
	var writes atomic.Int64
	var wg sync.WaitGroup
	var loadErr error
	wg.Add(1)
	go func() { defer wg.Done(); loadErr = writeLoad(disk1, stop, &writes) }()
	time.Sleep(200 * time.Millisecond)
	var worst time.Duration
	refs := []string{"att1", "att2"}
	on(t, "tc1", func() error {
		for _, seq := range []int64{1} {
			res, err := c.CaptureLocal(ctx, "alloc1", refs, seq)
			if err != nil {
				return err
			}
			worst = max(worst, res.Suspended)
			if len(res.Snaps) != 2 {
				return fmt.Errorf("capture: %+v", res)
			}
			// Idempotent.
			again, err := c.CaptureLocal(ctx, "alloc1", refs, seq)
			if err != nil || again.Suspended != 0 || again.Snaps["att1"].ThinID != res.Snaps["att1"].ThinID {
				return fmt.Errorf("capture again: %+v %v", again, err)
			}
		}
		return nil
	})
	// More captures under load, dropped right away.
	for seq := int64(100); seq < 105; seq++ {
		on(t, "tc1", func() error {
			res, err := c.CaptureLocal(ctx, "alloc1", refs, seq)
			if err != nil {
				return err
			}
			worst = max(worst, res.Suspended)
			for _, a := range refs {
				if err := c.DropLocalSnapshot(ctx, "alloc1", a, seq); err != nil {
					return err
				}
			}
			return nil
		})
	}
	close(stop)
	wg.Wait()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	t.Logf("worst suspend window %v with %d concurrent writes", worst, writes.Load())
	if worst > DefaultSuspendBudget {
		t.Fatalf("suspended for %v", worst)
	}

	// 2. Snapshot 1 reads origin data plus the writes (external origin
	// activation), and its delta is exactly the written blocks.
	var snap1 string
	on(t, "tc1", func() (err error) {
		snap1, _, err = c.LocalSnapshotPath(ctx, "alloc1", "att1", 1)
		return err
	})
	if hashDev(t, ctx, snap1) != sum1 {
		t.Fatal("snapshot 1 differs from the overlay at capture time")
	}
	var d1 []extent.Range
	on(t, "tc1", func() (err error) { d1, err = c.LocalDelta(ctx, "alloc1", "att1", 1, 0); return err })
	if got := rangesToBlocks(d1); !reflect.DeepEqual(got, blocks1) {
		t.Fatalf("delta 1: %v, want %v", got, blocks1)
	}

	// 3. Write snapshot 1 into "s1" on ts1 and ts2 (base vol1) over
	// read-write exports: only the delta ranges are written.
	e.send(t, ctx, "att1", 1, 0, "vol1", "s1", []string{"ts1", "ts2"})
	if e.scrubAll(t, ctx, "s1", []string{"ts1", "ts2"}) != sum1 {
		t.Fatal("s1 differs from snapshot 1")
	}

	// 4. Incremental: new writes plus a rewrite with identical content.
	w2 := [][2]int64{{5 << 20, 4096}, {64 << 20, 64 << 10}}
	blocks2 := guestWrite(t, disk0, w2)
	same := make([]byte, 64<<10)
	if f, err := os.Open(ov1); err != nil {
		t.Fatal(err)
	} else {
		f.ReadAt(same, 32<<20)
		f.Close()
	}
	if f, err := os.OpenFile(ov1, os.O_WRONLY, 0); err != nil {
		t.Fatal(err)
	} else {
		f.WriteAt(same, 32<<20)
		f.Sync()
		f.Close()
	}
	blocks2[uint64(32<<20/BlockSize)] = true
	sum2 := hashDev(t, ctx, ov1)
	on(t, "tc1", func() error {
		_, err := c.CaptureLocal(ctx, "alloc1", refs, 2)
		return err
	})
	var d2 []extent.Range
	on(t, "tc1", func() (err error) { d2, err = c.LocalDelta(ctx, "alloc1", "att1", 2, 1); return err })
	if got := rangesToBlocks(d2); !reflect.DeepEqual(got, blocks2) {
		t.Fatalf("delta 2: %v, want %v", got, blocks2)
	}
	e.send(t, ctx, "att1", 2, 1, "s1", "s2", []string{"ts1", "ts2"})
	if e.scrubAll(t, ctx, "s2", []string{"ts1", "ts2"}) != sum2 {
		t.Fatal("s2 differs from snapshot 2")
	}

	// 5. Dropping snapshot 1 keeps snapshot 2 intact.
	var snap2 string
	on(t, "tc1", func() (err error) {
		if err := c.DropLocalSnapshot(ctx, "alloc1", "att1", 1); err != nil {
			return err
		}
		snap2, _, err = c.LocalSnapshotPath(ctx, "alloc1", "att1", 2)
		return err
	})
	if hashDev(t, ctx, snap2) != sum2 {
		t.Fatal("snapshot 2 changed after dropping snapshot 1")
	}

	// 6. Daemon restart: a snapshot without its device, a thin ID only in
	// the pool, an interrupted create and a suspended overlay.
	c2, err := NewComputeNode(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var st ComputeState
	var snap2ID uint32
	const stray, crashed = 5000, 5001
	on(t, "tc1", func() error {
		st, err := c2.Rescan(ctx)
		if err != nil {
			return err
		}
		a := st.Allocations["alloc1"].Attachments["att1"]
		snap2ID = a.LocalSnaps[len(a.LocalSnaps)-1].ThinID
		if err := dm.Remove(ctx, names.LocalSnap("tc1", snap2ID, "alloc1", "att1", 2)); err != nil {
			return err
		}
		pool := names.Pool("tc1")
		if err := dm.CreateThinID(ctx, pool, stray); err != nil {
			return err
		}
		c2.mu.Lock()
		j, _ := c2.journal()
		j.Thins[crashed] = &thinEntry{State: thinCreating, Kind: kindLocalSnap, AllocID: "alloc1", AttID: "att1", Seq: 9}
		err = j.save()
		c2.mu.Unlock()
		if err != nil {
			return err
		}
		if err := dm.CreateThinID(ctx, pool, crashed); err != nil {
			return err
		}
		return dm.Suspend(ctx, a1Name(st), false)
	})
	c3, err := NewComputeNode(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	on(t, "tc1", func() (err error) { st, err = c3.Rescan(ctx); return err })
	if !reflect.DeepEqual(st.UnknownThins, []uint32{stray}) || len(st.Resumed) != 1 {
		t.Fatalf("rescan after restart: unknown %v resumed %v", st.UnknownThins, st.Resumed)
	}
	a := st.Allocations["alloc1"].Attachments["att1"]
	if len(a.LocalSnaps) != 1 || a.LocalSnaps[0].Seq != 2 || a.LocalSnaps[0].ThinID != snap2ID || a.LocalSnaps[0].State != SnapReady {
		t.Fatalf("snapshots after restart: %+v", a.LocalSnaps)
	}
	on(t, "tc1", func() (err error) {
		snap2, _, err = c3.LocalSnapshotPath(ctx, "alloc1", "att1", 2)
		return err
	})
	if hashDev(t, ctx, snap2) != sum2 {
		t.Fatal("reactivated snapshot 2 differs")
	}
	poolIDs := func() map[uint32]bool {
		m := map[uint32]bool{}
		on(t, "tc1", func() error {
			meta, err := c3.metaPath(ctx)
			if err != nil {
				return err
			}
			ids, err := dm.ThinIDs(ctx, names.Pool("tc1"), meta)
			for _, id := range ids {
				m[id] = true
			}
			return err
		})
		return m
	}
	ids := poolIDs()
	if ids[crashed] || !ids[stray] || !ids[snap2ID] {
		t.Fatalf("pool IDs after recovery: %v", ids)
	}
	// New IDs go above everything, the stray ID included.
	on(t, "tc1", func() error {
		res, err := c3.CaptureLocal(ctx, "alloc1", refs, 3)
		if err != nil {
			return err
		}
		for _, s := range res.Snaps {
			if s.ThinID <= stray {
				return fmt.Errorf("new thin ID %d", s.ThinID)
			}
		}
		return c3.DeleteThins(ctx, []uint32{stray})
	})
	if ids := poolIDs(); ids[stray] {
		t.Fatal("stray ID not deleted")
	}

	// 7. A capture over budget leaves nothing behind.
	cfg := c.cfg
	cfg.SuspendBudget = time.Nanosecond
	c4, err := NewComputeNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := poolIDs()
	on(t, "tc1", func() error {
		_, err := c4.CaptureLocal(ctx, "alloc1", refs, 4)
		if !errors.Is(err, ErrSuspendBudget) {
			return fmt.Errorf("capture over budget: %v", err)
		}
		st, err := c4.Rescan(ctx)
		if err != nil {
			return err
		}
		if len(st.Resumed) != 0 {
			return fmt.Errorf("devices left suspended: %v", st.Resumed)
		}
		for _, s := range st.Allocations["alloc1"].Attachments["att1"].LocalSnaps {
			if s.Seq == 4 {
				return fmt.Errorf("snapshot 4 left: %+v", s)
			}
		}
		return nil
	})
	if after := poolIDs(); !reflect.DeepEqual(before, after) {
		t.Fatalf("pool IDs %v, before %v", after, before)
	}
	// 8. Release everything: no thin IDs left in the pool.
	on(t, "tc1", func() error { return c3.Cleanup(ctx, "alloc1") })
	if ids := poolIDs(); len(ids) != 0 {
		t.Fatalf("pool IDs after cleanup: %v", ids)
	}
	on(t, "tc1", func() (err error) { st, err = c3.Rescan(ctx); return err })
	if len(st.Allocations) != 0 || st.LocalSnapshots != 0 {
		t.Fatalf("state after cleanup: %+v", st)
	}
}

// a1Name is the overlay name of att1.
func a1Name(st ComputeState) string {
	a := st.Allocations["alloc1"].Attachments["att1"]
	return names.Overlay("tc1", a.ThinID, "alloc1", "att1")
}
