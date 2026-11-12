package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmehost"
)

const itSize = 256 << 20

var storageNodes = []string{"ts1", "ts2", "ts3"}

// on runs fn in the network namespace of node and fails the test on error.
func on(t *testing.T, node string, fn func() error) {
	t.Helper()
	if err := inNS(node, fn); err != nil {
		t.Fatalf("%s: %v", node, err)
	}
}

func noErrs(t *testing.T, what string, errs []error) {
	t.Helper()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("%s [%d]: %v", what, i, err)
		}
	}
}

// replicate copies content id from src to the other nodes: CreateBlank,
// read-write export to src, WriteExtents of the mapped ranges, unexport,
// seal everywhere.
func (e *env) replicate(t *testing.T, ctx context.Context, src, id string, others []string) {
	t.Helper()
	var ranges []extent.Range
	on(t, src, func() (err error) { ranges, err = e.storage[src].MappedRanges(ctx, id); return err })
	var dsts []Remote
	for _, n := range others {
		on(t, n, func() error {
			if err := e.storage[n].CreateBlank(ctx, id, itSize, "content", ""); err != nil {
				return err
			}
			r, err := e.storage[n].Export(ctx, id, src, e.psk(src), true)
			dsts = append(dsts, r)
			return err
		})
	}
	on(t, src, func() error {
		noErrs(t, "replicate", e.storage[src].WriteExtents(ctx, id, dsts, e.psk(src), ranges, nil))
		return nil
	})
	for _, n := range others {
		on(t, n, func() error { return e.storage[n].Unexport(ctx, id, src, true) })
	}
	for _, n := range append([]string{src}, others...) {
		on(t, n, func() error { return e.storage[n].Seal(ctx, id) })
	}
}

func (e *env) scrubAll(t *testing.T, ctx context.Context, id string, nodes []string) [32]byte {
	t.Helper()
	var first [32]byte
	for i, n := range nodes {
		var h extent.Hashes
		on(t, n, func() (err error) { h, err = e.storage[n].Scrub(ctx, id); return err })
		if i == 0 {
			first = h.Sum()
		} else if h.Sum() != first {
			t.Fatalf("content %s differs on %s", id, n)
		}
	}
	return first
}

func hashDev(t *testing.T, ctx context.Context, path string) [32]byte {
	t.Helper()
	h, err := extent.Hash(ctx, path, BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	return h.Sum()
}

// guestWrite writes random data with O_DIRECT like Cloud Hypervisor with
// direct=on, and returns the 64KiB blocks it touched.
func guestWrite(t *testing.T, dev string, writes [][2]int64) map[uint64]bool {
	t.Helper()
	f, err := os.OpenFile(dev, os.O_WRONLY|unix.O_DIRECT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, 1<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(buf)
	blocks := map[uint64]bool{}
	for _, w := range writes {
		off, n := w[0], w[1]
		rand.Read(buf[:n])
		if _, err := f.WriteAt(buf[:n], off); err != nil {
			t.Fatal(err)
		}
		for b := off / BlockSize; b <= (off+n-1)/BlockSize; b++ {
			blocks[uint64(b)] = true
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	return blocks
}

func rangesToBlocks(rs []extent.Range) map[uint64]bool {
	m := map[uint64]bool{}
	for _, r := range rs {
		for b := r.Off / BlockSize; b < (r.Off+r.Len)/BlockSize; b++ {
			m[uint64(b)] = true
		}
	}
	return m
}

func queueAttr(t *testing.T, d devnode.Dev, attr string) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/sys/dev/block/%s/queue/%s", d, attr))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// exportRO exports content id read-only to tc1 from every storage node.
func (e *env) exportRO(t *testing.T, ctx context.Context, id string) []Remote {
	t.Helper()
	var ro []Remote
	for _, n := range storageNodes {
		on(t, n, func() error {
			r, err := e.storage[n].Export(ctx, id, "tc1", e.psk("tc1"), false)
			ro = append(ro, r)
			return err
		})
	}
	return ro
}

// slotDiskPath returns a device node for disk n of slot.
func (e *env) slotDiskPath(t *testing.T, ctx context.Context, slot string, n int) string {
	t.Helper()
	var p string
	on(t, "tc1", func() error {
		ds, err := e.compute.EnsureSlot(ctx, slot)
		if err != nil {
			return err
		}
		p, err = devnode.Ensure(e.compute.cfg.DevDir, fmt.Sprintf("slot%s-d%d", slot, n), ds[n])
		return err
	})
	return p
}

func TestStorageEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := e.compute

	// 1. An empty root on ts1 is a zero-filled raw device, copied to ts2
	// and ts3, sealed everywhere.
	on(t, "ts1", func() error {
		_, err := e.storage["ts1"].CreateRoot(ctx, RootRequest{ID: "root1", Size: itSize})
		return err
	})
	on(t, "ts1", func() error {
		rs, err := e.storage["ts1"].MappedRanges(ctx, "root1")
		if err == nil && len(rs) != 0 {
			err = fmt.Errorf("empty root has mapped ranges %v (formatted?)", rs)
		}
		return err
	})
	// Write something so the origin is not all zeros.
	on(t, "ts1", func() error {
		p, err := e.storage["ts1"].DevicePath(ctx, "root1")
		if err == nil {
			guestWrite(t, p, [][2]int64{{0, 1 << 20}, {64 << 20, 4096}})
		}
		return err
	})
	e.replicate(t, ctx, "ts1", "root1", []string{"ts2", "ts3"})
	e.scrubAll(t, ctx, "root1", storageNodes)

	s1 := e.storage["ts1"]

	// 2. Read-only exports of the sealed content to tc1.
	ro := e.exportRO(t, ctx, "root1")

	// The port requires TLS 1.3.
	for attr, want := range map[string]string{"addr_tsas": "tls1.3", "addr_treq": "required"} {
		b, _ := os.ReadFile(filepath.Join(s1.target.Root, "ports", fmt.Sprint(s1.port.ID), attr))
		if strings.TrimSpace(string(b)) != want {
			t.Fatalf("%s = %q", attr, b)
		}
	}

	// A connection without TLS is rejected.
	t.Run("PlainConnectRejected", func(t *testing.T) {
		err := inNS("tc1", func() error {
			h := names.HostNQN("tc1")
			opts := fmt.Sprintf("transport=tcp,traddr=%s,trsvcid=4420,nqn=%s,hostnqn=%s,hostid=%s", ro[0].Addr, ro[0].SubNQN, h, names.HostID(h))
			f, err := os.OpenFile(nvmehost.FabricsDev, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.Write([]byte(opts))
			return err
		})
		if err == nil {
			t.Fatal("plain TCP connect succeeded")
		}
		t.Logf("plain connect failed as expected: %v", err)
	})

	// A read-write export (also a repair export of sealed content) is
	// refused while a read-only one exists.
	on(t, "ts1", func() error {
		if _, err := s1.ExportSealedRW(ctx, "root1", "tc1", e.psk("tc1")); !errors.Is(err, ErrInUse) {
			return fmt.Errorf("repair export while attached: %v", err)
		}
		return nil
	})

	// 3. Compute: pool, slot disks, attach onto disk 1.
	var att AttachmentState
	slotPath := e.slotDiskPath(t, ctx, "0", 1)
	req := AttachRequest{AllocID: "alloc1", AttachmentID: "att1", Generation: 3, UID: "uid-1", ContentID: "root1",
		SizeBytes: itSize, Slot: "0", SlotDisk: 1, Replicas: ro, PSK: e.psk("tc1")}
	on(t, "tc1", func() error {
		if _, err := c.PreparePool(ctx); err != nil {
			return err
		}
		if c.PoolBootID() != bootID() {
			return fmt.Errorf("pool boot id %q", c.PoolBootID())
		}
		ds, err := c.EnsureSlot(ctx, "0")
		if err != nil {
			return err
		}
		if len(ds) != 2 {
			return fmt.Errorf("%d slot disks", len(ds))
		}
		for _, d := range ds {
			if sz, _ := devnode.Sectors(d); sz != 1 {
				return fmt.Errorf("new slot disk has %d sectors", sz)
			}
		}
		att, err = c.Attach(ctx, req)
		if err != nil {
			return err
		}
		if len(att.Origin) != 3 || att.Slot != "0" || att.SlotDisk != 1 || att.HostLink == "" {
			return fmt.Errorf("attach: %+v", att)
		}
		// Attach again is a no-op.
		again, err := c.Attach(ctx, req)
		if err != nil || again.ThinID != att.ThinID {
			return fmt.Errorf("second attach: %+v %v", again, err)
		}
		// Another attachment cannot take the same slot disk... (checked
		// in TestCaptureAndTransfer with a second volume).
		return nil
	})
	// An opener after the reload sees the new size.
	f, err := os.Open(slotPath)
	if err != nil {
		t.Fatal(err)
	}
	if sz, _ := f.Seek(0, 2); sz != itSize {
		t.Fatalf("slot size %d after attach", sz)
	}
	f.Close()
	// The host link points at the overlay.
	if p, err := filepath.EvalSymlinks(filepath.Join(c.cfg.VolumeLinkDir, "uid-1")); err != nil {
		t.Fatal(err)
	} else if d, _ := statDev(p); d != att.Dev {
		t.Fatalf("host link %s is %s, overlay %s", p, d, att.Dev)
	}
	// No discard and no write-zeroes reach the guest.
	sd, _ := statDev(slotPath)
	for _, d := range []devnode.Dev{att.Dev, sd} {
		for _, a := range []string{"discard_max_bytes", "write_zeroes_max_bytes"} {
			if v := queueAttr(t, d, a); v != "0" {
				t.Fatalf("%s %s = %s", d, a, v)
			}
		}
	}
	// The guest sees the content.
	rootSum := e.scrubAll(t, ctx, "root1", []string{"ts1"})
	if hashDev(t, ctx, slotPath) != rootSum {
		t.Fatal("guest view differs from content")
	}

	// 4. Guest writes, including partial blocks.
	guestWrite(t, slotPath, [][2]int64{
		{0, 4096}, {65536, 131072}, {1 << 20, 4096}, {5 << 20, 65536}, {100 << 20, 300 * 1024}, {itSize - 4096, 4096},
	})

	// 5. Failover: drop ts1's export; reads still work through ts2/ts3.
	on(t, "ts1", func() error { return s1.Unexport(ctx, "root1", "tc1", false) })
	guest := hashDev(t, ctx, slotPath)
	if hashDev(t, ctx, slotPath) != guest {
		t.Fatal("guest view changed")
	}
	var st ComputeState
	on(t, "tc1", func() (err error) { st, err = c.Rescan(ctx); return err })
	a := st.Allocations["alloc1"].Attachments["att1"]
	if a.ContentID != "root1" || a.Generation != 3 || a.UID != "uid-1" || st.Slots["0"][1].AttachmentID != "att1" || st.Allocations["alloc1"].Slot != "0" {
		t.Fatalf("rescan: %+v", st)
	}
	t.Logf("paths after losing ts1: %+v", a.Origin)

	// Restore ts1 and reinstate its path once the controller is live
	// again. Reconnects come from the initial network namespace, so this
	// needs a tlshd there (see docs/spikes/storage.md).
	on(t, "ts1", func() error {
		r, err := s1.Export(ctx, "root1", "tc1", e.psk("tc1"), false)
		ro[0] = r
		return err
	})
	req.Replicas = ro
	if out, _ := exec.Command("systemctl", "is-active", "tlshd").Output(); strings.TrimSpace(string(out)) == "active" {
		deadline := time.Now().Add(30 * time.Second)
		for {
			on(t, "tc1", func() error {
				_, err := c.RefreshPaths(ctx, req)
				return err
			})
			on(t, "tc1", func() (err error) { st, err = c.Rescan(ctx); return err })
			all := true
			for _, p := range st.Allocations["alloc1"].Attachments["att1"].Origin {
				all = all && p.Active
			}
			if all {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("paths not reinstated: %+v", st.Allocations["alloc1"].Attachments["att1"].Origin)
			}
			time.Sleep(500 * time.Millisecond)
		}
	} else {
		t.Log("no tlshd in the initial network namespace; skipping reconnect check")
	}

	// 6. Release: slot disk back to the error target, link, devices and
	// connections gone.
	on(t, "tc1", func() error { return c.ReleaseAttachment(ctx, "alloc1", "att1") })
	on(t, "tc1", func() (err error) { st, err = c.Rescan(ctx); return err })
	if len(st.Allocations) != 0 || st.Slots["0"][1].AttachmentID != "" {
		t.Fatalf("after release: %+v", st)
	}
	if sz, _ := devnode.Sectors(sd); sz != 1 {
		t.Fatalf("slot disk has %d sectors after release", sz)
	}
	if _, err := os.Lstat(filepath.Join(c.cfg.VolumeLinkDir, "uid-1")); !os.IsNotExist(err) {
		t.Fatalf("host link after release: %v", err)
	}
	cs, _ := nvmehost.Controllers()
	for _, x := range cs {
		if x.HostNQN == names.HostNQN("tc1") {
			t.Fatalf("controller %s still connected after release", x.Name)
		}
	}
	for _, n := range storageNodes {
		on(t, n, func() error { return e.storage[n].Unexport(ctx, "root1", "tc1", false) })
	}

	// 7. A child "out2" of root1 with changes, on ts1 and ts2.
	var out2Sum [32]byte
	for _, n := range []string{"ts1", "ts2"} {
		on(t, n, func() error { return e.storage[n].Snapshot(ctx, "root1", "out2", "content", "") })
	}
	on(t, "ts1", func() error {
		p, err := e.storage["ts1"].devPath(ctx, "out2")
		if err != nil {
			return err
		}
		guestWrite(t, p, [][2]int64{{7 * BlockSize, 2 * BlockSize}, {3 << 20, 4096}})
		return nil
	})
	// ts2 has a stale copy of out2: rebuild it from ts1 with thin_delta.
	e.repairFrom(t, ctx, "ts1", "ts2", "root1", "out2")
	out2Sum = e.scrubAll(t, ctx, "out2", []string{"ts1", "ts2"})

	// 8. Deleting the parent keeps the child intact; ts3 rebuilds out2
	// from scratch.
	for _, n := range storageNodes {
		on(t, n, func() error { return e.storage[n].Delete(ctx, "root1") })
	}
	if e.scrubAll(t, ctx, "out2", []string{"ts1", "ts2"}) != out2Sum {
		t.Fatal("child changed after deleting its parent")
	}
	e.repairFrom(t, ctx, "ts1", "ts3", "", "out2")
	if e.scrubAll(t, ctx, "out2", storageNodes) != out2Sum {
		t.Fatal("repaired replicas differ")
	}

	// 9. All paths gone: I/O errors instead of a hang.
	ro2 := e.exportRO(t, ctx, "out2")
	var att2 AttachmentState
	on(t, "tc1", func() (err error) {
		att2, err = c.Attach(ctx, AttachRequest{AllocID: "alloc2", AttachmentID: "att2", Generation: 1, ContentID: "out2", Replicas: ro2, PSK: e.psk("tc1")})
		return err
	})
	for _, n := range storageNodes {
		on(t, n, func() error { return e.storage[n].Unexport(ctx, "out2", "tc1", false) })
	}
	p2, _ := devnode.Ensure(c.cfg.DevDir, "thin2", att2.Dev)
	start := time.Now()
	rctx, rcancel := context.WithTimeout(ctx, 90*time.Second)
	_, err = extent.Hash(rctx, p2, BlockSize)
	rcancel()
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read with no paths: %v", err)
	}
	t.Logf("read with no paths failed after %v: %v", time.Since(start).Round(time.Second), err)
	on(t, "tc1", func() error { return c.Cleanup(ctx, "alloc2") })

	// 10. State and usage.
	on(t, "ts1", func() error {
		st, err := s1.State(ctx)
		if err != nil {
			return err
		}
		if len(st.Contents) != 1 || !st.Contents["out2"].Sealed || len(st.Exports) != 0 {
			return fmt.Errorf("state: %+v", st)
		}
		if st.Usage.LVCount != 1 || st.Usage.DataPercent <= 0 {
			return fmt.Errorf("usage: %+v", st.Usage)
		}
		return nil
	})
}

// repairFrom rebuilds content id on node dst from node src. base is a
// content present on both nodes ("" means start blank).
func (e *env) repairFrom(t *testing.T, ctx context.Context, src, dst, base, id string) {
	t.Helper()
	var cp, zero []extent.Range
	on(t, src, func() (err error) {
		if base == "" {
			cp, err = e.storage[src].MappedRanges(ctx, id)
			return err
		}
		cp, zero, err = e.storage[src].ThinDelta(ctx, base, id)
		return err
	})
	var r Remote
	on(t, dst, func() (err error) {
		s := e.storage[dst]
		if err := s.Delete(ctx, id); err != nil { // drop a stale or partial copy
			return err
		}
		if base == "" {
			err = s.CreateBlank(ctx, id, itSize, "content", "")
		} else {
			err = s.Snapshot(ctx, base, id, "content", "")
		}
		if err != nil {
			return err
		}
		r, err = s.Export(ctx, id, src, e.psk(src), true)
		return err
	})
	on(t, src, func() error {
		noErrs(t, "repair", e.storage[src].WriteExtents(ctx, id, []Remote{r}, e.psk(src), cp, zero))
		return nil
	})
	on(t, dst, func() error {
		if err := e.storage[dst].Unexport(ctx, id, src, true); err != nil {
			return err
		}
		return e.storage[dst].Seal(ctx, id)
	})
	on(t, src, func() error { return e.storage[src].Seal(ctx, id) })
}
