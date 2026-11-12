package node

// Root integration test of RealStorage (BLIP_ROOT_TESTS=1, run with
// sudo -E): 3 storage nodes and 1 compute node in network namespaces of
// one kernel, with VGs on loop devices under /mnt/nvme2/blip/node.
//
//	go test -c -o /tmp/opencode/node.test ./internal/node/
//	sudo -E BLIP_ROOT_TESTS=1 timeout -s TERM 600 /tmp/opencode/node.test -test.v -test.run TestRealStorageRoot

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/lvm"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/storagetest"
	"github.com/example/blip/internal/storage/tlskeys"
)

func rootTestDir() string {
	if d := os.Getenv("BLIP_TEST_DIR"); d != "" {
		return d
	}
	return "/mnt/nvme2/blip/node/itest"
}

var rtNet = &storagetest.Net{
	Prefix: "blipn", Bridge: "blipn0", Subnet: "10.97.0",
	Nodes: []string{"ns1", "ns2", "ns3", "nc1"}, Dir: rootTestDir(),
}

var rtStorage = []string{"ns1", "ns2", "ns3"}

type rootEnv struct {
	t     *testing.T
	key   []byte
	nodes map[string]*RealStorage
	lvms  map[string]*lvm.LVM
}

func (e *rootEnv) psk(node string) []byte { return tlskeys.DerivePSK(e.key, names.HostNQN(node)) }

// on runs fn in the netns of node and fails the test on error.
func (e *rootEnv) on(node string, fn func(r *RealStorage) error) {
	e.t.Helper()
	if err := rtNet.InNS(node, func() error { return fn(e.nodes[node]) }); err != nil {
		e.t.Fatalf("%s: %v", node, err)
	}
}

func (e *rootEnv) teardown() {
	ctx := context.Background()
	if c := e.nodes["nc1"]; c != nil {
		if err := c.ComputeNode().RemovePool(ctx); err != nil {
			e.t.Logf("teardown compute: %v", err)
		}
	}
	for _, n := range rtStorage {
		if r := e.nodes[n]; r != nil {
			if st, err := r.StorageNode().State(ctx); err == nil {
				for id := range st.Contents {
					_ = r.StorageNode().Delete(ctx, id)
				}
			}
		}
		if l := e.lvms[n]; l != nil {
			if err := l.RemoveVG(ctx); err != nil {
				e.t.Logf("teardown VG %s: %v", n, err)
			}
		}
	}
	rtNet.Down()
}

func newRootEnv(t *testing.T) *rootEnv {
	storagetest.NeedRoot(t)
	e := &rootEnv{t: t, key: make([]byte, 32), nodes: map[string]*RealStorage{}, lvms: map[string]*lvm.LVM{}}
	rand.Read(e.key)
	rtNet.Sweep()
	t.Cleanup(e.teardown)
	rtNet.Up(t)
	ctx := context.Background()
	tmo := storage.Timeouts{CtrlLoss: 10, FastIOFail: 2}
	for _, n := range rtStorage {
		loop := rtNet.Loop(t, n+".img", 1<<30)
		l, err := lvm.New(lvm.Config{VG: "blipn-" + n, Devices: []string{loop}})
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Setup(ctx, 64<<20); err != nil {
			t.Fatal(err)
		}
		e.lvms[n] = l
		r, err := NewRealStorage(RealConfig{
			Node: n, Addr: rtNet.Addr(n), VG: "blipn-" + n, Devices: []string{loop},
			DevDir: filepath.Join(rtNet.Dir, "dev-"+n), WorkDir: rtNet.Dir, Timeouts: tmo,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.nodes[n] = r
	}
	loop := rtNet.Loop(t, "nc1.img", 512<<20)
	r, err := NewRealStorage(RealConfig{
		Node: "nc1", ComputeDevice: loop, DevDir: filepath.Join(rtNet.Dir, "dev-nc1"),
		Timeouts: tmo,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.nodes["nc1"] = r
	if err := r.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile("/proc/sys/kernel/random/boot_id"); r.ComputeNode().PoolBootID() != string(bytes.TrimSpace(got)) {
		t.Fatalf("pool header boot ID %q", r.ComputeNode().PoolBootID())
	}
	for n, r := range e.nodes {
		if err := r.SetHostKey(ctx, names.HostNQN(n), e.psk(n)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// export exports content on each node to host and returns the paths.
func (e *rootEnv) export(ctx context.Context, nodes []string, id, host string, mode pb.ExportMode) []*pb.Path {
	var ps []*pb.Path
	for _, n := range nodes {
		e.on(n, func(r *RealStorage) error {
			res, err := r.Export(ctx, &pb.Export{ContentId: id, Mode: mode, HostNode: host, HostNqn: names.HostNQN(host), HostPsk: e.psk(host)})
			if err == nil {
				ps = append(ps, res.Path)
			}
			return err
		})
	}
	return ps
}

func (e *rootEnv) unexport(ctx context.Context, nodes []string, id, host string) {
	for _, n := range nodes {
		e.on(n, func(r *RealStorage) error {
			return r.Unexport(ctx, &pb.Unexport{ContentId: id, HostNqn: names.HostNQN(host)})
		})
	}
}

func (e *rootEnv) seal(ctx context.Context, nodes []string, id, uid string) {
	for _, n := range nodes {
		e.on(n, func(r *RealStorage) error {
			return r.Seal(ctx, &pb.Seal{ContentId: id, Blipvol: &pb.ObjectRef{Uid: uid}})
		})
	}
}

func allOK(t *testing.T, what string, ts []*pb.TargetResult, n int) {
	t.Helper()
	if len(ts) != n {
		t.Fatalf("%s: %d target results, want %d", what, len(ts), n)
	}
	for _, x := range ts {
		if !x.Ok {
			t.Fatalf("%s: target %s: %s", what, x.Node, x.Error)
		}
	}
}

// scrub returns the scrub hashes of id on each node and fails if they
// differ.
func (e *rootEnv) scrub(ctx context.Context, nodes []string, id string) []byte {
	var first []byte
	for _, n := range nodes {
		e.on(n, func(r *RealStorage) error {
			res, err := r.Scrub(ctx, &pb.Scrub{ContentId: id, BlocksPerHash: 64})
			if err != nil {
				return err
			}
			all := bytes.Join(res.Hashes, nil)
			if first == nil {
				first = all
			} else if !bytes.Equal(first, all) {
				e.t.Fatalf("scrub of %s differs on %s", id, n)
			}
			return nil
		})
	}
	return first
}

func TestRealStorageRoot(t *testing.T) {
	e := newRootEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	const size = 64 << 20
	others := rtStorage[1:]

	// 1. Import an empty root on ns1 into blank contents on ns2 and ns3.
	for _, n := range others {
		e.on(n, func(r *RealStorage) error {
			return r.CreateContent(ctx, &pb.CreateContent{ContentId: "root1", SizeBytes: size, Kind: pb.ContentKind_CONTENT_KIND_ROOT})
		})
	}
	targets := e.export(ctx, others, "root1", "ns1", pb.ExportMode_EXPORT_MODE_READ_WRITE)
	e.on("ns1", func(r *RealStorage) error {
		res, err := r.Import(ctx, &pb.Import{ContentId: "root1", SizeBytes: size, Blipvol: &pb.ObjectRef{Uid: "vol1"}, Targets: targets})
		if err == nil {
			allOK(t, "import", res.Targets, 2)
		}
		return err
	})
	e.unexport(ctx, others, "root1", "ns1")
	e.seal(ctx, rtStorage, "root1", "vol1")
	rootSum := e.scrub(ctx, rtStorage, "root1")
	e.on("ns2", func(r *RealStorage) error {
		st, err := r.State(ctx)
		if err != nil {
			return err
		}
		if len(st.Contents) != 1 || !st.Contents[0].Sealed || st.Contents[0].Kind != pb.ContentKind_CONTENT_KIND_ROOT {
			t.Fatalf("ns2 state: %v", st.Contents)
		}
		return nil
	})

	// 2. Export root1 read-only to nc1 from every replica.
	ro := e.export(ctx, rtStorage, "root1", "nc1", pb.ExportMode_EXPORT_MODE_READ_ONLY)
	e.on("ns1", func(r *RealStorage) error {
		_, err := r.Export(ctx, &pb.Export{ContentId: "root1", Mode: pb.ExportMode_EXPORT_MODE_READ_WRITE, RepairSealed: true,
			HostNode: "nc1", HostNqn: names.HostNQN("nc1"), HostPsk: e.psk("nc1")})
		if err == nil {
			t.Fatal("read-write export next to a read-only one")
		}
		return nil
	})

	// 3. Attach on nc1 as slot disk 2 and write through it.
	var disks []string
	vs := VolumeSpec{AllocationID: "al1", AttachmentID: "0123456789abcdef", Generation: 1, UID: "vol1", ContentID: "root1",
		SizeBytes: size, SlotID: "s0", SlotDisk: 2, Paths: ro}
	e.on("nc1", func(r *RealStorage) error {
		var err error
		if disks, err = r.SlotDisks(ctx, "s0"); err != nil {
			return err
		}
		if len(disks) != storage.DefaultDisksPerSlot {
			t.Fatalf("%d slot disks", len(disks))
		}
		host, err := r.AttachVolume(ctx, vs)
		if err != nil {
			return err
		}
		if host != "/dev/blip/volumes/vol1" {
			t.Fatalf("host link %q", host)
		}
		// Again: idempotent.
		_, err = r.AttachVolume(ctx, vs)
		return err
	})
	e.on("nc1", func(r *RealStorage) error {
		st, err := r.State(ctx)
		if err != nil {
			return err
		}
		a := st.Allocations["al1"][vs.AttachmentID]
		if !a.Overlay || a.SlotDisk != 2 || a.UID != "vol1" || a.Generation != 1 {
			t.Fatalf("attachment state %+v", a)
		}
		r.CheckPaths(ctx)
		return nil
	})
	data := make([]byte, 1<<20)
	rand.Read(data)
	writeAt := func(off int64) {
		f, err := os.OpenFile(disks[2], os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if fi, _ := f.Seek(0, 2); fi != size {
			t.Fatalf("slot disk size %d", fi)
		}
		if _, err := f.WriteAt(data, off); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	writeAt(4 << 20)

	// 4. Capture and write to ns2 and ns3 over read-write exports.
	e.on("nc1", func(r *RealStorage) error {
		_, err := r.CaptureLocal(ctx, "al1", []string{vs.AttachmentID}, 1)
		return err
	})
	if n := e.sendSnap(ctx, vs.AttachmentID, 1, 0, "root1", "snap1", []string{"ns2", "ns3"}); n < 1<<20 || n > 2<<20 {
		t.Fatalf("first write: %d bytes", n)
	}
	if bytes.Equal(e.scrub(ctx, []string{"ns2", "ns3"}, "snap1"), rootSum) {
		t.Fatal("the snapshot equals the root")
	}
	e.on("ns2", func(r *RealStorage) error {
		p, err := r.StorageNode().DevicePath(ctx, "snap1")
		if err != nil {
			return err
		}
		b := make([]byte, len(data))
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.ReadAt(b, 4<<20); err != nil {
			return err
		}
		if !bytes.Equal(b, data) {
			t.Fatal("received data differs")
		}
		return nil
	})

	// 5. Incremental: rewrite the same data and write the delta against
	// seq 1 (only the rewritten blocks); then check a full source.
	writeAt(4 << 20)
	e.on("nc1", func(r *RealStorage) error {
		_, err := r.CaptureLocal(ctx, "al1", []string{vs.AttachmentID}, 2)
		return err
	})
	if n := e.sendSnap(ctx, vs.AttachmentID, 2, 1, "snap1", "snap2", []string{"ns2", "ns3"}); n > int64(len(data))+128<<10 {
		t.Fatalf("incremental write: %d bytes", n)
	}
	e.on("nc1", func(r *RealStorage) error {
		src, err := r.SnapshotSource(ctx, "al1", vs.AttachmentID, 2, 0, true)
		if err != nil {
			return err
		}
		if !src.Full || src.Size != size || len(src.Ranges) != 1 || src.Ranges[0].Len != size {
			t.Fatalf("full source %+v", src)
		}
		return r.DropLocalSnapshot(ctx, "al1", vs.AttachmentID, 1)
	})

	// 6. Release.
	e.on("nc1", func(r *RealStorage) error {
		if err := r.ReleaseAttachment(ctx, "al1", vs.AttachmentID); err != nil {
			return err
		}
		if err := r.ReleaseAllocation(ctx, "al1"); err != nil {
			return err
		}
		st, err := r.State(ctx)
		if err == nil && len(st.Allocations) != 0 {
			t.Fatalf("allocations after release: %v", st.Allocations)
		}
		return err
	})
	e.unexport(ctx, rtStorage, "root1", "nc1")

	// Rebuild snap1 on ns3 with a repair from ns2 based on root1.
	e.on("ns3", func(r *RealStorage) error {
		if err := r.DeleteContent(ctx, &pb.DeleteContent{ContentIds: []string{"snap1"}}); err != nil {
			return err
		}
		_, err := r.Clone(ctx, &pb.Clone{ContentId: "snap1", ParentContentId: "root1", Mode: pb.CloneMode_CLONE_MODE_SNAPSHOT})
		return err
	})
	tgt := e.export(ctx, []string{"ns3"}, "snap1", "ns2", pb.ExportMode_EXPORT_MODE_READ_WRITE)
	e.on("ns2", func(r *RealStorage) error {
		res, err := r.Repair(ctx, &pb.Repair{ContentId: "snap1", BaseContentId: "root1", Target: tgt[0]})
		if err == nil {
			allOK(t, "repair", res.Targets, 1)
		}
		return err
	})
	e.unexport(ctx, []string{"ns3"}, "snap1", "ns2")
	e.seal(ctx, []string{"ns3"}, "snap1", "vol2")
	e.scrub(ctx, []string{"ns2", "ns3"}, "snap1")

	// 7. Delete everything.
	for _, n := range rtStorage {
		e.on(n, func(r *RealStorage) error {
			if err := r.DeleteContent(ctx, &pb.DeleteContent{ContentIds: []string{"snap2", "snap1", "root1"}}); err != nil {
				return err
			}
			st, err := r.State(ctx)
			if err == nil && len(st.Contents) != 0 {
				t.Fatalf("%s after delete: %v", n, st.Contents)
			}
			sc, _, err := r.Capacity(ctx)
			if err == nil && sc.LvCount != 0 {
				t.Fatalf("%s lv count %d", n, sc.LvCount)
			}
			return err
		})
	}
}

// sendSnap writes local snapshot seq of attachment att (delta against
// baseSeq) into new content id on dsts, prepared from baseContent and
// exported read-write to nc1, then unexports and seals it. It returns
// the number of bytes written per target.
func (e *rootEnv) sendSnap(ctx context.Context, att string, seq, baseSeq int64, baseContent, id string, dsts []string) int64 {
	t := e.t
	t.Helper()
	var src *SnapshotSource
	e.on("nc1", func(r *RealStorage) (err error) {
		src, err = r.SnapshotSource(ctx, "al1", att, seq, baseSeq, false)
		return err
	})
	for _, n := range dsts {
		e.on(n, func(r *RealStorage) error {
			return r.PrepareReceive(ctx, ReceiveSpec{ContentID: id, BaseContentID: baseContent, SizeBytes: src.Size, Owner: "o", Generation: 1})
		})
	}
	paths := e.export(ctx, dsts, id, "nc1", pb.ExportMode_EXPORT_MODE_READ_WRITE)
	e.on("nc1", func(r *RealStorage) error {
		errs, err := r.WriteSnapshot(ctx, "al1", att, seq, src.Ranges, paths)
		if err != nil {
			return err
		}
		for i, err := range errs {
			if err != nil {
				t.Fatalf("write to %s: %v", dsts[i], err)
			}
		}
		return nil
	})
	e.unexport(ctx, dsts, id, "nc1")
	e.seal(ctx, dsts, id, "o")
	return extent.Total(src.Ranges)
}
