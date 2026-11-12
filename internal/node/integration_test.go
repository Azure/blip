package node

// Root integration test: the node daemon drives a real guest booted by
// slotdev (blipd slot) with Cloud Hypervisor on /dev/kvm. Storage is
// fake; each slot disk is an image file (the fake storage's slot disk
// file), hot-plugged through the slot volume link exactly like in a pod,
// except that the link points at the host file instead of
// /dev/blip/disks/N. The guest is the blip-boot stub, then an alpine root
// whose init is a test script. Run with:
//
//	make -f hack/guest/Makefile guest rootfs
//	hack/guest/node-itest.sh

import (
	"context"
	"fmt"
	"github.com/example/blip/internal/node/nodetest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/meta"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/slot/chapi"
)

var itSeq atomic.Int32

type itEnv struct {
	out, work, rootfs, slotdev string
}

func itSetup(t *testing.T) itEnv {
	t.Helper()
	if os.Getenv("BLIP_ROOT_TESTS") != "1" {
		t.Skip("set BLIP_ROOT_TESTS=1 and run as root")
	}
	wd, _ := os.Getwd()
	root := wd
	for ; root != "/"; root = filepath.Dir(root) {
		if exists(filepath.Join(root, "go.mod")) {
			break
		}
	}
	base := os.Getenv("BLIP_GUEST_DIR")
	if base == "" {
		base = "/mnt/nvme2/blip/guest"
	}
	e := itEnv{rootfs: filepath.Join(base, "rootfs-alpine"), slotdev: filepath.Join(root, "_output/guest/slotdev")}
	e.work = filepath.Join(base, "itest", fmt.Sprintf("node-%d-%d", os.Getpid(), itSeq.Add(1)))
	if err := os.MkdirAll(e.work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if os.Getenv("BLIP_KEEP_TEST_DIR") == "" {
			os.RemoveAll(e.work)
		}
	})
	// Root without capabilities cannot read a home directory: copy.
	for _, f := range []string{"cloud-hypervisor", "vmlinuz", "initramfs.cpio.gz", "blip-meta"} {
		b, err := os.ReadFile(filepath.Join(root, "_output/guest", f))
		if err != nil {
			t.Fatalf("%v; run make -f hack/guest/Makefile guest", err)
		}
		if err := os.WriteFile(filepath.Join(e.work, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.out = e.work
	if !exists(e.rootfs) || !exists(e.slotdev) {
		t.Fatal("missing rootfs or slotdev; run make -f hack/guest/Makefile guest rootfs")
	}
	return e
}

func itRun(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if b, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, b)
	}
}

// itSlot starts slotdev in a new netns with slot dir dir.
func itSlot(t *testing.T, e itEnv, dir string) {
	n := itSeq.Add(1)
	ns := fmt.Sprintf("blipn-%d-%d", os.Getpid(), n)
	hostIf := fmt.Sprintf("bnh%d", n)
	hostIP, podIP := fmt.Sprintf("192.168.%d.1", 150+n), fmt.Sprintf("192.168.%d.2", 150+n)
	itRun(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	itRun(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", "eth0", "netns", ns)
	itRun(t, "ip", "addr", "add", hostIP+"/30", "dev", hostIf)
	itRun(t, "ip", "link", "set", hostIf, "up")
	itRun(t, "ip", "-n", ns, "addr", "add", podIP+"/30", "dev", "eth0")
	itRun(t, "ip", "-n", ns, "link", "set", "eth0", "up")
	itRun(t, "ip", "-n", ns, "link", "set", "lo", "up")
	itRun(t, "ip", "-n", ns, "route", "add", "default", "via", hostIP)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	logf, err := os.Create(filepath.Join(e.work, filepath.Base(dir)+"-slot.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", ns, e.slotdev,
		"--run-dir", dir,
		"--cloud-hypervisor", filepath.Join(e.out, "cloud-hypervisor"),
		"--kernel", filepath.Join(e.out, "vmlinuz"),
		"--initramfs", filepath.Join(e.out, "initramfs.cpio.gz"),
		"--poll", "100ms")
	cmd.Env = append(os.Environ(), "VM_CPUS=1", "VM_MEMORY=512Mi")
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); logf.Close(); close(done) }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-done
		if t.Failed() {
			for _, f := range []string{logf.Name(), filepath.Join(dir, slot.FileSerial)} {
				b, _ := os.ReadFile(f)
				t.Logf("--- %s:\n%s", f, b)
			}
		}
	})
}

// itNode builds a node with one slot whose VM is real. Slot
// disk i is the file <work>/dev/slot-dev-slot-0-d<i>.
func itNode(t *testing.T, e itEnv) (*Node, *nodetest.FakeStorage) {
	pods := &fakePods{m: map[string]PodRef{"slot-0": {Namespace: api.SystemNamespace, Name: "pool-0"}}}
	nc := &api.NodeConfig{Hypervisor: "kvm", Slots: 1, Compute: &api.NodeComputeConfig{Device: "/dev/x"}}
	nc.Default()
	devDir := filepath.Join(e.work, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	st := nodetest.NewFakeStorage("it", devDir)
	slotsDir := filepath.Join(e.work, "slots")
	n, err := New(Config{
		NodeName: "it", BootID: "b", NodeConfig: nc,
		SlotsDir: slotsDir, StateDir: filepath.Join(e.work, "state"),
		Storage: st, Pods: pods,
		Hypervisor:      &CloudHypervisor{UnplugTimeout: 20 * time.Second},
		ContainerRunDir: filepath.Join(slotsDir, "slot-0"),
		SlotDiskPath: func(slotID string, i int) string {
			return filepath.Join(devDir, fmt.Sprintf("slot-dev-%s-d%d", slotID, i))
		},
		Poll: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.hostNQN = api.HostNQN("it")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go n.Run(ctx)
	return n, st
}

const itRoot = "0123456789abcdef"

// itBoot boots a guest, assigns it, attaches the root volume (an ext4
// image of the rootfs with script as /sbin/blip-test-init) and starts it. It returns the node and the allocation ID.
func itBoot(t *testing.T, e itEnv, deadline time.Duration, script string) (*Node, string) {
	n, st := itNode(t, e)
	dir := n.slotDir("slot-0")
	disks, err := st.SlotDisks(context.Background(), "slot-0")
	if err != nil {
		t.Fatal(err)
	}
	rootDir := filepath.Join(e.work, "rootfs")
	itRun(t, "cp", "-a", e.rootfs, rootDir)
	if err := os.WriteFile(filepath.Join(rootDir, "sbin/blip-test-init"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	itRun(t, "cp", filepath.Join(e.out, "blip-meta"), filepath.Join(rootDir, "usr/bin/blip-meta"))
	itRun(t, "mkfs.ext4", "-q", "-F", "-d", rootDir, disks[0], "256M")
	os.RemoveAll(rootDir)
	itRun(t, "truncate", "-s", "64M", disks[1])
	itSlot(t, e, dir)
	itWait(t, "slot ready", 60*time.Second, func() bool { return exists(filepath.Join(dir, slot.FileReady)) })

	id := fmt.Sprintf("it-%d-%d", os.Getpid()%100000, itSeq.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := n.AssignSlot(ctx, &pb.AssignSlot{
		AllocationId: id, Blip: &pb.ObjectRef{Namespace: "t", Name: "it-blip", Uid: "uid-" + id},
		Pod: &pb.ObjectRef{Namespace: api.SystemNamespace, Name: "pool-0"}, Deadline: timestamppb.New(time.Now().Add(deadline)),
	}); err != nil {
		t.Fatal(err)
	}
	if as, err := readAssignment(dir); err != nil || as.AllocationID != id {
		t.Fatal("assignment", as, err)
	}
	r, err := n.AttachVolume(ctx, &pb.AttachVolume{AllocationId: id, AttachmentId: itRoot, Generation: 1, Uid: "uroot", Name: "root",
		ContentId: "croot", SizeBytes: 256 << 20, OriginPaths: []*pb.Path{{Node: "s1"}}, SlotDisk: 0})
	if err != nil {
		t.Fatal(err)
	}
	if r.GuestPath != api.GuestVolumePath("root") {
		t.Fatal(r)
	}
	if err := n.StartWorkload(ctx, &pb.StartWorkload{AllocationId: id, RootAttachmentId: itRoot,
		Params: &pb.RunParams{Init: []string{"/sbin/blip-test-init"}}}); err != nil {
		t.Fatal(err)
	}
	return n, id
}

// itReported waits until the node reports allocation id in a state that
// satisfies ok, and returns it.
func itReported(t *testing.T, n *Node, d time.Duration, what, id string, ok func(*pb.AllocationInfo) bool) *pb.AllocationInfo {
	t.Helper()
	var last *pb.AllocationInfo
	itWait(t, what, d, func() bool {
		if a := reported(drainOut(n), id); a != nil {
			last = a
		}
		return last != nil && ok(last)
	})
	return last
}

func started(a *pb.AllocationInfo) bool { return a.BootCount > 0 }
func exited(a *pb.AllocationInfo) bool  { return a.Exit != nil }

func itWait(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// itConsole returns the guest console output of the slot.
func itConsole(n *Node) string {
	b, _ := os.ReadFile(filepath.Join(n.slotDir("slot-0"), slot.FileSerial))
	return string(b)
}

// waitSerial is a guest shell function: wait until a disk with virtio
// serial $1 is present ($2 = 1) or absent ($2 = 0).
const itInitHead = `#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
has() { grep -qx "$1" /sys/block/*/serial 2>/dev/null; }
waitSerial() { i=0; while [ $i -lt 600 ]; do if has "$1"; then [ "$2" = 1 ] && return 0; else [ "$2" = 0 ] && return 0; fi; sleep 0.1; i=$((i+1)); done; return 1; }
`

// TestIntegrationVolumes starts a guest, attaches and detaches a data
// volume while it runs, and lets it power off.
func TestIntegrationVolumes(t *testing.T) {
	e := itSetup(t)
	n, id := itBoot(t, e, time.Hour, itInitHead+`echo init-running
waitSerial data 1 && echo saw-data
waitSerial data 0 && echo data-gone
/usr/bin/blip-meta exit 0
poweroff -f
`)
	itReported(t, n, 60*time.Second, "started", id, started)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := n.AttachVolume(ctx, &pb.AttachVolume{AllocationId: id, AttachmentId: "dddddddddddddddd", Generation: 1, Uid: "udata", Name: "data",
		ContentId: "cdata", SizeBytes: 64 << 20, OriginPaths: []*pb.Path{{Node: "s1"}}, SlotDisk: 1}); err != nil {
		t.Fatal(err)
	}
	w, err := meta.OpenWriter(filepath.Join(n.slotDir("slot-0"), slot.FileMeta))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if h, _, err := w.ReadHost(); err != nil || len(h.Volumes) != 2 || h.Boot.RootSerial != "root" {
		t.Fatal("host data", h, err)
	}
	itWait(t, "guest sees data", 30*time.Second, func() bool { return strings.Contains(itConsole(n), "saw-data") })
	if err := n.DetachVolume(ctx, &pb.DetachVolume{AllocationId: id, AttachmentId: "dddddddddddddddd", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if h, _, err := w.ReadHost(); err != nil || len(h.Volumes) != 1 {
		t.Fatal("host data after detach", h, err)
	}
	ex := itReported(t, n, 60*time.Second, "exited", id, exited).Exit
	if ex.Reason != api.ReasonSucceeded || ex.ExitCode == nil || *ex.ExitCode != 0 || !strings.Contains(itConsole(n), "data-gone") {
		t.Fatalf("%v\n%s", ex, itConsole(n))
	}
	if err := n.Release(ctx, id); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationNodeDeadline: a guest that never stops is killed at the
// deadline.
func TestIntegrationNodeDeadline(t *testing.T) {
	e := itSetup(t)
	n, id := itBoot(t, e, 5*time.Second, itInitHead+"sleep 1000\n")
	ex := itReported(t, n, 60*time.Second, "exited", id, exited).Exit
	if ex.Reason != api.ReasonTTLExceeded {
		t.Fatal(ex)
	}
}

// TestIntegrationGracefulKill: busybox init ignores the power button, so
// a graceful Kill ends in the hard kill after the timeout.
func TestIntegrationGracefulKill(t *testing.T) {
	e := itSetup(t)
	n, id := itBoot(t, e, time.Hour, itInitHead+"sleep 1000\n")
	itReported(t, n, 60*time.Second, "started", id, started)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := n.Kill(ctx, &pb.Kill{AllocationId: id, Reason: "test", Graceful: true, GracefulTimeout: durationpb.New(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if r := n.allocs[id].record(); r.HVExit == nil || r.HVExit.Reason != api.ReasonHypervisorExited {
		t.Fatal(r.HVExit)
	}
}

// TestIntegrationHotplug adds and removes a volume disk with the real
// Cloud Hypervisor: after remove-device the node must
// see that Cloud Hypervisor closed the backing file, and adding the same
// ID twice must be a no-op.
func TestIntegrationHotplug(t *testing.T) {
	e := itSetup(t)
	n, st := itNode(t, e)
	dir := n.slotDir("slot-0")
	disks, err := st.SlotDisks(context.Background(), "slot-0")
	if err != nil {
		t.Fatal(err)
	}
	itRun(t, "truncate", "-s", "64M", disks[3])
	itSlot(t, e, dir)
	itWait(t, "slot ready", 60*time.Second, func() bool { return exists(filepath.Join(dir, slot.FileReady)) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := n.ensureSlotLink("slot-0", "uvol", 3); err != nil {
		t.Fatal(err)
	}
	hv := n.cfg.Hypervisor
	d := chapi.VolumeDisk(n.containerVolumePath("slot-0", "uvol"), "aaaaaaaaaaaaaaaa", "vol")
	for i := 0; i < 2; i++ {
		if err := hv.AddDisk(ctx, dir, d); err != nil {
			t.Fatal(err)
		}
	}
	vmm := func(c string) bool { return strings.HasPrefix(c, "cloud-hyperv") }
	if pids, err := FDHolders("/proc", disks[3], vmm); err != nil || len(pids) != 1 {
		t.Fatal("cloud hypervisor does not hold the disk", pids, err)
	}
	if has, err := slot.Client(dir).HasDisk(ctx, d.ID); err != nil || !has {
		t.Fatal(has, err)
	}
	start := time.Now()
	if err := hv.RemoveDisk(ctx, dir, d.ID, disks[3]); err != nil {
		t.Fatal(err)
	}
	t.Logf("unplug confirmed after %v", time.Since(start))
	if pids, _ := FDHolders("/proc", disks[3], vmm); len(pids) != 0 {
		t.Fatal("still open", pids)
	}
	if err := hv.RemoveDisk(ctx, dir, d.ID, disks[3]); err != nil {
		t.Fatal("repeat", err)
	}
}
