package node

import (
	"bytes"
	"context"
	"fmt"
	"github.com/example/blip/internal/node/nodetest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// fakePods is a settable PodLister.
type fakePods struct {
	mu sync.Mutex
	m  map[string]PodRef
}

func (f *fakePods) set(m map[string]PodRef) {
	f.mu.Lock()
	f.m = m
	f.mu.Unlock()
}

func (f *fakePods) SlotPods(context.Context) (map[string]PodRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]PodRef{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}

// fakeHV records hot-plug calls per slot directory.
type fakeHV struct {
	mu      sync.Mutex
	disks   map[string]map[string]chapi.DiskConfig // slot dir base -> ID -> disk
	removed []string
	fail    error
	// buttons counts power button presses per slot; onButton runs on each.
	buttons  map[string]int
	onButton func(dir string)
}

func (f *fakeHV) PowerButton(_ context.Context, dir string) error {
	f.mu.Lock()
	if f.buttons == nil {
		f.buttons = map[string]int{}
	}
	f.buttons[filepath.Base(dir)]++
	hook := f.onButton
	f.mu.Unlock()
	if hook != nil {
		go hook(dir)
	}
	return nil
}

func (f *fakeHV) presses(slotID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buttons[slotID]
}

func (f *fakeHV) AddDisk(_ context.Context, dir string, d chapi.DiskConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	k := filepath.Base(dir)
	if f.disks[k] == nil {
		f.disks[k] = map[string]chapi.DiskConfig{}
	}
	f.disks[k][d.ID] = d
	return nil
}

func (f *fakeHV) RemoveDisk(_ context.Context, dir, id, hostDev string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	delete(f.disks[filepath.Base(dir)], id)
	f.removed = append(f.removed, filepath.Base(dir)+"/"+id+"@"+filepath.Base(hostDev))
	return nil
}

func (f *fakeHV) has(slotID, id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.disks[slotID][id]
	return ok
}

type harness struct {
	t      *testing.T
	n      *Node
	st     *nodetest.FakeStorage
	pods   *fakePods
	hv     *fakeHV
	cancel context.CancelFunc
	dir    string
	mu     sync.Mutex
}

func newHarness(t *testing.T, dir string, slots int) *harness {
	return newHarnessCfg(t, dir, slots, nil)
}

func newHarnessCfg(t *testing.T, dir string, slots int, mod func(*Config)) *harness {
	h := &harness{t: t, pods: &fakePods{}, dir: dir, hv: &fakeHV{disks: map[string]map[string]chapi.DiskConfig{}}}
	h.st = nodetest.NewFakeStorage("w1", filepath.Join(dir, "dev"))
	os.MkdirAll(filepath.Join(dir, "dev"), 0o755)
	h.st.AddContent("in", 1<<30)
	nc := &api.NodeConfig{Hypervisor: "kvm", Slots: slots, Compute: &api.NodeComputeConfig{Device: "/dev/x"}, Storage: &api.NodeStorageConfig{}}
	nc.Default()
	cfg := Config{
		NodeName: "w1", BootID: "boot-1", NodeConfig: nc,
		SlotsDir: filepath.Join(dir, "slots"), StateDir: filepath.Join(dir, "state"),
		Storage: h.st, Pods: h.pods,
		Hypervisor: h.hv,
		Poll:       40 * time.Millisecond, SlotLostAfter: 100 * time.Millisecond,
		ReleaseWait: 300 * time.Millisecond, SlotUnreachableAfter: time.Hour,
	}
	if mod != nil {
		mod(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.n = n
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	go n.Run(ctx)
	return h
}

// bootSlot makes slot id look booted for pod name.
func (h *harness) bootSlot(id, pod string) {
	d := h.n.slotDir(id)
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, slot.FileVsock), nil, 0o644)
	if err := meta.Create(filepath.Join(d, slot.FileMeta)); err != nil {
		h.t.Fatal(err)
	}
	// What blipd slot does when the stub reports WAITING.
	h.guest(id, &meta.GuestData{State: meta.StateWaiting, BootCount: 1})
	os.WriteFile(filepath.Join(d, slot.FileReady), nil, 0o644)
	os.WriteFile(filepath.Join(d, slot.FileResolvConf), []byte("nameserver 10.96.0.10\nsearch a.svc b\n"), 0o644)
	os.WriteFile(filepath.Join(d, slot.FileNetwork), []byte(`{"iface":"eth0","mac":"0a:58:0a:f4:01:05","mtu":1500,`+
		`"addresses":["10.244.1.5/24"],"routes":[{"destination":"10.244.1.1/32"},{"gateway":"10.244.1.1","onlink":true}]}`), 0o644)
	m, _ := h.pods.SlotPods(context.Background())
	m[id] = PodRef{Namespace: api.SystemNamespace, Name: pod}
	h.pods.set(m)
	h.eventually("slot ready", func() bool { return exists(filepath.Join(d, slot.FileReady)) })
}

// guest writes the guest area of the slot's metadata disk, as the stub.
func (h *harness) guest(id string, g *meta.GuestData) {
	h.t.Helper()
	d, err := meta.Open(filepath.Join(h.n.slotDir(id), slot.FileMeta))
	if err != nil {
		h.t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteGuest(g); err != nil {
		h.t.Fatal(err)
	}
}

// host reads the host data of the slot's metadata disk.
func (h *harness) host(id string) *meta.HostData {
	h.t.Helper()
	w, err := meta.OpenWriter(filepath.Join(h.n.slotDir(id), slot.FileMeta))
	if err != nil {
		h.t.Fatal(err)
	}
	defer w.Close()
	d, _, err := w.ReadHost()
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

func (h *harness) eventually(what string, f func() bool) {
	h.t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for %s", what)
}

// drain returns the queued messages, with each pending state built.
func (h *harness) drain() []*pb.NodeMessage { return drainOut(h.n) }

func drainOut(n *Node) []*pb.NodeMessage {
	var out []*pb.NodeMessage
	for n.out.len() > 0 {
		m, _ := n.out.pop(context.Background())
		if m.state {
			s, err := n.State(context.Background())
			if err != nil {
				continue
			}
			m.m = &pb.NodeMessage{Msg: &pb.NodeMessage_State{State: s}}
		}
		out = append(out, m.m)
	}
	return out
}

// reported returns allocation id from the last state in ms, or nil.
func reported(ms []*pb.NodeMessage, id string) *pb.AllocationInfo {
	for i := len(ms) - 1; i >= 0; i-- {
		if s := ms[i].GetState(); s != nil {
			for _, a := range s.Allocations {
				if a.AllocationId == id {
					return a
				}
			}
			return nil
		}
	}
	return nil
}

func assignCmd(id, pod string, deadline time.Time) *pb.AssignSlot {
	return &pb.AssignSlot{
		AllocationId: id, Blip: &pb.ObjectRef{Namespace: "team-a", Name: "build-7", Uid: "uid-" + id},
		Pod: &pb.ObjectRef{Namespace: api.SystemNamespace, Name: pod}, Deadline: timestamppb.New(deadline),
	}
}

func attachCmd(alloc, att, uid, name string, disk int32, gen int64) *pb.AttachVolume {
	return &pb.AttachVolume{
		AllocationId: alloc, AttachmentId: att, Generation: gen, Uid: uid, Name: name, ContentId: "c-" + uid,
		SizeBytes: 1 << 20, OriginPaths: []*pb.Path{{Node: "s1"}, {Node: "s2"}}, SlotDisk: disk,
		Blipvol: &pb.ObjectRef{Namespace: "team-a", Name: name, Uid: uid},
	}
}

func (h *harness) keyed() {
	h.n.mu.Lock()
	h.n.hostNQN = api.HostNQN("w1")
	h.n.mu.Unlock()
}

// run runs a command like Dispatch does and returns its result.
func (h *harness) run(c *pb.Command) *pb.CommandResult {
	if c.OperationId == "" {
		c.OperationId = "op"
	}
	return h.n.run(c)
}

// ready assigns a slot to a fresh allocation and attaches its root.
func (h *harness) ready(id, slotID, pod string) {
	h.t.Helper()
	ctx := context.Background()
	h.bootSlot(slotID, pod)
	if err := h.n.AssignSlot(ctx, assignCmd(id, pod, time.Now().Add(time.Hour))); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.n.AttachVolume(ctx, attachCmd(id, "root-"+id, "uroot-"+id, "root", 0, 1)); err != nil {
		h.t.Fatal(err)
	}
}

func startCmd(id string) *pb.StartWorkload {
	return &pb.StartWorkload{AllocationId: id, RootAttachmentId: "root-" + id, Params: &pb.RunParams{Init: []string{"/sbin/init"}}}
}

const (
	attRoot = "0123456789abcdef"
	attData = "fedcba9876543210"
)

func TestRunSuccessAndRelease(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 2)
	h.keyed()
	h.bootSlot("slot-1", "pool-a")
	id := "alloc-1"
	if err := h.n.AssignSlot(ctx, assignCmd(id, "pool-a", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	// Repeat is a no-op.
	if err := h.n.AssignSlot(ctx, assignCmd(id, "pool-a", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	dir := h.n.slotDir("slot-1")
	as, err := readAssignment(dir)
	if err != nil || as.AllocationID != id || !exists(filepath.Join(dir, slot.FileAssigned)) {
		t.Fatal("assignment", as, err)
	}
	if exists(filepath.Join(dir, slot.FileReady)) {
		t.Fatal("ready file kept after assignment")
	}
	// Start needs an attached root.
	if err := h.n.StartWorkload(ctx, &pb.StartWorkload{AllocationId: id, RootAttachmentId: attRoot, Params: &pb.RunParams{Init: []string{"/sbin/init"}}}); err == nil {
		t.Fatal("start without root")
	}
	for i := 0; i < 2; i++ {
		r, err := h.n.AttachVolume(ctx, attachCmd(id, attRoot, "uid-root", "root", 0, 3))
		if err != nil || r.GuestPath != api.GuestVolumePath("root") || r.HostPath != "/dev/blip/volumes/uid-root" {
			t.Fatal(r, err)
		}
	}
	if _, err := h.n.AttachVolume(ctx, attachCmd(id, attData, "uid-data", "data", 3, 7)); err != nil {
		t.Fatal(err)
	}
	if h.st.CallCount("AttachVolume") != 2 {
		t.Fatal("storage attach repeated", h.st.CallCount("AttachVolume"))
	}
	if l, err := os.Readlink(filepath.Join(dir, "volumes", "uid-data")); err != nil || l != "/dev/blip/disks/3" {
		t.Fatal("slot link", l, err)
	}
	if h.st.SlotDiskMapping("slot-1", 3) != id+"/"+attData {
		t.Fatal("slot disk mapping")
	}
	d, ok := h.hv.disks["slot-1"]["blip-"+attData]
	if !ok || d.Path != "/run/blip/volumes/uid-data" || d.Serial != "data" || !d.Direct || d.Sparse == nil || *d.Sparse {
		t.Fatalf("hot-plugged disk %+v", d)
	}
	if err := h.n.StartWorkload(ctx, &pb.StartWorkload{AllocationId: id, RootAttachmentId: attRoot, Params: &pb.RunParams{
		Init: []string{"/sbin/init", "quiet"},
	}}); err != nil {
		t.Fatal(err)
	}
	hd := h.host("slot-1")
	if hd.AllocationID != id || hd.Boot.RootSerial != "root" || len(hd.Boot.Init) != 2 || hd.Boot.Init[1] != "quiet" || hd.Boot.RootFSType != "ext4" ||
		hd.Hostname != "build-7" || hd.Identity.Name != "build-7" || hd.Identity.UID != "uid-"+id ||
		len(hd.Volumes) != 2 || hd.Volumes[0].Name != "data" || hd.Volumes[1].Serial != "root" ||
		hd.Network == nil || hd.Network.MAC != "0a:58:0a:f4:01:05" || hd.Network.DNS[0] != "10.96.0.10" || len(hd.Network.Routes) != 2 {
		t.Fatalf("host data %+v", hd)
	}
	// The stub execs init; then the guest reboots and execs again.
	h.guest("slot-1", &meta.GuestData{State: meta.StateExec, BootCount: 1})
	h.eventually("started 1", func() bool { return h.n.allocs[id].record().BootCount == 1 })
	h.guest("slot-1", &meta.GuestData{State: meta.StateWaiting, BootCount: 2})
	time.Sleep(50 * time.Millisecond)
	h.guest("slot-1", &meta.GuestData{State: meta.StateExec, BootCount: 2})
	h.eventually("started 2", func() bool { return h.n.allocs[id].record().BootCount == 2 })
	// Release before the VM stopped is refused.
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: id, AttachmentId: attData, Generation: 7}); err == nil {
		t.Fatal("release of a plugged attachment")
	}
	os.WriteFile(filepath.Join(dir, slot.FileExit), []byte(`{"exitCode":0,"cause":"exited","reason":"Succeeded","guestExitCode":0,"bootCount":2}`), 0o644)
	var rep *pb.AllocationInfo
	h.eventually("hv exit reported", func() bool {
		if r := reported(h.drain(), id); r != nil {
			rep = r
		}
		return rep.GetExit() != nil
	})
	if ex := rep.Exit; rep.BootCount != 2 || ex.Reason != api.ReasonSucceeded || ex.ExitCode == nil || *ex.ExitCode != 0 || ex.RestartCount != 1 {
		t.Fatalf("reported: %v", rep)
	}
	// Final capture of both after the stop, then release one by one.
	cr, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: id, Seq: 9, Attachments: []*pb.AttachmentRef{
		{AttachmentId: attRoot, Generation: 3}, {AttachmentId: attData, Generation: 7}}})
	if err != nil || len(cr.Snapshots) != 2 {
		t.Fatal(cr, err)
	}
	st, _ := h.n.State(ctx)
	ai := st.Allocations[0]
	if len(st.Allocations) != 1 || ai.Exit == nil || !ai.Assigned || ai.BootCount != 2 || ai.RootAttachmentId != attRoot || len(ai.Attachments) != 2 {
		t.Fatalf("state %v", st.Allocations)
	}
	for _, at := range ai.Attachments {
		if at.State != pb.AttachmentState_ATTACHMENT_STATE_DETACHED {
			t.Fatalf("attachment %v", at)
		}
	}
	if st.Capacity.Compute.DisksPerSlot != 8 {
		t.Fatal("disks per slot", st.Capacity.Compute)
	}
	for _, c := range []*pb.ReleaseAttachment{{AllocationId: id, AttachmentId: attData, Generation: 7}, {AllocationId: id, AttachmentId: attRoot, Generation: 3}} {
		if err := h.n.ReleaseAttachment(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := h.n.ReleaseAttachment(ctx, c); err != nil {
			t.Fatal("repeat", err)
		}
	}
	if exists(filepath.Join(dir, "volumes", "uid-data")) {
		t.Fatal("slot link kept")
	}
	if err := h.n.Release(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := h.n.Release(ctx, id); err != nil {
		t.Fatal("second release", err)
	}
	if h.st.CallCount("ReleaseAllocation") != 1 {
		t.Fatal("release count")
	}
	if err := h.n.StartWorkload(ctx, startCmd(id)); err == nil {
		t.Fatal("command for finished allocation accepted")
	} else if _, ok := err.(*errReject); !ok {
		t.Fatal(err)
	}
	if exists(h.n.allocPath(id)) {
		t.Fatal("record kept")
	}
	// Release-type commands for a finished allocation succeed.
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: id, AttachmentId: attData, Generation: 7}); err != nil {
		t.Fatal(err)
	}
}

func TestAssignChecks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 2)
	h.keyed()
	if err := h.n.AssignSlot(ctx, assignCmd("a1", "nope", time.Now().Add(time.Hour))); err == nil {
		t.Fatal(err)
	}
	h.bootSlot("slot-0", "p0")
	if err := h.n.AssignSlot(ctx, assignCmd("a1", "p0", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := h.n.AssignSlot(ctx, assignCmd("a2", "p0", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("second allocation on one slot")
	}
	c := assignCmd("a1", "p0", time.Now().Add(time.Hour))
	c.Blip.Uid = "other"
	if err := h.n.AssignSlot(ctx, c); err == nil {
		t.Fatal("changed blip accepted")
	}
	// Attach checks.
	for _, c := range []*pb.AttachVolume{
		attachCmd("a1", attRoot, "u", "toolongtoolongtoolong", 0, 1),
		attachCmd("a1", attRoot, "u", "blip-meta", 0, 1),
		attachCmd("a1", attRoot, "u", "n", 8, 1),
		attachCmd("a1", attRoot, "", "n", 0, 1),
	} {
		if _, err := h.n.AttachVolume(ctx, c); err == nil {
			t.Fatal("bad attach accepted", c)
		}
	}
	if _, err := h.n.AttachVolume(ctx, attachCmd("nope", attRoot, "u", "n", 0, 1)); ErrorCodeOf(err) != pb.ErrorCode_ERROR_CODE_NOT_FOUND {
		t.Fatal(err)
	}
}

func TestLiveAttachDetach(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 2)
	h.keyed()
	h.ready("a", "slot-0", "p0")
	h.ready("b", "slot-1", "p1")
	if err := h.n.StartWorkload(ctx, startCmd("a")); err != nil {
		t.Fatal(err)
	}
	// Conflicts: slot disk in use, BlipVol attached elsewhere, other
	// parameters for an existing attachment.
	for _, c := range []*pb.AttachVolume{
		attachCmd("a", attData, "u-x", "x", 0, 1),
		attachCmd("a", attData, "uroot-b", "x", 1, 1),
		attachCmd("a", "root-a", "uroot-a", "root", 5, 1),
	} {
		r := h.run(&pb.Command{Op: &pb.Command_AttachVolume{AttachVolume: c}})
		if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED || r.Code != pb.ErrorCode_ERROR_CODE_CONFLICT {
			t.Fatal(c, r)
		}
	}
	if _, err := h.n.AttachVolume(ctx, attachCmd("a", attData, "u-x", "x", 1, 4)); err != nil {
		t.Fatal(err)
	}
	if d := h.hv.disks["slot-0"]["blip-"+attData]; d.Serial != "x" {
		t.Fatal("serial", d)
	}
	// The root volume of a running VM cannot be detached.
	r := h.run(&pb.Command{Op: &pb.Command_DetachVolume{DetachVolume: &pb.DetachVolume{AllocationId: "a", AttachmentId: "root-a", Generation: 1}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED {
		t.Fatal(r)
	}
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: "a", AttachmentId: attData, Generation: 4}); err == nil {
		t.Fatal("release before detach")
	}
	// Detach is forced: the guest is not asked.
	r = h.run(&pb.Command{Op: &pb.Command_DetachVolume{DetachVolume: &pb.DetachVolume{AllocationId: "a", AttachmentId: attData, Generation: 4}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}
	if h.hv.has("slot-0", "blip-"+attData) || h.st.SlotDiskMapping("slot-0", 1) != "" || exists(h.n.slotLinkPath("slot-0", "u-x")) {
		t.Fatal("detach left the disk")
	}
	if len(h.hv.removed) != 1 || h.hv.removed[0] != "slot-0/blip-"+attData+"@slot-dev-slot-0-d1" {
		t.Fatal(h.hv.removed)
	}
	// Repeat is OK, the overlay stays until release; capture still works.
	if err := h.n.DetachVolume(ctx, &pb.DetachVolume{AllocationId: "a", AttachmentId: attData, Generation: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 1, Attachments: []*pb.AttachmentRef{{AttachmentId: attData, Generation: 4}}}); err != nil {
		t.Fatal(err)
	}
	// The slot disk is free again for another volume while x is detached.
	if _, err := h.n.AttachVolume(ctx, attachCmd("a", "aaaaaaaaaaaaaaaa", "u-y", "y", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if h.st.SlotDiskMapping("slot-0", 1) != "a/aaaaaaaaaaaaaaaa" {
		t.Fatal("slot disk not reused")
	}
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: "a", AttachmentId: attData, Generation: 4}); err != nil {
		t.Fatal(err)
	}
	// Unknown attachments: detach and release succeed.
	if err := h.n.DetachVolume(ctx, &pb.DetachVolume{AllocationId: "a", AttachmentId: "unknown", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: "a", AttachmentId: "unknown", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	// Re-attach of the released BlipVol in another allocation.
	if _, err := h.n.AttachVolume(ctx, attachCmd("b", attData, "u-x", "x", 1, 5)); err != nil {
		t.Fatal(err)
	}
	// Hot-plug failure is reported as HOTPLUG.
	h.hv.mu.Lock()
	h.hv.fail = os.ErrDeadlineExceeded
	h.hv.mu.Unlock()
	r = h.run(&pb.Command{Op: &pb.Command_AttachVolume{AttachVolume: attachCmd("b", "bbbbbbbbbbbbbbbb", "u-z", "z", 2, 1)}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_HOTPLUG {
		t.Fatal(r)
	}
	st, _ := h.n.State(ctx)
	for _, ai := range st.Allocations {
		for _, at := range ai.Attachments {
			if at.AttachmentId == "bbbbbbbbbbbbbbbb" && at.State != pb.AttachmentState_ATTACHMENT_STATE_ATTACHING {
				t.Fatal(at)
			}
		}
	}
}

func TestStaleGenerations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	h := newHarness(t, dir, 2)
	h.keyed()
	h.ready("a", "slot-0", "p0")
	if _, err := h.n.AttachVolume(ctx, attachCmd("a", attData, "u-x", "x", 1, 5)); err != nil {
		t.Fatal(err)
	}
	check := func(c *pb.Command, code pb.ErrorCode) {
		t.Helper()
		r := h.run(c)
		if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED || r.Code != code {
			t.Fatal(c, r)
		}
	}
	stale, conflict := pb.ErrorCode_ERROR_CODE_STALE_GENERATION, pb.ErrorCode_ERROR_CODE_CONFLICT
	check(&pb.Command{Op: &pb.Command_DetachVolume{DetachVolume: &pb.DetachVolume{AllocationId: "a", AttachmentId: attData, Generation: 4}}}, stale)
	check(&pb.Command{Op: &pb.Command_DetachVolume{DetachVolume: &pb.DetachVolume{AllocationId: "a", AttachmentId: attData, Generation: 6}}}, conflict)
	check(&pb.Command{Op: &pb.Command_AttachVolume{AttachVolume: attachCmd("a", attData, "u-x", "x", 1, 4)}}, stale)
	check(&pb.Command{Op: &pb.Command_CaptureLocal{CaptureLocal: &pb.CaptureLocal{AllocationId: "a", Seq: 1,
		Attachments: []*pb.AttachmentRef{{AttachmentId: attData, Generation: 4}}}}}, stale)
	check(&pb.Command{Op: &pb.Command_DropLocalSnapshot{DropLocalSnapshot: &pb.DropLocalSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 3, Seq: 1}}}, stale)
	check(&pb.Command{Op: &pb.Command_ReleaseAttachment{ReleaseAttachment: &pb.ReleaseAttachment{AllocationId: "a", AttachmentId: attData, Generation: 2}}}, stale)
	check(&pb.Command{Op: &pb.Command_WriteSnapshot{WriteSnapshot: &pb.WriteSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 1, Seq: 1,
		ContentId: "n", Targets: []*pb.Path{{Node: "s1", Address: "x", SubsystemNqn: "nqn.x"}}}}}, stale)
	// Unknown attachments for capture and send are NOT_FOUND.
	r := h.run(&pb.Command{Op: &pb.Command_CaptureLocal{CaptureLocal: &pb.CaptureLocal{AllocationId: "a", Seq: 1,
		Attachments: []*pb.AttachmentRef{{AttachmentId: "nope", Generation: 1}}}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_NOT_FOUND {
		t.Fatal(r)
	}
	if err := h.n.DetachVolume(ctx, &pb.DetachVolume{AllocationId: "a", AttachmentId: attData, Generation: 5}); err != nil {
		t.Fatal(err)
	}
	if err := h.n.ReleaseAttachment(ctx, &pb.ReleaseAttachment{AllocationId: "a", AttachmentId: attData, Generation: 5}); err != nil {
		t.Fatal(err)
	}
	// The node remembers generation 5 for the UID across restarts: a new
	// attachment with an older claim is refused.
	h.cancel()
	time.Sleep(50 * time.Millisecond)
	h2 := newHarness(t, dir, 2)
	h2.pods.set(map[string]PodRef{"slot-0": {Namespace: api.SystemNamespace, Name: "p0"}})
	h2.keyed()
	r = h2.run(&pb.Command{Op: &pb.Command_AttachVolume{AttachVolume: attachCmd("a", "1111111111111111", "u-x", "x", 1, 4)}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED || r.Code != stale {
		t.Fatal(r)
	}
	if _, err := h2.n.AttachVolume(ctx, attachCmd("a", "1111111111111111", "u-x", "x", 1, 6)); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureRules(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 1)
	h.keyed()
	h.ready("a", "slot-0", "p0")
	if _, err := h.n.AttachVolume(ctx, attachCmd("a", attData, "u-x", "x", 1, 2)); err != nil {
		t.Fatal(err)
	}
	both := []*pb.AttachmentRef{{AttachmentId: "root-a", Generation: 1}, {AttachmentId: attData, Generation: 2}}
	r1, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 5, Attachments: both})
	if err != nil || len(r1.Snapshots) != 2 || r1.Suspended == nil {
		t.Fatal(r1, err)
	}
	// Idempotent per seq; same set in another order is the same.
	r2, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 5, Attachments: []*pb.AttachmentRef{both[1], both[0]}})
	if err != nil || r2.Snapshots[0].Created.AsTime() != r1.Snapshots[0].Created.AsTime() || h.st.CallCount("CaptureLocal") != 2 {
		t.Fatal(r2, err)
	}
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 5, Attachments: both[:1]}); err == nil {
		t.Fatal("other set for the same seq")
	}
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 6, Attachments: both}); err != nil {
		t.Fatal(err)
	}
	// Retention: baseline + one in flight.
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 7, Attachments: both}); ErrorCodeOf(err) != pb.ErrorCode_ERROR_CODE_CONFLICT {
		t.Fatal(err)
	}
	if err := h.n.DropLocalSnapshot(ctx, &pb.DropLocalSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 2, Seq: 5}); err != nil {
		t.Fatal(err)
	}
	if err := h.n.DropLocalSnapshot(ctx, &pb.DropLocalSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 2, Seq: 5}); err != nil {
		t.Fatal("repeat drop", err)
	}
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 7, Attachments: both[1:]}); err != nil {
		t.Fatal(err)
	}
	// Older seq than an existing snapshot is refused.
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 3, Attachments: both[1:]}); err == nil {
		t.Fatal("older seq accepted")
	}
	// Suspend budget exceeded.
	h.st.FailNextCall("CaptureLocal", Codef(pb.ErrorCode_ERROR_CODE_SUSPEND_TIMEOUT, "suspended too long"))
	if err := h.n.DropLocalSnapshot(ctx, &pb.DropLocalSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 2, Seq: 6}); err != nil {
		t.Fatal(err)
	}
	r := h.run(&pb.Command{Op: &pb.Command_CaptureLocal{CaptureLocal: &pb.CaptureLocal{AllocationId: "a", Seq: 8, Attachments: both[1:]}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_SUSPEND_TIMEOUT {
		t.Fatal(r)
	}
	// The failed seq is not recorded: a retry with another set works.
	if _, err := h.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 8, Attachments: both[1:]}); err != nil {
		t.Fatal(err)
	}
}

func TestGracefulKill(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 2)
	h.keyed()
	h.ready("a", "slot-0", "p0")
	if err := h.n.StartWorkload(ctx, startCmd("a")); err != nil {
		t.Fatal(err)
	}
	dir := h.n.slotDir("slot-0")
	// The guest powers off on the power button.
	h.hv.onButton = func(d string) {
		if filepath.Base(d) == "slot-0" {
			time.Sleep(50 * time.Millisecond)
			os.WriteFile(filepath.Join(d, slot.FileExit), []byte(`{"exitCode":0,"cause":"exited","reason":"Succeeded","bootCount":1}`), 0o644)
		}
	}
	r := h.run(&pb.Command{Op: &pb.Command_Kill{Kill: &pb.Kill{AllocationId: "a", Reason: "Cancelled", Graceful: true, GracefulTimeout: durationpb.New(5 * time.Second)}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}
	if exists(filepath.Join(dir, slot.FileKill)) || h.hv.presses("slot-0") != 1 {
		t.Fatal("graceful stop killed", h.hv.presses("slot-0"))
	}
	rec := h.n.allocs["a"].record()
	if rec.HVExit == nil || rec.HVExit.Reason != api.ReasonSucceeded || rec.HVExit.ExitCode != nil {
		t.Fatalf("%+v", rec)
	}
	if rec.Attachments["root-a"].State != pb.AttachmentState_ATTACHMENT_STATE_DETACHED {
		t.Fatal("attachments not detached after exit")
	}
	if ex := reported(h.drain(), "a").GetExit(); ex.GetReason() != api.ReasonSucceeded {
		t.Fatal("exit not reported", ex)
	}
	// Kill again: the VM is gone, OK at once.
	if r := h.run(&pb.Command{Op: &pb.Command_Kill{Kill: &pb.Kill{AllocationId: "a", Graceful: true}}}); r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}

	// A guest that ignores the power button is killed after the timeout.
	h.ready("b", "slot-1", "p1")
	dir = h.n.slotDir("slot-1")
	go func() {
		for !exists(filepath.Join(dir, slot.FileKill)) {
			time.Sleep(10 * time.Millisecond)
		}
		os.WriteFile(filepath.Join(dir, slot.FileExit), []byte(`{"exitCode":-1,"signal":"killed","cause":"killed","reason":"HypervisorExited"}`), 0o644)
	}()
	start := time.Now()
	r = h.run(&pb.Command{Op: &pb.Command_Kill{Kill: &pb.Kill{AllocationId: "b", Reason: "TTLExceeded", Graceful: true, GracefulTimeout: durationpb.New(200 * time.Millisecond)}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || time.Since(start) < 200*time.Millisecond || h.hv.presses("slot-1") != 1 {
		t.Fatal(r, time.Since(start))
	}
	if rec := h.n.allocs["b"].record(); rec.HVExit == nil || rec.HVExit.Reason != api.ReasonHypervisorExited || rec.KillReason != "TTLExceeded" {
		t.Fatalf("%+v", rec.HVExit)
	}
}

func TestDeadlineFailureAndSlotLost(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 4)
	h.keyed()
	h.bootSlot("slot-0", "p0")
	h.bootSlot("slot-1", "p1")
	h.bootSlot("slot-2", "p2")
	h.bootSlot("slot-3", "p3")

	// Deadline: the node does not kill. blipd slot kills at deadline +
	// kill_grace (assignment.json); the exit is reported as written.
	dl := time.Now().Add(50 * time.Millisecond)
	ac := assignCmd("d", "p0", dl)
	ac.KillGrace = durationpb.New(time.Minute)
	if err := h.n.AssignSlot(ctx, ac); err != nil {
		t.Fatal(err)
	}
	if as, err := readAssignment(h.n.slotDir("slot-0")); err != nil || !as.KillTime.Equal(dl.Add(time.Minute)) {
		t.Fatal("kill time", as, err)
	}
	time.Sleep(200 * time.Millisecond)
	if exists(filepath.Join(h.n.slotDir("slot-0"), slot.FileKill)) {
		t.Fatal("node killed at the deadline")
	}
	os.WriteFile(filepath.Join(h.n.slotDir("slot-0"), slot.FileExit), []byte(`{"exitCode":-1,"signal":"killed","cause":"deadline","reason":"TTLExceeded","message":"the deadline passed"}`), 0o644)
	h.eventually("hv exit", func() bool { r := h.n.allocs["d"].record(); return r.HVExit != nil })
	if r := h.n.allocs["d"].record(); r.HVExit.Reason != api.ReasonTTLExceeded || r.HVExit.Message != "the deadline passed" {
		t.Fatalf("%+v", r.HVExit)
	}

	// Exit classes from exit.json.
	cases := []struct {
		slotID, id, exit string
		want             string
		code             int32
		msg              string
		restarts         int32
	}{
		{"slot-1", "f", `{"exitCode":0,"cause":"exited","reason":"BootFailed","message":"boot failed (RootMountFailed): no ext4","bootCount":1}`, api.ReasonBootFailed, -1, "boot failed (RootMountFailed): no ext4", 0},
		{"slot-3", "p", `{"exitCode":-1,"signal":"killed","cause":"panic","reason":"InitExited","message":"init exited with code 3","guestExitCode":3,"bootCount":3}`, api.ReasonInitExited, 3, "init exited with code 3", 2},
	}
	for _, c := range cases {
		h.ready(c.id, c.slotID, "p"+c.slotID[len(c.slotID)-1:])
		if err := h.n.StartWorkload(ctx, startCmd(c.id)); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(h.n.slotDir(c.slotID), slot.FileExit), []byte(c.exit), 0o644)
		h.eventually("exit "+c.id, func() bool { return h.n.allocs[c.id].record().HVExit != nil })
		ex := h.n.allocs[c.id].record().HVExit.exited(c.id)
		if ex.Reason != c.want || ex.Message != c.msg || ex.RestartCount != c.restarts || (c.code < 0) != (ex.ExitCode == nil) || (c.code >= 0 && *ex.ExitCode != c.code) {
			t.Fatalf("%s: %v", c.id, ex)
		}
	}

	// Slot lost: the pod goes away.
	if err := h.n.AssignSlot(ctx, assignCmd("l", "p2", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	m, _ := h.pods.SlotPods(ctx)
	delete(m, "slot-2")
	h.pods.set(m)
	h.eventually("slot lost reported", func() bool { return reported(h.drain(), "l").GetSlotLost() != "" })
	// Release of a lost slot works and does not wait for an exit.
	if err := h.n.Release(ctx, "l"); err != nil {
		t.Fatal(err)
	}
}

func TestRestartResumes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	h := newHarness(t, dir, 1)
	h.keyed()
	h.ready("r", "slot-0", "p0")
	if err := h.n.StartWorkload(ctx, startCmd("r")); err != nil {
		t.Fatal(err)
	}
	h.guest("slot-0", &meta.GuestData{State: meta.StateExec, BootCount: 1})
	h.eventually("started", func() bool { return h.n.allocs["r"].record().BootCount == 1 })
	h.n.mu.Lock()
	h.n.finished["old"] = time.Now()
	h.n.saveState()
	h.n.mu.Unlock()
	h.cancel()
	time.Sleep(50 * time.Millisecond)

	// Same boot: the record and the finished set come back, and the
	// watcher resumes.
	h2 := newHarness(t, dir, 1)
	h2.st = h.st
	h2.pods.set(map[string]PodRef{"slot-0": {Namespace: api.SystemNamespace, Name: "p0"}})
	if h2.n.allocs["r"] == nil || !h2.n.isFinished("old") {
		t.Fatal("state not loaded")
	}
	if at := h2.n.allocs["r"].record().Attachments["root-r"]; at == nil || at.State != pb.AttachmentState_ATTACHMENT_STATE_ATTACHED {
		t.Fatal("attachment not loaded", at)
	}
	// A reboot after the restart is reported once.
	h2.drain()
	h2.guest("slot-0", &meta.GuestData{State: meta.StateExec, BootCount: 2})
	h2.eventually("started 2", func() bool { return h2.n.allocs["r"].record().BootCount == 2 })
	// UpdateCredentials after a restart writes the new token; a volume
	// change keeps it although the node no longer has it in memory.
	if err := h2.n.UpdateCredentials(ctx, &pb.UpdateCredentials{AllocationId: "r", Credentials: &pb.Credentials{Token: []byte("T2")}}); err != nil {
		t.Fatal(err)
	}
	h2.n.allocs["r"].mu.Lock()
	h2.n.allocs["r"].creds = nil
	h2.n.allocs["r"].mu.Unlock()
	if _, err := h2.n.AttachVolume(ctx, attachCmd("r", "data-r", "udata-r", "data", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if hd := h2.host("slot-0"); hd.Credentials == nil || hd.Credentials.Token != "T2" || len(hd.Volumes) != 2 {
		t.Fatalf("host data %+v", hd)
	}

	// New boot: everything is dropped.
	h2.cancel()
	time.Sleep(50 * time.Millisecond)
	nc := h2.n.cfg
	nc.BootID = "boot-2"
	n3, err := New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if len(n3.allocs) != 0 || n3.isFinished("old") || len(n3.gens) != 0 {
		t.Fatal("state survived a reboot")
	}
}

func TestStateReportsUnknownDevices(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 1)
	// Devices of an allocation the node has no record of.
	if _, err := h.st.AttachVolume(ctx, VolumeSpec{AllocationID: "ghost", AttachmentID: attData, Generation: 2, UID: "u", ContentID: "c", Paths: []*pb.Path{{Node: "s1"}}}); err != nil {
		t.Fatal(err)
	}
	st, err := h.n.State(ctx)
	if err != nil || len(st.Allocations) != 1 || st.Allocations[0].AllocationId != "ghost" || len(st.Allocations[0].Attachments) != 1 ||
		st.Allocations[0].Attachments[0].Generation != 2 {
		t.Fatal(st, err)
	}
	if err := h.n.Release(ctx, "ghost"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.n.State(ctx); len(st.Allocations) != 0 {
		t.Fatal(st.Allocations)
	}
}

func TestResetSlotDirLosesAllocation(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 1)
	h.keyed()
	h.bootSlot("slot-0", "p0")
	if err := h.n.AssignSlot(ctx, assignCmd("x", "p0", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := h.n.resetSlotDir("slot-0"); err != nil {
		t.Fatal(err)
	}
	if h.n.allocs["x"].record().SlotLost == "" {
		t.Fatal("not lost")
	}
	if ents, _ := os.ReadDir(h.n.slotDir("slot-0")); len(ents) != 1 || ents[0].Name() != slot.DirVolumes {
		t.Fatal("slot dir not reset", ents)
	}
}

func TestFDHolders(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dev")
	os.WriteFile(p, nil, 0o600)
	comm, _ := os.ReadFile("/proc/self/comm")
	me := func(c string) bool { return c == strings.TrimSpace(string(comm)) }
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	pids, err := FDHolders("/proc", p, me)
	if err != nil || len(pids) != 1 || pids[0] != os.Getpid() {
		t.Fatal(pids, err)
	}
	f.Close()
	if pids, _ := FDHolders("/proc", p, me); len(pids) != 0 {
		t.Fatal(pids)
	}
	h := &CloudHypervisor{IsVMM: me, UnplugTimeout: 100 * time.Millisecond}
	f, _ = os.Open(p)
	defer f.Close()
	if err := h.waitClosed(context.Background(), p); err == nil {
		t.Fatal("wait succeeded with the file open")
	}
}

func TestUnknownThinsDeletedAfterGrace(t *testing.T) {
	h := newHarnessCfg(t, t.TempDir(), 1, func(c *Config) { c.UnknownThinGrace = 400 * time.Millisecond })
	h.st.SetUnknownThins(7, 9)
	start := time.Now()
	// Not deleted before the grace.
	h.n.collectUnknownThins(context.Background())
	if h.st.CallCount("DeleteThins") != 0 {
		t.Fatal("deleted before grace")
	}
	// 9 becomes known again: it restarts its grace.
	h.st.SetUnknownThins(7)
	h.n.collectUnknownThins(context.Background())
	h.st.SetUnknownThins(7, 9)
	h.eventually("7 deleted", func() bool { return len(h.st.DeletedThins()) > 0 })
	deleted := h.st.DeletedThins()
	if deleted[0] != 7 || time.Since(start) < 400*time.Millisecond {
		t.Fatalf("deleted %v after %v", deleted, time.Since(start))
	}
	if len(deleted) > 1 && deleted[1] == 9 && time.Since(start) < 500*time.Millisecond {
		t.Fatalf("9 deleted too early")
	}
}

func TestCredentialsPortsAndInit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	h := newHarness(t, dir, 1)
	h.keyed()
	h.bootSlot("slot-0", "pool-c")
	id := "cred"
	ac := assignCmd(id, "pool-c", time.Now().Add(time.Hour))
	ac.Ports = []uint32{22, 8080}
	if err := h.n.AssignSlot(ctx, ac); err != nil {
		t.Fatal(err)
	}
	sdir := h.n.slotDir("slot-0")
	as, err := readAssignment(sdir)
	if err != nil || len(as.Ports) != 2 || as.Ports[0] != 22 || as.Ports[1] != 8080 {
		t.Fatal("assignment ports", as, err)
	}
	if _, err := h.n.AttachVolume(ctx, attachCmd(id, "root-"+id, "uroot-"+id, "root", 0, 1)); err != nil {
		t.Fatal(err)
	}
	// Before the start, the credentials are kept for StartWorkload.
	r := h.run(&pb.Command{OperationId: "u1", Op: &pb.Command_UpdateCredentials{UpdateCredentials: &pb.UpdateCredentials{
		AllocationId: id, Credentials: &pb.Credentials{Token: []byte("SECRET-1"), CaCrt: []byte("ca"), Namespace: "team-a"}}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}
	if w, err := meta.OpenWriter(filepath.Join(sdir, slot.FileMeta)); err != nil {
		t.Fatal(err)
	} else if _, _, err := w.ReadHost(); !meta.IsEmpty(err) {
		t.Fatal("host data written before the start", err)
	}
	sc := startCmd(id)
	sc.Params.RootMountOptions = "noatime"
	if err := h.n.StartWorkload(ctx, sc); err != nil {
		t.Fatal(err)
	}
	hd := h.host("slot-0")
	if hd.Credentials == nil || hd.Credentials.Token != "SECRET-1" || hd.Credentials.CACrt != "ca" || hd.Credentials.Namespace != "team-a" ||
		hd.Identity.Name != "build-7" || hd.Identity.Namespace != "team-a" || hd.Boot.RootMountOptions != "noatime" {
		t.Fatalf("host data %+v", hd)
	}
	// After the start, they are rewritten in the host slot.
	r = h.run(&pb.Command{OperationId: "u2", Op: &pb.Command_UpdateCredentials{UpdateCredentials: &pb.UpdateCredentials{
		AllocationId: id, Credentials: &pb.Credentials{Token: []byte("SECRET-2")}}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}
	if hd := h.host("slot-0"); hd.Credentials.Token != "SECRET-2" || hd.Boot.RootSerial != "root" {
		t.Fatalf("host data %+v", hd)
	}
	// Init must be an absolute argv.
	bad := startCmd(id)
	bad.Params.Init = []string{"init"}
	if err := h.n.StartWorkload(ctx, bad); err == nil {
		t.Fatal("relative init accepted")
	}
	// Credentials are on no other disk file than the metadata disk.
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Mode()&os.ModeType != 0 || filepath.Base(p) == slot.FileMeta {
			return nil
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("SECRET-")) {
			t.Errorf("credentials in %s", p)
		}
		return nil
	})
}

// TestOutboxNeverLosesExit: the node used to queue events and drop the
// oldest when the queue was full, so an Exited event could be lost.
// Now results are never dropped and the state is rebuilt when sent, so
// the exit is in the last state however much is queued around it.
func TestOutboxNeverLosesExit(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), 1)
	h.keyed()
	h.ready("a", "slot-0", "p0")
	if err := h.n.StartWorkload(ctx, startCmd("a")); err != nil {
		t.Fatal(err)
	}
	const many = 10000 // more than the old queue limit of 4096
	result := func(i int) *pb.NodeMessage {
		return &pb.NodeMessage{Msg: &pb.NodeMessage_Result{Result: &pb.CommandResult{OperationId: fmt.Sprint(i)}}}
	}
	for i := 0; i < many; i++ {
		h.n.out.push(result(i))
		h.n.out.markDirty()
	}
	h.guest("slot-0", &meta.GuestData{State: meta.StateExec, BootCount: 1})
	h.eventually("started", func() bool { return h.n.allocs["a"].record().BootCount == 1 })
	os.WriteFile(filepath.Join(h.n.slotDir("slot-0"), slot.FileExit), []byte(`{"exitCode":0,"cause":"exited","reason":"Succeeded","bootCount":1}`), 0o644)
	h.eventually("exit", func() bool { return h.n.allocs["a"].record().HVExit != nil })
	// A result queued after the exit: the state goes first.
	h.n.out.push(result(many))
	ms := h.drain()
	var results, states int
	for i, m := range ms {
		if r := m.GetResult(); r != nil {
			if r.OperationId != fmt.Sprint(results) {
				t.Fatalf("result %d is %s", results, r.OperationId)
			}
			results++
		}
		if m.GetState() != nil {
			states++
			if i != 0 {
				t.Fatalf("state at %d, want only before the results", i)
			}
		}
	}
	if results != many+1 || states != 1 {
		t.Fatalf("%d results, %d states", results, states)
	}
	if a := reported(ms, "a"); a.GetExit().GetReason() != api.ReasonSucceeded || a.BootCount != 1 {
		t.Fatalf("reported %v", a)
	}
}
