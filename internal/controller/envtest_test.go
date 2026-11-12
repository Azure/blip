package controller

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
)

func TestHappyPath(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "happy", "s1")
	in := skipVol(t, ns, "ws")
	if in.Labels[api.LabelLineage] != string(in.UID) || in.Status.Size.String() != "20Gi" || cur(t, in).StorageGroup == "" ||
		len(cur(t, in).Replicas) != 3 || in.Status.RootContentID != cur(t, in).ContentID || len(in.Finalizers) != 1 {
		t.Fatalf("input status: %+v labels %v", in.Status, in.Labels)
	}
	data := emptyVol(t, ns, "data")
	setWork(ns, "build", fakenode.Succeed(time.Second))
	ttl := int64(3)
	newBlip(t, ns, "build", "", "happy", func(b *v1.Blip) {
		b.Spec.TTLSecondsAfterFinished = &ttl
	}, vol("root", "ws"), vol("data", "data"))
	// While running: claims, holds, attachments.
	b := waitBlip(t, ns, "build", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	if b.Status.Allocation == nil || b.Status.StartTime == nil || b.Status.Deadline == nil || !isTrue(b.Status.Conditions, api.CondVolumesReady) {
		t.Fatalf("status %+v", b.Status)
	}
	if b.Status.Deadline.Sub(b.Status.StartTime.Time) != time.Hour {
		t.Fatal("deadline")
	}
	for i, name := range []string{"root", "data"} {
		vs := volState(b, name)
		if vs == nil || vs.State != v1.VolumeAttached || vs.Generation != 1 || len(vs.AttachmentID) != 16 || *vs.SlotDisk != int32(i) ||
			vs.DevicePath != api.GuestVolumePath(name) {
			t.Fatalf("volume %s: %+v", name, vs)
		}
	}
	if ss(b, "root") == nil || ss(b, "data") == nil || volState(b, "data").Snapshot != 1 {
		t.Fatal("shutdown snapshot not recorded")
	}
	if v := getVol(ns, "data"); v.Status.Claim == nil || v.Status.Claim.BlipUID != string(b.UID) || v.Status.Claim.Node != "s1" ||
		v.Status.ClaimGeneration != 1 || !hasHold(v, v1.HoldAttachment, string(b.UID)) {
		t.Fatalf("data claim %+v holds %+v", v.Status.Claim, v.Status.Holds)
	}
	var p corev1.Pod
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: b.Status.Allocation.PodName}, &p); err != nil {
		t.Fatal(err)
	}
	if b.Status.PodIP == "" || b.Status.PodIP != p.Status.PodIP {
		t.Fatalf("podIP %q, slot pod has %q", b.Status.PodIP, p.Status.PodIP)
	}
	if p.Labels[api.LabelSlot] != api.SlotAssigned || p.Labels[api.LabelName] != "build" || p.Labels[api.LabelNamespace] != ns ||
		len(p.OwnerReferences) != 0 || p.Annotations[api.AnnotationBlipUID] != string(b.UID) || p.Annotations[api.AnnotationAllocationID] != b.Status.Allocation.ID {
		t.Fatalf("claimed pod %+v", p.ObjectMeta)
	}
	b = complete(t, ns, "build")
	if sh := ss(b, "root"); sh.State != v1.ShutdownSnapshotSkipped {
		t.Fatalf("root shutdown snapshot %+v", sh)
	}
	sh := ss(b, "data")
	if sh == nil || sh.State != v1.ShutdownSnapshotReady || sh.Reason != v1.ReleaseCompleted || sh.Sequence != 2 {
		t.Fatalf("data shutdown snapshot %+v", sh)
	}
	dv := getVol(ns, "data")
	o := dv.Snapshot(2)
	if dv.Status.Current != 2 || o == nil || o.State != v1.SnapshotReady || o.ContentID != api.SnapshotContentID(string(data.UID), 2) ||
		o.Reason != v1.SnapshotShutdown || o.Base != cur(t, data).ContentID || o.Writer == nil || o.Writer.BlipName != "build" ||
		len(o.Replicas) < 2 || dv.Status.RootContentID != data.Status.RootContentID || len(dv.Status.Holds) != 0 || o.Result == nil {
		t.Fatalf("data snapshot %+v status %+v", o, dv.Status)
	}
	for _, r := range o.Replicas {
		if c := env.nodes[r.Node].Content(o.ContentID); c == nil || !c.Sealed || env.nodes[r.Node].Origin(o.ContentID) != cur(t, data).ContentID {
			t.Fatalf("replica %s: %+v", r.Node, c)
		}
	}
	if v := getVol(ns, "ws"); v.Status.Current != 1 || len(v.Status.Snapshots) != 1 {
		t.Fatalf("ws advanced: %+v", v.Status)
	}
	released(t, ns, b, "ws", "data")
	for _, n := range []string{"root", "data"} {
		if volState(b, n).State != v1.VolumeReleased {
			t.Fatalf("%s: %s", n, volState(b, n).State)
		}
	}
	ops := opsFor(env.nodes["s1"], b.Status.Allocation.ID)
	for _, pair := range [][2]string{{"assign", "attach"}, {"attach", "start"}, {"start", "capture"}, {"capture", "send"}, {"send", "release"}, {"relatt", "release"}} {
		if !before(ops, pair[0], pair[1]) {
			t.Fatalf("%s not before %s: %v", pair[0], pair[1], ops)
		}
	}
	if strings.Count(strings.Join(ops, ","), "capture") != 1 || strings.Contains(strings.Join(ops, ","), "kill") {
		t.Fatalf("ops %v", ops)
	}
	// The root was exported read-only and attached with its sealed content.
	for _, c := range env.nodes["s1"].Commands() {
		if a := c.GetAttachVolume(); a != nil && a.AllocationId == b.Status.Allocation.ID && a.Name == "root" &&
			(a.ContentId != cur(t, in).ContentID || len(a.OriginPaths) != 3 || a.Generation != 1 || a.Uid != string(in.UID)) {
			t.Fatalf("attach %+v", a)
		}
		if s := c.GetStartWorkload(); s != nil && s.AllocationId == b.Status.Allocation.ID && (s.RootAttachmentId != volState(b, "root").AttachmentID || len(s.Volumes) != 2) {
			t.Fatalf("start %+v", s)
		}
	}
	eventually(t, 10*time.Second, "pod deleted", func() bool { return podGone(ns, b.Status.Allocation.PodName) })
	eventually(t, 15*time.Second, "ttl delete", func() bool { return getBlip(ns, "build") == nil })
	if v := getVol(ns, "data"); v == nil || v.Status.Current != 2 {
		t.Fatal("the snapshot must outlive the blip")
	}
}

func TestFailNeverStillSnapshots(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "never", "s2")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Fail(3))
	newBlip(t, ns, "b", "", "never", nil, vol("root", "ws"))
	b := failedWith(t, ns, "b", api.ReasonError)
	if b.Status.LastExitCode == nil || *b.Status.LastExitCode != 3 || b.Status.Message != "the guest powered off with exit code 3" ||
		!isTrue(b.Status.Conditions, api.CondStarted) {
		t.Fatalf("status %+v", b.Status)
	}
	// A failed run never discards a requested snapshot.
	sh := ss(b, "root")
	if sh == nil || sh.State != v1.ShutdownSnapshotReady || sh.Reason != v1.ReleaseFailed {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	if o := snap(ns, "ws", sh.Sequence); o == nil || o.Result == nil || o.Result.ExitCode != 3 {
		t.Fatalf("snapshot %+v", o)
	}
	released(t, ns, b, "ws")
	eventually(t, 5*time.Second, "pod deleted", func() bool { return podGone(ns, b.Status.Allocation.PodName) })
}

// TestGuestFailures covers the guest exit classifications that fail a Blip.
func TestGuestFailures(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "sf", "s2", "s2", "s2")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "ws2")
	emptyVol(t, ns, "ws3")
	setWork(ns, "blank", fakenode.BootFailed("RootMountFailed", "no ext4 filesystem"))
	setWork(ns, "panic", fakenode.Panic("Kernel panic - not syncing: VFS"))
	setWork(ns, "init", fakenode.InitExited(127))
	newBlip(t, ns, "blank", "ws", "sf", nil)
	newBlip(t, ns, "panic", "ws2", "sf", nil)
	newBlip(t, ns, "init", "ws3", "sf", nil)
	// Booting from a blank volume fails cleanly with BootFailed.
	b := failedWith(t, ns, "blank", api.ReasonBootFailed)
	if !strings.Contains(b.Status.Message, "RootMountFailed") || !strings.Contains(b.Status.Message, "no ext4 filesystem") || isTrue(b.Status.Conditions, api.CondStarted) {
		t.Fatalf("status %+v", b.Status)
	}
	released(t, ns, b, "ws")
	b = failedWith(t, ns, "panic", api.ReasonGuestPanic)
	if !strings.Contains(b.Status.Message, "Kernel panic") || !isTrue(b.Status.Conditions, api.CondStarted) || b.Status.LastExitCode != nil {
		t.Fatalf("status %+v", b.Status)
	}
	released(t, ns, b, "ws2")
	b = failedWith(t, ns, "init", api.ReasonInitExited)
	if b.Status.LastExitCode == nil || *b.Status.LastExitCode != 127 || !strings.Contains(b.Status.Message, "code 127") {
		t.Fatalf("status %+v", b.Status)
	}
	released(t, ns, b, "ws3")
}

// TestRebootsThenPoweroff: guest reboots count as restarts; a poweroff
// with exit code 0 completes the Blip.
func TestRebootsThenPoweroff(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "retry", "s3")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", func(n *fakenode.Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		time.Sleep(300 * time.Millisecond)
		n.GuestReboot(s.AllocationId)
		n.Poweroff(s.AllocationId, fakenode.Code(0))
	})
	newBlip(t, ns, "b", "", "retry", nil, vol("root", "ws"))
	b := complete(t, ns, "b")
	if b.Status.RestartCount != 1 || b.Status.LastExitCode == nil || *b.Status.LastExitCode != 0 {
		t.Fatalf("status %+v", b.Status)
	}
	if o := snap(ns, "ws", ss(b, "root").Sequence); o == nil || o.Result == nil || o.Result.RestartCount != 1 {
		t.Fatalf("snapshot result %+v", o)
	}
}

func TestDeadline(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "deadline", "s1")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "deadline", func(b *v1.Blip) { b.Spec.MaxTTLSeconds = 3 }, vol("root", "ws"))
	b := failedWith(t, ns, "b", api.ReasonTTLExceeded)
	if sh := ss(b, "root"); sh.State != v1.ShutdownSnapshotReady || sh.Reason != v1.ReleaseDeadlineExceeded {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	if env.nodes["s1"].CountOps(func(c *nodepb.Command) bool {
		return c.GetKill() != nil && c.GetKill().AllocationId == b.Status.Allocation.ID && c.GetKill().Graceful
	}) != 1 {
		t.Fatal("no graceful kill")
	}
	// blipd slot kills only after the graceful stop could finish.
	if env.nodes["s1"].CountOps(func(c *nodepb.Command) bool {
		a := c.GetAssignSlot()
		return a != nil && a.AllocationId == b.Status.Allocation.ID && a.KillGrace.AsDuration() == env.ctrl.opts.GracefulTimeout+slotKillMargin
	}) != 1 {
		t.Fatal("assign without kill grace")
	}
	released(t, ns, b, "ws")
}

// When the controller cannot stop the VM at the deadline, blipd slot
// kills it at deadline + kill grace (the backstop), and the Blip still
// finishes.
func TestDeadlineSlotBackstop(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "backstop", "s3")
	emptyVol(t, ns, "ws")
	s3 := env.nodes["s3"]
	s3.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if c.GetKill() == nil {
			return nil
		}
		return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Error: "kill refused"}
	})
	defer func() { s3.SetHook(nil) }()
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "backstop", func(b *v1.Blip) { b.Spec.MaxTTLSeconds = 2 }, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 40*time.Second, func(b *v1.Blip) bool { return isFinished(b) })
	if condReason(b.Status.Conditions, api.CondFailed) != api.ReasonTTLExceeded {
		t.Fatalf("status %+v", b.Status)
	}
	if e := s3.Exit(b.Status.Allocation.ID); e.GetReason() != api.ReasonTTLExceeded {
		t.Fatalf("exit %v", e)
	}
}

func TestHypervisorExited(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "hv", "s1")
	emptyVol(t, ns, "ws")
	setWork(ns, "crash", func(n *fakenode.Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		n.Crash(s.AllocationId, 1)
	})
	newBlip(t, ns, "crash", "", "hv", nil, vol("root", "ws"))
	b := failedWith(t, ns, "crash", api.ReasonHypervisorExited)
	if b.Status.Message != "the VM exited (crashed, status 1)" {
		t.Fatalf("message %q", b.Status.Message)
	}
	// The crash-consistent overlay is still saved.
	if sh := ss(b, "root"); sh.State != v1.ShutdownSnapshotReady {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	// The VM had already exited: no Kill.
	if env.nodes["s1"].CountOps(func(c *nodepb.Command) bool {
		return c.GetKill() != nil && c.GetKill().AllocationId == b.Status.Allocation.ID
	}) != 0 {
		t.Fatal("kill after exit")
	}
}

func TestCancelByDelete(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "cancel", "s2")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "cancel", nil, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	if env.nodes["s2"].CountOps(func(c *nodepb.Command) bool {
		return c.GetKill() != nil && c.GetKill().Reason == api.ReasonCancelled && c.GetKill().Graceful
	}) == 0 {
		t.Fatal("no graceful Kill with reason Cancelled")
	}
	// The guest shut down on the power button.
	if s2, id := env.nodes["s2"], b.Status.Allocation.ID; s2.PowerButtons(id) != 1 || s2.Exit(id).GetReason() != api.ReasonSucceeded {
		t.Fatalf("power button %d, exit %v", s2.PowerButtons(id), s2.Exit(id))
	}
	// The finalizer waited for the shutdown snapshot.
	if v := getVol(ns, "ws"); v.Status.Current != 2 || v.Snapshot(2).Reason != v1.SnapshotShutdown {
		t.Fatalf("snapshots %+v", v.Status.Snapshots)
	}
	released(t, ns, b, "ws")
	if !podGone(ns, b.Status.Allocation.PodName) {
		t.Fatal("pod left")
	}
}

func TestSkipShutdownDiscards(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "discard", "s3")
	skipVol(t, ns, "ws")
	skipVol(t, ns, "scratch")
	newBlip(t, ns, "b", "", "discard", nil, vol("root", "ws"), vol("scratch", "scratch"))
	b := complete(t, ns, "b")
	for _, n := range []string{"ws", "scratch"} {
		if v := getVol(ns, n); v.Status.LastSequence != 1 {
			t.Fatalf("%s advanced: %+v", n, v.Status)
		}
	}
	if sh := ss(b, "scratch"); sh.State != v1.ShutdownSnapshotSkipped {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	ops := strings.Join(opsFor(env.nodes["s3"], b.Status.Allocation.ID), ",")
	if strings.Contains(ops, "capture") || strings.Count(ops, "relatt") != 2 {
		t.Fatalf("ops %s", ops)
	}
	released(t, ns, b, "ws", "scratch")
}

// The node is lost: the run fails, but claims stay until the node is
// fenced; then the release snapshot is Unavailable and the claim goes.
func TestNodeLostAndFence(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "lost", "c9", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "lost", nil, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	c9 := env.nodes["c9"]
	c9.Pause()
	b = waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		return isFailed(b) && condReason(b.Status.Conditions, api.CondFinished) == api.ReasonNodeUnreachable
	})
	if b.Status.Phase != v1.BlipSaving || condReason(b.Status.Conditions, api.CondFailed) != api.ReasonNodeLost {
		t.Fatalf("status %+v", b.Status)
	}
	time.Sleep(2 * time.Second)
	if v := getVol(ns, "ws"); v.Status.Claim == nil || isFinished(getBlip(ns, "b")) {
		t.Fatal("claim released without fencing")
	}
	// Another Blip cannot take the volume meanwhile.
	pool(t, ns, "lost2", "s1")
	newBlip(t, ns, "other", "ws", "lost2", nil)
	waitBlip(t, ns, "other", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonVolumeInUse
	})
	taint(t, "c9", true)
	defer taint(t, "c9", false)
	b = failedWith(t, ns, "b", api.ReasonNodeLost)
	if sh := ss(b, "root"); sh.State != v1.ShutdownSnapshotUnavailable {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	if v := getVol(ns, "ws"); v.Status.Current != 1 || v.Status.LastSequence != 1 {
		t.Fatalf("ws %+v", v.Status)
	}
	released(t, ns, b, "ws")
	// The next claim has a higher generation.
	o := complete(t, ns, "other")
	if g := volState(o, "root").Generation; g != 2 {
		t.Fatalf("generation %d", g)
	}
	taint(t, "c9", false)
	c9.Resume()
	eventually(t, 10*time.Second, "welcome lists finished allocation", func() bool {
		w := c9.Welcome()
		if w == nil {
			return false
		}
		for _, id := range w.FinishedAllocationIds {
			if id == b.Status.Allocation.ID {
				return c9.Alloc(id) == nil
			}
		}
		return false
	})
}

func TestSlotLost(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "slotlost", "s3", "s3", "s3")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "ws2")
	setWork(ns, "podgone", fakenode.Hang())
	setWork(ns, "event", func(n *fakenode.Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 0)
		time.Sleep(200 * time.Millisecond)
		n.SlotLost(s.AllocationId)
	})
	newBlip(t, ns, "podgone", "ws", "slotlost", nil)
	b := waitBlip(t, ns, "podgone", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: b.Status.Allocation.PodName}}
	if err := env.k.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	failedWith(t, ns, "podgone", api.ReasonSlotLost)
	// The kubelet rejected the slot pod after a node restart: phase
	// Failed without container statuses.
	emptyVol(t, ns, "ws3")
	setWork(ns, "rejected", fakenode.Hang())
	newBlip(t, ns, "rejected", "ws3", "slotlost", nil)
	b = waitBlip(t, ns, "rejected", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	var rp corev1.Pod
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: b.Status.Allocation.PodName}, &rp); err != nil {
		t.Fatal(err)
	}
	rp.Status = corev1.PodStatus{Phase: corev1.PodFailed, Reason: "UnexpectedAdmissionError", Message: "Allocate failed"}
	if err := env.k.Status().Update(context.Background(), &rp); err != nil {
		t.Fatal(err)
	}
	// The node no longer lists the pod and reports the slot lost.
	if b = failedWith(t, ns, "rejected", api.ReasonSlotLost); b.Status.Message != "slot pod is gone" {
		t.Fatalf("message %q", b.Status.Message)
	}
	newBlip(t, ns, "event", "ws2", "slotlost", nil)
	b = failedWith(t, ns, "event", api.ReasonSlotLost)
	released(t, ns, b, "ws2")
}

// A slot the node refuses fails the run like any other start failure;
// the controller trusts pod readiness and does not retry the slot.
func TestAssignSlotRefusedFails(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "refused", "c9")
	emptyVol(t, ns, "ws")
	c9 := env.nodes["c9"]
	c9.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if c.GetAssignSlot() == nil {
			return nil
		}
		return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Error: "slot is not usable"}
	})
	defer func() { c9.SetHook(nil) }()
	newBlip(t, ns, "b", "ws", "refused", nil)
	b := failedWith(t, ns, "b", api.ReasonStartFailed)
	if !strings.Contains(b.Status.Message, "slot is not usable") {
		t.Fatalf("message %q", b.Status.Message)
	}
	released(t, ns, b, "ws")
}

// Transfers that cannot reach 2 replicas are retried, then the release
// snapshot fails; the run result stays and the Blip still finishes.
func TestReleaseSnapshotFailure(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "writefail", "c9")
	in := emptyVol(t, ns, "ws")
	c9 := env.nodes["c9"]
	for _, r := range cur(t, in).Replicas[:2] {
		c9.FailTransfersTo(r.Node, true)
	}
	defer func() {
		for _, r := range cur(t, in).Replicas {
			c9.FailTransfersTo(r.Node, false)
		}
	}()
	newBlip(t, ns, "b", "", "writefail", nil, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 40*time.Second, func(b *v1.Blip) bool { return isFinished(b) })
	if !isTrue(b.Status.Conditions, api.CondComplete) {
		t.Fatalf("status %+v", b.Status)
	}
	sh := ss(b, "root")
	if sh.State != v1.ShutdownSnapshotFailed || sh.Sequence != 2 {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	if v := getVol(ns, "ws"); v.Status.Current != 1 || v.Snapshot(2) == nil || v.Snapshot(2).State != v1.SnapshotFailed || len(v.Status.Holds) != 0 {
		t.Fatalf("ws %+v", v.Status)
	}
	if n := c9.CountOps(isOp((*nodepb.Command).GetWriteSnapshot)); n < 3 {
		t.Fatalf("%d sends, want retries", n)
	}
	released(t, ns, b, "ws")
}

// Finished is set only after the release snapshots settled.
func TestFinishedOnlyAfterReleases(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "slowsend", "c9")
	emptyVol(t, ns, "ws")
	c9 := env.nodes["c9"]
	var hold atomic.Bool
	hold.Store(true)
	c9.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if c.GetWriteSnapshot() != nil && hold.Load() {
			return &nodepb.CommandResult{} // no result yet
		}
		return nil
	})
	defer c9.SetHook(nil)
	newBlip(t, ns, "b", "", "slowsend", nil, vol("root", "ws"))
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		return isTrue(b.Status.Conditions, api.CondComplete) && volState(b, "root").State == v1.VolumeCapturing && ss(b, "root").Sequence != 0
	})
	time.Sleep(time.Second)
	b := getBlip(ns, "b")
	if isFinished(b) || b.Status.Phase != v1.BlipSaving || ss(b, "root").State != v1.ShutdownSnapshotPending {
		t.Fatalf("status %+v", b.Status)
	}
	if v := getVol(ns, "ws"); v.Status.Claim == nil {
		t.Fatal("claim released before the snapshot")
	}
	hold.Store(false)
	// The pending send is resent after a reconnect.
	c9.Pause()
	c9.Resume()
	b = complete(t, ns, "b")
	if ss(b, "root").State != v1.ShutdownSnapshotReady {
		t.Fatal("snapshot not ready")
	}
}

func TestQuota(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, map[string]string{api.QuotaAnnotation("quota"): "1"})
	pool(t, ns, "quota", "s1", "s2", "s3")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "ws2")
	release := make(chan struct{})
	setWork(ns, "a", func(n *fakenode.Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 0)
		<-release
		fakenode.Succeed(0)(n, s)
	})
	newBlip(t, ns, "a", "ws", "quota", nil)
	waitBlip(t, ns, "a", 20*time.Second, func(b *v1.Blip) bool { return b.Status.Allocation != nil })
	newBlip(t, ns, "b", "ws2", "quota", nil)
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonQuotaExceeded
	})
	time.Sleep(time.Second)
	if b := getBlip(ns, "b"); b.Status.Allocation != nil {
		t.Fatal("over quota")
	}
	// A waiting Blip keeps no claims.
	if v := getVol(ns, "ws2"); v.Status.Claim != nil {
		t.Fatal("waiting blip holds a claim")
	}
	close(release)
	complete(t, ns, "a")
	complete(t, ns, "b")
}

func TestSchedulingWaits(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	emptyVol(t, ns, "ws")
	// Unknown SKU.
	newBlip(t, ns, "unknown", "ws", "nosuchsku", nil)
	waitBlip(t, ns, "unknown", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonUnknownSKU && b.Status.Phase == v1.BlipPending
	})
	// No capacity: the SKU's only slot pod is taken, then a free one appears.
	taken := slot(t, ns, "empty", "s2")
	taken.Labels[api.LabelSlot] = api.SlotAssigned
	if err := env.k.Update(context.Background(), taken); err != nil {
		t.Fatal(err)
	}
	emptyVol(t, ns, "ws2")
	newBlip(t, ns, "nocap", "ws2", "empty", nil)
	waitBlip(t, ns, "nocap", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonNoCapacity
	})
	slot(t, ns, "empty", "s2")
	complete(t, ns, "nocap")
	// Input missing: waits, then runs once it exists.
	newBlip(t, ns, "noinput", "ws-late", "empty", nil)
	waitBlip(t, ns, "noinput", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonWaitingForBlipVol
	})
	emptyVol(t, ns, "ws-late")
	slot(t, ns, "empty", "s2")
	complete(t, ns, "noinput")
	// More volumes than disks per slot (c8 has 2).
	pool(t, ns, "twodisks", "c8")
	emptyVol(t, ns, "d1")
	emptyVol(t, ns, "d2")
	newBlip(t, ns, "toomany", "", "twodisks", nil, vol("root", "ws"), vol("d1", "d1"), vol("d2", "d2"))
	waitBlip(t, ns, "toomany", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonTooManyVolumes
	})
	// Unknown SKU blip can be deleted while pending.
	for _, n := range []string{"unknown", "toomany"} {
		if err := env.k.Delete(context.Background(), getBlip(ns, n)); err != nil {
			t.Fatal(err)
		}
		eventually(t, 10*time.Second, "pending blip deleted", func() bool { return getBlip(ns, n) == nil })
	}
}

func TestWaitingForBlipVol(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "waitvol", "s3")
	// Drop Import on every storage node, so the volume stays Importing.
	var mu sync.Mutex
	var primary *fakenode.Node
	for _, n := range env.nodes {
		n.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
			if c.GetImport() != nil {
				mu.Lock()
				primary = n
				mu.Unlock()
				return &nodepb.CommandResult{} // no result
			}
			return nil
		})
	}
	newVol(t, ns, "ws", v1.BlipVolSpec{})
	newBlip(t, ns, "b", "ws", "waitvol", nil)
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonWaitingForBlipVol
	})
	eventually(t, 10*time.Second, "import sent", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return primary != nil
	})
	// The node reconnects; the controller resends the pending Import.
	for _, n := range env.nodes {
		n.SetHook(nil)
	}
	mu.Lock()
	p := primary
	mu.Unlock()
	p.Pause()
	p.Resume()
	complete(t, ns, "b")
}

func TestInputFailed(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	for _, n := range env.nodes {
		n.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
			if c.GetImport() != nil {
				return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Code: nodepb.ErrorCode_ERROR_CODE_IMAGE_PULL, Error: "unauthorized"}
			}
			return nil
		})
	}
	defer func() {
		for _, n := range env.nodes {
			n.SetHook(nil)
		}
	}()
	newVol(t, ns, "img", v1.BlipVolSpec{Image: &v1.ImageSource{Reference: "example.com/nope:1"}})
	eventually(t, 10*time.Second, "vol failed", func() bool {
		v := getVol(ns, "img")
		return v != nil && v.Status.Phase == v1.BlipVolFailed && condReason(v.Status.Conditions, api.CondFailed) == "ImagePullFailed"
	})
	newBlip(t, ns, "b", "img", "default", nil)
	failedWith(t, ns, "b", api.ReasonInputBlipVolFailed)
}

func TestDeleteAttachedBlocked(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "delblock", "s1")
	v := emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "delblock", nil)
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	if err := env.k.Delete(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "DeletionBlocked", func() bool {
		v := getVol(ns, "ws")
		return v != nil && condReason(v.Status.Conditions, api.CondReady) == api.ReasonDeletionBlocked
	})
	for _, r := range cur(t, v).Replicas {
		if env.nodes[r.Node].Content(cur(t, v).ContentID) == nil {
			t.Fatal("content of an attached volume deleted")
		}
	}
	// A new Blip cannot claim a volume being deleted.
	pool(t, ns, "delblock2", "s2")
	newBlip(t, ns, "late", "ws", "delblock2", nil)
	waitBlip(t, ns, "late", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonWaitingForBlipVol
	})
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "volume deleted", func() bool { return getVol(ns, "ws") == nil })
	for _, n := range env.nodes {
		for _, id := range []string{api.SnapshotContentID(string(v.UID), 1), api.SnapshotContentID(string(v.UID), 2)} {
			if n.Content(id) != nil {
				t.Fatalf("content %s left on %s", id, n.Name())
			}
		}
	}
}

// Claims and deletions race: exactly one wins every time.
func TestClaimVsDeletionRace(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	ctx := context.Background()
	// A real Blip (waiting forever) so its claims are not stale.
	newBlip(t, ns, "holder", "nothing", "nosuchsku", nil)
	b := getBlip(ns, "holder")
	for i := range 6 {
		name := "race-" + string(rune('a'+i))
		v := emptyVol(t, ns, name)
		vs := &v1.BlipVolumeStatus{Name: "x", AttachmentID: newID(), BlipVolRef: &v1.ObjectRef{Name: v.Name, UID: string(v.UID)}}
		var wg sync.WaitGroup
		var claimErr, delErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, _, claimErr = env.ctrl.claimVol(ctx, b, vs) }()
		go func() { defer wg.Done(); delErr = env.k.Delete(ctx, v) }()
		wg.Wait()
		if delErr != nil {
			t.Fatal(delErr)
		}
		if claimErr == nil {
			// The claim won: the volume and its data stay.
			time.Sleep(time.Second)
			cur := getVol(ns, name)
			if cur == nil || cur.Status.Claim == nil {
				t.Fatalf("%s: claimed volume deleted", name)
			}
			if err := env.ctrl.releaseClaim(ctx, b, vs); err != nil {
				t.Fatal(err)
			}
		} else if _, ok := claimErr.(*refusal); !ok {
			t.Fatalf("%s: %v", name, claimErr)
		}
		eventually(t, 10*time.Second, name+" deleted", func() bool { return getVol(ns, name) == nil })
	}
}

// Multi-volume claims are all-or-nothing.
func TestMultiClaimRollback(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "multi", "s1", "s2")
	emptyVol(t, ns, "shared")
	emptyVol(t, ns, "own")
	setWork(ns, "a", fakenode.Hang())
	newBlip(t, ns, "a", "shared", "multi", nil)
	a := waitBlip(t, ns, "a", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	newBlip(t, ns, "b", "", "multi", nil, vol("root", "own"), vol("shared", "shared"))
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonVolumeInUse
	})
	time.Sleep(time.Second)
	if v := getVol(ns, "own"); v.Status.Claim != nil || len(v.Status.Holds) != 0 {
		t.Fatalf("claim on own not rolled back: %+v", v.Status)
	}
	if err := env.k.Delete(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	b := complete(t, ns, "b")
	if volState(b, "shared").Generation != 2 || getVol(ns, "shared").Status.ClaimGeneration != 2 {
		t.Fatalf("generation %d", volState(b, "shared").Generation)
	}
	// Commands of the second claim carry the higher generation.
	gens := map[int64]bool{}
	for _, n := range []string{"s1", "s2"} {
		for _, c := range env.nodes[n].Commands() {
			if at := c.GetAttachVolume(); at != nil && at.Uid == volState(b, "shared").BlipVolRef.UID {
				gens[at.Generation] = true
			}
		}
	}
	if !gens[1] || !gens[2] {
		t.Fatalf("generations %v", gens)
	}
}

// Live attach and (forced) detach.
func TestLiveAttachDetach(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "live", "s2")
	emptyVol(t, ns, "ws")
	data := emptyVol(t, ns, "data")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "live", nil)
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("data", "data")) })
	b = waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeAttached
	})
	vs := volState(b, "data")
	if *vs.SlotDisk != 1 || vs.DevicePath != api.GuestVolumePath("data") || vs.Generation != 1 {
		t.Fatalf("data %+v", vs)
	}
	s2 := env.nodes["s2"]
	if at := s2.Attachments(b.Status.Allocation.ID); len(at) != 2 || at[1].Uid != string(data.UID) || at[1].SlotDisk != 1 {
		t.Fatalf("node attachments %+v", at)
	}
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return vols[:1] })
	b = waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeReleased
	})
	sh := ss(b, "data")
	if sh == nil || sh.State != v1.ShutdownSnapshotReady || sh.Reason != v1.ReleaseDetach || getVol(ns, "data").Status.Current != 2 {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	released(t, ns, b, "data")
	if n := s2.CountOps(func(c *nodepb.Command) bool {
		return c.GetDetachVolume() != nil && c.GetDetachVolume().AttachmentId == vs.AttachmentID
	}); n != 1 {
		t.Fatalf("%d detach commands, want 1", n)
	}
	if isFinished(b) || len(s2.Attachments(b.Status.Allocation.ID)) != 1 {
		t.Fatal("the blip must keep running with the root only")
	}
	// Re-add: a new attachment with a new generation.
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("data", "data")) })
	b = waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeAttached
	})
	if nv := volState(b, "data"); nv.AttachmentID == vs.AttachmentID || nv.Generation != 2 || nv.Snapshot != 2 || nv.ShutdownSnapshot == nil || nv.ShutdownSnapshot.State != "" {
		t.Fatalf("re-attach %+v", nv)
	}
	// A failed live attach (stale generation) ends Failed and releases the claim.
	emptyVol(t, ns, "bad")
	s2.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if a := c.GetAttachVolume(); a != nil && a.Name == "bad" {
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_REJECTED, Code: nodepb.ErrorCode_ERROR_CODE_STALE_GENERATION, Error: "stale"}
		}
		return nil
	})
	defer s2.SetHook(nil)
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("bad", "bad")) })
	b = waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "bad")
		return vs != nil && vs.State == v1.VolumeFailed && strings.HasPrefix(vs.Message, api.ReasonAttachFailed)
	})
	released(t, ns, b, "bad")
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	released(t, ns, b, "ws", "data", "bad")
}

func TestBlipVolCloneImportDelete(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg"}, Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)}}
	if err := env.k.Create(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	img := readyVol(t, ns, "img", v1.BlipVolSpec{Image: &v1.ImageSource{Reference: "example.com/ws:1", PullSecretRef: &v1.LocalObjectRef{Name: "reg"}}, Size: q("1Gi")})
	is := cur(t, img)
	if !strings.HasPrefix(img.Status.ImageDigest, "sha256:") || img.Status.Size.String() != "1Gi" {
		t.Fatalf("image status %+v", img.Status)
	}
	found := false
	for _, n := range env.nodes {
		for _, c := range n.Commands() {
			if im := c.GetImport(); im != nil && im.ContentId == is.ContentID {
				found = string(im.PullSecretDockerconfigjson) == `{"auths":{}}` && len(im.Targets) == 2 && im.SizeBytes == 1<<30
			}
		}
	}
	if !found {
		t.Fatal("import command without credentials or targets")
	}
	cl := readyVol(t, ns, "clone", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "img"}})
	cs := cur(t, cl)
	if cs.StorageGroup != is.StorageGroup || cl.Status.RootContentID != img.Status.RootContentID || cs.Base != is.ContentID ||
		cl.Status.Origin == nil || cl.Status.Origin.ContentID != is.ContentID || cl.Status.Origin.Snapshot != 1 || cl.Labels[api.LabelLineage] != string(cl.UID) ||
		cl.Status.Size.String() != "1Gi" || cs.Sequence != 1 || cs.Reason != v1.SnapshotInitial {
		t.Fatalf("clone status %+v labels %v", cl.Status, cl.Labels)
	}
	snaps := 0
	for _, n := range env.nodes {
		snaps += n.CountOps(func(c *nodepb.Command) bool {
			return c.GetClone() != nil && c.GetClone().ContentId == cs.ContentID && c.GetClone().Mode == nodepb.CloneMode_CLONE_MODE_SNAPSHOT
		})
	}
	if snaps != 3 {
		t.Fatalf("%d snapshot clones", snaps)
	}
	// The Clone hold went away with the finished clone.
	if p := getVol(ns, "img"); len(p.Status.Holds) != 0 {
		t.Fatalf("holds %+v", p.Status.Holds)
	}
	// Delete the parent: content removed from all replicas, clone unaffected.
	if err := env.k.Delete(context.Background(), img); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "parent gone", func() bool { return getVol(ns, "img") == nil })
	for _, r := range is.Replicas {
		if env.nodes[r.Node].Content(is.ContentID) != nil {
			t.Fatal("parent content left")
		}
	}
	if v := getVol(ns, "clone"); v == nil || v.Status.Phase != v1.BlipVolReady {
		t.Fatal("clone affected")
	}
}

func TestFullCopyClone(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	p := emptyVol(t, ns, "parent")
	ps := cur(t, p)
	full := env.nodes[ps.Replicas[0].Node]
	full.SetStorageCapacity(&nodepb.StorageCapacity{DataPercent: 85, MaxLvs: 5000})
	defer full.SetStorageCapacity(&nodepb.StorageCapacity{MaxLvs: 5000})
	time.Sleep(300 * time.Millisecond)
	cl := readyVol(t, ns, "copy", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "parent"}})
	cs := cur(t, cl)
	if cs.StorageGroup == ps.StorageGroup || cl.Status.RootContentID != cs.ContentID || cs.Base != "" {
		t.Fatalf("copy status %+v", cl.Status)
	}
	copies := 0
	for _, n := range env.nodes {
		copies += n.CountOps(func(c *nodepb.Command) bool {
			return c.GetClone() != nil && c.GetClone().ContentId == cs.ContentID && c.GetClone().Mode == nodepb.CloneMode_CLONE_MODE_COPY && len(c.GetClone().Targets) == 3
		})
	}
	if copies != 1 {
		t.Fatalf("%d copy commands", copies)
	}
	// StorageFull: blips whose root is in the parent group wait at 90%.
	full.SetStorageCapacity(&nodepb.StorageCapacity{DataPercent: 95, MaxLvs: 5000})
	eventually(t, 10*time.Second, "controller sees the full pool", func() bool {
		return env.ctrl.nodes.Info(ps.Replicas[0].Node).Capacity.GetStorage().GetDataPercent() == 95
	})
	pool(t, ns, "full", "s1")
	newBlip(t, ns, "b", "parent", "full", nil)
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonStorageFull
	})
	if err := env.k.Delete(context.Background(), getBlip(ns, "b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
}

// A release snapshot whose base group is full goes to the least full group
// as a whole-device send with an empty base.
func TestReleaseToOtherGroupWhenFull(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "fullrel", "c9")
	in := emptyVol(t, ns, "ws")
	setWork(ns, "b", func(n *fakenode.Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 0)
		time.Sleep(500 * time.Millisecond)
		fakenode.Succeed(0)(n, s)
	})
	newBlip(t, ns, "b", "", "fullrel", nil, vol("root", "ws"))
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	full := env.nodes[cur(t, in).Replicas[0].Node]
	full.SetStorageCapacity(&nodepb.StorageCapacity{DataPercent: 95, MaxLvs: 5000})
	defer full.SetStorageCapacity(&nodepb.StorageCapacity{MaxLvs: 5000})
	b := complete(t, ns, "b")
	o := snap(ns, "ws", ss(b, "root").Sequence)
	if o == nil || o.StorageGroup == cur(t, in).StorageGroup || o.Base != "" || o.State != v1.SnapshotReady {
		t.Fatalf("shutdown snapshot %+v", o)
	}
	fullSend := false
	for _, c := range env.nodes["c9"].Commands() {
		if s := c.GetWriteSnapshot(); s != nil && s.ContentId == o.ContentID {
			fullSend = s.Full
		}
	}
	if !fullSend {
		t.Fatal("no whole-device send")
	}
}

func TestOrphanAndRepair(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	v := emptyVol(t, ns, "ws")
	id := cur(t, v).ContentID
	nodes := []*fakenode.Node{}
	for _, r := range cur(t, v).Replicas {
		nodes = append(nodes, env.nodes[r.Node])
	}
	// An orphan LV is removed after the orphan age.
	nodes[0].Storage().PutContent(&nodepb.ContentInfo{ContentId: "orphan-x", Sealed: true})
	// A lost replica is rebuilt.
	nodes[1].Storage().DropContent(id)
	eventually(t, 20*time.Second, "orphan removed", func() bool { return nodes[0].Content("orphan-x") == nil })
	eventually(t, 20*time.Second, "replica repaired", func() bool {
		c := nodes[1].Content(id)
		return c != nil && c.Sealed
	})
	if n := nodes[0].CountOps(isOp((*nodepb.Command).GetRepair)) + nodes[2].CountOps(isOp((*nodepb.Command).GetRepair)); n == 0 {
		t.Fatal("no Repair command")
	}
}

func TestScrub(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	v := readyVol(t, ns, "ws", v1.BlipVolSpec{Size: q("64Mi")})
	s1 := cur(t, v)
	id := s1.ContentID
	ref := snapRef{vol: v, snap: s1}
	cfg, _ := env.ctrl.storageConfig(context.Background())
	g := cfg.Group(s1.StorageGroup)
	bad := env.nodes[s1.Replicas[1].Node]
	bad.Storage().Corrupt(id, 777)
	if err := env.ctrl.Scrub(context.Background(), g, ref); err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, n := range env.nodes {
		for _, c := range n.Commands() {
			if r := c.GetRepair(); r != nil && r.ContentId == id && len(r.Extents) == 1 &&
				r.Extents[0].OffsetBytes == 777*api.DefaultChunkBytes && r.Target.Node == bad.Name() {
				ok = true
			}
		}
	}
	if !ok {
		t.Fatal("no extent repair for the minority replica")
	}
	bad.Storage().Repaired(id)
	// No majority: chunk 3 differs on all three replicas, so the volume fails.
	env.nodes[s1.Replicas[0].Node].Storage().CorruptWith(id, 3, 1)
	env.nodes[s1.Replicas[1].Node].Storage().CorruptWith(id, 3, 2)
	if err := env.ctrl.Scrub(context.Background(), g, ref); err != nil {
		t.Fatal(err)
	}
	if got := getVol(ns, "ws"); got.Status.Phase != v1.BlipVolFailed || got.Snapshot(1).State != v1.SnapshotFailed || condReason(got.Status.Conditions, api.CondFailed) != "ScrubMismatch" {
		t.Fatalf("status %+v", got.Status)
	}
	for _, r := range s1.Replicas {
		env.nodes[r.Node].Storage().Repaired(id)
	}
}

func TestControllerObjects(t *testing.T) {
	skipNoEnv(t)
	ctx := context.Background()
	var s corev1.Secret
	if err := env.k.Get(ctx, types.NamespacedName{Namespace: sys, Name: api.NVMePSKSecret}, &s); err != nil || len(s.Data[keyPSK]) != 32 {
		t.Fatal("psk secret", err)
	}
	w := env.nodes["s1"].Welcome()
	if w.HostNqn != api.HostNQN("s1") || string(w.HostPsk) != string(PSK(s.Data[keyPSK], api.HostNQN("s1"))) {
		t.Fatal("welcome psk")
	}
	var cm corev1.ConfigMap
	eventually(t, 10*time.Second, "CA ConfigMap", func() bool {
		return env.k.Get(ctx, types.NamespacedName{Namespace: sys, Name: api.CAConfigMap}, &cm) == nil && len(cm.Data) > 0
	})
	// Export commands carry the PSK of the host they allow.
	for _, c := range env.nodes["s1"].Commands() {
		if e := c.GetExport(); e != nil && string(e.HostPsk) != string(PSK(s.Data[keyPSK], api.HostNQN(e.HostNode))) {
			t.Fatal("export psk")
		}
	}
}

// TestTokenAuthenticator checks a real projected token with TokenReview.
func TestTokenAuthenticator(t *testing.T) {
	skipNoEnv(t)
	ctx := context.Background()
	k := env.k
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: sys, Name: NodeServiceAccount}}
	if err := k.Create(ctx, sa); err != nil {
		t.Fatal(err)
	}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: sys, Name: "blip-node-x"},
		Spec: corev1.PodSpec{NodeName: "s1", ServiceAccountName: NodeServiceAccount, Containers: []corev1.Container{{Name: "n", Image: "n"}}}}
	if err := k.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{Audiences: []string{"blip"},
		BoundObjectRef: &authnv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: p.Name, UID: p.UID}}}
	if err := k.SubResource("token").Create(ctx, sa, tr); err != nil {
		t.Fatal(err)
	}
	a := &TokenAuthenticator{Client: k, Namespace: sys}
	node, err := a.Authenticate(ctx, tr.Status.Token)
	if err != nil || node != "s1" {
		t.Fatalf("node %q err %v", node, err)
	}
	// Wrong audience.
	tr2 := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{Audiences: []string{"other"},
		BoundObjectRef: &authnv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: p.Name, UID: p.UID}}}
	if err := k.SubResource("token").Create(ctx, sa, tr2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(ctx, tr2.Status.Token); err == nil {
		t.Fatal("wrong audience accepted")
	}
}

// TestControllerRestart restarts the controller during a run. The new
// controller rebuilds from the CRs and the node state in Hello, re-issues
// commands with the same operation IDs, and publishes the output once.
func TestControllerRestart(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "restart", "s2")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "restart", nil, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	env.cancelCtrl()
	// The guest finishes while no controller runs.
	s2 := env.nodes["s2"]
	s2.Poweroff(b.Status.Allocation.ID, nil)
	env.cancelCtrl = startController(context.Background())
	b = complete(t, ns, "b")
	if getVol(ns, "ws").Status.LastSequence != 2 || ss(b, "root").State != v1.ShutdownSnapshotReady {
		t.Fatalf("status %+v", b.Status)
	}
	for _, kind := range []func(*nodepb.Command) bool{
		func(c *nodepb.Command) bool {
			return c.GetAssignSlot() != nil && c.GetAssignSlot().AllocationId == b.Status.Allocation.ID
		},
		func(c *nodepb.Command) bool {
			return c.GetAttachVolume() != nil && c.GetAttachVolume().AllocationId == b.Status.Allocation.ID
		},
	} {
		if n := s2.CountOps(kind); n != 1 {
			t.Fatalf("sent %d times", n)
		}
	}
	released(t, ns, b, "ws")
}

// A failed ReleaseAttachment is retried with a new operation ID (nodes
// cache results by operation ID, so resending the old one never succeeds).
func TestReleaseAttachmentRetry(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "relretry", "c8")
	emptyVol(t, ns, "ws")
	c8 := env.nodes["c8"]
	var failed atomic.Int32
	c8.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if c.GetReleaseAttachment() != nil && failed.Add(1) == 1 {
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Error: "injected"}
		}
		return nil
	})
	defer c8.SetHook(nil)
	newBlip(t, ns, "b", "", "relretry", nil, vol("root", "ws"))
	b := complete(t, ns, "b")
	if failed.Load() < 2 {
		t.Fatalf("relatt tried %d times", failed.Load())
	}
	released(t, ns, b, "ws")
}

// A live attach that fails transiently is retried with new operation IDs;
// one that keeps failing ends AttachFailed after attachAttempts.
func TestLiveAttachRetry(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "lretry", "s2")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "flaky")
	emptyVol(t, ns, "broken")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "lretry", nil)
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	s2 := env.nodes["s2"]
	var mu sync.Mutex
	flaky := 0
	ids := map[string]bool{}
	s2.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		a := c.GetAttachVolume()
		if a == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		switch a.Name {
		case "flaky":
			ids[c.OperationId] = true
			if flaky++; flaky <= 2 {
				return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Code: nodepb.ErrorCode_ERROR_CODE_HOTPLUG, Error: "hot-plug: timeout"}
			}
		case "broken":
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Code: nodepb.ErrorCode_ERROR_CODE_HOTPLUG, Error: "hot-plug: add-device failed"}
		}
		return nil
	})
	defer s2.SetHook(nil)
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("flaky", "flaky")) })
	waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "flaky")
		return vs != nil && vs.State == v1.VolumeAttached
	})
	mu.Lock()
	if len(ids) != 3 {
		t.Fatalf("attach operation IDs %v, want 3 distinct", ids)
	}
	mu.Unlock()
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("broken", "broken")) })
	b := waitBlip(t, ns, "b", 60*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "broken")
		return vs != nil && vs.State == v1.VolumeFailed
	})
	if vs := volState(b, "broken"); !strings.HasPrefix(vs.Message, api.ReasonAttachFailed) || !strings.Contains(vs.Message, "4 attempts") {
		t.Fatalf("broken %+v", vs)
	}
	if n := s2.CountOps(func(c *nodepb.Command) bool { return c.GetAttachVolume().GetName() == "broken" }); n != attachAttempts {
		t.Fatalf("%d attach commands, want %d", n, attachAttempts)
	}
	released(t, ns, b, "broken")
}

// DetachVolume NOT_FOUND counts as detached only once the node state no
// longer lists the allocation; until then it is retried (with ListState).
func TestDetachNotFound(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "dnf", "s2")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "data")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "dnf", nil)
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return append(vols, vol("data", "data")) })
	b := waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeAttached
	})
	allocID, attID := b.Status.Allocation.ID, volState(b, "data").AttachmentID
	s2 := env.nodes["s2"]
	// The controller has seen the allocation in the node's state.
	eventually(t, 10*time.Second, "allocation reported", func() bool { return env.ctrl.nodes.ReportsAlloc("s2", allocID) })
	var forget atomic.Bool
	s2.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if d := c.GetDetachVolume(); d != nil && d.AttachmentId == attID {
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_FAILED, Code: nodepb.ErrorCode_ERROR_CODE_NOT_FOUND, Error: "allocation not found on this node"}
		}
		if ra := c.GetReleaseAttachment(); ra != nil && ra.AttachmentId == attID && forget.Load() {
			// A node without the allocation releases nothing.
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_OK}
		}
		if c.GetListState() != nil && forget.Load() {
			st := s2.State()
			st.Allocations = slices.DeleteFunc(st.Allocations, func(a *nodepb.AllocationInfo) bool { return a.AllocationId == allocID })
			return &nodepb.CommandResult{Status: nodepb.ResultStatus_RESULT_STATUS_OK, Result: &nodepb.CommandResult_State{State: st}}
		}
		return nil
	})
	defer s2.SetHook(nil)
	patchVolumes(t, ns, "b", func(vols []v1.BlipVolume) []v1.BlipVolume { return vols[:1] })
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeDetaching && strings.Contains(vs.Message, "not found")
	})
	eventually(t, 10*time.Second, "state refreshed", func() bool {
		return s2.CountOps(func(c *nodepb.Command) bool {
			return c.GetListState() != nil && strings.Contains(c.OperationId, "detach-ls")
		}) > 0
	})
	if getVol(ns, "data").Status.Claim == nil {
		t.Fatal("claim released while the node still reports the allocation")
	}
	forget.Store(true)
	waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool {
		vs := volState(b, "data")
		return vs != nil && vs.State == v1.VolumeReleased
	})
	released(t, ns, b, "data")
}

// The graceful timeout of Kill counts from the persisted stop request, so
// a controller restart gives the guest only the rest of it, not a hard
// kill and not a new full timeout.
func TestKillBudgetSurvivesRestart(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "killrs", "s2")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "killrs", nil, vol("root", "ws"))
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	allocID := b.Status.Allocation.ID
	s2 := env.nodes["s2"]
	var mu sync.Mutex
	var kills []*nodepb.Kill
	drop := true
	s2.SetHook(func(c *nodepb.Command) *nodepb.CommandResult {
		if k := c.GetKill(); k != nil && k.AllocationId == allocID {
			mu.Lock()
			defer mu.Unlock()
			kills = append(kills, proto.Clone(k).(*nodepb.Kill))
			if drop {
				return &nodepb.CommandResult{} // no answer
			}
		}
		return nil
	})
	defer s2.SetHook(nil)
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	b = waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool { return b.Status.StopRequestedTime != nil })
	env.cancelCtrl()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	drop = false
	if len(kills) == 0 || !kills[0].Graceful || kills[0].GracefulTimeout.AsDuration() != 2*time.Second {
		t.Fatalf("first kill %v", kills)
	}
	n := len(kills)
	mu.Unlock()
	env.cancelCtrl = startController(context.Background())
	eventually(t, 20*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	mu.Lock()
	defer mu.Unlock()
	if len(kills) <= n {
		t.Fatal("no kill after the restart")
	}
	k := kills[n]
	if d := k.GracefulTimeout.AsDuration(); !k.Graceful || d > 1700*time.Millisecond || d <= 0 {
		t.Fatalf("kill after restart: graceful %v timeout %v", k.Graceful, d)
	}
	released(t, ns, b, "ws")
}

// A Blip recreated with the name of a deleted one is not held back by the
// old one's assumed claim (kubectl blip shell --recreate).
func TestRecreateSameNameIgnoresOldAssumedClaim(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "recreate", "s1")
	skipVol(t, ns, "ws")
	key := podKey(ns, "gone-slot")
	env.ctrl.schedMu.Lock()
	env.ctrl.assumed[key] = assumedClaim{blip: types.NamespacedName{Namespace: ns, Name: "same"}, uid: "old-uid",
		namespace: ns, sku: "recreate", allocID: "old", at: time.Now()}
	env.ctrl.schedMu.Unlock()
	defer func() {
		env.ctrl.schedMu.Lock()
		delete(env.ctrl.assumed, key)
		env.ctrl.schedMu.Unlock()
	}()
	setWork(ns, "same", fakenode.Succeed(time.Second))
	newBlip(t, ns, "same", "ws", "recreate", nil)
	waitBlip(t, ns, "same", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
}
