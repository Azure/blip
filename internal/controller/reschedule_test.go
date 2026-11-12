package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
)

func TestRescheduleBackoffAndReasons(t *testing.T) {
	p := &v1.ReschedulePolicy{InitialBackoffSeconds: 10, MaxBackoffSeconds: 60}
	for n, want := range map[int32]time.Duration{1: 10 * time.Second, 2: 20 * time.Second, 3: 40 * time.Second, 4: time.Minute, 9: time.Minute} {
		if got := rescheduleBackoff(p, n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
	for _, r := range []string{api.ReasonError, api.ReasonNodeLost, api.ReasonSlotLost, api.ReasonHypervisorExited, api.ReasonStartFailed, api.ReasonAttachFailed, api.ReasonGuestPanic, api.ReasonInitExited, api.ReasonBootFailed} {
		if !retryableReason(r) {
			t.Errorf("%s not retryable", r)
		}
	}
	for _, r := range []string{api.ReasonTTLExceeded, api.ReasonCancelled, api.ReasonInputBlipVolFailed, api.ReasonSucceeded} {
		if retryableReason(r) {
			t.Errorf("%s retryable", r)
		}
	}
}

// failFirst fails the first n starts (exit 3, restart Never), then succeeds.
func failFirst(n int) fakenode.Workload {
	var mu sync.Mutex
	seen := 0
	return func(node *fakenode.Node, s *nodepb.StartWorkload) {
		mu.Lock()
		seen++
		k := seen
		mu.Unlock()
		if k <= n {
			fakenode.Fail(3)(node, s)
			return
		}
		fakenode.Succeed(100*time.Millisecond)(node, s)
	}
}

func reschedPolicy(limit *int32, initial int32) func(*v1.Blip) {
	return func(b *v1.Blip) {
		b.Spec.Reschedule = &v1.ReschedulePolicy{Limit: limit, InitialBackoffSeconds: initial, MaxBackoffSeconds: 300}
	}
}

// attempts runs each workload in turn, one per start (the last repeats).
func attempts(ws ...fakenode.Workload) fakenode.Workload {
	var mu sync.Mutex
	n := 0
	return func(node *fakenode.Node, s *nodepb.StartWorkload) {
		mu.Lock()
		w := ws[min(n, len(ws)-1)]
		n++
		mu.Unlock()
		w(node, s)
	}
}

// Two failed attempts, then success: each failed attempt saves its
// overlay as a Reschedule snapshot of the same BlipVol (even with
// skipShutdown) and the next attempt attaches it; the deadline is kept.
func TestRescheduleConnected(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rs", "s1", "s1", "s2", "s2")
	ws := skipVol(t, ns, "ws")
	setWork(ns, "b", failFirst(2))
	newBlip(t, ns, "b", "", "rs", reschedPolicy(nil, 1), vol("root", "ws"))
	b := waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool { return b.Status.RescheduleCount == 1 })
	// The retry may already have claimed a slot after the 1s backoff, which
	// sets Rescheduling=False/Rescheduled; either state shows the reschedule.
	c := findCond(b.Status.Conditions, api.CondRescheduling)
	if c == nil || (c.Status != metav1.ConditionTrue && c.Reason != "Rescheduled") || c.Reason == api.ReasonResumedFromOlderSnapshot || isFailed(b) ||
		b.Status.LastFailure == nil || b.Status.LastFailure.Reason != api.ReasonError || b.Status.StartTime == nil || b.Status.Deadline == nil {
		t.Fatalf("status after first failure %+v", b.Status)
	}
	if vs := volState(b, "root"); vs.BlipVolRef == nil || vs.BlipVolRef.Name != "ws" || vs.ResumedFrom != nil {
		t.Fatalf("volume after reschedule %+v", vs)
	}
	s2 := snap(ns, "ws", 2)
	if s2 == nil || s2.Reason != v1.SnapshotReschedule || s2.State != v1.SnapshotReady || s2.Writer == nil || s2.Writer.BlipUID != string(b.UID) || s2.Result != nil {
		t.Fatalf("reschedule snapshot %+v", s2)
	}
	start, deadline := b.Status.StartTime.Time, b.Status.Deadline.Time
	b = complete(t, ns, "b")
	if b.Status.RescheduleCount != 2 || !b.Status.StartTime.Time.Equal(start) || !b.Status.Deadline.Time.Equal(deadline) || isTrue(b.Status.Conditions, api.CondRescheduling) {
		t.Fatalf("final status %+v", b.Status)
	}
	// The final attempt started from snapshot 3 (the second reschedule)
	// and, with skipShutdown, saved nothing at the end.
	vs := volState(b, "root")
	if vs.Snapshot != 3 || vs.ShutdownSnapshot.State != v1.ShutdownSnapshotSkipped {
		t.Fatalf("final volume %+v %+v", vs, vs.ShutdownSnapshot)
	}
	v := getVol(ns, "ws")
	if v.Status.Current != 3 || v.Status.LastSequence != 3 || v.Snapshot(3).Reason != v1.SnapshotReschedule || v.Status.RootContentID != ws.Status.RootContentID {
		t.Fatalf("ws %+v", v.Status)
	}
	released(t, ns, b, "ws")
}

func TestRescheduleLimitAndNonRetryable(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rl", "s3", "s3", "s3", "s3")
	emptyVol(t, ns, "ws")
	emptyVol(t, ns, "ws2")
	emptyVol(t, ns, "ws3")
	one := int32(1)
	setWork(ns, "lim", fakenode.Fail(3))
	newBlip(t, ns, "lim", "ws", "rl", reschedPolicy(&one, 1))
	b := failedWith(t, ns, "lim", api.ReasonError)
	if b.Status.RescheduleCount != 1 || !strings.Contains(b.Status.Message, "limit 1") || isTrue(b.Status.Conditions, api.CondRescheduling) {
		t.Fatalf("status %+v", b.Status)
	}
	released(t, ns, b, "ws")
	// The deadline is non-retryable.
	setWork(ns, "ttl", fakenode.Hang())
	newBlip(t, ns, "ttl", "ws2", "rl", func(b *v1.Blip) { reschedPolicy(nil, 1)(b); b.Spec.MaxTTLSeconds = 3 })
	if b = failedWith(t, ns, "ttl", api.ReasonTTLExceeded); b.Status.RescheduleCount != 0 {
		t.Fatalf("rescheduled after TTLExceeded")
	}
	// The next attempt would start after the deadline.
	setWork(ns, "late", fakenode.Fail(3))
	newBlip(t, ns, "late", "ws3", "rl", func(b *v1.Blip) { reschedPolicy(nil, 60)(b); b.Spec.MaxTTLSeconds = 30 })
	if b = failedWith(t, ns, "late", api.ReasonError); b.Status.RescheduleCount != 0 || !strings.Contains(b.Status.Message, "deadline") {
		t.Fatalf("status %+v", b.Status)
	}
}

// The deadline passes before the next attempt gets a slot (the only slot
// pod is gone): TTLExceeded.
func TestRescheduleDeadlineInBackoff(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rd", "s2")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Fail(3))
	newBlip(t, ns, "b", "ws", "rd", func(b *v1.Blip) { reschedPolicy(nil, 1)(b); b.Spec.MaxTTLSeconds = 8 })
	b := failedWith(t, ns, "b", api.ReasonTTLExceeded)
	if b.Status.RescheduleCount != 1 || b.Status.Allocation != nil {
		t.Fatalf("status %+v", b.Status)
	}
	released(t, ns, b, "ws")
}

// Deleting a Blip in its backoff cancels it and releases everything.
func TestRescheduleDeleteInBackoff(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rdel", "s1", "s1")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Fail(3))
	b0 := newBlip(t, ns, "b", "ws", "rdel", reschedPolicy(nil, 120))
	b := waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonRescheduleBackoff && b.Status.NextScheduleTime != nil
	})
	// Waiting for the next attempt: no claim or hold is kept; the vol
	// has the attempt's snapshot.
	if v := getVol(ns, "ws"); v.Status.Claim != nil || len(v.Status.Holds) != 0 || v.Status.Current != 2 {
		t.Fatalf("ws %+v", v.Status)
	}
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	released(t, ns, b0, "ws")
}

// rescheduleOpts sets the salvage timeout and node loss policy.
func rescheduleOpts(initial int32, salvage time.Duration, loss v1.NodeLossPolicy) func(*v1.Blip) {
	return func(b *v1.Blip) {
		reschedPolicy(nil, initial)(b)
		b.Spec.Reschedule.SalvageTimeout = &metav1.Duration{Duration: salvage}
		b.Spec.Reschedule.NodeLoss = loss
	}
}

// started waits for the first attempt to run and returns its allocation.
func started(t *testing.T, ns, name string) *v1.Blip {
	t.Helper()
	return waitBlip(t, ns, name, 20*time.Second, func(b *v1.Blip) bool {
		return isTrue(b.Status.Conditions, api.CondStarted) && b.Status.Allocation != nil
	})
}

// resumedOlder waits for the Blip to wait for its next attempt after an
// attempt whose overlay was not saved, and checks resumedFrom.
func resumedOlder(t *testing.T, ns, name string, seq int64) *v1.Blip {
	t.Helper()
	b := waitBlip(t, ns, name, 30*time.Second, func(b *v1.Blip) bool {
		return b.Status.RescheduleCount >= 1 && condReason(b.Status.Conditions, api.CondRescheduling) == api.ReasonResumedFromOlderSnapshot
	})
	vs := volState(b, "root")
	if vs == nil || vs.ResumedFrom == nil || vs.ResumedFrom.Sequence != seq || vs.ResumedFrom.CaptureTime == nil ||
		!strings.Contains(findCond(b.Status.Conditions, api.CondRescheduling).Message, "lost") {
		t.Fatalf("resumed %+v conditions %+v", vs, b.Status.Conditions)
	}
	return b
}

// overlayDiscarded waits for the OverlayDiscarded event of an allocation.
func overlayDiscarded(t *testing.T, ns, name, alloc string) {
	t.Helper()
	eventually(t, 20*time.Second, "OverlayDiscarded event", func() bool {
		var l corev1.EventList
		if err := env.k.List(context.Background(), &l, client.InNamespace(ns)); err != nil {
			return false
		}
		for _, e := range l.Items {
			if e.Reason == api.EventOverlayDiscarded && e.InvolvedObject.Name == name && e.Type == corev1.EventTypeWarning && strings.Contains(e.Message, alloc) {
				return true
			}
		}
		return false
	})
}

// The node reboots during the attempt: the allocation is gone when it
// returns, the overlay cannot be saved (Unavailable) and the next attempt
// resumes from the newest Ready snapshot.
func TestRescheduleRebootedNode(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rb", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rb", reschedPolicy(nil, 3))
	b := started(t, ns, "b")
	c9 := env.nodes["c9"]
	c9.Reboot("boot-rebooted")
	c9.Pause()
	c9.Resume()
	b = resumedOlder(t, ns, "b", 1)
	if b.Status.LastFailure == nil || b.Status.LastFailure.Reason != api.ReasonSlotLost {
		t.Fatalf("last failure %+v", b.Status.LastFailure)
	}
	if v := getVol(ns, "ws"); v.Status.Current != 1 || v.Status.Claim != nil {
		t.Fatalf("ws %+v", v.Status)
	}
	// A snapshot made Ready meanwhile is where the next attempt resumes
	// from, and resumedFrom says so.
	appendSnaps(t, ns, "ws", 1)
	want := getVol(ns, "ws").Status.Current
	pool(t, ns, "rb", "s1")
	b = complete(t, ns, "b")
	if vs := volState(b, "root"); want <= 1 || vs.Snapshot != want || vs.ResumedFrom == nil || vs.ResumedFrom.Sequence != want || vs.ResumedFrom.CaptureTime == nil {
		t.Fatalf("final volume %+v", vs)
	}
	// The running attempt keeps the loss visible, naming the claimed snapshot.
	if c := findCond(b.Status.Conditions, api.CondRescheduling); c == nil || c.Status != metav1.ConditionFalse ||
		c.Reason != api.ReasonResumedFromOlderSnapshot || !strings.Contains(c.Message, fmt.Sprintf("snapshot %d", want)) {
		t.Fatalf("rescheduling condition %+v", c)
	}
	released(t, ns, b, "ws")
}

// A fenced node is abandoned at once; when it returns, its stale
// allocation is released and OverlayDiscarded is reported.
func TestRescheduleFenced(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rfen", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rfen", rescheduleOpts(1, time.Hour, v1.NodeLossFence))
	b := started(t, ns, "b")
	old := b.Status.Allocation.ID
	c9 := env.nodes["c9"]
	c9.Pause()
	defer c9.Resume()
	// Within the salvage window: wait for the node.
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		c := findCond(b.Status.Conditions, api.CondRescheduling)
		return c != nil && c.Status == metav1.ConditionTrue && c.Reason == api.ReasonNodeUnreachable
	})
	if v := getVol(ns, "ws"); v.Status.Claim == nil {
		t.Fatal("claim released before fencing")
	}
	taint(t, "c9", true)
	defer taint(t, "c9", false)
	resumedOlder(t, ns, "b", 1)
	// The replicas stop exporting the abandoned snapshot to the node.
	s1 := getVol(ns, "ws").Snapshot(1)
	eventually(t, 10*time.Second, "abandoned export removed", func() bool {
		for _, r := range s1.Replicas {
			found := false
			for _, c := range env.nodes[r.Node].Commands() {
				if u := c.GetUnexport(); u != nil && u.ContentId == s1.ContentID && u.HostNqn == api.HostNQN("c9") {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	})
	pool(t, ns, "rfen", "s2")
	b = complete(t, ns, "b")
	if volState(b, "root").Generation != 2 {
		t.Fatalf("generation %d", volState(b, "root").Generation)
	}
	taint(t, "c9", false)
	c9.Resume()
	overlayDiscarded(t, ns, "b", old)
	eventually(t, 10*time.Second, "stale allocation released", func() bool { return c9.Alloc(old) == nil })
}

// A node whose Node object is gone counts as fenced.
func TestRescheduleNodeNotFound(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rnf", "c8")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rnf", rescheduleOpts(1, time.Hour, v1.NodeLossFence))
	started(t, ns, "b")
	c8 := env.nodes["c8"]
	c8.Pause()
	defer c8.Resume()
	ctx := context.Background()
	var node corev1.Node
	if err := env.k.Get(ctx, types.NamespacedName{Name: "c8"}, &node); err != nil {
		t.Fatal(err)
	}
	if err := env.k.Delete(ctx, &node); err != nil {
		t.Fatal(err)
	}
	defer func() {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "c8"}}
		if err := env.k.Create(ctx, n); err != nil {
			t.Error(err)
			return
		}
		n.Status.Addresses = node.Status.Addresses
		_ = env.k.Status().Update(ctx, n)
	}()
	b := resumedOlder(t, ns, "b", 1)
	if b.Status.LastFailure.Reason != api.ReasonNodeLost {
		t.Fatalf("last failure %+v", b.Status.LastFailure)
	}
	pool(t, ns, "rnf", "s3")
	b = complete(t, ns, "b")
	released(t, ns, b, "ws")
}

// The node returns within the salvage window: the overlay is saved.
func TestRescheduleSalvageWindow(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rsal", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rsal", rescheduleOpts(1, time.Minute, v1.NodeLossAbandon))
	b := started(t, ns, "b")
	att := volState(b, "root").AttachmentID
	c9 := env.nodes["c9"]
	c9.Pause()
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondRescheduling) == api.ReasonNodeUnreachable
	})
	c9.Resume()
	b = waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool { return b.Status.RescheduleCount == 1 })
	s2 := snap(ns, "ws", 2)
	if s2 == nil || s2.Reason != v1.SnapshotReschedule || s2.State != v1.SnapshotReady || s2.Writer.AttachmentID != att {
		t.Fatalf("salvaged snapshot %+v", s2)
	}
	if c := findCond(b.Status.Conditions, api.CondRescheduling); c.Reason == api.ReasonResumedFromOlderSnapshot {
		t.Fatalf("rescheduling %+v", c)
	}
	pool(t, ns, "rsal", "s1")
	b = complete(t, ns, "b")
	if vs := volState(b, "root"); vs.Snapshot != 2 || vs.ResumedFrom != nil {
		t.Fatalf("final volume %+v", vs)
	}
}

// nodeLoss Abandon: after the salvage window the overlay is abandoned
// without fencing; the returning node's stale allocation is released.
func TestRescheduleAbandon(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rab", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rab", rescheduleOpts(1, 2*time.Second, v1.NodeLossAbandon))
	b := started(t, ns, "b")
	old := b.Status.Allocation.ID
	c9 := env.nodes["c9"]
	c9.Pause()
	defer c9.Resume()
	resumedOlder(t, ns, "b", 1)
	pool(t, ns, "rab", "s1")
	b = complete(t, ns, "b")
	if volState(b, "root").Generation != 2 {
		t.Fatalf("generation %d", volState(b, "root").Generation)
	}
	c9.Resume()
	overlayDiscarded(t, ns, "b", old)
	eventually(t, 10*time.Second, "stale allocation released", func() bool { return c9.Alloc(old) == nil })
}

// nodeLoss Fence: after the salvage window the Blip keeps waiting for the
// node (Rescheduling=False/NodeUnreachable) with the claim held.
func TestRescheduleFenceAfterSalvage(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "rfa", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", attempts(fakenode.Hang(), fakenode.Succeed(0)))
	newBlip(t, ns, "b", "ws", "rfa", rescheduleOpts(1, 2*time.Second, ""))
	started(t, ns, "b")
	c9 := env.nodes["c9"]
	c9.Pause()
	defer c9.Resume()
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool {
		c := findCond(b.Status.Conditions, api.CondRescheduling)
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == api.ReasonNodeUnreachable
	})
	time.Sleep(2 * time.Second)
	if b := getBlip(ns, "b"); b.Status.RescheduleCount != 0 || b.Status.Allocation == nil || getVol(ns, "ws").Status.Claim == nil {
		t.Fatalf("abandoned without fencing: %+v", b.Status)
	}
	taint(t, "c9", true)
	defer taint(t, "c9", false)
	resumedOlder(t, ns, "b", 1)
	// The replicas stop exporting the abandoned snapshot to the node.
	s1 := getVol(ns, "ws").Snapshot(1)
	eventually(t, 10*time.Second, "abandoned export removed", func() bool {
		for _, r := range s1.Replicas {
			found := false
			for _, c := range env.nodes[r.Node].Commands() {
				if u := c.GetUnexport(); u != nil && u.ContentId == s1.ContentID && u.HostNqn == api.HostNQN("c9") {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	})
	pool(t, ns, "rfa", "s2")
	complete(t, ns, "b")
}
