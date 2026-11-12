package controller

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

func pod(name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func TestSortCandidates(t *testing.T) {
	cs := []candidate{
		{Pod: pod("a"), Score: 0, Free: 9, Load: 0},
		{Pod: pod("b"), Score: 100, Free: 1, Load: 0.5},
		{Pod: pod("c"), Score: 100, Free: 3, Load: 0.9},
		{Pod: pod("d"), Score: 100, Free: 3, Load: 0.1},
		{Pod: pod("e"), Score: 100, Free: 3, Load: 0.1},
		{Pod: pod("f"), Score: 3, Free: 9, Load: 0},
		{Pod: pod("g"), Score: 101, Free: 1, Load: 0.9},
	}
	sortCandidates(cs)
	var got string
	for _, c := range cs {
		got += c.Pod.Name
	}
	// Root locality dominates; data volume groups add to it.
	if got != "gdecbfa" {
		t.Fatalf("order %s", got)
	}
	// Pods of the pool's current shape come before any others.
	cs = []candidate{{Pod: pod("a"), Score: 100}, {Pod: pod("b"), Current: true}}
	sortCandidates(cs)
	if cs[0].Pod.Name != "b" {
		t.Fatalf("current shape not preferred")
	}
}

func TestQuotaLimit(t *testing.T) {
	a := map[string]string{api.QuotaAnnotation("default"): "3", api.QuotaAnnotation("big"): "x", api.QuotaAnnotation("zero"): " 0 "}
	for sku, want := range map[string]int{"default": 3, "big": 10, "zero": 0, "other": 10} {
		if got := quotaLimit(a, sku, 10); got != want {
			t.Errorf("%s: got %d want %d", sku, got, want)
		}
	}
}

func TestStorageFullness(t *testing.T) {
	if f := storageFullness(&nodepb.StorageCapacity{DataPercent: 10, MetadataPercent: 30, LvCount: 4000, MaxLvs: 5000}); f != 80 {
		t.Fatal(f)
	}
	if f := storageFullness(&nodepb.StorageCapacity{DataPercent: 91, MetadataPercent: 30}); f != 91 {
		t.Fatal(f)
	}
	if storageFullness(nil) != 0 {
		t.Fatal("nil")
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 300 * time.Second, 300 * time.Second}
	for i, w := range want {
		if got := backoff(i, 10*time.Second, 5*time.Minute); got != w {
			t.Errorf("attempt %d: got %s want %s", i, got, w)
		}
	}
}

func TestConditions(t *testing.T) {
	b := &v1.Blip{}
	if !initConditions(b) || len(b.Status.Conditions) != 5 || b.Status.Phase != v1.BlipPending {
		t.Fatal("init")
	}
	if initConditions(b) {
		t.Fatal("init twice changed")
	}
	setFailed(b, api.ReasonError, "line1\nline2")
	if !isFailed(b) || isFinished(b) || b.Status.Message != "line1\nline2" || b.Status.Phase != v1.BlipFailed {
		t.Fatal("failed")
	}
	now := time.Now()
	setFinished(b, now)
	if !isFinished(b) || condReason(b.Status.Conditions, api.CondFinished) != api.ReasonError || b.Status.CompletionTime == nil {
		t.Fatal("finished")
	}
	b2 := &v1.Blip{}
	initConditions(b2)
	setCond(&b2.Status.Conditions, 0, api.CondComplete, true, api.ReasonSucceeded, "")
	setFinished(b2, now)
	if condReason(b2.Status.Conditions, api.CondFinished) != api.ReasonSucceeded {
		t.Fatal("success reason")
	}
}

func TestExitOutcome(t *testing.T) {
	for _, tc := range []struct {
		e        *nodepb.Exited
		complete bool
		reason   string
		msg      string
	}{
		{&nodepb.Exited{Reason: api.ReasonSucceeded, Message: "the guest powered off"}, true, api.ReasonSucceeded, "the guest powered off"},
		{&nodepb.Exited{Reason: api.ReasonGuestPanic, Message: "oops"}, false, api.ReasonGuestPanic, "oops"},
		{&nodepb.Exited{Message: "?"}, false, api.ReasonHypervisorExited, "?"},
	} {
		complete, reason, msg := exitOutcome(tc.e)
		if complete != tc.complete || reason != tc.reason || msg != tc.msg {
			t.Errorf("%v: got %v %q %q", tc.e, complete, reason, msg)
		}
	}
}

func TestFreeSlot(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Labels: map[string]string{api.LabelSKU: "default", api.LabelSlot: api.SlotFree}},
		Spec:       corev1.PodSpec{NodeName: "n1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	if !freeSlot(p, "default") || freeSlot(p, "big") {
		t.Fatal("sku")
	}
	p.Status.Conditions[0].Status = corev1.ConditionFalse
	if freeSlot(p, "default") {
		t.Fatal("not ready")
	}
}

func TestPSKAndMajority(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	a, b := PSK(k, api.HostNQN("n1")), PSK(k, api.HostNQN("n2"))
	if len(a) != 32 || bytes.Equal(a, b) || !bytes.Equal(a, PSK(k, api.HostNQN("n1"))) {
		t.Fatal("psk")
	}
	h, _ := majority(map[string][]byte{"a": {1}, "b": {2}, "c": {1}})
	if !bytes.Equal(h, []byte{1}) {
		t.Fatal("majority")
	}
	if h, _ := majority(map[string][]byte{"a": {1}, "b": {2}, "c": {3}}); h != nil {
		t.Fatal("no majority")
	}
}

func TestParseFlags(t *testing.T) {
	o, err := ParseFlags([]string{"--slot-image=img", "--default-quota=3", "--snapshot-interval-scale=15", "--node-lost-timeout=1m", "--slot-vmm-overhead=300Mi"})
	if err != nil || o.DefaultQuota != 3 || o.SnapshotIntervalScale != 15 || o.NodeLostTimeout != time.Minute || o.TransferAttempts != 5 || o.TokenTTL != time.Hour ||
		o.SlotImage != "img" || o.SlotCPUOvercommit != 4 || o.SlotMemoryOvercommit != 1.5 || o.SlotVMMOverhead.Value() != 300<<20 {
		t.Fatal(o, err)
	}
	if _, err := ParseFlags(nil); err == nil || !strings.Contains(err.Error(), "--slot-image") {
		t.Fatalf("missing --slot-image: %v", err)
	}
	for _, bad := range []string{"--snapshot-interval-scale=0.5", "--token-ttl=5m", "--transfer-attempts=0", "--compact-keep=3", "--slot-cpu-overcommit=0.5", "--slot-vmm-overhead=x"} {
		if _, err := ParseFlags([]string{"--slot-image=img", bad}); err == nil {
			t.Fatalf("%s: expected error", bad)
		}
	}
}

// Allocation IDs become the virtio-blk serial of the guest disk (max 20 bytes).
func TestNewIDFitsSerial(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newID()
		if len(id) > 20 || len(id) == 0 {
			t.Fatalf("id %q has %d bytes", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestCompactPlan(t *testing.T) {
	R, F, P := v1.SnapshotReady, v1.SnapshotFailed, v1.SnapshotPending
	m := func(q int64, st v1.SnapshotState) compactSnap { return compactSnap{Seq: q, State: st} }
	pin := func(s compactSnap) compactSnap { s.Protect = protectPinned; return s }
	held := func(s compactSnap) compactSnap { s.Protect = protectHeld; return s }
	cases := []struct {
		name     string
		ss       []compactSnap
		limit    int32
		want     string
		exceeded string
	}{
		{"within limit", []compactSnap{m(1, R), m(2, R)}, 2, "[]", ""},
		{"oldest ready go", []compactSnap{m(1, R), m(2, R), m(3, R), m(4, R)}, 2, "[1 2]", ""},
		{"limit 1 keeps the newest ready", []compactSnap{m(3, R), m(1, R), m(2, R)}, 1, "[1 2]", ""},
		{"failed older than newest ready go, newer stay", []compactSnap{m(1, R), m(2, F), m(3, R), m(4, F)}, 5, "[2]", ""},
		{"pending never", []compactSnap{m(1, R), m(2, P), m(3, R), m(4, P)}, 1, "[1]", ""},
		{"held kept beyond the limit", []compactSnap{held(m(1, R)), m(2, R), m(3, R)}, 1, "[2]", protectHeld},
		{"pinned wins over held", []compactSnap{held(m(1, R)), pin(m(2, R)), m(3, R), m(4, R)}, 1, "[3]", protectPinned},
		{"protected within the limit is not exceeded", []compactSnap{pin(m(1, R)), m(2, R)}, 2, "[]", ""},
		{"without ready only the newest limit failed stay", []compactSnap{m(1, F), m(2, F), m(3, F), m(4, F)}, 2, "[1 2]", ""},
		{"protected failed kept", []compactSnap{held(m(1, F)), m(2, R)}, 3, "[]", ""},
		{"empty", nil, 1, "[]", ""},
	}
	for _, c := range cases {
		del, ex := compactPlan(c.ss, c.limit)
		if fmt.Sprint(del) != c.want && !(c.want == "[]" && len(del) == 0) || ex != c.exceeded {
			t.Errorf("%s: got %v %q, want %s %q", c.name, del, ex, c.want, c.exceeded)
		}
	}
}

func TestProtection(t *testing.T) {
	v := &v1.BlipVol{}
	v.Status.Snapshots = []v1.VolSnapshot{
		{Sequence: 1, ContentID: "u-1", State: v1.SnapshotReady},
		{Sequence: 2, ContentID: "u-2", State: v1.SnapshotReady},
		{Sequence: 3, ContentID: "u-3", State: v1.SnapshotReady},
		{Sequence: 4, ContentID: "u-4", State: v1.SnapshotReady},
		{Sequence: 5, ContentID: "u-5", State: v1.SnapshotPending, Base: "u-4"},
	}
	v.Status.Claim = &v1.Claim{Snapshot: 2, Baseline: 0}
	v.Status.Holds = []v1.Hold{{Kind: v1.HoldClone, Snapshot: 3}, {Kind: v1.HoldAttachment}}
	p := protection(v, map[int64]bool{1: true, 3: true})
	want := map[int64]string{1: protectPinned, 2: protectHeld, 3: protectPinned, 4: protectHeld}
	if fmt.Sprint(p) != fmt.Sprint(want) {
		t.Fatalf("protection %v, want %v", p, want)
	}
}

func TestSnapshotHelpers(t *testing.T) {
	now := metav1.Now()
	later := metav1.NewTime(now.Add(time.Minute))
	w := func(att string) *v1.Writer { return &v1.Writer{AttachmentID: att} }
	v := &v1.BlipVol{Status: v1.BlipVolStatus{Phase: v1.BlipVolReady, Snapshots: []v1.VolSnapshot{
		{Sequence: 1, State: v1.SnapshotReady, CaptureTime: &now},
		{Sequence: 2, State: v1.SnapshotReady, Writer: w("a"), CaptureTime: &now},
		{Sequence: 3, State: v1.SnapshotFailed, Writer: w("a"), CaptureTime: &later},
		{Sequence: 4, State: v1.SnapshotPending, Writer: w("b"), CaptureTime: &later},
	}}}
	if !syncCurrent(v) || v.Status.Current != 2 {
		t.Fatalf("current %d", v.Status.Current)
	}
	if p := pendingCapture(v, "b"); p == nil || p.Sequence != 4 || pendingCapture(v, "a") != nil {
		t.Fatal("pendingCapture")
	}
	if tm := lastCaptureBy(v, "a", true); tm == nil || !tm.Equal(&later) {
		t.Fatal("lastCaptureBy failed")
	}
	if tm := lastCaptureBy(v, "a", false); tm == nil || !tm.Equal(&now) {
		t.Fatal("lastCaptureBy")
	}
	// The failed capture of a is retried a minute after it, not an
	// interval after the last good one.
	if n := nextInterval(v, "a", time.Hour); !n.Equal(later.Add(time.Minute)) {
		t.Fatalf("nextInterval %v", n)
	}
	// With a short interval the failure is still not retried at once,
	// although the last good capture is more than an interval old.
	if n := nextInterval(v, "a", 30*time.Second); !n.Equal(later.Add(30 * time.Second)) {
		t.Fatalf("nextInterval short %v", n)
	}
	if !capturedAfter(v, now) || capturedAfter(v, later) {
		t.Fatal("capturedAfter")
	}
	if !failCaptures(v, "b", "gone") || v.Snapshot(4).State != v1.SnapshotFailed {
		t.Fatal("failCaptures")
	}
	// Failing the current snapshot moves current back.
	if !setSnapFailed(v, 2, "scrub", true) || v.Status.Current != 1 || v.Status.Phase != v1.BlipVolReady {
		t.Fatalf("scrub failed: current %d phase %s", v.Status.Current, v.Status.Phase)
	}
	setSnapFailed(v, 1, "scrub", true)
	if v.Status.Current != 0 || v.Status.Phase != v1.BlipVolFailed {
		t.Fatalf("no ready left: current %d phase %s", v.Status.Current, v.Status.Phase)
	}
}

func TestRescheduling(t *testing.T) {
	b := &v1.Blip{}
	initConditions(b)
	if rescheduling(b) {
		t.Fatal("fresh blip rescheduling")
	}
	setCond(&b.Status.Conditions, 0, api.CondRescheduling, true, api.ReasonNodeLost, "")
	if !rescheduling(b) {
		t.Fatal("Rescheduling=True")
	}
	// Waiting for a node past the salvage timeout (nodeLoss Fence).
	setCond(&b.Status.Conditions, 0, api.CondRescheduling, false, api.ReasonNodeUnreachable, "")
	if rescheduling(b) {
		t.Fatal("no allocation")
	}
	b.Status.Allocation = &v1.Allocation{ID: "a"}
	if !rescheduling(b) || releaseReason(b) != v1.ReleaseReschedule {
		t.Fatal("NodeUnreachable with an allocation")
	}
	setCond(&b.Status.Conditions, 0, api.CondRescheduling, false, "Rescheduled", "")
	if rescheduling(b) {
		t.Fatal("Rescheduled")
	}
	if (&v1.ReschedulePolicy{}).SalvageTimeoutOrDefault() != 5*time.Minute {
		t.Fatal("default salvage timeout")
	}
}

func TestHoldHelpers(t *testing.T) {
	bv := &v1.BlipVol{}
	h := v1.HolderRef{Kind: "Blip", Name: "b", UID: "u1"}
	if !setHold(bv, v1.HoldAttachment, h, "") || setHold(bv, v1.HoldAttachment, h, "") || !setHold(bv, v1.HoldClone, h, "") {
		t.Fatal("setHold")
	}
	if !hasHold(bv, v1.HoldClone, "u1") || hasHold(bv, v1.HoldClone, "u2") {
		t.Fatal("hasHold")
	}
	if !removeHold(bv, v1.HoldAttachment, "u1") || removeHold(bv, v1.HoldAttachment, "u1") || len(bv.Status.Holds) != 1 {
		t.Fatal("removeHold")
	}
	removeHold(bv, v1.HoldClone, "u1")
	if bv.Status.Holds != nil {
		t.Fatal("holds not nil")
	}
}

func TestReleaseReasonAndDisks(t *testing.T) {
	b := &v1.Blip{}
	initConditions(b)
	setFailed(b, api.ReasonTTLExceeded, "")
	if releaseReason(b) != v1.ReleaseDeadlineExceeded {
		t.Fatal(releaseReason(b))
	}
	setFailed(b, api.ReasonError, "")
	if releaseReason(b) != v1.ReleaseFailed {
		t.Fatal("failed")
	}
	now := metav1.Now()
	b.DeletionTimestamp = &now
	if releaseReason(b) != v1.ReleaseDeleted {
		t.Fatal("deleted")
	}
	d := func(n int32) *int32 { return &n }
	b.Status.Volumes = []v1.BlipVolumeStatus{{SlotDisk: d(0), State: v1.VolumeAttached}, {SlotDisk: d(1), State: v1.VolumeReleased}, {SlotDisk: d(2), State: v1.VolumeDetaching}}
	if n, ok := freeDisk(b, 3); !ok || n != 1 {
		t.Fatal(n, ok)
	}
	b.Status.Volumes[1].State = v1.VolumeAttaching
	if _, ok := freeDisk(b, 3); ok {
		t.Fatal("no disk should be free")
	}
}
