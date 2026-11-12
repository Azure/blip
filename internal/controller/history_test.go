package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A run advances its BlipVols: the shutdown snapshot is sequence 2, the
// next attach starts from it.
func TestShutdownAdvancesVol(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "adv", "s1", "s1")
	ws := emptyVol(t, ns, "ws")
	s1 := cur(t, ws)
	if ws.Status.Current != 1 || ws.Status.LastSequence != 1 || s1.Reason != v1.SnapshotInitial || s1.ContentID != api.SnapshotContentID(string(ws.UID), 1) ||
		s1.Writer != nil || s1.CaptureTime == nil || len(s1.Replicas) != 3 || ws.Status.RootContentID != s1.ContentID {
		t.Fatalf("initial %+v", ws.Status)
	}
	setWork(ns, "a", fakenode.Fail(7))
	newBlip(t, ns, "a", "ws", "adv", nil)
	a := failedWith(t, ns, "a", api.ReasonError)
	sh := ss(a, "root")
	if sh == nil || sh.State != v1.ShutdownSnapshotReady || sh.Reason != v1.ReleaseFailed || sh.Sequence != 2 || volState(a, "root").Snapshot != 1 {
		t.Fatalf("shutdown snapshot %+v", sh)
	}
	v := getVol(ns, "ws")
	s2 := v.Snapshot(2)
	if v.Status.Current != 2 || s2 == nil || s2.State != v1.SnapshotReady || s2.Reason != v1.SnapshotShutdown || s2.Base != s1.ContentID ||
		s2.StorageGroup != s1.StorageGroup || s2.Writer == nil || s2.Writer.BlipUID != string(a.UID) || s2.Writer.AttachmentID != volState(a, "root").AttachmentID ||
		s2.Result == nil || s2.Result.ExitCode != 7 || len(s2.Replicas) < 2 || v.Status.Claim != nil {
		t.Fatalf("snapshot 2 %+v (status %+v)", s2, v.Status)
	}
	for _, r := range s2.Replicas {
		if c := env.nodes[r.Node].Content(s2.ContentID); c == nil || !c.Sealed || env.nodes[r.Node].Origin(s2.ContentID) != s1.ContentID {
			t.Fatalf("replica %s: %+v", r.Node, c)
		}
	}
	released(t, ns, a, "ws")
	// The next run attaches snapshot 2.
	newBlip(t, ns, "b", "ws", "adv", nil)
	b := complete(t, ns, "b")
	if volState(b, "root").Snapshot != 2 || ss(b, "root").Sequence != 3 || getVol(ns, "ws").Status.Current != 3 {
		t.Fatalf("second run %+v", volState(b, "root"))
	}
	for _, c := range env.nodes["s1"].Commands() {
		if at := c.GetAttachVolume(); at != nil && at.AllocationId == b.Status.Allocation.ID && at.ContentId != s2.ContentID {
			t.Fatalf("attached %s, want %s", at.ContentId, s2.ContentID)
		}
	}
}

// skipShutdown discards the writes; the vol stays at its snapshot.
// Several volumes with the same sequences captured in one allocation.
func TestSameSequenceVolumes(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "same", "s2")
	emptyVol(t, ns, "a")
	emptyVol(t, ns, "b")
	emptyVol(t, ns, "c")
	newBlip(t, ns, "x", "", "same", nil, vol("root", "a"), vol("b", "b"), vol("c", "c"))
	b := complete(t, ns, "x")
	for _, n := range []string{"root", "b", "c"} {
		if sh := ss(b, n); sh.State != v1.ShutdownSnapshotReady || sh.Sequence != 2 {
			t.Fatalf("%s: %+v", n, sh)
		}
	}
}

func TestSkipShutdown(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "skip", "s3")
	skipVol(t, ns, "ws")
	emptyVol(t, ns, "keep")
	newBlip(t, ns, "b", "", "skip", nil, vol("root", "ws"), vol("keep", "keep"))
	b := complete(t, ns, "b")
	if sh := ss(b, "root"); sh == nil || sh.State != v1.ShutdownSnapshotSkipped || sh.Sequence != 0 {
		t.Fatalf("skipped %+v", sh)
	}
	if v := getVol(ns, "ws"); v.Status.Current != 1 || len(v.Status.Snapshots) != 1 || v.Status.LastSequence != 1 {
		t.Fatalf("ws %+v", v.Status)
	}
	if sh := ss(b, "keep"); sh.State != v1.ShutdownSnapshotReady || getVol(ns, "keep").Status.Current != 2 {
		t.Fatalf("keep %+v", sh)
	}
	ops := strings.Join(opsFor(env.nodes["s3"], b.Status.Allocation.ID), ",")
	if strings.Count(ops, "capture") != 1 || strings.Count(ops, "relatt") != 2 {
		t.Fatalf("ops %s", ops)
	}
	released(t, ns, b, "ws", "keep")
}

// Interval snapshots while attached: incremental against the baseline,
// compaction to the limit (the snapshot the attachment started from is
// held), failures set SnapshotsBehind, the shutdown snapshot ends it.
func TestIntervalSnapshots(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "iv", "c9")
	policyVol(t, ns, "ws", every(2))
	emptyVol(t, ns, "scratch")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "", "iv", nil, vol("root", "ws"), vol("scratch", "scratch"))
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	att := volState(b, "root").AttachmentID
	eventually(t, 30*time.Second, "3 interval snapshots", func() bool {
		v := getVol(ns, "ws")
		return v.Status.LastSequence >= 4 && v.Status.Current >= 4
	})
	v := getVol(ns, "ws")
	for _, s := range v.Status.Snapshots[1:] {
		if s.Reason != v1.SnapshotInterval || s.Writer == nil || s.Writer.AttachmentID != att {
			t.Fatalf("snapshot %+v", s)
		}
	}
	if cl := v.Status.Claim; cl == nil || cl.Snapshot != 1 || cl.Baseline != v.Status.Current {
		t.Fatalf("claim %+v", cl)
	}
	// Compaction: limit 2, snapshot 1 is held by the claim.
	eventually(t, 20*time.Second, "compaction", func() bool {
		v := getVol(ns, "ws")
		r := readySeqs(v)
		return len(r) == 3 && r[0] == 1 && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == api.ReasonHeld
	})
	// Dropped local snapshots are remembered, not sent again.
	eventually(t, 10*time.Second, "drops remembered", func() bool {
		env.ctrl.mu.Lock()
		defer env.ctrl.mu.Unlock()
		return len(env.ctrl.dropped[att]) >= 2
	})
	drops := map[int64]int{}
	for _, c := range env.nodes["c9"].Commands() {
		if d := c.GetDropLocalSnapshot(); d != nil && d.AttachmentId == att {
			drops[d.Seq]++
		}
	}
	for seq, n := range drops {
		if n != 1 {
			t.Fatalf("local snapshot %d dropped %d times", seq, n)
		}
	}
	// Incremental: later sends use the baseline as local base.
	node := env.nodes["c9"]
	inc := 0
	for _, c := range node.Commands() {
		if s := c.GetWriteSnapshot(); s != nil && s.AllocationId == b.Status.Allocation.ID && s.BaseSeq != 0 && !s.Full {
			inc++
		}
	}
	if inc == 0 {
		t.Fatal("no incremental send")
	}
	// The scratch volume has no interval.
	if sv := getVol(ns, "scratch"); sv.Status.LastSequence != 1 {
		t.Fatalf("scratch %+v", sv.Status)
	}
	// Transfers to 2 of 3 replicas fail: a Failed snapshot, SnapshotsBehind.
	for _, r := range cur(t, getVol(ns, "ws")).Replicas[:2] {
		node.FailTransfersTo(r.Node, true)
	}
	eventually(t, 40*time.Second, "a failed snapshot", func() bool {
		for _, s := range getVol(ns, "ws").Status.Snapshots {
			if s.State == v1.SnapshotFailed {
				return true
			}
		}
		return false
	})
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondSnapshotsBehind) })
	for _, n := range env.nodes {
		node.FailTransfersTo(n.Name(), false)
	}
	waitBlip(t, ns, "b", 30*time.Second, func(b *v1.Blip) bool { return !isTrue(b.Status.Conditions, api.CondSnapshotsBehind) })
	// The failed one is compacted once older than the newest Ready.
	eventually(t, 20*time.Second, "failed compacted", func() bool {
		for _, s := range getVol(ns, "ws").Status.Snapshots {
			if s.State == v1.SnapshotFailed {
				return false
			}
		}
		return true
	})
	if err := env.k.Delete(context.Background(), getBlip(ns, "b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	released(t, ns, b, "ws", "scratch")
	// Both volumes saved a shutdown snapshot in the same allocation (their
	// sequences are per BlipVol; local sequences must not collide).
	if b := getVol(ns, "scratch"); b.Status.Current != 2 || b.Snapshot(2).Reason != v1.SnapshotShutdown {
		t.Fatalf("scratch %+v", b.Status)
	}
	// Without the claim, snapshot 1 goes too.
	eventually(t, 20*time.Second, "within limit", func() bool {
		v := getVol(ns, "ws")
		r := readySeqs(v)
		return len(r) == 2 && r[0] != 1 && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == "WithinLimit" &&
			v.Snapshot(v.Status.Current).Reason == v1.SnapshotShutdown
	})
	// Deleted snapshots' content is gone from the nodes.
	s1 := api.SnapshotContentID(string(v.UID), 1)
	eventually(t, 20*time.Second, "content of snapshot 1 deleted", func() bool {
		for _, n := range env.nodes {
			if n.Content(s1) != nil {
				return false
			}
		}
		return true
	})
}

// appendSnaps adds fake Ready snapshots to a BlipVol (content sealed on
// the members of its group).
func appendSnaps(t *testing.T, ns, name string, n int) {
	t.Helper()
	ctx := context.Background()
	_, err := env.ctrl.updateVolStatus(ctx, nsName(ns, name), "", func(v *v1.BlipVol) (bool, error) {
		base := v.Snapshot(v.Status.Current)
		for range n {
			seq := v.Status.LastSequence + 1
			now := metav1.NewTime(time.Now().Truncate(time.Second))
			s := v1.VolSnapshot{Sequence: seq, ContentID: api.SnapshotContentID(string(v.UID), seq), Reason: v1.SnapshotInterval, State: v1.SnapshotReady,
				CaptureTime: &now, StorageGroup: base.StorageGroup, Base: base.ContentID, Replicas: base.Replicas}
			for _, r := range base.Replicas {
				env.nodes[r.Node].Storage().PutContent(&nodepb.ContentInfo{ContentId: s.ContentID, Sealed: true, SizeBytes: 1 << 20})
			}
			v.Status.Snapshots = append(v.Status.Snapshots, s)
			v.Status.LastSequence = seq
		}
		syncCurrent(v)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func setLimit(t *testing.T, ns, name string, limit int32) {
	t.Helper()
	for range 50 {
		v := getVol(ns, name)
		v.Spec.SnapshotPolicy = &v1.SnapshotPolicy{Limit: limit}
		err := env.k.Update(context.Background(), v)
		if err == nil {
			return
		}
		if !apierrors.IsConflict(err) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("update kept conflicting")
}

// Compaction keeps held and pinned snapshots beyond the limit.
func TestCompactionHoldsAndPins(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	ctx := context.Background()
	src := policyVol(t, ns, "src", &v1.SnapshotPolicy{Limit: 10})
	appendSnaps(t, ns, "src", 3) // 2, 3, 4
	// A derived BlipVol pins snapshot 3.
	three := int64(3)
	d := readyVol(t, ns, "d", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src", Snapshot: &three}})
	if o := d.Status.Origin; o == nil || o.Snapshot != 3 || o.UID != string(src.UID) || o.ContentID != api.SnapshotContentID(string(src.UID), 3) {
		t.Fatalf("origin %+v", d.Status.Origin)
	}
	// A clone in progress holds snapshot 2.
	holder := v1.HolderRef{Kind: "BlipVol", Namespace: ns, Name: "d", UID: string(d.UID)}
	if err := env.ctrl.addHold(ctx, ns, v1.ObjectRef{Name: "src", UID: string(src.UID)}, v1.HoldClone, holder, "test", 2); err != nil {
		t.Fatal(err)
	}
	setLimit(t, ns, "src", 1)
	eventually(t, 20*time.Second, "1 compacted, 2 and 3 kept", func() bool {
		v := getVol(ns, "src")
		return fmt.Sprint(readySeqs(v)) == "[2 3 4]" && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == api.ReasonPinned
	})
	c1 := api.SnapshotContentID(string(src.UID), 1)
	eventually(t, 10*time.Second, "content 1 deleted", func() bool {
		for _, n := range env.nodes {
			if n.Content(c1) != nil {
				return false
			}
		}
		return true
	})
	// The hold goes: 2 is deleted, 3 stays pinned.
	if err := env.ctrl.dropHold(ctx, ns, v1.ObjectRef{Name: "src", UID: string(src.UID)}, v1.HoldClone, string(d.UID)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "2 compacted", func() bool {
		v := getVol(ns, "src")
		return fmt.Sprint(readySeqs(v)) == "[3 4]" && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == api.ReasonPinned
	})
	// The derived BlipVol goes: the pin goes.
	if err := env.k.Delete(ctx, d); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "3 compacted", func() bool {
		v := getVol(ns, "src")
		return fmt.Sprint(readySeqs(v)) == "[4]" && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == "WithinLimit"
	})
	// Deleting the source is not blocked by derived BlipVols.
	d2 := readyVol(t, ns, "d2", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src"}})
	if d2.Status.Origin.Snapshot != 4 {
		t.Fatalf("origin %+v", d2.Status.Origin)
	}
	if err := env.k.Delete(ctx, getVol(ns, "src")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "source deleted", func() bool { return getVol(ns, "src") == nil })
	if v := getVol(ns, "d2"); v == nil || v.Status.Phase != v1.BlipVolReady {
		t.Fatal("derived vol affected")
	}
}

// Derive from an idle BlipVol (newest Ready) and from a historical
// snapshot; a missing snapshot waits or fails.
func TestDeriveIdleAndHistorical(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	src := policyVol(t, ns, "src", &v1.SnapshotPolicy{Limit: 10})
	appendSnaps(t, ns, "src", 2) // 2, 3
	d := readyVol(t, ns, "newest", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src"}})
	s := d.Snapshot(1)
	if o := d.Status.Origin; o == nil || o.Snapshot != 3 || o.Name != "src" || o.Namespace != ns ||
		s.Reason != v1.SnapshotInitial || s.Base != o.ContentID || d.Status.RootContentID != src.Status.RootContentID || d.Status.Current != 1 {
		t.Fatalf("derived %+v", d.Status)
	}
	two := int64(2)
	h := readyVol(t, ns, "hist", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src", Snapshot: &two}})
	if h.Status.Origin.Snapshot != 2 {
		t.Fatalf("historical %+v", h.Status.Origin)
	}
	// Clone holds go once the clones are done.
	if v := getVol(ns, "src"); len(v.Status.Holds) != 0 {
		t.Fatalf("holds %+v", v.Status.Holds)
	}
	// A snapshot that does not exist yet waits; a deleted one fails.
	nine := int64(9)
	newVol(t, ns, "future", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src", Snapshot: &nine}})
	eventually(t, 10*time.Second, "SnapshotNotYetTaken wait", func() bool {
		v := getVol(ns, "future")
		return v.Status.Phase == v1.BlipVolPending && condReason(v.Status.Conditions, api.CondReady) == api.ReasonSnapshotNotYetTaken
	})
	newVol(t, ns, "noparent", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "nosuch"}})
	eventually(t, 10*time.Second, "ParentNotFound", func() bool {
		return condReason(getVol(ns, "noparent").Status.Conditions, api.CondReady) == api.ReasonParentNotFound
	})
	setLimit(t, ns, "src", 1)
	eventually(t, 10*time.Second, "1 compacted", func() bool { return snap(ns, "src", 1) == nil })
	one := int64(1)
	newVol(t, ns, "gone", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src", Snapshot: &one}})
	eventually(t, 10*time.Second, "SnapshotNotFound failure", func() bool {
		v := getVol(ns, "gone")
		return v.Status.Phase == v1.BlipVolFailed && condReason(v.Status.Conditions, api.CondFailed) == api.ReasonSnapshotNotFound
	})
}

// Derive from a BlipVol attached to a running Blip: a capture is taken
// for it; while the source node is unreachable the derive waits.
func TestDeriveLive(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "live", "c9")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "live", nil)
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	d := newVol(t, ns, "d", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "ws"}})
	d = readyVolNamed(t, ns, "d")
	v := getVol(ns, "ws")
	o := d.Status.Origin
	ps := v.Snapshot(o.Snapshot)
	if o.Snapshot != 2 || ps == nil || ps.Reason != v1.SnapshotDerive || ps.CaptureTime.Unix() <= d.CreationTimestamp.Unix() ||
		ps.Writer.AttachmentID != volState(b, "root").AttachmentID {
		t.Fatalf("origin %+v, parent snapshot %+v", o, ps)
	}
	// The source node goes away: a new derive waits with SourceUnreachable.
	c9 := env.nodes["c9"]
	c9.Pause()
	newVol(t, ns, "d2", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "ws"}})
	eventually(t, 15*time.Second, "SourceUnreachable", func() bool {
		return condReason(getVol(ns, "d2").Status.Conditions, api.CondReady) == api.ReasonSourceUnreachable
	})
	// An explicit older snapshot does not wait.
	one := int64(1)
	readyVol(t, ns, "d3", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "ws", Snapshot: &one}})
	c9.Resume()
	d2 := readyVolNamed(t, ns, "d2")
	if d2.Status.Origin.Snapshot <= 2 {
		t.Fatalf("d2 origin %+v", d2.Status.Origin)
	}
	if err := env.k.Delete(context.Background(), getBlip(ns, "b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
	_ = d
}

func readyVolNamed(t *testing.T, ns, name string) *v1.BlipVol {
	t.Helper()
	var bv *v1.BlipVol
	eventually(t, 30*time.Second, "blipvol "+name+" ready", func() bool {
		bv = getVol(ns, name)
		return bv != nil && bv.Status.Phase == v1.BlipVolReady
	})
	return bv
}

// A lost response to the status write that appends a capture does not
// make a second snapshot.
func TestLostAppendResponse(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "lost", "s2")
	emptyVol(t, ns, "ws")
	loseAppend.Store(true)
	defer loseAppend.Store(false)
	newBlip(t, ns, "b", "ws", "lost", nil)
	b := complete(t, ns, "b")
	if loseAppend.Load() {
		t.Fatal("write not intercepted")
	}
	v := getVol(ns, "ws")
	if len(v.Status.Snapshots) != 2 || v.Status.LastSequence != 2 || ss(b, "root").Sequence != 2 || ss(b, "root").State != v1.ShutdownSnapshotReady {
		t.Fatalf("snapshots %+v", v.Status.Snapshots)
	}
}
