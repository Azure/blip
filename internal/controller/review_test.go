package controller

import (
	"context"
	"testing"
	"time"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/testing/fakenode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// fakeClaim gives a BlipVol a claim of a (nonexistent) Blip attachment
// and, with pending, a Pending capture written by it (sequence 2).
func fakeClaim(t *testing.T, ns, name, blipUID, att string, gen int64, pending bool) {
	t.Helper()
	_, err := env.ctrl.updateVolStatus(context.Background(), nsName(ns, name), "", func(v *v1.BlipVol) (bool, error) {
		now := metav1.NewTime(time.Now())
		v.Status.ClaimGeneration = gen
		v.Status.Claim = &v1.Claim{BlipName: "fake", BlipUID: blipUID, AttachmentID: att, Generation: gen, Since: &now, Snapshot: v.Status.Current}
		if pending {
			base := v.Snapshot(v.Status.Current)
			seq := v.Status.LastSequence + 1
			ct := metav1.NewTime(now.Truncate(time.Second))
			v.Status.Snapshots = append(v.Status.Snapshots, v1.VolSnapshot{Sequence: seq, ContentID: api.SnapshotContentID(string(v.UID), seq),
				Reason: v1.SnapshotInterval, State: v1.SnapshotPending, CaptureTime: &ct, StorageGroup: base.StorageGroup, Base: base.ContentID,
				Writer: &v1.Writer{BlipName: "fake", BlipUID: blipUID, AttachmentID: att, Generation: gen}})
			v.Status.LastSequence = seq
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fakeRun(ns, uid string) *blipRun {
	b := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "fake", UID: types.UID(uid)}}
	return &blipRun{b: b, key: nsName(ns, "fake"), now: time.Now()}
}

// A capture whose entry was marked Failed by another writer while it was
// being sealed reports the failure and does not advance the volume.
func TestSnapshotReadyAfterFailed(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	ctx := context.Background()
	emptyVol(t, ns, "ws")
	fakeClaim(t, ns, "ws", "u1", "a1", 1, true)
	v := getVol(ns, "ws")
	s := *v.Snapshot(2)
	if _, err := env.ctrl.updateVolStatus(ctx, nsName(ns, "ws"), "", func(x *v1.BlipVol) (bool, error) {
		return setSnapFailed(x, 2, "released", false), nil
	}); err != nil {
		t.Fatal(err)
	}
	vs := &v1.BlipVolumeStatus{Name: "root", AttachmentID: "a1", Generation: 1}
	st, msg := env.ctrl.snapshotReady(ctx, fakeRun(ns, "u1"), v, &s, vs, []string{"n1", "n2"}, nil)
	if st != saveFailed || msg != "released" {
		t.Fatalf("got %v %q", st, msg)
	}
	if v.Snapshot(2).State != v1.SnapshotPending {
		t.Fatal("cached copy mutated")
	}
	v = getVol(ns, "ws")
	if v.Status.Current != 1 || v.Status.Claim.Baseline != 0 || v.Snapshot(2).State != v1.SnapshotFailed {
		t.Fatalf("status %+v", v.Status)
	}
	// An entry that is gone is a failure too.
	s.Sequence = 9
	if st, _ := env.ctrl.snapshotReady(ctx, fakeRun(ns, "u1"), v, &s, vs, []string{"n1", "n2"}, nil); st != saveFailed {
		t.Fatalf("gone entry: %v", st)
	}
}

// A capture of an attachment whose claim generation is not the current
// one is refused, and the writer records the generation.
func TestStartCaptureClaimGeneration(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	ctx := context.Background()
	emptyVol(t, ns, "ws")
	fakeClaim(t, ns, "ws", "u1", "a1", 3, false)
	v := getVol(ns, "ws")
	r := fakeRun(ns, "u1")
	_, err := env.ctrl.startCapture(ctx, r, &v1.BlipVolumeStatus{Name: "root", AttachmentID: "a1", Generation: 2}, v, v1.SnapshotInterval)
	if rf, ok := err.(*refusal); !ok || rf.reason != "ClaimLost" {
		t.Fatalf("stale generation: %v", err)
	}
	s, err := env.ctrl.startCapture(ctx, r, &v1.BlipVolumeStatus{Name: "root", AttachmentID: "a1", Generation: 3}, v, v1.SnapshotInterval)
	if err != nil || s.Writer.Generation != 3 {
		t.Fatalf("capture %+v %v", s, err)
	}
}

// A Pending capture whose writer lost the claim is marked Failed by
// compaction.
func TestAbandonedCaptureFailed(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	emptyVol(t, ns, "ws")
	fakeClaim(t, ns, "ws", "u1", "a1", 1, true)
	if _, err := env.ctrl.updateVolStatus(context.Background(), nsName(ns, "ws"), "", func(v *v1.BlipVol) (bool, error) {
		v.Status.Claim = nil
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "abandoned capture failed", func() bool {
		s := snap(ns, "ws", 2)
		return s != nil && s.State == v1.SnapshotFailed && s.Message == "the writer no longer holds the claim"
	})
	// A claim of a newer generation does not own it either.
	fakeClaim(t, ns, "ws", "u1", "a1", 1, true)
	fakeClaim(t, ns, "ws", "u1", "a1", 2, false)
	eventually(t, 20*time.Second, "stale-generation capture failed", func() bool {
		s := snap(ns, "ws", 3)
		return s != nil && s.State == v1.SnapshotFailed
	})
}

// Derives of explicit old snapshots racing compaction to the limit: the
// snapshot a derive targets is kept while it provisions and pinned once
// it is done.
func TestCompactionVsDerive(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	policyVol(t, ns, "src", &v1.SnapshotPolicy{Limit: 20})
	appendSnaps(t, ns, "src", 8) // 2..9
	var names []string
	for i := int64(2); i <= 8; i++ {
		seq := i
		n := "d" + string(rune('0'+i))
		newVol(t, ns, n, v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "src", Snapshot: &seq}})
		names = append(names, n)
	}
	setLimit(t, ns, "src", 1)
	for i, n := range names {
		d := readyVolNamed(t, ns, n)
		if d.Status.Origin.Snapshot != int64(i+2) {
			t.Fatalf("%s origin %+v", n, d.Status.Origin)
		}
	}
	eventually(t, 20*time.Second, "pins kept, 1 compacted", func() bool {
		v := getVol(ns, "src")
		return v.Snapshot(1) == nil && len(readySeqs(v)) == 8 && condReason(v.Status.Conditions, api.CondRetentionLimitExceeded) == api.ReasonPinned
	})
}

// A derive of an explicit snapshot that is not there yet does not make
// the source's Blip capture.
func TestExplicitDeriveNoCapture(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "expl", "c8")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "expl", nil)
	waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	nine := int64(9)
	newVol(t, ns, "d", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "ws", Snapshot: &nine}})
	eventually(t, 10*time.Second, "derive waits", func() bool {
		v := getVol(ns, "d")
		return v.Status.Origin != nil && condReason(v.Status.Conditions, api.CondReady) == api.ReasonSnapshotNotYetTaken
	})
	time.Sleep(3 * time.Second)
	if v := getVol(ns, "ws"); v.Status.LastSequence != 1 {
		t.Fatalf("captured: %+v", v.Status.Snapshots)
	}
	if err := env.k.Delete(context.Background(), getBlip(ns, "b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "blip removed", func() bool { return getBlip(ns, "b") == nil })
}
