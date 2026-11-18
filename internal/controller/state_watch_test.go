package controller

import (
	"context"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestCopySourceMapping(t *testing.T) {
	r := &StateReconciler{}
	tests := []struct {
		name   string
		object client.Object
		want   []reconcile.Request
	}{
		{
			name:   "copy",
			object: &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cp"}, Spec: v1.BlipStateSpec{CopyFrom: "src"}},
			want:   []reconcile.Request{req(ns, "src")},
		},
		{
			name:   "copy of itself",
			object: &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "src"}, Spec: v1.BlipStateSpec{CopyFrom: "src"}},
		},
		{
			name:   "not a copy",
			object: &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "src"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.copySource(context.Background(), tt.object); !slices.Equal(got, tt.want) {
				t.Fatalf("mapped %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCopyCommitEnqueuesSource covers the deletion latency bug: while a copy
// is in flight the source finalizer waits for it. The copy's commit update
// must enqueue the source directly so its deletion completes without waiting
// for the periodic resync.
func TestCopyCommitEnqueuesSource(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("src", "n1", "n2")
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 2
	})
	e.run(e.state, ns, "cp")
	before := e.getState("cp").DeepCopy()
	if before.Status.CopiedFrom == nil || before.Status.Pending == nil {
		t.Fatalf("copy not planned: %+v", before.Status)
	}

	// The source deletion waits for the in-flight copy.
	e.must(e.c.Delete(e.ctx, e.getState("src")))
	e.run(e.state, ns, "src")
	if st := e.getState("src"); !strings.Contains(st.Status.Message, "copy cp") || len(st.Finalizers) == 0 {
		t.Fatalf("source deletion not blocked by the copy: %+v", st.Status)
	}

	// The copy commits and becomes Ready.
	p := before.Status.Pending
	e.hold("cp", p.CommitID, p.Replicas...)
	e.run(e.state, ns, "cp")
	after := e.getState("cp")
	if after.Status.Committed == nil || after.Status.Phase != v1.StateReady {
		t.Fatalf("copy did not commit: %+v", after.Status)
	}

	// Its update is not filtered out and enqueues exactly the source.
	upd := event.UpdateEvent{ObjectOld: before, ObjectNew: after}
	if !copySourcePredicate().Update(upd) {
		t.Fatal("copy commit was filtered out of the source watch")
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	handler.EnqueueRequestsFromMapFunc(e.state.copySource).Update(e.ctx, upd, q)
	if q.Len() != 1 {
		t.Fatalf("copy commit enqueued %d requests, want 1", q.Len())
	}
	item, _ := q.Get()
	q.Done(item)
	if item != req(ns, "src") {
		t.Fatalf("copy commit enqueued %v, want %v", item, req(ns, "src"))
	}

	// Reconcile only the source, as that wakeup would; the finalizer now
	// completes without any resync.
	e.run(e.state, ns, "src")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "src"}, &v1.BlipState{}); err == nil {
		t.Fatal("source not deleted after the copy committed")
	}

	// Status churn that cannot change the source's blockers must not wake
	// it, so the source and copy do not bounce updates in a loop.
	noise := after.DeepCopy()
	noise.Status.Message = "saving generation 1"
	if copySourcePredicate().Update(event.UpdateEvent{ObjectOld: after, ObjectNew: noise}) {
		t.Fatal("unrelated copy status update was mapped to the source")
	}
}

// TestFailedCopyReleasesSourceDeletion covers a copy that can never commit
// (its size is smaller than the source): it must not pin the source's
// finalizer, and its failure transition must wake the source.
func TestFailedCopyReleasesSourceDeletion(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	srcSize := resource.MustParse("10Gi")
	e.newState("src", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.Size = &srcSize
	})
	e.run(e.state, ns, "src")
	src := e.getState("src")
	e.hold("src", src.Status.Pending.CommitID, src.Status.Pending.Replicas...)
	e.run(e.state, ns, "src")
	src = e.getState("src")
	if src.Status.Phase != v1.StateReady {
		t.Fatalf("source not ready: %+v", src.Status)
	}

	smallSize := resource.MustParse("1Gi")
	e.newState("small", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.CopyFrom = "src"
		st.Spec.Size = &smallSize
	})
	e.run(e.state, ns, "small")
	after := e.getState("small")
	if after.Status.Phase != v1.StateFailed || after.Status.Committed != nil {
		t.Fatalf("copy did not fail: %+v", after.Status)
	}
	if after.Status.CopiedFrom == nil {
		t.Fatal("failed copy lost its informational source reference")
	}
	if copyBlocksDeletion(after, src) {
		t.Fatal("failed copy still blocks its source")
	}

	// The status it had before the size check failed still blocked the
	// source; only the phase changed, and that transition must reach the
	// source without a resync.
	before := after.DeepCopy()
	before.Status.Phase = v1.StatePending
	before.Status.Message = ""
	before.Status.CopiedFrom = after.Status.CopiedFrom.DeepCopy()
	if !copyBlocksDeletion(before, src) {
		t.Fatal("in-flight copy unexpectedly does not block its source")
	}
	upd := event.UpdateEvent{ObjectOld: before, ObjectNew: after}
	if !copySourcePredicate().Update(upd) {
		t.Fatal("copy failure was filtered out of the source watch")
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	handler.EnqueueRequestsFromMapFunc(e.state.copySource).Update(e.ctx, upd, q)
	if q.Len() != 1 {
		t.Fatalf("copy failure enqueued %d requests, want 1", q.Len())
	}
	item, _ := q.Get()
	q.Done(item)
	if item != req(ns, "src") {
		t.Fatalf("copy failure enqueued %v, want %v", item, req(ns, "src"))
	}

	// That wake is enough: the source finalizer completes without deleting
	// the failed copy first.
	e.must(e.c.Delete(e.ctx, src))
	e.run(e.state, ns, "src")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "src"}, &v1.BlipState{}); err == nil {
		t.Fatal("source deletion still blocked by a failed copy")
	}
	if cp := e.getState("small"); cp.Status.CopiedFrom == nil {
		t.Fatal("failed copy lost its source reference while the source was deleted")
	}
}

// TestDeletingCopyReleasesSourceDeletion: a copy the user deleted cannot be
// built any more, so it must stop blocking its source. The deletion transition
// wakes the source through the copy watch.
func TestDeletingCopyReleasesSourceDeletion(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("src", "n1", "n2")
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	before := e.getState("cp")
	src := e.getState("src")
	if before.Status.Pending == nil || !copyBlocksDeletion(before, src) {
		t.Fatalf("in-flight copy does not block: %+v", before.Status)
	}

	e.must(e.c.Delete(e.ctx, before))
	after := e.getState("cp")
	if after.DeletionTimestamp == nil {
		t.Fatal("copy was not marked for deletion")
	}
	if copyBlocksDeletion(after, src) {
		t.Fatal("deleting copy still blocks its source")
	}
	upd := event.UpdateEvent{ObjectOld: before, ObjectNew: after}
	if !copySourcePredicate().Update(upd) {
		t.Fatal("copy deletion was filtered out of the source watch")
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	handler.EnqueueRequestsFromMapFunc(e.state.copySource).Update(e.ctx, upd, q)
	if q.Len() != 1 {
		t.Fatalf("copy deletion enqueued %d requests, want 1", q.Len())
	}
	item, _ := q.Get()
	q.Done(item)
	if item != req(ns, "src") {
		t.Fatalf("copy deletion enqueued %v, want %v", item, req(ns, "src"))
	}

	e.must(e.c.Delete(e.ctx, src))
	e.run(e.state, ns, "src")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "src"}, &v1.BlipState{}); err == nil {
		t.Fatal("source deletion still blocked by a deleting copy")
	}
}
