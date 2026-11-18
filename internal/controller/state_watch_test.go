package controller

import (
	"context"
	"slices"
	"strings"
	"testing"

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
