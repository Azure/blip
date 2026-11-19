package blipchat

import (
	"context"
	"errors"
	"sync"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A CAS conflict while reserving a sequence can race a delete+recreate of the
// thread. The retry must pin the turn to the live incarnation, not keep the
// dead UID from the snapshot.
func TestReserveSeqPinsLiveIncarnationOnConflict(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("old-incarnation")
	turn := testTurn("one", "proj")
	var once sync.Once
	funcs := interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			first := false
			if _, ok := obj.(*v1.BlipThread); ok && sub == "status" {
				once.Do(func() {
					first = true
					old := &v1.BlipThread{}
					if err := c.Get(ctx, client.ObjectKeyFromObject(obj), old); err != nil {
						t.Error(err)
						return
					}
					if err := c.Delete(ctx, old); err != nil {
						t.Error(err)
						return
					}
					live := testThread()
					live.UID = types.UID("new-incarnation")
					if err := c.Create(ctx, live); err != nil {
						t.Error(err)
					}
				})
				if first {
					return apierrors.NewConflict(
						k8sschema.GroupResource{Group: "blip.dev", Resource: "blipthreads"},
						obj.GetName(), errors.New("the object has been modified"))
				}
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}
	c := testClientWith(t, funcs, thread, turn)
	s := &Sequencer{Client: c}
	ctx := context.Background()
	if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Seq != 1 || got.Status.ThreadUID != "new-incarnation" {
		t.Errorf("turn status = %+v, want seq 1 pinned to the live incarnation", got.Status)
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if live.UID != "new-incarnation" {
		t.Fatalf("thread UID = %q", live.UID)
	}
	if live.Status.LastSeq != 1 {
		t.Errorf("live thread lastSeq = %d, want 1", live.Status.LastSeq)
	}
}
