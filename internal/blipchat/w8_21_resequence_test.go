package blipchat

import (
	"context"
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Two sequencers overlap during a leader change. While the old leader patches
// the metadata labels, the new leader sequences the turn. The patch response
// refreshes the old leader's copy with the peer's status.seq and a new
// resourceVersion; it must not use that fresh object to overwrite the sealed
// sequence with a second reservation.
func TestSequencerKeepsSeqAssignedDuringLabelPatch(t *testing.T) {
	ctx := context.Background()
	thread := testThread()
	thread.UID = types.UID("inc")
	turn := testTurn("one", "proj")

	var injected atomic.Bool
	var late *Sequencer
	funcs := interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*v1.BlipTurn); ok && !injected.Swap(true) {
				// The newer leader sequences the turn while the older
				// leader is patching its labels.
				if _, err := late.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err != nil {
					t.Errorf("late sequencer: %v", err)
				}
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
	c := testClientWith(t, funcs, thread, turn)
	late = &Sequencer{Client: c}
	early := &Sequencer{Client: c}

	if _, err := early.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err != nil {
		t.Fatal(err)
	}

	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "one"}, &got); err != nil {
		t.Fatal(err)
	}
	var th v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &th); err != nil {
		t.Fatal(err)
	}
	if got.Status.Seq != 1 {
		t.Errorf("turn seq = %d, want the peer's immutable seq 1", got.Status.Seq)
	}
	if th.Status.LastSeq != 1 {
		t.Errorf("lastSeq = %d, want 1 without the stale leader's reservation", th.Status.LastSeq)
	}
}
