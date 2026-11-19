package blipchat

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A turn can be sealed while the counter write is lost (the pre-CAS writer
// order, or an interrupted upgrade). Sequencing new turns before the sealed
// turn reconciles must still reserve above every number already recorded on a
// turn, or the new turns reuse a consumed sequence and vanish from
// pendingTurns.
func TestSequencerReservesAboveSealedTurnWithLaggingCounter(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("inc")
	fresh := metav1.NewTime(time.Now())
	thread.Status.LastSeq = 3
	thread.Status.ConsumedSeq = 5
	sealed := testTurn("old-sealed", "proj")
	sealed.Status = v1.BlipTurnStatus{Seq: 5, ThreadUID: "inc", AcceptedTime: &fresh}
	one := testTurn("new-one", "proj")
	two := testTurn("new-two", "proj")
	c := testClient(t, thread, sealed, one, two)
	s := &Sequencer{Client: c}
	ctx := context.Background()

	for _, name := range []string{one.Name, two.Name} {
		if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}

	var got v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &got); err != nil {
		t.Fatal(err)
	}
	seqOne, seqTwo := testSeq(t, c, one.Name), testSeq(t, c, two.Name)
	if seqOne <= 5 || seqTwo <= 5 {
		t.Errorf("new turns got %d/%d, want both above the sealed seq 5", seqOne, seqTwo)
	}
	if seqOne == seqTwo {
		t.Errorf("new turns share seq %d", seqOne)
	}
	pending, err := (&Server{Client: c}).pendingTurns(ctx, &got)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Errorf("pendingTurns = %v, want both new turns", names(pending))
	}
}

func testSeq(t *testing.T, c client.Client, name string) int64 {
	t.Helper()
	var turn v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
		t.Fatal(err)
	}
	return turn.Status.Seq
}
