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

// creationTimestamp has one-second resolution, so turns created in the same
// second used to be ordered by name. The deterministic producer names
// blip-<uid>-rN and blip-<uid>-fin sort the finish turn before the report that
// preceded it. resourceVersion records the actual write order and must decide.
func TestSequencerOrdersSameSecondTurnsByResourceVersion(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	ts := metav1.NewTime(time.Now().Truncate(time.Second))

	report := testTurn("blip-uid-r1", "proj")
	report.CreationTimestamp = ts
	report.ResourceVersion = "101"
	finish := testTurn("blip-uid-fin", "proj")
	finish.CreationTimestamp = ts
	finish.ResourceVersion = "102"

	c := testClient(t, thread, report, finish)
	s := &Sequencer{Client: c}
	ctx := context.Background()
	if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: finish.Name}}); err != nil {
		t.Fatal(err)
	}

	want := map[string]int64{"blip-uid-r1": 1, "blip-uid-fin": 2}
	for name, seq := range want {
		var turn v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
			t.Fatal(err)
		}
		if turn.Status.Seq != seq {
			t.Errorf("%s seq = %d, want %d (creation order)", name, turn.Status.Seq, seq)
		}
	}
}
