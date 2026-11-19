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

// A turn created directly through the API has no ownerReference. Sequencing it
// must adopt it for the current thread incarnation so deleting the thread
// garbage-collects the turn instead of leaving its text for orphan pruning.
func TestSequencerOwnsDirectlyCreatedTurn(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	c := testClient(t, thread)
	ctx := context.Background()
	turn := testTurn("direct", "proj")
	if err := c.Create(ctx, turn); err != nil {
		t.Fatal(err)
	}

	if _, err := (&Sequencer{Client: c}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: turn.Name}}); err != nil {
		t.Fatal(err)
	}

	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Seq != 1 {
		t.Fatalf("turn seq = %d, want 1", got.Status.Seq)
	}
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %v, want one thread owner", got.OwnerReferences)
	}
	ref := got.OwnerReferences[0]
	if ref.APIVersion != v1.GroupVersion.String() || ref.Kind != "BlipThread" || ref.Name != "proj" || ref.UID != "thread-uid" {
		t.Errorf("owner reference = %+v, want the current BlipThread", ref)
	}
	if ref.Controller != nil || ref.BlockOwnerDeletion != nil {
		t.Errorf("owner reference = %+v, want no controller or blockOwnerDeletion", ref)
	}
}

// Adopting a directly created turn must not replace owner references some
// other producer already wrote.
func TestSequencerPreservesExistingOwnerReferences(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	existing := metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "cfg", UID: types.UID("cfg-uid")}
	turn := testTurn("direct", "proj")
	turn.OwnerReferences = []metav1.OwnerReference{existing}
	c := testClient(t, thread, turn)
	ctx := context.Background()

	if _, err := (&Sequencer{Client: c}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: turn.Name}}); err != nil {
		t.Fatal(err)
	}

	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.OwnerReferences) != 2 {
		t.Fatalf("ownerReferences = %v, want the existing reference plus the thread", got.OwnerReferences)
	}
	if got.OwnerReferences[0] != existing {
		t.Errorf("existing owner reference = %+v, want %+v", got.OwnerReferences[0], existing)
	}
	if ref := got.OwnerReferences[1]; ref.Kind != "BlipThread" || ref.UID != "thread-uid" {
		t.Errorf("added owner reference = %+v", ref)
	}
}

// A turn created by createTurnIn already has a controller reference; the
// sequencer must keep it (and not append a duplicate).
func TestSequencerKeepsControllerRefFromCreateTurnIn(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	c := testClient(t, thread)
	ctx := context.Background()
	if err := createTurnIn(ctx, c, "ns", "owned", turnSpec{Thread: "proj", AuthorKind: v1.TurnAuthorUser, AuthorName: "alice"}); err != nil {
		t.Fatal(err)
	}

	if _, err := (&Sequencer{Client: c}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "owned"}}); err != nil {
		t.Fatal(err)
	}

	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "owned"}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %v, want the original controller reference", got.OwnerReferences)
	}
	ref := got.OwnerReferences[0]
	if ref.Controller == nil || !*ref.Controller || ref.Name != "proj" || ref.UID != "thread-uid" {
		t.Errorf("owner reference = %+v, want the controller reference", ref)
	}
}
