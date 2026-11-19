package blipchat

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Turns created before the incarnation label existed (and long-thread turns
// carrying the old name-derived hash) are migrated when the sequencer sees
// them, so the in-guest proxy's UID selector keeps showing current history.
func TestSequencerBackfillsTurnIncarnationLabels(t *testing.T) {
	thread := testThread()
	thread.Name = "long-" + strings.Repeat("x", 70)
	thread.UID = types.UID("current-incarnation")
	legacyLabel := "thread-" + strings.Repeat("a", 56)
	turn := testTurn("legacy-turn", thread.Name)
	turn.Labels = map[string]string{v1.LabelThread: legacyLabel}
	turn.Status = v1.BlipTurnStatus{Seq: 1, ThreadUID: "current-incarnation"}

	c := testClient(t, thread, turn)
	s := &Sequencer{Client: c}
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(turn)}); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[v1.LabelThread] != v1.ThreadLabel(thread.Name) {
		t.Errorf("thread label = %q, want %q", got.Labels[v1.LabelThread], v1.ThreadLabel(thread.Name))
	}
	if got.Labels[v1.LabelThreadUID] != "current-incarnation" {
		t.Errorf("thread UID label = %q, want the current incarnation", got.Labels[v1.LabelThreadUID])
	}
}

// A turn labelled for an earlier incarnation is never adopted or relabelled by
// the recreated thread.
func TestSequencerDoesNotAdoptEarlierIncarnationLabel(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("current-incarnation")
	turn := testTurn("stale-turn", thread.Name)
	turn.Labels = map[string]string{
		v1.LabelThread:    v1.ThreadLabel(thread.Name),
		v1.LabelThreadUID: "old-incarnation",
	}
	c := testClient(t, thread, turn)
	s := &Sequencer{Client: c}
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(turn)}); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Seq != 0 {
		t.Errorf("stale turn was sequenced: %+v", got.Status)
	}
	if got.Labels[v1.LabelThreadUID] != "old-incarnation" {
		t.Errorf("stale turn was relabelled: %q", got.Labels[v1.LabelThreadUID])
	}
}

// A current-incarnation turn without labels gets both labels as part of
// sequencing, so the proxy can select it.
func TestSequencerLabelsNewTurn(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("current-incarnation")
	turn := testTurn("new-turn", thread.Name)
	c := testClient(t, thread, turn)
	s := &Sequencer{Client: c}
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(turn)}); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(turn), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Seq != 1 {
		t.Fatalf("turn was not sequenced: %+v", got.Status)
	}
	if got.Labels[v1.LabelThread] != v1.ThreadLabel(thread.Name) || got.Labels[v1.LabelThreadUID] != "current-incarnation" {
		t.Errorf("labels = %v, want the current thread and incarnation", got.Labels)
	}
}
