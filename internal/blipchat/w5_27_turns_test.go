package blipchat

import (
	"context"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Turns are immutable at admission. A deterministic report/finish turn
// reconciled again with different cleaned content must not fail: the watcher
// would retry forever. The first turn's text stays authoritative.
func TestCreateTurnInKeepsContentForSameProducer(t *testing.T) {
	thread := testThread()
	thread.UID = "thread-uid"
	c := testClient(t, thread)
	ctx := context.Background()
	first := turnSpec{
		Thread: "proj", ThreadUID: "thread-uid",
		AuthorKind: v1.TurnAuthorBlip, AuthorName: "blip-a",
		Topic: "blip.report", Text: "tests pass",
	}
	if err := createTurnIn(ctx, c, "ns", "blip-uid-r1", first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Text = "tests pass, cleaned differently"
	if err := createTurnIn(ctx, c, "ns", "blip-uid-r1", second); err != nil {
		t.Fatalf("reconciling changed content failed: %v", err)
	}
	var got v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "blip-uid-r1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Text != first.Text {
		t.Errorf("turn text = %q, want the immutable original %q", got.Spec.Text, first.Text)
	}
}
