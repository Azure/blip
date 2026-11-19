package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// cleanAttributes must select the same subset of oversized attribute maps on
// every call: a random subset makes an idempotent turn re-create itself.
func TestCleanAttributesUsesStableSubset(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < 20; i++ {
		in[fmt.Sprintf("key-%02d", i)] = fmt.Sprintf("value-%02d", i)
	}
	want := cleanAttributes(in)
	if len(want) != 16 {
		t.Fatalf("cleanAttributes kept %d attributes, want the 16-attribute cap", len(want))
	}
	for i := 0; i < 50; i++ {
		if got := cleanAttributes(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("cleanAttributes changed between calls:\nfirst %v\nnow   %v", want, got)
		}
	}
}

// A report turn has a deterministic name. Reconciles triggered by unrelated
// Blip metadata updates must not replace it and reset the sequencer state that
// decides whether the report was already consumed.
func TestWatcherKeepsReportTurnOnMetadataUpdates(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	report := map[string]string{}
	for i := 0; i < 20; i++ {
		report[fmt.Sprintf("field-%02d", i)] = fmt.Sprintf("value-%02d", i)
	}
	text, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reporter",
			Namespace: "ns",
			UID:       types.UID("blip-uid"),
			Labels: map[string]string{
				v1.LabelThread: v1.ThreadLabel("proj"),
				v1.LabelOwner:  v1.ThreadOwner("ns", "proj"),
			},
		},
		Status: v1.BlipStatus{
			Report: &v1.BlipReport{Seq: 1, Text: string(text)},
		},
	}
	c := testClient(t, thread, blip)
	w := &Watcher{Client: c}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "reporter"}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	name := "blip-blip-uid-r1"
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
		t.Fatal(err)
	}
	turn.Status = v1.BlipTurnStatus{Seq: 7, ThreadUID: "thread-uid"}
	if err := c.Status().Update(ctx, &turn); err != nil {
		t.Fatal(err)
	}

	// An annotation change is what makes the watcher reconcile a Blip whose
	// report has not changed.
	for i := 0; i < 20; i++ {
		var current v1.Blip
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "reporter"}, &current); err != nil {
			t.Fatal(err)
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations["probe"] = fmt.Sprint(i)
		if err := c.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
		var got v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &got); err != nil {
			t.Fatalf("reconcile %d: report turn was replaced: %v", i, err)
		}
		if got.Status.Seq != 7 || got.Status.ThreadUID != "thread-uid" {
			t.Fatalf("reconcile %d: turn status = %+v, want the original seq and incarnation", i, got.Status)
		}
		var turns v1.BlipTurnList
		if err := c.List(ctx, &turns, client.InNamespace("ns"), client.MatchingFields{turnField: "proj"}); err != nil {
			t.Fatal(err)
		}
		if len(turns.Items) != 1 {
			t.Fatalf("reconcile %d: %d report turns survive, want 1", i, len(turns.Items))
		}
	}
}
