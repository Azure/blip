package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// cleanAttributes must select the same subset of oversized attribute maps on
// every call: a random subset makes an idempotent turn re-create itself.
// A prompt that cannot fit every turn must not advance consumedSeq past a
// turn it neither rendered nor summarized: that permanently loses input.
func TestPromptOverflowDoesNotConsumeUnshownTurns(t *testing.T) {
	const count = 30
	fresh := metav1.NewTime(timeNow())
	thread := testThread()
	objs := []client.Object{thread}
	for i := 1; i <= count; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 1900))
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	prompt := requestPrompt(t, (*requests)[0])
	if !strings.Contains(prompt, "TURN30-MARKER") {
		t.Errorf("prompt omitted the newest turn")
	}
	for i := 1; i <= count; i++ {
		if strings.Contains(prompt, fmt.Sprintf("TURN%02d-MARKER", i)) {
			continue
		}
		if updated.Status.ConsumedSeq >= int64(i) {
			t.Errorf("turn %d was neither rendered nor summarized, but consumedSeq = %d passed it", i, updated.Status.ConsumedSeq)
		}
	}
}

// When even compact summaries of the older turns cannot fit, the renderer
// must consume a prefix it rendered and leave the newer turns pending.
func TestBoardTurnsLeavesNewestPendingWithoutRoomToSummarize(t *testing.T) {
	fresh := metav1.NewTime(timeNow())
	turns := make([]v1.BlipTurn, 0, 20)
	for i := 1; i <= 20; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 400))
		turns = append(turns, *turn)
	}
	var b strings.Builder
	last := boardTurns(&b, turns, 200)
	out := b.String()
	if !strings.Contains(out, "TURN01-MARKER") {
		t.Errorf("oldest turn was not rendered:\n%s", out)
	}
	if strings.Contains(out, "TURN20-MARKER") {
		t.Errorf("newest turn was rendered although consuming it would skip older ones:\n%s", out)
	}
	if last != 1 {
		t.Errorf("highest shown seq = %d, want the rendered prefix ending at 1", last)
	}
	if !strings.Contains(out, "newer turns left for a later step") {
		t.Errorf("missing notice about the pending newer turns:\n%s", out)
	}
}

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
