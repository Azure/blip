package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A step that is in flight while its thread is deleted and recreated must not
// write the old incarnation's sequence, board, summary, timers or tokens into
// the new one, nor attach its replies to the new thread.
func TestStepAbandonsRecreatedThreadIncarnation(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("old-incarnation")
	thread.Status.Summary = "old summary"
	thread.Status.Tasks = []v1.ThreadTask{{ID: "oldtask", Title: "old", Open: true}}
	fresh := metav1.NewTime(timeNow())
	turn := testTurn("one", "proj")
	turn.Status.Seq = 2
	turn.Status.ThreadUID = "old-incarnation"
	turn.Status.AcceptedTime = &fresh
	turn.Spec.Wake = v1.WakeNow
	// A turn the recreated thread receives while the old step is in flight.
	newTurn := testTurn("new-turn", "proj")
	newTurn.Status.Seq = 1
	newTurn.Status.ThreadUID = "new-incarnation"
	newTurn.Status.AcceptedTime = &fresh
	newTurn.Spec.Wake = v1.WakeNow
	c := testClient(t, thread, turn, newTurn)

	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			ctx := context.Background()
			old := &v1.BlipThread{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, old); err != nil {
				t.Error(err)
				return
			}
			if err := c.Delete(ctx, old); err != nil {
				t.Error(err)
				return
			}
			recreated := testThread()
			recreated.UID = types.UID("new-incarnation")
			recreated.Status.Summary = "new summary"
			recreated.Status.Tasks = []v1.ThreadTask{{ID: "newtask", Title: "new", Open: true}}
			if err := c.Create(ctx, recreated); err != nil {
				t.Error(err)
			}
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": Message{Role: "assistant", ToolCalls: []ToolCall{
				toolCall("remember", `{"text":"old summary v2"}`),
				toolCall("reply", `{"inReplyTo":1,"text":"old reply"}`),
			}}}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer server.Close()
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	if err := s.step(context.Background(), thread); err != nil {
		t.Fatalf("the step should be abandoned, not fail: %v", err)
	}
	ctx := context.Background()
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &live); err != nil {
		t.Fatal(err)
	}
	if live.UID != "new-incarnation" {
		t.Fatalf("thread UID = %q", live.UID)
	}
	if live.Status.ConsumedSeq != 0 {
		t.Errorf("old step advanced the new incarnation consumedSeq to %d", live.Status.ConsumedSeq)
	}
	if live.Status.Summary != "new summary" {
		t.Errorf("old step overwrote the new summary with %q", live.Status.Summary)
	}
	if len(live.Status.Tasks) != 1 || live.Status.Tasks[0].ID != "newtask" {
		t.Errorf("old step overwrote the new board with %+v", live.Status.Tasks)
	}
	if live.Status.TokensToday != 0 {
		t.Errorf("old step charged %d tokens to the new incarnation", live.Status.TokensToday)
	}
	pending, err := s.pendingTurns(ctx, &live)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Name != "new-turn" {
		t.Errorf("new incarnation pending turns = %v, want its own turn", names(pending))
	}
	var turns v1.BlipTurnList
	if err := c.List(ctx, &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	for _, x := range turns.Items {
		if x.Spec.Author.Kind == v1.TurnAuthorCoordinator {
			t.Errorf("old step created coordinator turn %s in the recreated thread", x.Name)
		}
	}
}

// createTurnIn must not fall back to the live thread when the caller pinned a
// different incarnation: that would adopt an old step's reply.
func TestCreateTurnInRejectsRecreatedThread(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("new-incarnation")
	c := testClient(t, thread)
	err := createTurnIn(context.Background(), c, "ns", "coord-old", turnSpec{
		Thread: "proj", ThreadUID: "old-incarnation",
		AuthorKind: v1.TurnAuthorCoordinator, AuthorName: "proj", Text: "old reply",
	})
	if !errors.Is(err, errStaleIncarnation) {
		t.Fatalf("err = %v, want errStaleIncarnation", err)
	}
	var turn v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "coord-old"}, &turn); err == nil {
		t.Fatal("turn was created for a different incarnation")
	}
}

// prune() receives a thread object from the Steps list snapshot. If the name
// was deleted and recreated since that snapshot, the pass must skip rather
// than delete the new incarnation's turns or restore its old board.
func TestPruneSkipsRecreatedThreadIncarnation(t *testing.T) {
	oldUpdated := metav1.NewTime(timeNow().Add(-100 * time.Hour))
	stale := testThread()
	stale.UID = types.UID("old-incarnation")
	stale.Status.Tasks = []v1.ThreadTask{{ID: "oldtask", Title: "old", Open: false, Updated: &oldUpdated}}

	recreated := testThread()
	recreated.UID = types.UID("new-incarnation")
	recreated.Status.Tasks = []v1.ThreadTask{{ID: "newtask", Title: "new", Open: true}}
	fresh := metav1.NewTime(timeNow())
	newTurn := testTurn("new-turn", "proj")
	newTurn.Status.Seq = 1
	newTurn.Status.ThreadUID = "new-incarnation"
	newTurn.Status.AcceptedTime = &fresh
	newTurn.Spec.Wake = v1.WakeNone

	c := testClient(t, recreated, newTurn)
	s := &Server{Client: c}
	if err := s.prune(context.Background(), stale); err != nil {
		t.Fatalf("prune of a replaced incarnation: %v", err)
	}
	var turn v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "new-turn"}, &turn); err != nil {
		t.Errorf("stale prune deleted the new incarnation's turn: %v", err)
	}
	var thread v1.BlipThread
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if len(thread.Status.Tasks) != 1 || thread.Status.Tasks[0].ID != "newtask" {
		t.Errorf("stale prune overwrote the new board with %+v", thread.Status.Tasks)
	}
}
