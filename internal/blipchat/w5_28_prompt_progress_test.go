package blipchat

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A step whose wake turn lies beyond the rendered prefix must still make
// progress: the over-budget context before it is summarized so the contiguous
// prefix through the wake turn can be consumed. It must never move
// consumedSeq backwards.
func TestOverBudgetWakeDoesNotRewindConsumedSeq(t *testing.T) {
	now := timeNow()
	fresh := metav1.NewTime(now)
	thread := testThread()
	thread.Status.ConsumedSeq = 100
	objs := []client.Object{thread}
	for i := 101; i <= 200; i++ {
		turn := testTurn(fmt.Sprintf("turn-%03d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%03d-MARKER %s", i, strings.Repeat("x", 1900))
		if i == 151 {
			turn.Spec.Wake = v1.WakeNow
		}
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("made %d LLM requests, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if !strings.Contains(prompt, "TURN151-MARKER") {
		t.Errorf("the wake turn is missing from the prompt:\n%s", prompt)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != 151 {
		t.Errorf("consumedSeq = %d, want the rendered prefix through the wake turn 151", updated.Status.ConsumedSeq)
	}
	if updated.Status.ConsumedSeq < 100 {
		t.Errorf("consumedSeq rewound below the old value 100: %d", updated.Status.ConsumedSeq)
	}
	pending, err := s.pendingTurns(ctx, &updated)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 49 || pending[0].Status.Seq != 152 {
		t.Errorf("pending = %d turns, want 49 starting at 152", len(pending))
	}
	if s.shouldStep(ctx, &updated) {
		t.Error("thread still wants to step after consuming the wake turn")
	}
}

// The ordinary shape of a chat-propose/report backlog has a Wake=None turn
// followed by Wake=Batch turns. It must advance too, not stall on the gap.
func TestOverBudgetBatchBacklogAdvances(t *testing.T) {
	fresh := metav1.NewTime(timeNow())
	thread := testThread()
	objs := []client.Object{thread}
	for i := 1; i <= 100; i++ {
		turn := testTurn(fmt.Sprintf("turn-%03d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Text = fmt.Sprintf("TURN%03d-MARKER %s", i, strings.Repeat("x", 1900))
		if i == 1 {
			turn.Spec.Wake = v1.WakeNone
		}
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("the backlog step made no LLM request")
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq < 1 {
		t.Fatalf("consumedSeq = %d, want the backlog to advance", updated.Status.ConsumedSeq)
	}
	if err := s.step(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != 100 {
		t.Errorf("consumedSeq = %d, want the whole backlog consumed after two steps", updated.Status.ConsumedSeq)
	}
	if s.shouldStep(ctx, &updated) {
		t.Error("thread still wants to step after consuming the backlog")
	}
}

// When even compact summaries cannot show the oldest pending turn, the step
// must not call the model with an identical prompt every tick. It defers on a
// bounded backoff and keeps the turns pending.
func TestUnrenderableBacklogDefersWithoutLLM(t *testing.T) {
	now := timeNow()
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }
	fresh := metav1.NewTime(now)
	thread := testThread()
	thread.Status.Timers = []v1.ThreadTimer{{
		ID: "t1", At: metav1.NewTime(now.Add(-time.Hour)), Note: "retry deploy",
	}}
	objs := []client.Object{thread}
	for i := 1; i <= 2600; i++ {
		turn := testTurn(fmt.Sprintf("turn-%04d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", i, strings.Repeat("x", 200))
		if i == 2000 {
			turn.Spec.Wake = v1.WakeNow
		}
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 0 {
		t.Fatalf("made %d LLM requests for an unrenderable prompt, want none", len(*requests))
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != 0 {
		t.Errorf("consumedSeq = %d, want 0 when nothing was rendered", updated.Status.ConsumedSeq)
	}
	if updated.Status.NextWake == nil || !updated.Status.NextWake.After(now) {
		t.Errorf("nextWake = %v, want a deferred wake after now", updated.Status.NextWake)
	}
	if len(updated.Status.Timers) != 1 {
		t.Errorf("timers = %+v, want the unprocessed due timer kept", updated.Status.Timers)
	}
	if s.shouldStep(ctx, &updated) {
		t.Error("thread immediately wants to step again after making no progress")
	}
	// After the bounded backoff the thread may try again instead of stalling
	// forever.
	timeNow = func() time.Time { return now.Add(stalledPromptBackoff + time.Second) }
	if !s.shouldStep(ctx, &updated) {
		t.Error("deferred thread did not wake after the backoff")
	}
}

// A maximal, legal task board alone used to be ~935 KB, pushing the turn
// budget negative. The board must be bounded and disclose its truncation
// while keeping the newest tasks and the turns section.
func TestBoardPromptBoundsMaximalBoard(t *testing.T) {
	tasks := make([]v1.ThreadTask, 0, 200)
	for i := 1; i <= 200; i++ {
		attrs := make(map[string]string, 16)
		for a := 0; a < 16; a++ {
			attrs[fmt.Sprintf("attr%02d", a)] = strings.Repeat(string(rune('a'+a)), 256)
		}
		tasks = append(tasks, v1.ThreadTask{
			ID:         fmt.Sprintf("t%03d", i),
			Title:      fmt.Sprintf("TASK%03d %s", i, strings.Repeat("title", 20)),
			Open:       i%2 == 0,
			Attributes: attrs,
			Note:       strings.Repeat("note", 64),
		})
	}
	thread := testThread()
	turn := testTurn("turn-1", "proj")
	turn.Status.Seq = 1
	turn.Spec.Text = "please look at the board"
	prompt, last := boardPrompt(thread, tasks, []v1.BlipTurn{*turn}, nil, "")
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if last != 1 {
		t.Errorf("last rendered seq = %d, want the turn", last)
	}
	if !strings.Contains(prompt, "TASK200") {
		t.Errorf("prompt omitted the newest task:\n%s", prompt)
	}
	if strings.Contains(prompt, "TASK001") {
		t.Errorf("prompt kept the oldest task instead of bounding the board:\n%s", prompt)
	}
	if !strings.Contains(prompt, "older tasks omitted") && !strings.Contains(prompt, "task board compacted") {
		t.Errorf("prompt did not disclose the truncation:\n%s", prompt)
	}
	if !strings.Contains(prompt, "please look at the board") {
		t.Errorf("board crowding removed the turns section:\n%s", prompt)
	}
}
