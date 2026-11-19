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

// A step that cannot spend because the daily budget is already gone must not
// pretend it handled the pending turns or timers: both stay queued for the
// next day.
func TestBudgetExhaustedStepLeavesTurnsAndTimersPending(t *testing.T) {
	now := timeNow()
	thread := testThread()
	thread.Spec.DailyTokens = 100
	thread.Status.TokenDay = now.Format("2006-01-02")
	thread.Status.TokensToday = 100
	turn := testTurn("one", "proj")
	turn.Status.Seq = 1
	turn.Status.AcceptedTime = &metav1.Time{Time: now.Add(-time.Minute)}
	thread.Status.Timers = []v1.ThreadTimer{{
		ID: "t1", At: metav1.NewTime(now.Add(-time.Hour)), Note: "retry deploy",
	}}
	c := testClient(t, thread, turn)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
	}
	if err := s.step(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Paused == nil || updated.Status.Paused.Reason != "daily token budget exhausted" {
		t.Fatalf("paused = %+v, want budget pause", updated.Status.Paused)
	}
	if updated.Status.ConsumedSeq != 0 {
		t.Errorf("budget-exhausted step consumedSeq = %d, want 0", updated.Status.ConsumedSeq)
	}
	if len(updated.Status.Timers) != 1 || updated.Status.Timers[0].ID != "t1" {
		t.Errorf("budget-exhausted step lost the due timer: %+v", updated.Status.Timers)
	}
}

// Tokens spent yesterday must not count against today's budget, and a step
// today must not pause a thread that has only spent today's small amount.
func TestDailyTokenBudgetRollsOverAtDayBoundary(t *testing.T) {
	yesterday := timeNow().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	thread := testThread()
	thread.Spec.DailyTokens = 40
	thread.Status.TokenDay = yesterday
	thread.Status.TokensToday = 600
	server := llmServer(t,
		Message{Role: "assistant", Content: "ok"},
		Message{Role: "assistant", Content: "ok"},
	)
	c := testClient(t, thread)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	for step := 1; step <= 2; step++ {
		var current v1.BlipThread
		if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &current); err != nil {
			t.Fatal(err)
		}
		if err := s.step(ctx, &current); err != nil {
			t.Fatal(err)
		}
		var updated v1.BlipThread
		if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.TokenDay != timeNow().UTC().Format("2006-01-02") {
			t.Errorf("after step %d tokenDay = %q, want today", step, updated.Status.TokenDay)
		}
		if want := int64(step * 15); updated.Status.TokensToday != want {
			t.Errorf("after step %d tokensToday = %d, want %d", step, updated.Status.TokensToday, want)
		}
		if updated.Status.Paused != nil {
			t.Errorf("after step %d paused = %+v; today's spend is under the budget", step, updated.Status.Paused)
		}
	}
}

// The pending window must not hide an older Wake=Now turn from shouldStep, nor
// let a step consume turns it never showed to the coordinator.
func TestOlderWakeNowTurnStillStepsAndAppearsInPrompt(t *testing.T) {
	fresh := metav1.NewTime(timeNow())
	objs := []client.Object{}
	for i := 1; i <= 51; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Text = fmt.Sprintf("turn-%d", i)
		objs = append(objs, turn)
	}
	objs[0].(*v1.BlipTurn).Spec.Wake = v1.WakeNow
	thread := testThread()
	objs = append(objs, thread)
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if !s.shouldStep(ctx, thread) {
		t.Error("an older Wake=Now turn did not wake the thread")
	}
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != 51 {
		t.Errorf("consumedSeq = %d, want 51", updated.Status.ConsumedSeq)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	messages, ok := (*requests)[0]["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("request messages = %#v", (*requests)[0]["messages"])
	}
	user, ok := messages[1].(map[string]any)
	if !ok {
		t.Fatalf("user message = %#v", messages[1])
	}
	content, _ := user["content"].(string)
	if !strings.Contains(content, "#1 ") || !strings.Contains(content, "turn-1") {
		t.Errorf("prompt dropped the oldest turn (Wake=Now):\n%s", content)
	}
}

// Retention advances the API, so a step later in the same tick must see the
// pruned board and must not write the old tasks back.
func TestPrunedTasksStayPrunedAfterSameTickStep(t *testing.T) {
	old := metav1.NewTime(timeNow().Add(-100 * time.Hour))
	fresh := metav1.NewTime(timeNow())
	thread := testThread()
	thread.Spec.Retention.ClosedTasks = &metav1.Duration{Duration: time.Hour}
	thread.Status.Tasks = []v1.ThreadTask{
		{ID: "old", Title: "old closed task", Open: false, Updated: &old},
		{ID: "live", Title: "live open task", Open: true, Updated: &fresh},
	}
	c := testClient(t, thread)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.prune(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Status.Tasks) != 1 || updated.Status.Tasks[0].ID != "live" {
		t.Errorf("tasks after prune+step = %+v, want only the live task", updated.Status.Tasks)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	messages, ok := (*requests)[0]["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("request messages = %#v", (*requests)[0]["messages"])
	}
	user, ok := messages[1].(map[string]any)
	if !ok {
		t.Fatalf("user message = %#v", messages[1])
	}
	content, _ := user["content"].(string)
	if strings.Contains(content, "old closed task") {
		t.Errorf("step prompt still showed the pruned task:\n%s", content)
	}
}

// set_timer with an already-past time must not strand the timer: it wakes the
// thread on the next tick, and that step delivers the note.
func TestPastTimerWakesImmediatelyAndDeliversNote(t *testing.T) {
	thread := testThread()
	server, requests := llmServerWithRequests(t,
		Message{Role: "assistant", ToolCalls: []ToolCall{
			toolCall("set_timer", fmt.Sprintf(`{"at":%q,"note":"retry deploy"}`, timeNow().Add(-time.Hour).Format(time.RFC3339))),
		}},
		Message{Role: "assistant", Content: "timer set"},
		Message{Role: "assistant", Content: "noted"},
	)
	c := testClient(t, thread)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Status.Timers) != 1 {
		t.Fatalf("timers after set_timer = %+v, want the past timer retained", updated.Status.Timers)
	}
	if updated.Status.NextWake == nil {
		t.Fatalf("past timer stored but nextWake is nil")
	}
	if updated.Status.NextWake.After(timeNow()) {
		t.Errorf("nextWake = %s, want now or earlier", updated.Status.NextWake)
	}
	if !s.shouldStep(ctx, &updated) {
		t.Fatal("a due timer did not make the thread step")
	}
	if err := s.step(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Status.Timers) != 0 {
		t.Errorf("timers after the wake step = %+v, want none", updated.Status.Timers)
	}
	if len(*requests) < 2 {
		t.Fatalf("got %d LLM requests, want at least 2", len(*requests))
	}
	last := (*requests)[len(*requests)-1]
	messages, ok := last["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("second step request messages = %#v", last["messages"])
	}
	user, ok := messages[1].(map[string]any)
	if !ok {
		t.Fatalf("user message = %#v", messages[1])
	}
	content, _ := user["content"].(string)
	if !strings.Contains(content, "retry deploy") {
		t.Errorf("due timer note was not delivered:\n%s", content)
	}
}

// Only the automatic budget pause is cleared at a day boundary. A pause set by
// an operator stays in effect with its token counter untouched.
func TestMaybeUnpauseOnlyClearsBudgetPause(t *testing.T) {
	yesterday := timeNow().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	tests := []struct {
		name       string
		reason     string
		wantPaused bool
		wantTokens int64
	}{
		{name: "budget pause", reason: budgetPauseReason, wantPaused: false, wantTokens: 0},
		{name: "manual pause", reason: "operator hold", wantPaused: true, wantTokens: 42},
		{name: "empty reason", reason: "", wantPaused: true, wantTokens: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thread := testThread()
			thread.Status.Paused = &v1.ThreadPause{Reason: tt.reason}
			thread.Status.TokenDay = yesterday
			thread.Status.TokensToday = 42
			c := testClient(t, thread)
			s := &Server{Client: c}
			s.maybeUnpause(context.Background(), thread)
			var updated v1.BlipThread
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
				t.Fatal(err)
			}
			if got := updated.Status.Paused != nil; got != tt.wantPaused {
				t.Errorf("paused = %+v, want paused=%v", updated.Status.Paused, tt.wantPaused)
			}
			if updated.Status.TokensToday != tt.wantTokens {
				t.Errorf("tokensToday = %d, want %d", updated.Status.TokensToday, tt.wantTokens)
			}
			if tt.wantPaused && updated.Status.TokenDay != yesterday {
				t.Errorf("tokenDay = %q, want unchanged %q", updated.Status.TokenDay, yesterday)
			}
		})
	}
}
