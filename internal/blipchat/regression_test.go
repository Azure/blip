package blipchat

import (
	"context"
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
