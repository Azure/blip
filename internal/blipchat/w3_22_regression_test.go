package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A prompt over budget must keep the newest turns (the actionable ones) and
// report exactly how many older turns it left out. ConsumedSeq must never
// advance past the last turn the prompt actually rendered.
func TestBoardPromptTruncatesOldestTurnsNotNewest(t *testing.T) {
	const count = 30
	fresh := metav1.NewTime(timeNow())
	objs := []client.Object{testThread()}
	for i := 1; i <= count; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 1900))
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
	if err := s.step(ctx, objs[0].(*v1.BlipThread)); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(objs[0]), &updated); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	prompt := requestPrompt(t, (*requests)[0])

	if !strings.Contains(prompt, "TURN30-MARKER") {
		t.Errorf("prompt omitted the newest turn:\n%s", prompt)
	}
	shown, highest := 0, int64(0)
	for i := 1; i <= count; i++ {
		if strings.Contains(prompt, fmt.Sprintf("TURN%02d-MARKER", i)) {
			shown++
			highest = int64(i)
		}
	}
	if shown == count {
		t.Fatalf("test did not exceed the prompt budget: all %d turns fit", count)
	}
	notice := regexp.MustCompile(`\((\d+) older turns omitted\)`).FindStringSubmatch(prompt)
	if notice == nil {
		t.Fatalf("prompt kept %d/%d turns without an accurate omission notice:\n%s", shown, count, prompt)
	}
	omitted, err := strconv.Atoi(notice[1])
	if err != nil {
		t.Fatal(err)
	}
	if want := count - shown; omitted != want {
		t.Errorf("omission notice says %d older turns omitted, want %d:\n%s", omitted, want, prompt)
	}
	if updated.Status.ConsumedSeq != highest {
		t.Errorf("consumedSeq = %d, want the highest rendered seq %d", updated.Status.ConsumedSeq, highest)
	}
	if updated.Status.ConsumedSeq > int64(count) {
		t.Errorf("consumedSeq = %d passed the newest pending turn %d", updated.Status.ConsumedSeq, count)
	}

	// The newest pending turn must still be able to step after the truncated
	// step consumed the rendered suffix.
	freshPtr := metav1.NewTime(timeNow())
	next := testTurn("turn-next", "proj")
	next.Status.Seq = count + 1
	next.Status.AcceptedTime = &freshPtr
	next.Spec.Wake = v1.WakeNone
	next.Spec.Text = "TURN31-MARKER"
	if err := c.Create(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := s.step(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(objs[0]), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != count+1 {
		t.Errorf("second step consumedSeq = %d, want %d", updated.Status.ConsumedSeq, count+1)
	}
	last := requestPrompt(t, (*requests)[len(*requests)-1])
	if !strings.Contains(last, "TURN31-MARKER") {
		t.Errorf("second step prompt omitted the newest turn:\n%s", last)
	}
}

// Crossing the daily budget after a completion was paid for must still run
// that completion's tool calls, including reply, and consume only input that
// was shown to the model.
func TestMidStepBudgetExhaustionRunsPaidToolCalls(t *testing.T) {
	now := timeNow()
	thread := testThread()
	thread.Spec.DailyTokens = 100
	thread.Status.TokenDay = now.UTC().Format("2006-01-02")
	thread.Status.TokensToday = 99
	turn := testTurn("one", "proj")
	turn.Status.Seq = 1
	turn.Status.AcceptedTime = &metav1.Time{Time: now.Add(-time.Minute)}
	thread.Status.Timers = []v1.ThreadTimer{{
		ID: "t1", At: metav1.NewTime(now.Add(-time.Hour)), Note: "timer-note",
	}}
	c := testClient(t, thread, turn)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", ToolCalls: []ToolCall{
		toolCall("reply", `{"inReplyTo":1,"text":"the answer"}`),
	}})
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
	if updated.Status.ConsumedSeq != 1 {
		t.Errorf("consumedSeq = %d, want the turn whose completion was paid for", updated.Status.ConsumedSeq)
	}
	if updated.Status.Paused == nil || updated.Status.Paused.Reason != budgetPauseReason {
		t.Errorf("paused = %+v, want the budget pause", updated.Status.Paused)
	}
	if updated.Status.TokensToday != 114 {
		t.Errorf("tokensToday = %d, want 99+15", updated.Status.TokensToday)
	}
	if len(*requests) != 1 {
		t.Errorf("made %d LLM requests, want only the completion already paid for", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if !strings.Contains(prompt, "please fix it") || !strings.Contains(prompt, "timer-note") {
		t.Errorf("step did not show the pending turn and due timer:\n%s", prompt)
	}
	var turns v1.BlipTurnList
	if err := c.List(ctx, &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range turns.Items {
		turn := &turns.Items[i]
		if turn.Spec.Author.Kind == v1.TurnAuthorCoordinator && turn.Spec.InReplyTo == 1 && turn.Spec.Text == "the answer" {
			found = true
		}
	}
	if !found {
		t.Errorf("paid completion's reply tool call was not delivered: %+v", turns.Items)
	}
}

// The daily budget day boundary is UTC, not the process local zone. Commit
// must also stamp tokenDay with the UTC date.
func TestDailyBudgetDayBoundaryUsesUTC(t *testing.T) {
	orig := timeNow
	defer func() { timeNow = orig }()
	zone := time.FixedZone("UTC+11", 11*60*60)

	t.Run("pause survives until UTC midnight", func(t *testing.T) {
		timeNow = func() time.Time { return time.Date(2026, 11, 19, 23, 30, 0, 0, time.UTC).In(zone) }
		thread := testThread()
		thread.Status.Paused = &v1.ThreadPause{Reason: budgetPauseReason}
		thread.Status.TokenDay = "2026-11-19"
		thread.Status.TokensToday = 100
		c := testClient(t, thread)
		s := &Server{Client: c}
		s.maybeUnpause(context.Background(), thread)
		var updated v1.BlipThread
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.Paused == nil {
			t.Error("maybeUnpause cleared the budget pause before the UTC day ended")
		}
		if updated.Status.TokenDay != "2026-11-19" || updated.Status.TokensToday != 100 {
			t.Errorf("status after pre-UTC-midnight unpause check = day %q tokens %d, want unchanged", updated.Status.TokenDay, updated.Status.TokensToday)
		}
	})

	t.Run("pause clears after UTC midnight", func(t *testing.T) {
		timeNow = func() time.Time { return time.Date(2026, 11, 20, 0, 30, 0, 0, time.UTC).In(zone) }
		thread := testThread()
		thread.Status.Paused = &v1.ThreadPause{Reason: budgetPauseReason}
		thread.Status.TokenDay = "2026-11-19"
		thread.Status.TokensToday = 100
		c := testClient(t, thread)
		s := &Server{Client: c}
		s.maybeUnpause(context.Background(), thread)
		var updated v1.BlipThread
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.Paused != nil {
			t.Errorf("maybeUnpause kept the pause after UTC midnight: %+v", updated.Status.Paused)
		}
		if updated.Status.TokenDay != "2026-11-20" || updated.Status.TokensToday != 0 {
			t.Errorf("status after UTC reset = day %q tokens %d, want 2026-11-20/0", updated.Status.TokenDay, updated.Status.TokensToday)
		}
	})

	t.Run("commit stamps the UTC date", func(t *testing.T) {
		timeNow = func() time.Time { return time.Date(2026, 11, 19, 23, 30, 0, 0, time.UTC).In(zone) }
		thread := testThread()
		thread.Spec.DailyTokens = 1000
		thread.Status.TokenDay = "2026-11-18"
		thread.Status.TokensToday = 50
		turn := testTurn("one", "proj")
		turn.Status.Seq = 1
		turn.Status.AcceptedTime = &metav1.Time{Time: timeNow().Add(-time.Minute)}
		c := testClient(t, thread, turn)
		server := llmServer(t, Message{Role: "assistant", Content: "ok"})
		s := &Server{
			Client: c,
			Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
			LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
		}
		if err := s.step(context.Background(), thread); err != nil {
			t.Fatal(err)
		}
		var updated v1.BlipThread
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.TokenDay != "2026-11-19" {
			t.Errorf("tokenDay = %q, want the UTC date 2026-11-19 (local is 2026-11-20)", updated.Status.TokenDay)
		}
		if updated.Status.TokensToday != 15 {
			t.Errorf("tokensToday = %d, want 15 from this step", updated.Status.TokensToday)
		}
	})
}

// Tokens spent on completions that later fail must still be charged, so
// retries cannot bypass the daily cap.
func TestFailedStepChargesSpentTokens(t *testing.T) {
	thread := testThread()
	thread.Spec.DailyTokens = 1000
	turn := testTurn("one", "proj")
	turn.Status.Seq = 1
	turn.Status.AcceptedTime = &metav1.Time{Time: timeNow().Add(-time.Minute)}
	c := testClient(t, thread, turn)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests%2 == 0 {
			http.Error(w, "upstream failed", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": Message{
				Role:      "assistant",
				ToolCalls: []ToolCall{toolCall("note", `{"text":"paid"}`)},
			}}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer server.Close()
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	for step := 1; step <= 3; step++ {
		var current v1.BlipThread
		if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &current); err != nil {
			t.Fatal(err)
		}
		if err := s.step(ctx, &current); err == nil {
			t.Fatalf("step %d succeeded, want the upstream error", step)
		}
		var updated v1.BlipThread
		if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
			t.Fatal(err)
		}
		if want := int64(step * 15); updated.Status.TokensToday != want {
			t.Errorf("after failed step %d tokensToday = %d, want %d", step, updated.Status.TokensToday, want)
		}
		if updated.Status.TokenDay != timeNow().UTC().Format("2006-01-02") {
			t.Errorf("after failed step %d tokenDay = %q, want today UTC", step, updated.Status.TokenDay)
		}
	}
}

// requestPrompt returns the user message content from a recorded request.
func requestPrompt(t *testing.T, request map[string]any) string {
	t.Helper()
	messages, ok := request["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("request messages = %#v", request["messages"])
	}
	user, ok := messages[1].(map[string]any)
	if !ok {
		t.Fatalf("user message = %#v", messages[1])
	}
	content, _ := user["content"].(string)
	return content
}
