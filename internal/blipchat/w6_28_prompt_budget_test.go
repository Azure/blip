package blipchat

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func promptBudgetBacklog(t *testing.T, count, wakeAt int) (*v1.BlipThread, []client.Object) {
	t.Helper()
	now := timeNow()
	fresh := metav1.NewTime(now.Add(-time.Minute))
	thread := testThread()
	thread.Spec.DailyTokens = 0
	objs := []client.Object{thread}
	for i := 1; i <= count; i++ {
		turn := testTurn(fmt.Sprintf("turn-%04d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", i, strings.Repeat("x", 1900))
		if i == wakeAt {
			turn.Spec.Wake = v1.WakeNow
		}
		objs = append(objs, turn)
	}
	return thread, objs
}

func newPromptBudgetServer(c client.Client, server *httptest.Server) *Server {
	return &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
}

// A legal 16 384-rune summary can be 64 KiB as UTF-8. It must not push the
// fixed prompt over the budget and force the turn renderer onto an
// unsummarizable path: the summary is truncated with a notice, and the waking
// turn is still shown and consumed.
func TestPromptBudgetTruncatesMaxSummary(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 60, 30)
	const marker = "SUMMARY-MARKER "
	thread.Status.Summary = marker + strings.Repeat("\U0001F600", 16384-len(marker))
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)
	ctx := context.Background()

	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1: an oversized summary deferred the step", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	t.Logf("summary bytes=%d prompt=%d budget=%d", len(thread.Status.Summary), len(prompt), promptBudget)
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, marker) {
		t.Error("prompt dropped the summary's leading content")
	}
	if !strings.Contains(prompt, "summary truncated to fit the prompt budget") {
		t.Error("prompt did not disclose the summary truncation")
	}
	if !strings.Contains(prompt, "TURN0030-MARKER") {
		t.Error("prompt dropped the waking turn")
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if live.Status.ConsumedSeq < 30 {
		t.Errorf("consumedSeq = %d, want the waking turn 30 consumed", live.Status.ConsumedSeq)
	}
}

// 32 legal timer notes have no length limit at all. They must be included
// under their own budget, with a notice when notes are clipped, rather than
// crowding the whole prompt past promptBudget. The waking turn stays visible.
func TestPromptBudgetTruncatesLongTimerNotes(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 40, 20)
	now := timeNow()
	for i := 0; i < 32; i++ {
		thread.Status.Timers = append(thread.Status.Timers, v1.ThreadTimer{
			ID:   fmt.Sprintf("t%d", i),
			At:   metav1.NewTime(now.Add(-time.Minute)),
			Note: fmt.Sprintf("TIMER%02d-MARKER %s", i, strings.Repeat("t", 4096)),
		})
	}
	addMaxBoard(thread)
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)
	ctx := context.Background()

	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1: oversized timer notes deferred the step", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	t.Logf("timer notes=%d prompt=%d budget=%d", len(thread.Status.Timers), len(prompt), promptBudget)
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "Timers that fired:") {
		t.Error("prompt dropped the fired timers")
	}
	if !strings.Contains(prompt, "timer notes truncated to fit the prompt budget") {
		t.Error("prompt did not disclose the timer note truncation")
	}
	for i := 0; i < 32; i++ {
		if !strings.Contains(prompt, fmt.Sprintf("TIMER%02d-MARKER", i)) {
			t.Errorf("prompt dropped timer note %d", i)
		}
	}
	if !strings.Contains(prompt, "TURN0020-MARKER") {
		t.Error("prompt dropped the waking turn")
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if len(live.Status.Timers) != 0 {
		t.Errorf("timers = %d, want all due timers consumed by the step", len(live.Status.Timers))
	}
	if live.Status.ConsumedSeq < 20 {
		t.Errorf("consumedSeq = %d, want the waking turn 20 consumed", live.Status.ConsumedSeq)
	}
}

// The fixed sections can all be at their legal maxima at once. The combined
// prompt still has to stay bounded and keep the waking turn.
func TestPromptBudgetTruncatesMaxSummaryAndTimersTogether(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 40, 20)
	const marker = "SUMMARY-MARKER "
	thread.Status.Summary = marker + strings.Repeat("\U0001F600", 16384-len(marker))
	now := timeNow()
	for i := 0; i < 32; i++ {
		thread.Status.Timers = append(thread.Status.Timers, v1.ThreadTimer{
			ID:   fmt.Sprintf("t%d", i),
			At:   metav1.NewTime(now.Add(-time.Minute)),
			Note: fmt.Sprintf("TIMER%02d-MARKER %s", i, strings.Repeat("t", 4096)),
		})
	}
	addMaxBoard(thread)
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)
	ctx := context.Background()

	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1: maximal fixed sections deferred the step", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	t.Logf("summary+timer notes prompt=%d budget=%d", len(prompt), promptBudget)
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, marker) || !strings.Contains(prompt, "summary truncated") {
		t.Error("prompt did not include and disclose the clipped summary")
	}
	if !strings.Contains(prompt, "timer notes truncated") {
		t.Error("prompt did not disclose the clipped timer notes")
	}
	if !strings.Contains(prompt, "TURN0020-MARKER") {
		t.Error("prompt dropped the waking turn")
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if live.Status.ConsumedSeq < 20 {
		t.Errorf("consumedSeq = %d, want the waking turn 20 consumed", live.Status.ConsumedSeq)
	}
}

// A turn line can be up to 2048 runes, which is 8 KiB for four-byte runes.
// Combined with maximal fixed sections, the renderer's forced newest line must
// still leave the whole prompt inside the budget.
func TestPromptBudgetBoundsWideRuneTurnsWithMaxFixedSections(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 40, 20)
	for _, obj := range objs[1:] {
		turn := obj.(*v1.BlipTurn)
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", turn.Status.Seq, strings.Repeat("\U0001F600", 1900))
	}
	const marker = "SUMMARY-MARKER "
	thread.Status.Summary = marker + strings.Repeat("\U0001F600", 16384-len(marker))
	now := timeNow()
	for i := 0; i < 32; i++ {
		thread.Status.Timers = append(thread.Status.Timers, v1.ThreadTimer{
			ID:   fmt.Sprintf("t%d", i),
			At:   metav1.NewTime(now.Add(-time.Minute)),
			Note: fmt.Sprintf("TIMER%02d-MARKER %s", i, strings.Repeat("t", 4096)),
		})
	}
	addMaxBoard(thread)
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)
	ctx := context.Background()

	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1: wide turn lines deferred the step", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	t.Logf("wide-rune turns prompt=%d budget=%d", len(prompt), promptBudget)
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "TURN0020-MARKER") {
		t.Error("prompt dropped the waking turn")
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if live.Status.ConsumedSeq < 20 {
		t.Errorf("consumedSeq = %d, want the waking turn 20 consumed", live.Status.ConsumedSeq)
	}
}

func addMaxBoard(thread *v1.BlipThread) {
	attrs := make(map[string]string, 16)
	for a := 0; a < 16; a++ {
		attrs[fmt.Sprintf("attr%02d", a)] = strings.Repeat(string(rune('a'+a)), 256)
	}
	for i := 1; i <= 200; i++ {
		thread.Status.Tasks = append(thread.Status.Tasks, v1.ThreadTask{
			ID: fmt.Sprintf("t%03d", i), Title: fmt.Sprintf("TASK%03d %s", i, strings.Repeat("title", 20)),
			Open: true, Attributes: attrs, Note: strings.Repeat("note", 64),
		})
	}
}
