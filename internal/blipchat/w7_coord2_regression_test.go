package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A CRD-legal turn may have 2048 code points, which is ~8 KiB as UTF-8. Its
// whole text must reach the prompt: a 2048-byte line cap used to drop the tail
// (often the actionable request) while still marking the turn consumed.
func TestPromptKeepsLegalWideRuneTurn(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 1, 1)
	turn := objs[1].(*v1.BlipTurn)
	const head = "HEAD-REQUEST: deploy the fix."
	const tail = "TAIL-REQUEST: do not deploy."
	fill := 2039 - utf8.RuneCountInString(head) - utf8.RuneCountInString(tail) - 2
	turn.Spec.Text = head + " " + strings.Repeat("\U0001F600", fill) + " " + tail
	if got := utf8.RuneCountInString(turn.Spec.Text); got != 2039 {
		t.Fatalf("test turn has %d runes, want 2039", got)
	}
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)
	ctx := context.Background()

	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	t.Logf("turn bytes=%d prompt bytes=%d budget=%d", len(turn.Spec.Text), len(prompt), promptBudget)
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	for _, want := range []string{head, tail} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lost legal turn content %q", want)
		}
	}
	if strings.Contains(prompt, "turn truncated") {
		t.Errorf("prompt claimed to truncate a legal turn:\n%.500s", prompt)
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if live.Status.ConsumedSeq != 1 {
		t.Errorf("consumedSeq = %d, want 1", live.Status.ConsumedSeq)
	}
}

// When even the compact board does not fit, every open task must still reach
// the prompt: the coordinator has no other board listing tool.
func TestBoardPromptShowsAllOpenTasks(t *testing.T) {
	thread := testThread()
	addMaxBoard(thread)
	turn := testTurn("turn-1", "proj")
	turn.Status.Seq = 1
	turn.Spec.Text = "please look at the board"
	prompt, last := boardPrompt(thread, thread.Status.Tasks, []v1.BlipTurn{*turn}, nil, "")
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if last != 1 {
		t.Errorf("last rendered seq = %d, want the turn", last)
	}
	for i := 1; i <= 200; i++ {
		id := fmt.Sprintf("t%03d", i)
		if !strings.Contains(prompt, "- "+id+" open") {
			t.Fatalf("prompt omitted open task %s", id)
		}
	}
	if !strings.Contains(prompt, "task board compacted") {
		t.Error("prompt did not disclose the compacted board")
	}
	if !strings.Contains(prompt, "please look at the board") {
		t.Error("board crowding removed the turns section")
	}
}

// task_create and task_update share the CRD's 16-attribute cap. Neither may
// silently drop an attribute: create must reject an oversized map just like
// update does.
func TestTaskAttributeCapIsEnforcedOnCreateAndUpdate(t *testing.T) {
	st := &step{}
	attrs := map[string]string{}
	for i := 0; i < 17; i++ {
		attrs[fmt.Sprintf("k%02d", i)] = "v"
	}
	create, err := json.Marshal(map[string]any{"id": "t1", "title": "task", "attributes": attrs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_create", string(create)); err == nil || !strings.Contains(err.Error(), "maximum is 16") {
		t.Fatalf("task_create with 17 attributes = %v, want a maximum-is-16 error", err)
	}
	if len(st.tasks) != 0 {
		t.Fatalf("rejected task_create stored %d tasks", len(st.tasks))
	}

	delete(attrs, "k16")
	create, err = json.Marshal(map[string]any{"id": "t1", "title": "task", "attributes": attrs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_create", string(create)); err != nil {
		t.Fatalf("task_create with 16 attributes: %v", err)
	}
	if got := len(st.tasks[0].Attributes); got != 16 {
		t.Fatalf("stored attributes = %d, want 16", got)
	}

	update, err := json.Marshal(map[string]any{
		"id":         "t1",
		"attributes": map[string]string{"extra": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_update", string(update)); err == nil || !strings.Contains(err.Error(), "maximum is 16") {
		t.Fatalf("task_update to 17 attributes = %v, want a maximum-is-16 error", err)
	}
	if got := len(st.tasks[0].Attributes); got != 16 {
		t.Errorf("attributes after rejected update = %d, want 16", got)
	}
}

// When a turn is oversized through fields other than text, clipping must be
// disclosed rather than presented as the whole turn.
func TestPromptDisclosesClippedTurn(t *testing.T) {
	thread, objs := promptBudgetBacklog(t, 1, 1)
	turn := objs[1].(*v1.BlipTurn)
	turn.Spec.Text = strings.Repeat("\U0001F600", 2048)
	turn.Spec.Attributes = map[string]string{}
	for i := 0; i < 16; i++ {
		turn.Spec.Attributes[string(rune('a'+i))] = strings.Repeat("\U0001F600", 256)
	}
	objs[0] = thread
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := newPromptBudgetServer(c, server)

	if err := s.step(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("LLM requests = %d, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "turn truncated") {
		t.Error("prompt clipped a turn without disclosing it")
	}
}
