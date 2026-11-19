package blipchat

import (
	"context"
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
