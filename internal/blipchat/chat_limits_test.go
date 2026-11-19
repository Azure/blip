package blipchat

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestChatMessageAndHistoryLimits(t *testing.T) {
	history := func(n int) []chatMessage {
		out := make([]chatMessage, n)
		for i := range out {
			out[i] = chatMessage{Role: "user", Content: "x"}
		}
		return out
	}
	longHistory := []chatMessage{
		{Role: "user", Content: strings.Repeat("x", 8000)},
		{Role: "assistant", Content: strings.Repeat("x", 8000)},
		{Role: "user", Content: strings.Repeat("x", 8000)},
		{Role: "assistant", Content: strings.Repeat("x", 8000)},
		{Role: "user", Content: strings.Repeat("x", 1)},
	}
	tests := []struct {
		name    string
		request chatRequest
		ok      bool
	}{
		{name: "message at limit", request: chatRequest{Thread: "proj", Message: strings.Repeat("x", maxMessageRunes)}, ok: true},
		{name: "message over limit", request: chatRequest{Thread: "proj", Message: strings.Repeat("x", maxMessageRunes+1)}},
		{name: "history at limit", request: chatRequest{Thread: "proj", Message: "hi", History: history(maxHistoryMessages)}, ok: true},
		{name: "history count over limit", request: chatRequest{Thread: "proj", Message: "hi", History: history(maxHistoryMessages + 1)}},
		{name: "history bytes over limit", request: chatRequest{Thread: "proj", Message: "hi", History: longHistory}},
		{name: "history entry at limit", request: chatRequest{Thread: "proj", Message: "hi", History: []chatMessage{{Role: "user", Content: strings.Repeat("x", maxMessageRunes)}}}, ok: true},
		{name: "history entry over limit", request: chatRequest{Thread: "proj", Message: "hi", History: []chatMessage{{Role: "user", Content: strings.Repeat("x", maxMessageRunes+1)}}}},
		{name: "history entry over limit within total", request: chatRequest{Thread: "proj", Message: "hi", History: []chatMessage{
			{Role: "user", Content: strings.Repeat("x", maxMessageRunes)},
			{Role: "assistant", Content: strings.Repeat("x", maxMessageRunes)},
			{Role: "user", Content: strings.Repeat("x", maxMessageRunes+1)},
		}}},
		{name: "single history entry at total limit", request: chatRequest{Thread: "proj", Message: "hi", History: []chatMessage{{Role: "user", Content: strings.Repeat("x", maxHistoryRunes)}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			payload, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatal(err)
			}
			c := testClient(t, testThread())
			rec := chatRequestFor(t, c, upstream, "alice", "ns", string(payload))
			if tt.ok {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
				}
				if len(*requests) != 1 {
					t.Errorf("got %d model requests, want 1", len(*requests))
				}
				return
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if len(*requests) != 0 {
				t.Errorf("oversized request reached the model (%d requests)", len(*requests))
			}
		})
	}
}

// A history entry at the per-entry bound must reach the model whole; the
// handler rejects oversized entries instead of truncating them.
func TestChatHistoryEntryDeliveredWhole(t *testing.T) {
	entry := strings.Repeat("x", maxMessageRunes)
	payload, err := json.Marshal(chatRequest{
		Thread:  "proj",
		Message: "hi",
		History: []chatMessage{{Role: "user", Content: entry}},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "ns", string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 1 {
		t.Fatalf("got %d model requests, want 1", len(*requests))
	}
	messages, _ := (*requests)[0]["messages"].([]any)
	for _, m := range messages {
		msg, _ := m.(map[string]any)
		if msg["role"] == "user" && msg["content"] == entry {
			return
		}
	}
	t.Errorf("upstream did not receive the %d-rune history entry intact", maxMessageRunes)
}

// json.Decoder stops at the end of the first value, so a valid prefix must not
// let the rest of an oversized body through.
func TestChatRejectsBodyOverLimitAfterJSON(t *testing.T) {
	body := `{"thread":"proj","message":"hi"}` + "\n" + strings.Repeat("A", 2<<20)
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "ns", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 0 {
		t.Errorf("oversized body reached the model (%d requests)", len(*requests))
	}
}

func TestChatRejectsTrailingJSONValue(t *testing.T) {
	body := `{"thread":"proj","message":"hi"}{"thread":"proj","message":"again"}`
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "ns", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 0 {
		t.Errorf("trailing JSON value reached the model (%d requests)", len(*requests))
	}
}

func TestChatAllowsTrailingWhitespace(t *testing.T) {
	body := `{"thread":"proj","message":"hi"}` + "\n\t  "
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "ns", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 1 {
		t.Errorf("trailing whitespace produced %d model requests, want 1", len(*requests))
	}
}
