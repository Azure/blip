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
