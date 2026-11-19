package blipchat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatRejectsDuplicateForwardedUser(t *testing.T) {
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
	req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(`{"thread":"proj","message":"hi"}`))
	req.Header.Add("X-Forwarded-User", "attacker")
	req.Header.Add("X-Forwarded-User", "realuser")
	rec := httptest.NewRecorder()
	(&Chat{Server: s}).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 0 {
		t.Errorf("duplicate identity still reached the model (%d requests)", len(*requests))
	}
	if turns := chatTurns(t, c); len(turns) != 0 {
		t.Errorf("duplicate identity created %d turns", len(turns))
	}
}

// A proxy may join repeated header values with commas into one line. That is
// still multiple identities and must not be trusted as one user.
func TestChatRejectsCommaJoinedForwardedUser(t *testing.T) {
	for _, value := range []string{
		"attacker, alice",
		"attacker,alice",
		"attacker , alice",
		"attacker,\talice",
		",alice",
		"alice,",
	} {
		t.Run(value, func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			c := testClient(t, testThread())
			s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
			req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(`{"thread":"proj","message":"hi"}`))
			req.Header.Set("X-Forwarded-User", value)
			rec := httptest.NewRecorder()
			(&Chat{Server: s}).ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if len(*requests) != 0 {
				t.Errorf("multi-identity value reached the model (%d requests)", len(*requests))
			}
			if turns := chatTurns(t, c); len(turns) != 0 {
				t.Errorf("multi-identity value created %d turns", len(turns))
			}
		})
	}
}
