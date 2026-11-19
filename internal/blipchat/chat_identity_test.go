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

// TurnAuthor.Name is limited to 253 characters. Reject an identity the turn
// could never be authored by at the HTTP boundary instead of failing later.
func TestChatValidatesForwardedUserLength(t *testing.T) {
	tests := []struct {
		name string
		user string
		want int
	}{
		{name: "at limit", user: strings.Repeat("a", 253), want: http.StatusOK},
		{name: "over ascii limit", user: strings.Repeat("a", 254), want: http.StatusBadRequest},
		{name: "over multi-byte limit", user: strings.Repeat("é", 254), want: http.StatusBadRequest},
		{name: "far over limit", user: strings.Repeat("a", 300), want: http.StatusBadRequest},
		{name: "invalid utf-8", user: "\xff", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			c := testClient(t, testThread())
			s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
			req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(`{"thread":"proj","message":"hi"}`))
			req.Header["X-Forwarded-User"] = []string{tt.user}
			rec := httptest.NewRecorder()
			(&Chat{Server: s}).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusBadRequest {
				if len(*requests) != 0 {
					t.Errorf("invalid identity reached the model (%d requests)", len(*requests))
				}
				if turns := chatTurns(t, c); len(turns) != 0 {
					t.Errorf("invalid identity created %d turns", len(turns))
				}
			}
		})
	}
}
