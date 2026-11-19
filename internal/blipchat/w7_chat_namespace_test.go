package blipchat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A present namespace parameter must never be treated as absent. Only an
// omitted parameter defaults to "default"; an empty or malformed one is a
// client error, not a lookup in the default namespace.
func TestChatNamespaceParameterPresence(t *testing.T) {
	tests := []struct {
		name      string
		rawQuery  string
		namespace string // namespace of the thread the request should reach
		want      int
	}{
		{name: "absent defaults", rawQuery: "", namespace: "default", want: http.StatusOK},
		{name: "empty", rawQuery: "?namespace=", namespace: "default", want: http.StatusBadRequest},
		{name: "malformed escape", rawQuery: "?namespace=%zz", namespace: "default", want: http.StatusBadRequest},
		{name: "valid", rawQuery: "?namespace=ns", namespace: "ns", want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			thread := testThread()
			thread.Namespace = tt.namespace
			s := &Server{Client: testClient(t, thread), Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
			req := httptest.NewRequest(http.MethodPost, "/chat"+tt.rawQuery, strings.NewReader(`{"thread":"proj","message":"hi"}`))
			req.Header.Set("X-Forwarded-User", "alice")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			(&Chat{Server: s}).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusBadRequest {
				if !strings.Contains(rec.Body.String(), "invalid namespace") {
					t.Errorf("body = %q, want invalid namespace", rec.Body.String())
				}
				if len(*requests) != 0 {
					t.Errorf("invalid namespace reached the model (%d requests)", len(*requests))
				}
			}
		})
	}
}
