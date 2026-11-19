package blipchat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /chat parses JSON, so it must require the JSON media type. A form or
// text/plain body is a browser "simple" request that is not preflighted; not
// parsing it keeps a hostile page from driving the model through the victim's
// browser.
func TestChatRequiresJSONContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        int
	}{
		{name: "json", contentType: "application/json", want: http.StatusOK},
		{name: "json with charset", contentType: "application/json; charset=utf-8", want: http.StatusOK},
		{name: "missing", contentType: "", want: http.StatusUnsupportedMediaType},
		{name: "cross-site text", contentType: "text/plain;charset=UTF-8", want: http.StatusUnsupportedMediaType},
		{name: "cross-site form", contentType: "application/x-www-form-urlencoded", want: http.StatusUnsupportedMediaType},
		{name: "other json type", contentType: "application/json-patch+json", want: http.StatusUnsupportedMediaType},
		{name: "invalid", contentType: "not a media type", want: http.StatusUnsupportedMediaType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			c := testClient(t, testThread())
			s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
			req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(`{"thread":"proj","message":"hi"}`))
			req.Header.Set("X-Forwarded-User", "alice")
			req.Header.Set("Origin", "https://evil.example")
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			(&Chat{Server: s}).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want != http.StatusOK {
				if len(*requests) != 0 {
					t.Errorf("non-JSON request reached the model (%d requests)", len(*requests))
				}
				if turns := chatTurns(t, c); len(turns) != 0 {
					t.Errorf("non-JSON request created turns %v", names(turns))
				}
			}
		})
	}
}
