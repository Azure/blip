package blipchat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatDoesNotReflectUpstreamError(t *testing.T) {
	const secret = "SECRET-INTERNAL-DETAIL"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key","upstream":"llm-proxy.corp.internal","echo":"` + secret + `"}`))
	}))
	defer upstream.Close()
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "ns", `{"thread":"proj","message":"hi"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{secret, upstream.URL, "llm-proxy", "tenant", "bad key"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "chat backend unavailable") {
		t.Errorf("response = %q, want a generic backend error", body)
	}
}
