package blipchat

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChatMethodNotAllowedSetsAllow(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Chat{Server: &Server{}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/chat", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow = %q, want POST", got)
	}
}

func TestHealthAndReadyEndpoints(t *testing.T) {
	h := (&httpRunnable{s: &Server{}}).handler()
	for _, tt := range []struct {
		path   string
		method string
		code   int
		allow  string
	}{
		{path: "/healthz", method: http.MethodGet, code: http.StatusOK},
		{path: "/healthz", method: http.MethodHead, code: http.StatusOK},
		{path: "/healthz", method: http.MethodPost, code: http.StatusMethodNotAllowed, allow: "GET, HEAD"},
		{path: "/readyz", method: http.MethodGet, code: http.StatusOK},
		{path: "/readyz", method: http.MethodPost, code: http.StatusMethodNotAllowed, allow: "GET, HEAD"},
	} {
		t.Run(tt.path+" "+tt.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
			if got := rec.Header().Get("Allow"); got != tt.allow {
				t.Errorf("Allow = %q, want %q", got, tt.allow)
			}
		})
	}
}
