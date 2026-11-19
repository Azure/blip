package blipchat

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
func (r errorReader) Close() error             { return nil }

// Body read and decode failures must not echo transport details such as the
// pod's bound socket address back to the client.
func TestChatDoesNotReflectBodyErrors(t *testing.T) {
	timeout := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 8080},
		Addr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 41732},
		Err:    os.ErrDeadlineExceeded,
	}
	tests := []struct {
		name string
		body io.Reader
		want int
	}{
		{name: "slow body timeout", body: errorReader{err: timeout}, want: http.StatusRequestTimeout},
		{name: "malformed json", body: strings.NewReader(`{"thread":`), want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Client: testClient(t, testThread())}
			req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", nil)
			req.Header.Set("X-Forwarded-User", "alice")
			req.Body = io.NopCloser(tt.body)
			rec := httptest.NewRecorder()
			(&Chat{Server: s}).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			body := rec.Body.String()
			for _, leak := range []string{"10.0.0.5", "10.0.0.9", "i/o timeout", "unexpected EOF", "invalid character"} {
				if strings.Contains(body, leak) {
					t.Errorf("response leaks %q: %s", leak, body)
				}
			}
		})
	}
	if !errors.Is(timeout, os.ErrDeadlineExceeded) {
		t.Fatal("test timeout error is not a deadline")
	}
}
