package blipchat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func serveChat(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(body))
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	(&Chat{Server: s}).ServeHTTP(rec, req)
	return rec
}

// The handler's overall budget must expire before the HTTP server's write
// timeout, so a slow model still gets a response instead of a closed
// connection.
func TestChatBudgetFitsInsideWriteTimeout(t *testing.T) {
	if defaultChatTimeout >= writeTimeout {
		t.Errorf("chat timeout %s is not below write timeout %s", defaultChatTimeout, writeTimeout)
	}
	if defaultChatRoundTimeout > defaultChatTimeout {
		t.Errorf("chat round timeout %s exceeds the request timeout %s", defaultChatRoundTimeout, defaultChatTimeout)
	}
	var cfg Config
	cfg.defaults()
	if cfg.ChatTimeout != defaultChatTimeout || cfg.ChatRoundTimeout != defaultChatRoundTimeout || cfg.ChatMaxRounds != defaultChatMaxRounds {
		t.Errorf("defaults() = %s/%s/%d, want %s/%s/%d",
			cfg.ChatTimeout, cfg.ChatRoundTimeout, cfg.ChatMaxRounds,
			defaultChatTimeout, defaultChatRoundTimeout, defaultChatMaxRounds)
	}
}

// A model that never answers must be canceled by the request deadline, and
// the client must see a response rather than an EOF.
func TestChatRequestDeadlineStopsSlowModel(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-release
	}))
	defer func() {
		close(release)
		upstream.Close()
	}()

	c := testClient(t, testThread())
	s := &Server{
		Client: c,
		Config: Config{Model: "test", ChatTimeout: 500 * time.Millisecond},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	start := time.Now()
	rec := serveChat(t, s, `{"thread":"proj","message":"hi"}`)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("chat took %s, want it bounded by the request deadline", elapsed)
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504: %s", rec.Code, rec.Body.String())
	}
	if calls.Load() == 0 {
		t.Error("the model was never called, so the deadline did not bound a slow call")
	}
	if turns := chatTurns(t, c); len(turns) != 0 {
		t.Errorf("timed-out chat created turns %v", names(turns))
	}
}

// One stalled completion must not consume the whole request. The per-round
// deadline cancels it and the handler answers.
func TestChatRoundDeadlineStopsSlowModel(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		upstream.Close()
	}()

	c := testClient(t, testThread())
	s := &Server{
		Client: c,
		Config: Config{Model: "test", ChatTimeout: 10 * time.Second, ChatRoundTimeout: 300 * time.Millisecond},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	start := time.Now()
	rec := serveChat(t, s, `{"thread":"proj","message":"hi"}`)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("chat took %s, want it bounded by the round deadline", elapsed)
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504: %s", rec.Code, rec.Body.String())
	}
}

// The number of model rounds is capped so a model that keeps calling tools
// cannot run until the connection timeout.
func TestChatRoundsAreCapped(t *testing.T) {
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", ToolCalls: []ToolCall{
		toolCall("board", `{}`),
	}})
	c := testClient(t, testThread())
	s := &Server{
		Client: c,
		Config: Config{Model: "test", ChatMaxRounds: 3},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	rec := serveChat(t, s, `{"thread":"proj","message":"hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(*requests) != 3 {
		t.Errorf("model rounds = %d, want the configured cap 3", len(*requests))
	}
	var response chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Reply, "could not finish") {
		t.Errorf("reply = %q, want the round-limit answer", response.Reply)
	}
}

// A turn committed before the deadline must still get a response. The client
// sees 504, not an EOF after work was already recorded.
func TestChatDeadlineAfterSendReturnsResponse(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []any{map[string]any{"message": Message{Role: "assistant", ToolCalls: []ToolCall{
					toolCall("send", `{"topic":"chat.propose","text":"please add tests"}`),
				}}}},
				"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
			})
			return
		}
		<-release
	}))
	defer func() {
		close(release)
		upstream.Close()
	}()

	c := testClient(t, testThread())
	s := &Server{
		Client: c,
		Config: Config{Model: "test", ChatTimeout: 500 * time.Millisecond},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	start := time.Now()
	rec := serveChat(t, s, `{"thread":"proj","message":"please add tests"}`)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("chat took %s, want it bounded by the request deadline", elapsed)
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504: %s", rec.Code, rec.Body.String())
	}
	var turns v1.BlipTurnList
	if err := c.List(t.Context(), &turns); err != nil {
		t.Fatal(err)
	}
	if len(turns.Items) != 1 {
		t.Errorf("turns after a timed-out send = %d, want the one committed turn", len(turns.Items))
	}
}
