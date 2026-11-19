package blipchat

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAgent(send func(context.Context, []byte, bool) error) *acpAgent {
	return newACPAgent(send, func(json.RawMessage) {}, func() {}, func(string) {}, "always")
}

func TestACPFeedFramesSplitLines(t *testing.T) {
	var mu sync.Mutex
	var got []json.RawMessage
	a := newACPAgent(func(context.Context, []byte, bool) error { return nil }, func(raw json.RawMessage) {
		mu.Lock()
		got = append(got, raw)
		mu.Unlock()
	}, func() {}, func(string) {}, "always")

	first := `{"jsonrpc":"2.0","method":"session/update","params":{"n":1}}`
	a.Feed([]byte(first[:12]))
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("dispatched a partial line: %d", len(got))
	}
	mu.Unlock()
	a.Feed([]byte(first[12:] + "\n" + `{"jsonrpc":"2.0","method":"session/update","params":{"n":2}}` + "\n"))
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2", len(got))
	}
	if !strings.Contains(string(got[1]), `"n":2`) {
		t.Fatalf("second message = %s", got[1])
	}
}

func TestACPPromptResponseEndsTurn(t *testing.T) {
	var mu sync.Mutex
	var wire []byte
	done := make(chan struct{}, 1)
	a := newACPAgent(func(_ context.Context, data []byte, _ bool) error {
		mu.Lock()
		wire = append([]byte(nil), data...)
		mu.Unlock()
		return nil
	}, func(json.RawMessage) {}, func() { done <- struct{}{} }, func(string) {}, "always")
	a.SetSessionID("session-1")

	if err := a.Prompt(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	data := append([]byte(nil), wire...)
	mu.Unlock()
	var req struct {
		ID     string `json:"id"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Method != "session/prompt" || req.ID == "" {
		t.Fatalf("unexpected request: %s", data)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("request is not newline-delimited: %q", data)
	}
	if a.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", a.Pending())
	}
	a.Feed([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"stopReason":"end_turn"}}` + "\n"))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("prompt response did not finish the turn")
	}
	if a.Pending() != 0 {
		t.Fatalf("pending = %d, want 0", a.Pending())
	}
}

func TestACPPermissionPolicy(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"always", "allow"},
		{"never", "reject"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			sent := make(chan []byte, 1)
			a := newACPAgent(func(_ context.Context, data []byte, _ bool) error {
				select {
				case sent <- append([]byte(nil), data...):
				default:
				}
				return nil
			}, func(json.RawMessage) {}, nil, func(string) {}, tt.mode)
			a.Feed([]byte(`{"jsonrpc":"2.0","id":7,"method":"session/request_permission","params":{"options":[{"optionId":"allow","kind":"allow_once"},{"optionId":"reject","kind":"reject_once"}]}}` + "\n"))
			select {
			case data := <-sent:
				var reply struct {
					Result struct {
						Outcome struct {
							OptionID string `json:"optionId"`
						} `json:"outcome"`
					} `json:"result"`
				}
				if err := json.Unmarshal(data, &reply); err != nil {
					t.Fatal(err)
				}
				if reply.Result.Outcome.OptionID != tt.want {
					t.Fatalf("option = %q, want %q", reply.Result.Outcome.OptionID, tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no permission reply")
			}
		})
	}
}

func TestACPInitializeLoad(t *testing.T) {
	var methods []string
	var mu sync.Mutex
	var a *acpAgent
	a = newACPAgent(func(_ context.Context, data []byte, _ bool) error {
		var req struct {
			ID     string `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal(data, &req)
		mu.Lock()
		methods = append(methods, req.Method)
		mu.Unlock()
		switch req.Method {
		case "initialize":
			a.Feed([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"agentCapabilities":{"loadSession":true}}}` + "\n"))
		case "session/new":
			a.Feed([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"sessionId":"s1"}}` + "\n"))
		case "session/load":
			a.Feed([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{}}` + "\n"))
		}
		return nil
	}, func(json.RawMessage) {}, nil, func(string) {}, "always")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if a.SessionID() != "s1" {
		t.Fatalf("session = %q", a.SessionID())
	}
	if _, err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"initialize", "session/new", "initialize", "session/load"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
}
