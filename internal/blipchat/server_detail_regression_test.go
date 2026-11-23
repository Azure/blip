// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// detailReadWire lets a test fail or empty the log replay that backs the
// session detail, as the node's stream API can while a commit is being saved.
type detailReadWire struct {
	Wire
	fail  atomic.Bool
	empty atomic.Bool
}

func (w *detailReadWire) ReadLog(ctx context.Context, ns, state string, offset uint64) (io.ReadCloser, error) {
	if w.fail.Load() {
		return nil, errors.New("injected transcript read failure")
	}
	if w.empty.Load() {
		return io.NopCloser(strings.NewReader("")), nil
	}
	return w.Wire.ReadLog(ctx, ns, state, offset)
}

// newDetailGateway serves the API without a supervisor, so a detail request is
// the only reader of the ring.
func newDetailGateway(t *testing.T, wire Wire, fc *fakeCluster) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Options{
		Namespace:   "default",
		DefaultPool: "default",
		Profiles:    Profiles{DefaultProfileName: {}},
		Cluster:     fc,
		Wire:        wire,
		Log:         testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		s.Close()
	})
	return s, ts
}

func getSessionDetail(t *testing.T, ts *httptest.Server, name string) (int, sessionDetail) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/sessions/"+name, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, sessionDetail{}
	}
	var detail sessionDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	return resp.StatusCode, detail
}

// expireView makes the next detail request replay the ring instead of serving
// the one-second display cache.
func expireView(t *testing.T, s *Server, name string) {
	t.Helper()
	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()
	if entry, ok := s.views[name]; ok {
		entry.at = time.Now().Add(-2 * viewCacheTTL)
		s.views[name] = entry
	}
}

// A transient failed or truncated replay must not be served as an empty chat.
// The last complete view is append-only safe for the client's SSE cursor, and
// the failed read must not replace it in the cache.
func TestServerDetailFallsBackToLastCompleteView(t *testing.T) {
	for _, mode := range []string{"error", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			fc := newFakeCluster()
			newChat(fc, "chat-detail", DefaultProfileName)
			fw := newFakeWire()
			fw.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello", Original: "hello"})
			fw.emitACP(1, map[string]any{
				"jsonrpc": "2.0",
				"method":  "session/update",
				"params": map[string]any{"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]string{"type": "text", "text": "answer"},
				}},
			})
			wire := &detailReadWire{Wire: fw}
			s, ts := newDetailGateway(t, wire, fc)

			status, good := getSessionDetail(t, ts, "chat-detail")
			if status != http.StatusOK || len(good.Transcript) != 2 || good.Offset == 0 {
				t.Fatalf("healthy detail: status=%d transcript=%d offset=%d", status, len(good.Transcript), good.Offset)
			}

			expireView(t, s, "chat-detail")
			if mode == "error" {
				wire.fail.Store(true)
			} else {
				// A decoder that stops before EOF is a partial read, not an
				// empty chat.
				wire.Wire = &truncatedReadWire{Wire: fw}
			}
			status, detail := getSessionDetail(t, ts, "chat-detail")
			if status != http.StatusOK {
				t.Fatalf("detail during %s read: status=%d, want the last complete view", mode, status)
			}
			if len(detail.Transcript) == 0 {
				t.Fatal("detail served an empty transcript for a chat with history")
			}
			if detail.Offset != good.Offset || len(detail.Transcript) != len(good.Transcript) {
				t.Fatalf("fallback detail offset=%d transcript=%d, want offset=%d transcript=%d",
					detail.Offset, len(detail.Transcript), good.Offset, len(good.Transcript))
			}
			if cached := s.cachedViewAnyAge("chat-detail"); cached == nil || len(cached.Transcript) == 0 {
				t.Fatal("failed replay replaced the last complete view in the cache")
			}

			wire.fail.Store(false)
			wire.Wire = fw
			expireView(t, s, "chat-detail")
			status, recovered := getSessionDetail(t, ts, "chat-detail")
			if status != http.StatusOK || len(recovered.Transcript) != len(good.Transcript) {
				t.Fatalf("recovered detail: status=%d transcript=%d, want %d", status, len(recovered.Transcript), len(good.Transcript))
			}
		})
	}
}

// truncatedReadWire returns a syntactically incomplete log line, which the
// decoder reports as a non-EOF error.
type truncatedReadWire struct{ Wire }

func (w *truncatedReadWire) ReadLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(`{"o":1,"g":1,"t":7,"d":"`)), nil
}

// Without a complete earlier read there is nothing safe to serve, so the detail
// is a transient 503 instead of a confident empty 200. A read that succeeds but
// returns nothing for a chat with a committed generation is the same lie.
func TestServerDetailUnavailableInsteadOfEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fail  bool
		empty bool
	}{
		{name: "read error", fail: true},
		{name: "empty replay after commit", empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeCluster()
			st := newChat(fc, "chat-detail", DefaultProfileName)
			st.Status.Committed = &v1.Commit{ID: "commit-1", Generation: 1}
			fw := newFakeWire()
			fw.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello", Original: "hello"})
			fw.emitACP(1, map[string]any{
				"jsonrpc": "2.0",
				"method":  "session/update",
				"params": map[string]any{"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]string{"type": "text", "text": "answer"},
				}},
			})
			wire := &detailReadWire{Wire: fw}
			wire.fail.Store(tc.fail)
			wire.empty.Store(tc.empty)
			_, ts := newDetailGateway(t, wire, fc)

			status, _ := getSessionDetail(t, ts, "chat-detail")
			if status != http.StatusServiceUnavailable {
				t.Fatalf("detail status=%d, want 503 rather than an empty 200", status)
			}

			// Completing the save makes the full transcript readable again.
			wire.fail.Store(false)
			wire.empty.Store(false)
			fc.mu.Lock()
			fc.states[key("default", "chat-detail")].Status.Committed = &v1.Commit{ID: "commit-2", Generation: 2}
			fc.mu.Unlock()
			status, detail := getSessionDetail(t, ts, "chat-detail")
			if status != http.StatusOK || len(detail.Transcript) != 2 {
				t.Fatalf("completed detail: status=%d transcript=%d, want 200 with 2 frames", status, len(detail.Transcript))
			}
		})
	}
}

// A fork inherits history before its start offset, so an empty transcript is
// its honest state and must not be reported as unavailable.
func TestServerDetailForkMayBeEmpty(t *testing.T) {
	fc := newFakeCluster()
	st := newChat(fc, "chat-fork", DefaultProfileName)
	st.Annotations[AnnotationStart] = "500"
	st.Status.Committed = &v1.Commit{ID: "commit-1", Generation: 1}
	fw := newFakeWire()
	fw.note(noteRecord{Type: notePrompt, ID: "n1", Text: "inherited", Original: "inherited"})
	wire := &detailReadWire{Wire: fw}
	wire.empty.Store(true)
	_, ts := newDetailGateway(t, wire, fc)

	status, detail := getSessionDetail(t, ts, "chat-fork")
	if status != http.StatusOK {
		t.Fatalf("fork detail status=%d, want 200", status)
	}
	if len(detail.Transcript) != 0 || detail.Offset != 0 {
		t.Fatalf("fork detail transcript=%d offset=%d, want an empty inherited view", len(detail.Transcript), detail.Offset)
	}
}
