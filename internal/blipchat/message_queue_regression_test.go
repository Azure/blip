// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// queueAdmissionWire holds prompt writes after handleMessage's admission check,
// but before the fake ring's serialized append. Answers deliberately bypass it.
type queueAdmissionWire struct {
	*fakeWire
	entered  chan struct{}
	release  chan struct{}
	fail     atomic.Bool
	rollover atomic.Bool
}

func (w *queueAdmissionWire) Send(ctx context.Context, ns, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	var n noteRecord
	if note && json.Unmarshal(data, &n) == nil && n.Type == notePrompt {
		select {
		case w.entered <- struct{}{}:
		default:
		}
		select {
		case <-w.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		if w.fail.Swap(false) {
			return 0, errors.New("injected prompt append failure")
		}
		if w.rollover.Swap(false) {
			w.mu.Lock()
			gen := w.gen + 1
			w.mu.Unlock()
			w.start(gen)
			return 0, ErrPrecondition
		}
	}
	return w.fakeWire.Send(ctx, ns, state, data, eof, note, after)
}

func newQueueAdmissionServer(t *testing.T, queued int) (*Server, *queueAdmissionWire, http.Handler) {
	t.Helper()
	cluster := newFakeCluster()
	newChat(cluster, "queue-test", DefaultProfileName)
	wire := &queueAdmissionWire{fakeWire: newFakeWire(), entered: make(chan struct{}, maxQueue+2), release: make(chan struct{})}
	wire.start(1)
	for i := 0; i < queued; i++ {
		wire.note(noteRecord{Type: notePrompt, ID: fmt.Sprintf("seed-%d", i), Text: "waiting"})
	}
	s, err := New(Options{Cluster: cluster, Wire: wire, Log: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	// Freeze the consumer, not admission: the test measures accepted-but-unsent
	// notes without an engine consuming them while the HTTP requests run.
	s.engines["queue-test"] = &chatEngine{cancel: func() {}}
	t.Cleanup(s.Close)
	return s, wire, s.Handler()
}

func postQueueMessage(handler http.Handler) int {
	r := httptest.NewRequest(http.MethodPost, "/api/sessions/queue-test/message", strings.NewReader(`{"text":"hello"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-User", "alice")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Code
}

func TestServerMessageConcurrentQueueBound(t *testing.T) {
	for _, tc := range []struct {
		name     string
		queued   int
		requests int
		replicas int
	}{
		{name: "last_slot", queued: maxQueue - 1, requests: 2, replicas: 1},
		{name: "empty_queue_burst", queued: 0, requests: maxQueue + 2, replicas: 1},
		{name: "last_slot_across_replicas", queued: maxQueue - 1, requests: 2, replicas: 2},
		{name: "empty_queue_burst_across_replicas", queued: 0, requests: maxQueue + 2, replicas: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, wire, handler := newQueueAdmissionServer(t, tc.queued)
			handlers := []http.Handler{handler}
			for i := 1; i < tc.replicas; i++ {
				replica, err := New(Options{Cluster: s.cluster, Wire: wire, Log: testLogger()})
				if err != nil {
					t.Fatal(err)
				}
				replica.engines["queue-test"] = &chatEngine{cancel: func() {}}
				t.Cleanup(replica.Close)
				handlers = append(handlers, replica.Handler())
			}
			results := make(chan int, tc.requests)
			// Hold each initial append until every competing request has made
			// its admission decision. Releasing the barrier forces CAS losers
			// to replay and recheck capacity, including on another replica.
			var statuses []int
			for i := 0; i < tc.requests; i++ {
				handler := handlers[i%len(handlers)]
				go func() { results <- postQueueMessage(handler) }()
				select {
				case <-wire.entered:
				case status := <-results:
					statuses = append(statuses, status)
				case <-time.After(5 * time.Second):
					close(wire.release)
					t.Fatal("request neither reached append nor rejected")
				}
			}
			close(wire.release)
			for len(statuses) < tc.requests {
				select {
				case status := <-results:
					statuses = append(statuses, status)
				case <-time.After(5 * time.Second):
					t.Fatal("request did not finish after append barrier release")
				}
			}
			accepted, busy := 0, 0
			for _, status := range statuses {
				switch status {
				case http.StatusAccepted:
					accepted++
				case http.StatusServiceUnavailable:
					busy++
				default:
					t.Errorf("unexpected HTTP status %d", status)
				}
			}
			st, err := s.cluster.GetSession(context.Background(), "default", "queue-test")
			if err != nil {
				t.Fatal(err)
			}
			s.invalidateView(st.Name)
			view := s.readView(context.Background(), st)
			wantAccepted := min(tc.requests, maxQueue-tc.queued)
			if accepted != wantAccepted || busy != tc.requests-wantAccepted || len(view.Queued) > maxQueue {
				t.Fatalf("accepted=%d busy=%d queued=%d inflight=%v; want accepted=%d busy=%d queued<=%d", accepted, busy, len(view.Queued), view.Inflight != nil, wantAccepted, tc.requests-wantAccepted, maxQueue)
			}
			for _, sent := range wire.messages() {
				var note noteRecord
				if sent.note && json.Unmarshal(sent.raw, &note) == nil && note.Type == notePrompt && sent.after == 0 {
					t.Fatal("prompt bypassed conditional admission")
				}
			}
		})
	}
}

func TestServerMessageQueueGenerationChange(t *testing.T) {
	_, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
	close(wire.release)
	wire.rollover.Store(true)
	if got := postQueueMessage(handler); got != http.StatusAccepted {
		t.Fatalf("append across generation change status=%d, want 202", got)
	}
	if !hasNote(wire.notes(), noteAdmission, nil) {
		t.Fatal("new generation did not bootstrap a conditional-write offset")
	}
	if got := postQueueMessage(handler); got != http.StatusServiceUnavailable {
		t.Fatalf("full queue after generation change status=%d, want 503", got)
	}
}

func TestServerMessageQueueConflictRechecksQuestion(t *testing.T) {
	_, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
	// Leave one slot available, then open a question while its prompt append
	// is blocked. The CAS retry must classify the message as an answer.
	results := make(chan int, 1)
	go func() { results <- postQueueMessage(handler) }()
	select {
	case <-wire.entered:
	case <-time.After(5 * time.Second):
		close(wire.release)
		t.Fatal("prompt did not reach append barrier")
	}
	wire.note(noteRecord{Type: noteQuestion, ID: "new-question", Text: "Continue?"})
	close(wire.release)
	select {
	case got := <-results:
		if got != http.StatusAccepted {
			t.Fatalf("answer after conflict status=%d, want 202", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message did not finish")
	}
	if !hasNote(wire.notes(), noteAnswer, func(n noteRecord) bool { return n.QID == "new-question" }) {
		t.Fatal("conflicting question did not receive the message as its answer")
	}
	if hasNote(wire.notes(), notePrompt, nil) {
		t.Fatal("message became a prompt despite the conflicting question")
	}
}

func TestServerMessageQueueIgnoresStaleDisplayCache(t *testing.T) {
	s, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
	close(wire.release)
	st, err := s.cluster.GetSession(context.Background(), "default", "queue-test")
	if err != nil {
		t.Fatal(err)
	}
	stale := s.readView(context.Background(), st)
	wire.note(noteRecord{Type: notePrompt, ID: "last-slot", Text: "waiting"})
	if got := postQueueMessage(handler); got != http.StatusServiceUnavailable {
		t.Fatalf("full queue with cached spare slot status=%d, want 503", got)
	}
	// Simulate an older read completing after a successful invalidation. It
	// must not affect admission either, even though its cache timestamp is new.
	s.invalidateView(st.Name)
	s.viewsMu.Lock()
	s.views[st.Name] = cachedChatView{view: stale, at: time.Now()}
	s.viewsMu.Unlock()
	if got := postQueueMessage(handler); got != http.StatusServiceUnavailable {
		t.Fatalf("full queue with late stale cache publication status=%d, want 503", got)
	}
}

type queueReadFailureWire struct {
	Wire
	partial bool
}

func (w queueReadFailureWire) ReadLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	if w.partial {
		return io.NopCloser(strings.NewReader("{")), nil
	}
	return nil, errors.New("injected log read failure")
}

func TestServerMessageQueueReadFailureDoesNotAdmit(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%t", partial), func(t *testing.T) {
			s, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
			close(wire.release)
			s.wire = queueReadFailureWire{Wire: wire, partial: partial}
			if got := postQueueMessage(handler); got != http.StatusInternalServerError {
				t.Fatalf("read failure status=%d, want 500", got)
			}
			if hasNote(wire.notes(), notePrompt, nil) {
				t.Fatal("admitted a prompt after an incomplete replay")
			}
		})
	}
}

func TestServerMessageQueueAppendFailureReleasesCapacity(t *testing.T) {
	_, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
	close(wire.release)
	wire.fail.Store(true)
	if got := postQueueMessage(handler); got != http.StatusInternalServerError {
		t.Fatalf("failed append status=%d, want 500", got)
	}
	if got := postQueueMessage(handler); got != http.StatusAccepted {
		t.Fatalf("replacement append status=%d, want 202 (failed append must release capacity)", got)
	}
	if got := postQueueMessage(handler); got != http.StatusServiceUnavailable {
		t.Fatalf("full queue status=%d, want 503", got)
	}
}

func TestServerMessageFullQueueStillAnswersQuestion(t *testing.T) {
	_, wire, handler := newQueueAdmissionServer(t, maxQueue)
	close(wire.release)
	wire.note(noteRecord{Type: noteQuestion, ID: "open-question", Text: "Continue?"})
	if got := postQueueMessage(handler); got != http.StatusAccepted {
		t.Fatalf("answer at capacity status=%d, want 202", got)
	}
	if !hasNote(wire.notes(), noteAnswer, func(n noteRecord) bool { return n.QID == "open-question" }) {
		t.Fatalf("missing answer note: %+v", wire.notes())
	}
	if hasNote(wire.notes(), notePrompt, nil) {
		t.Fatal("answer incorrectly appended a prompt")
	}
}

func TestServerMessageQueueCountsInflight(t *testing.T) {
	s, wire, handler := newQueueAdmissionServer(t, maxQueue)
	close(wire.release)
	_, err := wire.fakeWire.Send(context.Background(), "default", "queue-test", []byte(`{"jsonrpc":"2.0","id":"p-seed-0","method":"session/prompt"}`), false, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.cluster.GetSession(context.Background(), "default", "queue-test")
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.messageView(context.Background(), st)
	if err != nil || view.Inflight == nil {
		t.Fatalf("expected in-flight prompt: view=%+v err=%v", view, err)
	}
	if got := postQueueMessage(handler); got != http.StatusServiceUnavailable {
		t.Fatalf("queue including in-flight prompt status=%d, want 503", got)
	}
}
