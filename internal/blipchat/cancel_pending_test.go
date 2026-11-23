// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// newCancelTestServer freezes the engine, so a handler test can inspect the
// durable intent a cancel records before any generation starts.
func newCancelTestServer(t *testing.T) (*Server, *fakeWire, http.Handler) {
	t.Helper()
	cluster := newFakeCluster()
	newChat(cluster, "chat-cancel", DefaultProfileName)
	wire := newFakeWire()
	s, err := New(Options{
		Namespace:   "default",
		DefaultPool: "default",
		Profiles:    Profiles{DefaultProfileName: {}},
		Cluster:     cluster,
		Wire:        &runningWire{fakeWire: wire, cluster: cluster},
		Log:         testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.engines["chat-cancel"] = &chatEngine{cancel: func() {}}
	t.Cleanup(s.Close)
	return s, wire, s.Handler()
}

func postCancel(handler http.Handler) int {
	r := httptest.NewRequest(http.MethodPost, "/api/sessions/chat-cancel/cancel", nil)
	r.Header.Set("X-Forwarded-User", "alice")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Code
}

// While a message is Pending no writer is attached, so the cancel note cannot
// be appended. The cancel must still be recorded durably: the prompt submitted
// before it is dropped when the generation attaches, instead of running the
// turn the user cancelled.
func TestCancelWithoutWriterDropsUnsentPrompt(t *testing.T) {
	s, wire, handler := newCancelTestServer(t)
	wire.note(noteRecord{Type: notePrompt, ID: "n-pending", Text: "pending", Original: "pending"})

	if got := postCancel(handler); got != http.StatusAccepted {
		t.Fatalf("cancel status=%d, want 202", got)
	}
	ctx := context.Background()
	st, err := s.cluster.GetSession(ctx, "default", "chat-cancel")
	if err != nil {
		t.Fatal(err)
	}
	if stopBefore(st) == 0 {
		t.Fatal("cancel without a writer recorded no durable boundary")
	}
	view, _ := s.readView(ctx, st)
	if view.hasWork() || len(view.Queued) != 0 {
		t.Fatalf("cancel kept work that was never sent: queued=%d inflight=%v", len(view.Queued), view.Inflight)
	}
	if prompt, ok := view.nextTurn(); ok {
		t.Fatalf("cancelled prompt is still deliverable: %+v", prompt)
	}
	e := &chatEngine{s: s, name: st.Name, view: view}
	if err := e.converge(ctx); err != errEngineIdle {
		t.Fatalf("engine with only cancelled work converge = %v, want idle", err)
	}
}

// A prompt the agent already received is marked done by the cancel and the
// engine sends session/cancel for it. The answer-turn variant records no Sent
// offset before this test, so its cancel was silently ignored.
func TestCancelMarksSentAnswerTurnDone(t *testing.T) {
	r := newStateRecorder(t)
	r.start(1)
	answerOff := r.note(1, noteRecord{Type: noteAnswer, QID: "q1", Text: "yes"})
	r.in(1, map[string]any{
		"jsonrpc": "2.0",
		"id":      answerRequestID(answerOff),
		"method":  "session/prompt",
		"params": map[string]any{
			"sessionId": "s1",
			"prompt":    []map[string]string{{"type": "text", "text": "Answer"}},
			"_meta":     map[string]any{"blip.dev/promptID": "answer-" + itoa(answerOff)},
		},
	})
	if r.view.Inflight == nil || r.view.Inflight.Sent == 0 {
		t.Fatalf("sent answer turn is not in flight with an offset: %+v", r.view.Inflight)
	}
	cancelOff := r.note(1, noteRecord{Type: noteCancel})
	if !r.view.Done[r.view.Inflight.ID] {
		t.Fatalf("cancel did not mark the sent answer turn done: %+v", r.view.Inflight)
	}
	if r.view.CancelSeq != cancelOff || r.view.CancelSeq < r.view.Inflight.Sent {
		t.Fatalf("cancel seq=%d sent=%d, the engine would not send session/cancel", r.view.CancelSeq, r.view.Inflight.Sent)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

// End to end: an already-sent prompt gets a session/cancel frame and is marked
// done, so it is neither retried nor reported as still running.
func TestCancelSendsSessionCancelForSentPrompt(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	g.wire.mu.Lock()
	g.wire.autoRespond = false
	g.wire.mu.Unlock()

	resp := g.request(t, http.MethodPost, "/api/sessions/"+name+"/message", map[string]any{"text": "work"}, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		resp.Body.Close()
		t.Fatalf("message status=%d", resp.StatusCode)
	}
	resp.Body.Close()
	g.waitPrompt(t, "work")

	resp = g.request(t, http.MethodPost, "/api/sessions/"+name+"/cancel", nil, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		resp.Body.Close()
		t.Fatalf("cancel status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	waitFor(t, "session/cancel frame", func() bool {
		for _, m := range g.wire.messages() {
			if m.method == "session/cancel" {
				return true
			}
		}
		return false
	})

	var promptID string
	for _, m := range g.wire.messages() {
		if m.method != "session/prompt" {
			continue
		}
		var msg struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if json.Unmarshal(m.raw, &msg) == nil {
			_ = json.Unmarshal(msg.Params.Meta["blip.dev/promptID"], &promptID)
		}
	}
	if promptID == "" {
		t.Fatal("sent prompt has no prompt id")
	}
	sent, err := g.cluster.GetSession(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	view, _ := g.srv.readView(context.Background(), sent)
	if !view.Done[promptID] {
		t.Fatalf("cancelled prompt %q was not marked done; inflight=%+v", promptID, view.Inflight)
	}
}
