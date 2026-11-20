// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// engineFixture is a single chat wired to the in-memory cluster and ring.
type engineFixture struct {
	srv     *Server
	cluster *fakeCluster
	wire    *fakeWire
	name    string
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	cluster := newFakeCluster()
	wire := newFakeWire()
	const name = "chat-1"
	newChat(cluster, name, DefaultProfileName)
	srv, err := New(Options{
		Namespace: "default",
		Cluster:   cluster,
		Wire:      wire,
		Log:       testLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)
	return &engineFixture{srv: srv, cluster: cluster, wire: wire, name: name}
}

// addBlip creates a Running blip for gen, as the controller would.
func (f *engineFixture) addBlip(t *testing.T, gen int64) {
	t.Helper()
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s-g%d", f.name, gen),
			Namespace:   "default",
			Labels:      map[string]string{LabelSession: f.name},
			Annotations: map[string]string{AnnotationGeneration: strconv.FormatInt(gen, 10)},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning},
	}
	if err := f.cluster.CreateBlip(context.Background(), "default", blip); err != nil {
		t.Fatalf("CreateBlip %s: %v", blip.Name, err)
	}
}

// startGeneration creates the blip and records the guest's start record.
func (f *engineFixture) startGeneration(t *testing.T, gen uint64) {
	t.Helper()
	f.addBlip(t, int64(gen))
	f.wire.start(gen)
}

func (f *engineFixture) start(t *testing.T) {
	t.Helper()
	if e := f.srv.ensureEngine(f.name); e == nil {
		t.Fatal("engine was not started")
	}
}

// startWith starts an engine with fields tuned before its goroutine runs, so a
// test can shorten the retry backoff without racing the engine loop.
func (f *engineFixture) startWith(t *testing.T, tune func(*chatEngine)) *chatEngine {
	t.Helper()
	ctx, cancel := context.WithCancel(f.srv.ctx)
	e := &chatEngine{s: f.srv, name: f.name, ctx: ctx, cancel: cancel}
	if tune != nil {
		tune(e)
	}
	f.srv.mu.Lock()
	f.srv.engines[f.name] = e
	f.srv.mu.Unlock()
	go e.run()
	return e
}

func (f *engineFixture) annotation(key string) string {
	st, err := f.cluster.GetSession(context.Background(), "default", f.name)
	if err != nil {
		return ""
	}
	return st.Annotations[key]
}

func (f *engineFixture) hasBlip(name string) bool {
	_, err := f.cluster.GetBlip(context.Background(), "default", name)
	return err == nil
}

func engineEOFCount(wire *fakeWire) int {
	n := 0
	for _, msg := range wire.messages() {
		if msg.eof {
			n++
		}
	}
	return n
}

// engineSentMethods lists client requests in send order, skipping notes and
// JSON-RPC responses such as permission replies.
func engineSentMethods(wire *fakeWire) []string {
	var out []string
	for _, msg := range wire.messages() {
		if msg.eof || msg.note || msg.method == "" {
			continue
		}
		out = append(out, msg.method)
	}
	return out
}

func engineSent(wire *fakeWire, id string) (sentMessage, bool) {
	for _, msg := range wire.messages() {
		if msg.id == id {
			return msg, true
		}
	}
	return sentMessage{}, false
}

func TestEnginePromptFlow(t *testing.T) {
	f := newEngineFixture(t)
	f.wire.autoRespond = true
	f.startGeneration(t, 1)
	f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "rendered text", Original: "original text", Sender: "alice"})
	f.start(t)

	waitFor(t, "prompt p-n1", func() bool {
		ids := f.wire.promptIDs()
		return len(ids) > 0 && ids[0] == "p-n1"
	})
	methods := engineSentMethods(f.wire)
	want := []string{"initialize", "session/new", "session/prompt"}
	if len(methods) < len(want) {
		t.Fatalf("sent methods = %v, want prefix %v", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Fatalf("sent methods = %v, want prefix %v", methods, want)
		}
	}

	waitFor(t, "acp session annotation", func() bool {
		return f.annotation(AnnotationACPSession) == "acp-session-1"
	})
	if got := f.wire.promptIDs(); len(got) != 1 || got[0] != "p-n1" {
		t.Fatalf("prompt ids = %v, want exactly [p-n1]", got)
	}
}

func TestEnginePromptsInOrder(t *testing.T) {
	f := newEngineFixture(t)
	f.wire.autoRespond = false
	f.startGeneration(t, 1)
	f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "first", Original: "first"})
	f.wire.note(noteRecord{Type: notePrompt, ID: "n2", Text: "second", Original: "second"})
	f.start(t)

	waitFor(t, "first prompt", func() bool {
		ids := f.wire.promptIDs()
		return len(ids) == 1 && ids[0] == "p-n1"
	})
	time.Sleep(300 * time.Millisecond)
	if ids := f.wire.promptIDs(); len(ids) != 1 {
		t.Fatalf("prompt ids = %v before the first response, want exactly one", ids)
	}

	f.wire.emitACP(1, map[string]any{
		"jsonrpc": "2.0",
		"id":      "p-n1",
		"result":  map[string]any{"stopReason": "end_turn"},
	})
	waitFor(t, "second prompt", func() bool {
		ids := f.wire.promptIDs()
		return len(ids) == 2 && ids[0] == "p-n1" && ids[1] == "p-n2"
	})

	f.wire.emitACP(1, map[string]any{
		"jsonrpc": "2.0",
		"id":      "p-n2",
		"result":  map[string]any{"stopReason": "end_turn"},
	})
	time.Sleep(300 * time.Millisecond)
	if ids := f.wire.promptIDs(); len(ids) != 2 {
		t.Fatalf("prompt ids = %v after both responses, want exactly [p-n1 p-n2]", ids)
	}
}

func TestEngineRetryAfterGenerationEnds(t *testing.T) {
	f := newEngineFixture(t)
	f.wire.autoRespond = false
	f.startGeneration(t, 1)
	f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "first", Original: "first"})
	f.wire.note(noteRecord{Type: notePrompt, ID: "n2", Text: "unsent", Original: "unsent"})
	f.startWith(t, func(e *chatEngine) {
		// Skip the 15s minimum backoff; the second prompt is still queued.
		e.delay = 5 * time.Millisecond
		e.nextAttempt = time.Now().Add(-time.Second)
	})

	waitFor(t, "first prompt", func() bool {
		ids := f.wire.promptIDs()
		return len(ids) == 1 && ids[0] == "p-n1"
	})

	f.wire.end(1)
	f.cluster.setActive("default", f.name, string(v1.BlipSucceeded))
	waitFor(t, "second-generation blip", func() bool {
		return f.hasBlip(f.name + "-g2")
	})
	names := f.cluster.blipNames()
	found := map[string]bool{}
	for _, name := range names {
		found[name] = true
	}
	if !found[f.name+"-g1"] || !found[f.name+"-g2"] {
		t.Fatalf("blips = %v, want %s-g1 and %s-g2", names, f.name, f.name)
	}
}

func TestEnginePreconditionDoesNotDuplicate(t *testing.T) {
	f := newEngineFixture(t)
	f.wire.autoRespond = false
	f.startGeneration(t, 1)
	noteOffset := f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello", Original: "hello"})

	// Another writer advances the generation's last input offset after this
	// view was built.
	ctx := context.Background()
	otherOffset, err := f.wire.Send(ctx, "default", f.name, cancelFrame("acp-session-1"), false, false, 0)
	if err != nil {
		t.Fatalf("Send other input: %v", err)
	}
	e := &chatEngine{s: f.srv, name: f.name, ctx: ctx}
	frame := promptFrame("n1", "acp-session-1", "hello", "hello", "")

	ok, err := e.send(ctx, frame, noteOffset)
	if err != nil {
		t.Fatalf("send with stale after: %v", err)
	}
	if ok {
		t.Fatal("a stale conditional append should lose")
	}
	if ids := f.wire.promptIDs(); len(ids) != 0 {
		t.Fatalf("prompt ids = %v after a lost append, want none", ids)
	}

	ok, err = e.send(ctx, frame, otherOffset)
	if err != nil || !ok {
		t.Fatalf("send with the refreshed after = %v, %v", ok, err)
	}
	if ids := f.wire.promptIDs(); len(ids) != 1 || ids[0] != "p-n1" {
		t.Fatalf("prompt ids = %v, want [p-n1]", ids)
	}

	// Replaying the loser must not append a second copy of the same prompt.
	if ok, err = e.send(ctx, frame, noteOffset); err != nil {
		t.Fatalf("replayed send: %v", err)
	} else if ok {
		t.Fatal("replayed stale send should lose")
	}
	if ids := f.wire.promptIDs(); len(ids) != 1 {
		t.Fatalf("prompt ids = %v after replay, want exactly one", ids)
	}
}

func TestEngineEOFAndIdle(t *testing.T) {
	f := newEngineFixture(t)
	f.startGeneration(t, 1)
	f.start(t)

	waitFor(t, "eof", func() bool {
		return engineEOFCount(f.wire) == 1
	})

	// With no active blip and no work left, the engine reports idle and stops.
	f.wire.end(1)
	f.cluster.setActive("default", f.name, string(v1.BlipSucceeded))
	waitFor(t, "engine exit", func() bool {
		return f.srv.lookupEngine(f.name) == nil
	})
	if got := engineEOFCount(f.wire); got != 1 {
		t.Fatalf("eof count = %d, want exactly one", got)
	}
}

func TestEnginePermission(t *testing.T) {
	f := newEngineFixture(t)
	f.startGeneration(t, 1)
	f.start(t)

	waitFor(t, "acp session annotation", func() bool {
		return f.annotation(AnnotationACPSession) == "acp-session-1"
	})

	permission := func(id, option string) map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  "session/request_permission",
			"params": map[string]any{
				"sessionId": "acp-session-1",
				"toolCall":  map[string]any{"toolCallId": "call-1", "title": "run a command"},
				"options": []any{
					map[string]string{"optionId": option, "kind": "allow_once"},
					map[string]string{"optionId": "deny-" + option, "kind": "reject_once"},
				},
			},
		}
	}

	f.wire.emitACP(1, permission("perm-1", "allow-1"))
	waitFor(t, "permission reply", func() bool {
		_, ok := engineSent(f.wire, "perm-1")
		return ok
	})
	msg, _ := engineSent(f.wire, "perm-1")
	var reply struct {
		Result struct {
			Outcome struct {
				Outcome  string `json:"outcome"`
				OptionID string `json:"optionId"`
			} `json:"outcome"`
		} `json:"result"`
	}
	if err := json.Unmarshal(msg.raw, &reply); err != nil {
		t.Fatalf("decode permission reply: %v", err)
	}
	if reply.Result.Outcome.Outcome != "selected" || reply.Result.Outcome.OptionID != "allow-1" {
		t.Fatalf("permission reply = %+v", reply.Result.Outcome)
	}

	// A blip that is no longer Running must not receive a reply.
	f.cluster.setActive("default", f.name, string(v1.BlipPending))
	f.wire.emitACP(1, permission("perm-2", "allow-2"))
	time.Sleep(400 * time.Millisecond)
	if _, ok := engineSent(f.wire, "perm-2"); ok {
		t.Fatal("engine answered a permission request while the blip was not Running")
	}

	// Once it runs again, the pending request is answered.
	f.cluster.setActive("default", f.name, string(v1.BlipRunning))
	waitFor(t, "permission reply after resume", func() bool {
		_, ok := engineSent(f.wire, "perm-2")
		return ok
	})
}
