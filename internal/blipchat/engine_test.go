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
	"k8s.io/apimachinery/pkg/types"

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

// addBlip creates a Running blip and its root writer. These older fixtures use
// the same VM ordinal and stream generation; generation comparison tests below
// deliberately separate them.
func (f *engineFixture) addBlip(t *testing.T, gen int64) {
	t.Helper()
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s-g%d", f.name, gen),
			UID:         types.UID(fmt.Sprintf("blip-%d", gen)),
			Namespace:   "default",
			Labels:      map[string]string{LabelSession: f.name},
			Annotations: map[string]string{AnnotationGeneration: strconv.FormatInt(gen, 10)},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, RootAttachmentID: fmt.Sprintf("root-%d", gen)},
	}
	if err := f.cluster.CreateBlip(context.Background(), "default", blip); err != nil {
		t.Fatalf("CreateBlip %s: %v", blip.Name, err)
	}
	f.cluster.mu.Lock()
	defer f.cluster.mu.Unlock()
	st := f.cluster.states[key("default", f.name)]
	st.Status.Writer = &v1.Writer{BlipName: blip.Name, BlipUID: string(blip.UID), AttachmentID: blip.Status.RootAttachmentID}
	if gen > 1 {
		st.Status.Committed = &v1.Commit{ID: fmt.Sprintf("commit-%d", gen-1), Generation: gen - 1}
		st.Status.Writer.BaseCommit = st.Status.Committed.ID
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

func TestEngineComparesStateWriteGeneration(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ordinal   int64
		committed int64 // -1 means no committed state yet.
		viewGen   uint64
		stop      bool
		mutate    func(*v1.BlipState, *v1.Blip)
		wantInit  bool
		wantStop  bool
	}{
		{name: "first VM from copied state", ordinal: 1, committed: 1, viewGen: 2, wantInit: true},
		{name: "higher copied generation", ordinal: 1, committed: 41, viewGen: 42, wantInit: true},
		{name: "later VM", ordinal: 3, committed: 8, viewGen: 9, wantInit: true},
		{name: "failed attempts exceed stream generation", ordinal: 7, committed: 1, viewGen: 2, wantInit: true},
		{name: "uncommitted state", ordinal: 4, committed: -1, viewGen: 1, wantInit: true},
		{name: "log lag", ordinal: 1, committed: 1, viewGen: 1},
		{name: "log lag with old stop", ordinal: 1, committed: 1, viewGen: 1, stop: true},
		{name: "later VM log lag", ordinal: 3, committed: 8, viewGen: 8},
		{name: "stream ahead of writer", ordinal: 7, committed: 1, viewGen: 3},
		{name: "explicit stop", ordinal: 1, committed: 1, viewGen: 2, stop: true, wantStop: true},
		{name: "pending explicit stop", ordinal: 1, committed: 1, viewGen: 2, stop: true, wantStop: true,
			mutate: func(_ *v1.BlipState, b *v1.Blip) { b.Status.Phase = v1.BlipPending }},
		{name: "pending cannot initialize", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(_ *v1.BlipState, b *v1.Blip) { b.Status.Phase = v1.BlipPending }},
		{name: "missing writer", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer = nil }},
		{name: "different writer name", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer.BlipName = "other" }},
		{name: "replaced writer UID", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer.BlipUID = "old-uid" }},
		{name: "missing writer UID", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer.BlipUID = "" }},
		{name: "different root attachment", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer.AttachmentID = "old-root" }},
		{name: "missing root attachment", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(_ *v1.BlipState, b *v1.Blip) { b.Status.RootAttachmentID = "" }},
		{name: "base already committed", ordinal: 1, committed: 1, viewGen: 2,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Committed.ID = "new-commit" }},
		{name: "mismatch cannot stop unrelated VM", ordinal: 1, committed: 1, viewGen: 3, stop: true,
			mutate: func(st *v1.BlipState, _ *v1.Blip) { st.Status.Writer.BlipName = "other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newEngineFixture(t)
			f.addBlip(t, tt.ordinal)
			f.cluster.mu.Lock()
			st := f.cluster.states[key("default", f.name)]
			b := f.cluster.blips[key("default", fmt.Sprintf("%s-g%d", f.name, tt.ordinal))]
			st.Status.Committed = nil
			st.Status.Writer.BaseCommit = ""
			if tt.committed >= 0 {
				st.Status.Committed = &v1.Commit{ID: "base", Generation: tt.committed}
				st.Status.Writer.BaseCommit = "base"
			}
			if tt.mutate != nil {
				tt.mutate(st, b)
			}
			f.cluster.mu.Unlock()
			f.wire.start(tt.viewGen)
			view := newChatView("")
			view.observe(streamLogRecord{Type: recordStart, Gen: tt.viewGen, Offset: 1})
			if tt.stop {
				view.observe(streamLogRecord{Type: recordNote, Gen: tt.viewGen, Offset: 2, Data: mustJSON(noteRecord{Type: noteStop})})
			}
			e := &chatEngine{s: f.srv, name: f.name, view: view}
			if err := e.converge(context.Background()); err != nil {
				t.Fatal(err)
			}
			methods := engineSentMethods(f.wire)
			if tt.wantInit {
				if len(methods) != 1 || methods[0] != "initialize" {
					t.Fatalf("sent methods = %v, want [initialize]", methods)
				}
				if _, ok := engineSent(f.wire, initRequestID(tt.viewGen)); !ok {
					t.Fatalf("initialize did not use stream generation %d", tt.viewGen)
				}
			} else if len(f.wire.messages()) != 0 {
				t.Fatalf("unexpected writes: %+v", f.wire.messages())
			}
			got, err := f.cluster.GetBlip(context.Background(), "default", b.Name)
			if err != nil {
				t.Fatal(err)
			}
			if got.Spec.Stop != tt.wantStop {
				t.Fatalf("spec.stop = %v, want %v", got.Spec.Stop, tt.wantStop)
			}
		})
	}
}

func TestEngineCopiedStatePromptFlow(t *testing.T) {
	f := newEngineFixture(t)
	f.wire.autoRespond = true
	f.addBlip(t, 1)
	f.cluster.mu.Lock()
	st := f.cluster.states[key("default", f.name)]
	st.Spec.CopyFrom = "base-state"
	st.Status.Committed = &v1.Commit{ID: "copied-commit", Generation: 1}
	st.Status.Writer.BaseCommit = "copied-commit"
	f.cluster.mu.Unlock()
	f.wire.start(2)
	f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello", Original: "hello"})
	f.start(t)
	waitFor(t, "copied-state prompt", func() bool {
		ids := f.wire.promptIDs()
		return len(ids) == 1 && ids[0] == "p-n1"
	})
	if _, ok := engineSent(f.wire, initRequestID(2)); !ok {
		t.Fatal("first VM did not initialize stream generation 2")
	}
	blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g1")
	if err != nil {
		t.Fatal(err)
	}
	if blip.Spec.Stop {
		t.Fatal("first VM was stopped because its ordinal differs from the stream generation")
	}
	if names := f.cluster.blipNames(); len(names) != 1 {
		t.Fatalf("unexpected retry VMs: %v", names)
	}
}

func TestEngineWriteGenerationWaitsForLogCatchup(t *testing.T) {
	f := newEngineFixture(t)
	f.addBlip(t, 1)
	f.cluster.mu.Lock()
	st := f.cluster.states[key("default", f.name)]
	st.Status.Committed = &v1.Commit{ID: "base", Generation: 8}
	st.Status.Writer.BaseCommit = "base"
	f.cluster.mu.Unlock()
	f.wire.start(9)
	view := newChatView("")
	view.observe(streamLogRecord{Type: recordStart, Gen: 8, Offset: 1})
	view.observe(streamLogRecord{Type: recordNote, Gen: 8, Offset: 2, Data: mustJSON(noteRecord{Type: noteStop})})
	e := &chatEngine{s: f.srv, name: f.name, view: view}
	if err := e.converge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.wire.messages()) != 0 {
		t.Fatal("wrote before the new stream's start record arrived")
	}
	view.observe(streamLogRecord{Type: recordStart, Gen: 9, Offset: 3})
	if err := e.converge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := engineSent(f.wire, initRequestID(9)); !ok {
		t.Fatal("did not initialize after the log caught up")
	}
	if got, _ := f.cluster.GetBlip(context.Background(), "default", f.name+"-g1"); got.Spec.Stop {
		t.Fatal("old stop killed the new stream while catching up")
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
