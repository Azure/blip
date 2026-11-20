// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestQuestionLifecycleClosesOpenQuestion(t *testing.T) {
	for _, event := range []string{"cancel", "stop", "end", "new generation"} {
		t.Run(event, func(t *testing.T) {
			r := newStateRecorder(t)
			r.start(1)
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-old", Text: "Old question?"})
			gen := uint64(1)
			switch event {
			case "cancel":
				r.note(1, noteRecord{Type: noteCancel})
			case "stop":
				r.note(1, noteRecord{Type: noteStop})
			case "end":
				r.end(1)
			case "new generation":
				gen = 2
				r.start(gen)
			}
			if q := r.view.Question; q != nil {
				t.Errorf("%s left question %q open", event, q.ID)
			}
			if !r.view.Expired["q-old"] || r.view.Questions["q-old"] == nil {
				t.Errorf("%s did not retire the question while preserving its history", event)
			}

			// Cleanup from the abandoned call must not close a later question,
			// including a question in the same generation after cancellation.
			if r.view.Ended {
				gen++
				r.start(gen)
			}
			r.note(gen, noteRecord{Type: noteQuestion, ID: "q-fresh", Text: "Fresh question?"})
			r.note(gen, noteRecord{Type: noteExpire, QID: "q-old"})
			if q := r.view.Question; q == nil || q.ID != "q-fresh" {
				t.Fatalf("old expiration changed the fresh question: %+v", q)
			}
		})
	}
}

func TestQuestionLifecycleGenerationReplay(t *testing.T) {
	r := newStateRecorder(t)
	r.start(1)
	r.note(1, noteRecord{Type: noteQuestion, ID: "q-old", Text: "Old question?"})
	// Observing any newer-generation record advances the view. Its explicit
	// start must not then retire a question already observed in that generation.
	r.note(2, noteRecord{Type: noteQuestion, ID: "q-fresh", Text: "Fresh question?"})
	r.start(2)
	if q := r.view.Question; q == nil || q.ID != "q-fresh" {
		t.Fatalf("same-generation start retired the fresh question: %+v", q)
	}
	if !r.view.Expired["q-old"] || r.view.Expired["q-fresh"] {
		t.Fatalf("expired questions = %+v", r.view.Expired)
	}
	r.note(2, noteRecord{Type: noteExpire, QID: "q-old"})
	if q := r.view.Question; q == nil || q.ID != "q-fresh" {
		t.Fatalf("old-generation cleanup retired the fresh question: %+v", q)
	}
}

func TestQuestionLifecyclePreservesHistoricalAnswers(t *testing.T) {
	for _, event := range []string{"cancel", "stop", "end", "new generation"} {
		t.Run(event, func(t *testing.T) {
			r := newStateRecorder(t)
			r.start(1)
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-answered", Text: "Answered question?"})
			r.note(1, noteRecord{Type: noteAnswer, QID: "q-answered", Text: "Keep this answer", Gen: 1})
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-open", Text: "Open question?"})
			switch event {
			case "cancel":
				r.note(1, noteRecord{Type: noteCancel})
			case "stop":
				r.note(1, noteRecord{Type: noteStop})
			case "end":
				r.end(1)
			case "new generation":
				r.start(2)
			}
			if len(r.view.Answers) != 1 || r.view.Answers[0].Text != "Keep this answer" {
				t.Fatalf("%s changed historical answers: %+v", event, r.view.Answers)
			}
			if r.view.Questions["q-answered"] == nil || r.view.Questions["q-open"] == nil {
				t.Fatalf("%s removed question history: %+v", event, r.view.Questions)
			}
			r.start(2)
			if turn, ok := r.view.nextTurn(); !ok || turn.Original != "Keep this answer" {
				t.Fatalf("historical answer unavailable in next generation: %+v, %t", turn, ok)
			}
		})
	}
}

func TestQuestionLifecycleNextMessageIsPrompt(t *testing.T) {
	for _, event := range []string{"cancel", "stop", "end"} {
		t.Run(event, func(t *testing.T) {
			g := newGateway(t, Options{})
			name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
			g.addRunningBlip(t, name)
			g.wire.note(noteRecord{Type: noteQuestion, ID: "q-old", Text: "Old question?"})
			if event == "end" {
				g.wire.end(1)
				g.srv.invalidateView(name)
			} else {
				resp := g.request(t, "POST", "/api/sessions/"+name+"/"+event, nil, "alice", nil)
				resp.Body.Close()
				if resp.StatusCode != http.StatusAccepted {
					t.Fatalf("%s: status %d", event, resp.StatusCode)
				}
			}

			resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": "Start a new task"}, "alice", nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("message: status %d", resp.StatusCode)
			}
			notes := g.wire.notes()
			if hasNote(notes, noteAnswer, func(n noteRecord) bool { return n.QID == "q-old" }) {
				t.Errorf("message after %s was misrouted as an answer: %+v", event, notes)
			}
			if !hasNote(notes, notePrompt, func(n noteRecord) bool { return n.Original == "Start a new task" }) {
				t.Errorf("message after %s did not become a new prompt: %+v", event, notes)
			}
		})
	}
}

func TestQuestionLifecycleLateCleanupPreservesFreshQuestion(t *testing.T) {
	for _, kind := range []string{noteExpire, noteConsumed, noteAnswer} {
		t.Run(kind, func(t *testing.T) {
			r := newStateRecorder(t)
			r.start(1)
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-old", Text: "Old question?"})
			r.note(1, noteRecord{Type: noteCancel})
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-fresh", Text: "Fresh question?"})
			r.note(1, noteRecord{Type: kind, QID: "q-old"})
			if q := r.view.Question; q == nil || q.ID != "q-fresh" {
				t.Fatalf("late %s changed the fresh question: %+v", kind, q)
			}
		})
	}
}

func TestQuestionLifecycleCancelStopEmitsStatus(t *testing.T) {
	for _, kind := range []string{noteCancel, noteStop} {
		t.Run(kind, func(t *testing.T) {
			r := newStateRecorder(t)
			r.start(1)
			r.note(1, noteRecord{Type: noteQuestion, ID: "q-old", Text: "Old question?"})
			note := noteRecord{Type: kind}
			offset := r.note(1, note)
			events := eventsFor(streamLogRecord{Offset: offset, Gen: 1, Type: recordNote, Data: mustJSON(note)}, r.view)
			for _, event := range events {
				if event.Type == "status" && event.Status != nil && event.Status.Question == nil {
					return
				}
			}
			t.Fatalf("%s did not emit a status clearing the question: %+v", kind, events)
		})
	}
}

// cancelQuestionWire cancels the caller immediately after the question is
// durably appended. Unlike fakeWire, it rejects writes on a cancelled context,
// so cleanup must use a context that outlives the abandoned MCP request.
type cancelQuestionWire struct {
	Wire
	onQuestion func(string)
	onExpire   func(context.Context)
}

func (w *cancelQuestionWire) Send(ctx context.Context, namespace, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	off, err := w.Wire.Send(ctx, namespace, state, data, eof, note, after)
	if err == nil && note {
		var n noteRecord
		if json.Unmarshal(data, &n) == nil && n.Type == noteQuestion {
			w.onQuestion(n.ID)
		} else if n.Type == noteExpire {
			w.onExpire(ctx)
		}
	}
	return off, err
}

func TestQuestionLifecycleCancelledMCPExpiresOnlyOwnQuestion(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		name := "no replacement"
		if fresh {
			name = "fresh question already opened"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fw := newFakeWire()
			fw.start(1)
			var qid string
			wire := &cancelQuestionWire{Wire: fw, onQuestion: func(id string) {
				qid = id
				if fresh {
					fw.note(noteRecord{Type: noteQuestion, ID: "q-fresh", Text: "Fresh question?"})
				}
				cancel()
			}, onExpire: func(cleanupCtx context.Context) {
				deadline, ok := cleanupCtx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > cancelTimeout {
					t.Errorf("cleanup context must have a bounded, live deadline: %v, %t", deadline, ok)
				}
			}}
			s, err := New(Options{Cluster: newFakeCluster(), Wire: wire, Log: testLogger()})
			if err != nil {
				t.Fatal(err)
			}
			defer s.cancel()
			st := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "chat-root"}}
			// Keep the test synchronous: there is no work for a driver to do.
			s.engines[st.Name] = &chatEngine{}
			_, err = s.toolAskUser(ctx, &Caller{Session: st}, "Old question?", nil)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ask_user error = %v, want context.Canceled", err)
			}
			if qid == "" {
				t.Fatal("ask_user did not append its question")
			}
			if !hasNote(fw.notes(), noteExpire, func(n noteRecord) bool { return n.QID == qid }) {
				t.Errorf("cancelled ask_user did not durably expire its question: %+v", fw.notes())
			}
			s.invalidateView(st.Name)
			q := s.readView(context.Background(), st).Question
			if fresh {
				if q == nil || q.ID != "q-fresh" {
					t.Errorf("old MCP cleanup changed the fresh question: %+v", q)
				}
			} else if q != nil {
				t.Errorf("cancelled ask_user left question %q open", q.ID)
			}
		})
	}
}
