// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMessageOfflineStopIntegration(t *testing.T) {
	for _, question := range []bool{false, true} {
		name := "full_queue"
		if question {
			name = "question_without_end"
		}
		t.Run(name, func(t *testing.T) {
			s, wire, handler := newQueueAdmissionServer(t, maxQueue)
			close(wire.release)
			if question {
				// An abnormal guest exit can leave a question with no end
				// record to retire it. The offline stop must do so instead.
				wire.note(noteRecord{Type: noteQuestion, ID: "abandoned", Text: "Old question?"})
			}
			s.wire = &runningWire{fakeWire: wire.fakeWire, cluster: s.cluster.(*fakeCluster)}
			req := httptest.NewRequest(http.MethodPost, "/api/sessions/queue-test/stop", nil)
			req.Header.Set("X-Forwarded-User", "alice")
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != http.StatusAccepted {
				t.Fatalf("offline stop status=%d body=%s", resp.Code, resp.Body.String())
			}
			st, err := s.cluster.GetSession(context.Background(), "default", "queue-test")
			if err != nil {
				t.Fatal(err)
			}
			if stopBefore(st) == 0 {
				t.Fatal("offline stop did not persist its exclusive ring boundary")
			}
			if got := postQueueMessage(handler); got != http.StatusAccepted {
				t.Fatalf("message after offline stop status=%d, want 202", got)
			}
			if hasNote(wire.notes(), noteAnswer, nil) {
				t.Error("new message answered the question abandoned before the stop")
			}
			if !hasNote(wire.notes(), notePrompt, func(n noteRecord) bool { return n.Original == "hello" }) {
				t.Error("message after offline stop did not become a new prompt")
			}
			view, err := s.messageView(context.Background(), st)
			if err != nil {
				t.Fatal(err)
			}
			if len(view.Queued) != 1 || view.Question != nil {
				t.Errorf("stopped work reappeared: queued=%d question=%+v", len(view.Queued), view.Question)
			}
			if question && (!view.Expired["abandoned"] || view.Questions["abandoned"] == nil) {
				t.Error("stopped question was not retired while preserving its history")
			}
		})
	}
}

func TestMessageStopBoundaryRefreshesAfterConflict(t *testing.T) {
	s, wire, handler := newQueueAdmissionServer(t, maxQueue-1)
	results := make(chan int, 1)
	go func() { results <- postQueueMessage(handler) }()
	select {
	case <-wire.entered:
	case <-time.After(5 * time.Second):
		close(wire.release)
		t.Fatal("prompt did not reach append barrier")
	}
	// Another input invalidates this request's CAS snapshot. An offline stop
	// then cancels that now-full queue without appending a stop note.
	wire.note(noteRecord{Type: notePrompt, ID: "last-slot", Text: "cancelled"})
	before, err := wire.LogEnd(context.Background(), "default", "queue-test")
	if err != nil {
		close(wire.release)
		t.Fatal(err)
	}
	if err := s.cluster.RecordStop(context.Background(), "default", "queue-test", before); err != nil {
		close(wire.release)
		t.Fatal(err)
	}
	close(wire.release)
	select {
	case got := <-results:
		if got != http.StatusAccepted {
			t.Fatalf("message after conflicting stop status=%d, want 202", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message did not finish after append barrier release")
	}
}

func TestStopBoundaryRetiresOnlyEarlierQuestions(t *testing.T) {
	for _, loadBeforeReplay := range []bool{false, true} {
		name := "after_replay"
		if loadBeforeReplay {
			name = "before_replay"
		}
		t.Run(name, func(t *testing.T) {
			v := newChatView("")
			if loadBeforeReplay {
				v.applyStopBefore(20)
			}
			v.observe(streamLogRecord{Type: recordNote, Gen: 1, Offset: 10, Data: mustJSON(noteRecord{Type: noteQuestion, ID: "old"})})
			v.applyStopBefore(20)
			if v.Question != nil || !v.Expired["old"] || v.Questions["old"] == nil {
				t.Errorf("old question was not retired with history preserved: question=%+v expired=%v", v.Question, v.Expired)
			}
			for _, offset := range []uint64{20, 21} {
				v.observe(streamLogRecord{Type: recordNote, Gen: 1, Offset: offset, Data: mustJSON(noteRecord{Type: noteQuestion, ID: "fresh"})})
				v.applyStopBefore(20)
				if v.Question == nil || v.Question.ID != "fresh" || v.Expired["fresh"] {
					t.Fatalf("exclusive stop boundary retired a question at offset %d", offset)
				}
			}
		})
	}
}
