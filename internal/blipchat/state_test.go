// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// stateRecorder feeds synthetic ring records to a chatView in order, with
// monotonically increasing offsets so conditional-append state behaves like
// the real ring.
type stateRecorder struct {
	t      *testing.T
	view   *chatView
	offset uint64
}

func newStateRecorder(t *testing.T) *stateRecorder {
	t.Helper()
	return &stateRecorder{t: t, view: newChatView(""), offset: 100}
}

func (r *stateRecorder) add(gen uint64, typ streamRecordType, data []byte) uint64 {
	r.offset += streamRecordHeader + uint64(len(data))
	r.view.observe(streamLogRecord{Offset: r.offset, Gen: gen, Type: typ, Data: data})
	return r.offset
}

func (r *stateRecorder) start(gen uint64) uint64 { return r.add(gen, recordStart, nil) }

func (r *stateRecorder) end(gen uint64) uint64 {
	return r.add(gen, recordEnd, mustJSON(map[string]any{"code": 0, "reason": "exit"}))
}

func (r *stateRecorder) note(gen uint64, note noteRecord) uint64 {
	return r.add(gen, recordNote, mustJSON(note))
}

func (r *stateRecorder) in(gen uint64, v any) uint64 {
	return r.add(gen, recordIn, mustJSON(v))
}

func (r *stateRecorder) inRaw(gen uint64, data []byte) uint64 {
	return r.add(gen, recordIn, data)
}

func (r *stateRecorder) out(gen uint64, v any) uint64 {
	data := mustJSON(v)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return r.add(gen, recordOut, data)
}

func (r *stateRecorder) err(gen uint64, text string) uint64 {
	return r.add(gen, recordErr, []byte(text))
}

// stateFrame is the part of a transcript frame these tests inspect.
type stateFrame struct {
	Method   string
	Update   string
	Content  string
	Sender   string
	PromptID string
	Stream   string
	Text     string
}

func decodeStateFrame(t *testing.T, raw json.RawMessage) stateFrame {
	t.Helper()
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				SessionUpdate string          `json:"sessionUpdate"`
				Content       json.RawMessage `json:"content"`
				Sender        string          `json:"sender"`
				PromptID      string          `json:"promptID"`
			} `json:"update"`
			Stream string `json:"stream"`
			Text   string `json:"text"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode transcript frame %s: %v", raw, err)
	}
	return stateFrame{
		Method:   msg.Method,
		Update:   msg.Params.Update.SessionUpdate,
		Content:  contentText(msg.Params.Update.Content),
		Sender:   msg.Params.Update.Sender,
		PromptID: msg.Params.Update.PromptID,
		Stream:   msg.Params.Stream,
		Text:     msg.Params.Text,
	}
}

func stateUserFrames(t *testing.T, transcript []json.RawMessage) []stateFrame {
	t.Helper()
	var out []stateFrame
	for _, raw := range transcript {
		var msg struct {
			Params struct {
				Update struct {
					SessionUpdate string `json:"sessionUpdate"`
				} `json:"update"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &msg) == nil && msg.Params.Update.SessionUpdate == "user_message_chunk" {
			out = append(out, decodeStateFrame(t, raw))
		}
	}
	return out
}

func stateAgentChunk(text string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params": map[string]any{
			"sessionId": "acp-session-1",
			"update": map[string]any{
				"sessionUpdate": "agent_message_chunk",
				"content":       map[string]string{"type": "text", "text": text},
			},
		},
	}
}

func stateSessionInfo(title any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params": map[string]any{
			"sessionId": "acp-session-1",
			"update": map[string]any{
				"sessionUpdate": "session_info_update",
				"title":         title,
			},
		},
	}
}

func TestStatePromptLifecycle(t *testing.T) {
	r := newStateRecorder(t)
	v := r.view
	r.start(1)

	note := noteRecord{Type: notePrompt, ID: "n1", Text: "rendered text", Original: "original text", Sender: "alice"}
	offset := r.note(1, note)
	if len(v.Queued) != 1 {
		t.Fatalf("queued = %v, want one prompt", v.Queued)
	}
	queued := v.Queued[0]
	if queued.ID != "n1" || queued.Text != "rendered text" || queued.Original != "original text" || queued.Sender != "alice" || queued.Offset != offset {
		t.Fatalf("queued prompt = %+v", queued)
	}
	if v.busy() || v.Inflight != nil {
		t.Fatal("prompt note should not be in flight before session/prompt")
	}
	user := stateUserFrames(t, v.Transcript)
	if len(user) != 1 {
		t.Fatalf("user frames = %d, want 1", len(user))
	}
	if user[0].Content != "original text" || user[0].Sender != "alice" || user[0].PromptID != "n1" {
		t.Fatalf("user frame = %+v", user[0])
	}
	turn, ok := v.nextTurn()
	if !ok || turn.ID != "n1" || turn.Text != "rendered text" {
		t.Fatalf("nextTurn = %+v, %v", turn, ok)
	}

	r.in(1, json.RawMessage(promptFrame("n1", "acp-session-1", "rendered text", "original text", "alice")))
	if v.Inflight == nil || v.Inflight.ID != "n1" || v.Inflight.Original != "original text" || v.Inflight.Offset != offset {
		t.Fatalf("inflight = %+v", v.Inflight)
	}
	if got := v.queuedPrompts(); len(got) != 0 {
		t.Fatalf("queuedPrompts while busy = %v", got)
	}
	if _, ok := v.nextTurn(); ok {
		t.Fatal("nextTurn returned work while a prompt is in flight")
	}

	r.out(1, map[string]any{"jsonrpc": "2.0", "id": "p-n1", "result": map[string]any{"stopReason": "end_turn"}})
	if !v.Done["n1"] {
		t.Fatal("prompt should be done after its response")
	}
	if v.Inflight != nil {
		t.Fatalf("inflight = %+v after response", v.Inflight)
	}
	if len(v.Queued) != 0 {
		t.Fatalf("queued = %v after response", v.Queued)
	}
	if _, ok := v.nextTurn(); ok {
		t.Fatal("completed prompt was offered again")
	}
	if v.hasWork() {
		t.Fatal("completed chat still reports work")
	}
}

func TestStateLegacyPrompt(t *testing.T) {
	r := newStateRecorder(t)
	v := r.view
	r.start(1)

	// A log written before note records existed: the session/prompt has a
	// request id but no matching note.
	r.in(1, json.RawMessage(promptFrame("legacy-1", "acp-session-1", "hello from an old log", "", "bob")))
	user := stateUserFrames(t, v.Transcript)
	if len(user) != 1 {
		t.Fatalf("user frames = %d, want 1", len(user))
	}
	if user[0].Content != "hello from an old log" || user[0].Sender != "bob" || user[0].PromptID != "legacy-1" {
		t.Fatalf("legacy user frame = %+v", user[0])
	}
	if len(v.Queued) != 0 || v.busy() {
		t.Fatalf("legacy prompt queued = %v, inflight = %+v", v.Queued, v.Inflight)
	}

	// Malformed input records and unknown prompt ids must not crash the view.
	lastSeq := v.LastSeq
	r.inRaw(1, []byte("{not json"))
	if v.LastSeq <= lastSeq || v.LastSeqGen != 1 {
		t.Fatalf("LastSeq = %d, LastSeqGen = %d after malformed input", v.LastSeq, v.LastSeqGen)
	}
	r.in(1, json.RawMessage(promptFrame("legacy-2", "acp-session-1", "second old message", "", "")))
	if got := len(stateUserFrames(t, v.Transcript)); got != 2 {
		t.Fatalf("user frames = %d, want 2", got)
	}
}

func TestStateCancelAndStop(t *testing.T) {
	t.Run("cancel marks inflight done and blocks resend", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: notePrompt, ID: "n1", Text: "first", Original: "first"})
		r.in(1, json.RawMessage(promptFrame("n1", "acp-session-1", "first", "first", "")))
		if v.Inflight == nil || v.Inflight.ID != "n1" {
			t.Fatalf("inflight = %+v", v.Inflight)
		}

		cancelOffset := r.note(1, noteRecord{Type: noteCancel})
		if v.CancelSeq != cancelOffset {
			t.Fatalf("CancelSeq = %d, want %d", v.CancelSeq, cancelOffset)
		}
		if !v.Done["n1"] {
			t.Fatal("cancel should mark the in-flight prompt done")
		}
		if v.Inflight == nil || v.Inflight.ID != "n1" {
			t.Fatalf("cancel should keep the prompt in flight until its response or end: %+v", v.Inflight)
		}
		if len(v.Queued) != 0 {
			t.Fatalf("cancelled prompt still queued: %v", v.Queued)
		}
		if _, ok := v.nextTurn(); ok {
			t.Fatal("cancelled prompt was offered again before its response")
		}

		// A new prompt queues behind the cancelled turn but cannot start yet.
		r.note(1, noteRecord{Type: notePrompt, ID: "n2", Text: "second", Original: "second"})
		if len(v.Queued) != 1 || v.Queued[0].ID != "n2" {
			t.Fatalf("queued = %v, want n2", v.Queued)
		}
		if _, ok := v.nextTurn(); ok {
			t.Fatal("nextTurn returned work while the cancelled prompt is still in flight")
		}

		// The agent's late response releases the chat.
		r.out(1, map[string]any{"jsonrpc": "2.0", "id": "p-n1", "result": map[string]any{"stopReason": "cancelled"}})
		if v.Inflight != nil {
			t.Fatalf("inflight = %+v after response", v.Inflight)
		}
		turn, ok := v.nextTurn()
		if !ok || turn.ID != "n2" {
			t.Fatalf("nextTurn = %+v, %v, want n2", turn, ok)
		}
	})

	t.Run("cancel drops prompts that were never started", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: notePrompt, ID: "n1", Text: "first", Original: "first"})
		if _, ok := v.nextTurn(); !ok {
			t.Fatal("prompt not offered")
		}
		r.note(1, noteRecord{Type: noteCancel})
		if len(v.Queued) != 0 {
			t.Fatalf("queued = %v after cancel", v.Queued)
		}
		if _, ok := v.nextTurn(); ok {
			t.Fatal("cancel should drop a prompt that had not started")
		}
		if v.hasWork() {
			t.Fatal("cancelled prompt still counts as work")
		}
	})

	t.Run("stop drops older queued prompts and keeps later ones", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: notePrompt, ID: "n0", Text: "inflight", Original: "inflight"})
		r.in(1, json.RawMessage(promptFrame("n0", "acp-session-1", "inflight", "inflight", "")))
		r.note(1, noteRecord{Type: notePrompt, ID: "n1", Text: "queued", Original: "queued"})
		if v.Inflight == nil || len(v.Queued) != 2 {
			t.Fatalf("inflight = %+v, queued = %v", v.Inflight, v.Queued)
		}

		stopOffset := r.note(1, noteRecord{Type: noteStop})
		if v.StopSeq != stopOffset {
			t.Fatalf("StopSeq = %d, want %d", v.StopSeq, stopOffset)
		}
		if v.Inflight != nil {
			t.Fatalf("stop should drop the older in-flight prompt: %+v", v.Inflight)
		}
		if len(v.Queued) != 0 {
			t.Fatalf("stop should drop older queued prompts: %v", v.Queued)
		}

		r.note(1, noteRecord{Type: notePrompt, ID: "n2", Text: "after stop", Original: "after stop"})
		if len(v.Queued) != 1 || v.Queued[0].ID != "n2" {
			t.Fatalf("queued = %v, want only n2", v.Queued)
		}
		turn, ok := v.nextTurn()
		if !ok || turn.ID != "n2" {
			t.Fatalf("nextTurn = %+v, %v, want n2", turn, ok)
		}
	})
}

func TestStateQuestionAnswer(t *testing.T) {
	t.Run("live answer is tracked and waits for ask_user", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: noteQuestion, ID: "q1", Text: "Which one?", Options: []string{"a", " b ", ""}})
		q := v.Question
		if q == nil || q.ID != "q1" || q.Text != "Which one?" {
			t.Fatalf("question = %+v", q)
		}
		if len(q.Options) != 2 || q.Options[0] != "a" || q.Options[1] != "b" {
			t.Fatalf("options = %v, want [a b]", q.Options)
		}
		if v.QuestionGen != 1 || v.Questions["q1"] == nil {
			t.Fatalf("QuestionGen = %d, questions = %v", v.QuestionGen, v.Questions)
		}

		answerOffset := r.note(1, noteRecord{Type: noteAnswer, QID: "q1", Text: "b", Sender: "user", Gen: 1})
		if v.Question != nil {
			t.Fatalf("answer should clear the open question: %+v", v.Question)
		}
		if len(v.Answers) != 1 {
			t.Fatalf("answers = %v, want one", v.Answers)
		}
		answer := v.Answers[0]
		if answer.QID != "q1" || answer.Text != "b" || answer.Sender != "user" || answer.Offset != answerOffset || answer.Gen != 1 {
			t.Fatalf("answer = %+v", answer)
		}
		if _, ok := v.nextTurn(); ok {
			t.Fatal("a live answer should be left for the waiting ask_user call")
		}
	})

	t.Run("consumed answer is not sent again", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: noteQuestion, ID: "q1", Text: "Which one?"})
		r.note(1, noteRecord{Type: noteAnswer, QID: "q1", Text: "a", Sender: "user", Gen: 1})
		r.note(1, noteRecord{Type: noteConsumed, QID: "q1"})
		if !v.Consumed["q1"] {
			t.Fatal("consumed map did not record q1")
		}
		if len(v.Answers) != 0 {
			t.Fatalf("answers = %v after consumed", v.Answers)
		}
		if v.Question != nil {
			t.Fatalf("question = %+v after consumed", v.Question)
		}

		// A late second answer for a consumed question is ignored.
		r.note(1, noteRecord{Type: noteAnswer, QID: "q1", Text: "late", Sender: "user", Gen: 1})
		if len(v.Answers) != 0 {
			t.Fatalf("answers = %v after a late consumed answer", v.Answers)
		}
		if _, ok := v.nextTurn(); ok {
			t.Fatal("consumed answer was offered as a turn")
		}
	})

	t.Run("expired question delivers the answer as a stale prompt", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: noteQuestion, ID: "q2", Text: "Which option?"})
		answerOffset := r.note(1, noteRecord{Type: noteAnswer, QID: "q2", Text: "b", Sender: "user", Gen: 1})
		r.note(1, noteRecord{Type: noteExpire, QID: "q2"})
		if !v.Expired["q2"] {
			t.Fatal("expire map did not record q2")
		}
		if v.Question != nil {
			t.Fatalf("question = %+v after expire", v.Question)
		}

		turn, ok := v.nextTurn()
		if !ok {
			t.Fatal("expired answer was not offered as a turn")
		}
		want := fmt.Sprintf("Answer to your question %q: %s", "Which option?", "b")
		if turn.ID != fmt.Sprintf("answer-%d", answerOffset) {
			t.Fatalf("turn id = %q, want answer-%d", turn.ID, answerOffset)
		}
		if turn.Text != want {
			t.Fatalf("turn text = %q, want %q", turn.Text, want)
		}
		if turn.Original != "b" || turn.Sender != "user" || turn.Offset != answerOffset {
			t.Fatalf("turn = %+v", turn)
		}
		if !v.hasWork() {
			t.Fatal("stale answer should count as work")
		}

		// Delivering it as a turn consumes the answer.
		r.in(1, json.RawMessage(promptFrame(turn.ID, "acp-session-1", turn.Text, turn.Original, turn.Sender)))
		if v.Inflight == nil || v.Inflight.ID != turn.ID {
			t.Fatalf("inflight = %+v", v.Inflight)
		}
		r.out(1, map[string]any{"jsonrpc": "2.0", "id": "p-" + turn.ID, "result": map[string]any{}})
		if len(v.Answers) != 0 || v.Inflight != nil {
			t.Fatalf("answers = %v, inflight = %+v after delivery", v.Answers, v.Inflight)
		}
	})

	t.Run("answer from an older generation is stale", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: noteQuestion, ID: "q3", Text: "Old question?"})
		r.note(1, noteRecord{Type: noteAnswer, QID: "q3", Text: "old answer", Sender: "user", Gen: 1})
		r.start(2)
		turn, ok := v.nextTurn()
		if !ok {
			t.Fatal("answer from the previous generation was not offered as a turn")
		}
		want := fmt.Sprintf("Answer to your question %q: %s", "Old question?", "old answer")
		if turn.Text != want {
			t.Fatalf("turn text = %q, want %q", turn.Text, want)
		}
	})
}

func TestStateReplyAndTranscript(t *testing.T) {
	t.Run("reply chunks and title", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.note(1, noteRecord{Type: notePrompt, ID: "n1", Text: "hi", Original: "hi"})
		r.in(1, json.RawMessage(promptFrame("n1", "acp-session-1", "hi", "hi", "")))

		r.out(1, stateAgentChunk("Hello, "))
		r.out(1, stateAgentChunk("world"))
		if v.Reply != "Hello, world" {
			t.Fatalf("reply = %q", v.Reply)
		}
		if got := len(v.Transcript); got != 3 {
			t.Fatalf("transcript len = %d, want user frame plus two chunks", got)
		}

		titleOffset := r.out(1, stateSessionInfo("A chat"))
		if !v.HasTitle || v.Title != "A chat" || v.TitleSeq != titleOffset {
			t.Fatalf("title = %q, has = %v, seq = %d (record %d)", v.Title, v.HasTitle, v.TitleSeq, titleOffset)
		}
		r.out(1, stateSessionInfo(nil))
		if !v.HasTitle || v.Title != "" {
			t.Fatalf("title after null = %q, has = %v", v.Title, v.HasTitle)
		}

		r.err(1, "warning\n")
		if len(v.Transcript) == 0 {
			t.Fatal("stderr did not produce a transcript frame")
		}
		out := decodeStateFrame(t, v.Transcript[len(v.Transcript)-1])
		if out.Method != "blip/output" || out.Stream != "stderr" || out.Text != "warning\n" {
			t.Fatalf("stderr frame = %+v", out)
		}
	})

	t.Run("reply is capped", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		r.out(1, stateAgentChunk(strings.Repeat("x", maxReplyBytes+512)))
		if len(v.Reply) != maxReplyBytes {
			t.Fatalf("reply length = %d, want %d", len(v.Reply), maxReplyBytes)
		}
		r.out(1, stateAgentChunk("more"))
		if len(v.Reply) != maxReplyBytes {
			t.Fatalf("reply length = %d after another chunk, want %d", len(v.Reply), maxReplyBytes)
		}
	})

	t.Run("transcript is capped", func(t *testing.T) {
		r := newStateRecorder(t)
		v := r.view
		r.start(1)
		for i := 0; i < maxTranscriptMessages+10; i++ {
			r.err(1, "tick")
		}
		if len(v.Transcript) != maxTranscriptMessages {
			t.Fatalf("transcript len = %d, want %d", len(v.Transcript), maxTranscriptMessages)
		}
		if !v.Truncated {
			t.Fatal("transcript should be marked truncated")
		}
		r.err(1, "after")
		if len(v.Transcript) != maxTranscriptMessages {
			t.Fatalf("transcript grew past the cap: %d", len(v.Transcript))
		}

		// The byte cap is independent of the message cap.
		v2 := newChatView("")
		r2 := &stateRecorder{t: t, view: v2, offset: 100}
		r2.start(1)
		v2.TranscriptBytes = maxTranscriptBytes
		r2.err(1, "over")
		// The newest message is kept even when it is the only one, but the
		// transcript is flagged as truncated.
		if len(v2.Transcript) != 1 || !v2.Truncated {
			t.Fatalf("byte cap: transcript len = %d, truncated = %v", len(v2.Transcript), v2.Truncated)
		}
	})
}

func TestStateCanWriteGenerations(t *testing.T) {
	r := newStateRecorder(t)
	v := r.view
	if _, ok := v.canWrite(); ok {
		t.Fatal("canWrite should be false before any input")
	}
	r.start(1)
	if _, ok := v.canWrite(); ok {
		t.Fatal("canWrite should be false until the generation writes input")
	}

	noteOffset := r.note(1, noteRecord{Type: notePrompt, ID: "n1", Text: "hi", Original: "hi"})
	if n, ok := v.canWrite(); !ok || n != noteOffset || v.LastSeqGen != 1 {
		t.Fatalf("canWrite = %d, %v (LastSeqGen %d)", n, ok, v.LastSeqGen)
	}

	initOffset := r.in(1, json.RawMessage(initializeFrame(1)))
	if initOffset <= noteOffset {
		t.Fatalf("input offset %d did not advance past note offset %d", initOffset, noteOffset)
	}
	if n, ok := v.canWrite(); !ok || n != initOffset {
		t.Fatalf("canWrite = %d, %v after input", n, ok)
	}

	// Build up per-generation state to prove a new start resets it.
	r.in(1, json.RawMessage(newSessionFrame(1, "/", nil)))
	r.out(1, map[string]any{"jsonrpc": "2.0", "id": "g1-session", "result": map[string]any{"sessionId": "s1"}})
	r.in(1, json.RawMessage(promptFrame("n1", "s1", "hi", "hi", "")))
	if !v.InitSent || !v.SessionSent || !v.SessionReady || v.Inflight == nil {
		t.Fatalf("init = %v, session sent = %v, ready = %v, inflight = %+v",
			v.InitSent, v.SessionSent, v.SessionReady, v.Inflight)
	}

	r.start(2)
	if v.Gen != 2 || !v.Started || v.Ended {
		t.Fatalf("generation = %d, started = %v, ended = %v", v.Gen, v.Started, v.Ended)
	}
	if v.InitSent || v.InitDone || v.SessionSent || v.SessionReady || v.SessionFailed || v.Inflight != nil || v.Permission != nil {
		t.Fatalf("per-generation state survived: %+v", v)
	}
	if _, ok := v.canWrite(); ok {
		t.Fatalf("canWrite should be false for gen %d while LastSeqGen is %d", v.Gen, v.LastSeqGen)
	}

	note2 := r.note(2, noteRecord{Type: notePrompt, ID: "n2", Text: "again", Original: "again"})
	if v.LastSeqGen != 2 {
		t.Fatalf("LastSeqGen = %d, want 2", v.LastSeqGen)
	}
	if n, ok := v.canWrite(); !ok || n != note2 {
		t.Fatalf("canWrite = %d, %v in the new generation", n, ok)
	}
}

func TestStateAnswerSurvivesGenerationEnd(t *testing.T) {
	r := newStateRecorder(t)
	v := r.view
	r.start(1)
	r.note(1, noteRecord{Type: noteQuestion, ID: "q1", Text: "Proceed?"})
	if v.Question == nil {
		t.Fatal("question not recorded")
	}
	// A replica can die while ask_user waits. The answer is written by
	// another replica after the turn already ended.
	gen := v.questionGen(v.Question.ID)
	r.end(1)
	r.note(1, noteRecord{Type: noteAnswer, QID: "q1", Text: "yes", Sender: "user", Gen: gen})
	if _, ok := v.pendingAnswer(); !ok {
		t.Fatal("answer after the turn ended must still be delivered")
	}
	if !v.hasWork() {
		t.Fatal("stale answer should count as work")
	}
	r.start(2)
	turn, ok := v.nextTurn()
	if !ok || turn.Original != "yes" {
		t.Fatalf("nextTurn = %+v, %v", turn, ok)
	}
	if !strings.Contains(turn.Text, `Answer to your question "Proceed?"`) {
		t.Fatalf("answer prompt = %q", turn.Text)
	}
}
