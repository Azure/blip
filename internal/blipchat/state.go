// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A chat's durable state is the trajectory ring of its BlipState. Blipchat
// writes user intent as "note" records next to the ACP traffic. When no writer
// is attached, a stop boundary on the BlipState cancels older queued work.
// No durable state lives in the blipchat pod.
const (
	maxTranscriptMessages = 10000
	maxTranscriptBytes    = 16 << 20
	maxQuestionBytes      = 4000
	maxQuestionOptions    = 8
	maxReplyBytes         = 64 << 10
)

// Note kinds stored as recordNote payloads. A note is not part of the ACP
// conversation; the agent never sees it.
const (
	notePrompt   = "prompt"
	noteCancel   = "cancel"
	noteStop     = "stop"
	noteQuestion = "question"
	noteAnswer   = "answer"
	noteConsumed = "consumed"
	noteExpire   = "expire"
)

// noteRecord is the JSON payload of a recordNote record.
type noteRecord struct {
	Type     string   `json:"t"`
	ID       string   `json:"id,omitempty"`
	Text     string   `json:"text,omitempty"`
	Original string   `json:"orig,omitempty"`
	Sender   string   `json:"sender,omitempty"`
	QID      string   `json:"qid,omitempty"`
	Options  []string `json:"options,omitempty"`
	// Gen is the generation that asked the question an answer belongs to. An
	// answer from an older generation can no longer be consumed by a waiting
	// ask_user call, so it is delivered as the next prompt instead.
	Gen uint64 `json:"gen,omitempty"`
}

// Question is an ask_user question waiting for the user.
type Question struct {
	ID      string    `json:"id"`
	Text    string    `json:"question"`
	Options []string  `json:"options,omitempty"`
	AskedAt time.Time `json:"askedAt,omitzero"`
}

func (q *Question) clone() *Question {
	if q == nil {
		return nil
	}
	c := *q
	c.Options = append([]string(nil), q.Options...)
	return &c
}

func cleanOptions(options []string) []string {
	out := make([]string, 0, len(options))
	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		out = append(out, shorten(option, 200))
		if len(out) == maxQuestionOptions {
			break
		}
	}
	return out
}

func shorten(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-1]) + "…"
}

// promptRef is a prompt note that has not completed yet.
type promptRef struct {
	ID       string
	Text     string
	Original string
	Sender   string
	Offset   uint64
	// Sent is the ring offset of the session/prompt frame, when one exists.
	// Cancel only abandons a prompt the engine actually sent.
	Sent uint64
}

// answerRef is an answer note that the agent has not consumed or received.
type answerRef struct {
	QID    string
	Text   string
	Sender string
	Offset uint64
	Gen    uint64
}

// permissionRef is an agent request that blipchat answers itself.
type permissionRef struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
}

// chatView is everything blipchat knows about a chat, derived only from the
// ring. It is rebuilt by replaying the log and then updated incrementally.
type chatView struct {
	Gen     uint64
	Started bool
	Ended   bool
	// StartSeq is the offset of the start record for Gen.
	StartSeq uint64
	// Newest is the offset of the newest record of any kind.
	Newest uint64

	// LastSeq is the offset of the newest input record (in or note). It is
	// used for conditional appends, but only while LastSeqGen == Gen because
	// the node starts counting input records again for each attachment.
	LastSeq    uint64
	LastSeqGen uint64

	InitSent  bool
	InitDone  bool
	CanResume bool

	SessionSent     bool
	SessionReady    bool
	SessionFailed   bool
	SessionMethod   string
	SessionFallback bool
	SessionID       string

	Inflight     *promptRef
	Queued       []promptRef
	Done         map[string]bool
	Answers      []answerRef
	Consumed     map[string]bool
	Expired      map[string]bool
	Questions    map[string]*Question
	QuestionGens map[string]uint64
	Question     *Question
	QuestionGen  uint64
	Permission   *permissionRef

	CancelSeq    uint64
	LastCancelIn uint64
	StopSeq      uint64
	stopBefore   uint64

	Title     string
	TitleSeq  uint64
	outOffset uint64
	HasTitle  bool

	Reply           string
	Transcript      []json.RawMessage
	TranscriptBytes int
	Truncated       bool
	Gapped          bool

	outBuf  []byte
	noteIDs map[string]bool
	// emitted holds the transcript frames produced by the record most
	// recently passed to observe. Event streams use it to forward only what
	// that record added.
	emitted []json.RawMessage
}

func newChatView(sessionID string) *chatView {
	return &chatView{
		SessionID: sessionID,
		Done:      map[string]bool{},
		Consumed:  map[string]bool{},
		Expired:   map[string]bool{},
		Questions: map[string]*Question{},
		noteIDs:   map[string]bool{},
	}
}

// observe folds one log record into the view. It records the transcript
// frames the record produced in emitted.
func (v *chatView) observe(rec streamLogRecord) {
	v.emitted = v.emitted[:0]
	if rec.Offset > v.Newest {
		v.Newest = rec.Offset
	}
	if rec.Type == recordGap {
		v.Gapped = true
		v.Truncated = true
		return
	}
	if rec.Gen > v.Gen {
		v.startGeneration(rec.Gen)
	}
	switch rec.Type {
	case recordStart:
		v.startGeneration(rec.Gen)
		v.StartSeq = rec.Offset
		v.Started = true
	case recordEnd:
		v.retireQuestion(rec.Gen)
		v.Ended = true
		v.Started = false
		v.Inflight = nil
		v.Permission = nil
		v.outBuf = nil
	case recordIn:
		v.observeIn(rec)
	case recordOut:
		v.observeOut(rec)
	case recordErr:
		v.appendTranscript(outputFrame("stderr", string(rec.Data)))
	case recordNote:
		v.observeNote(rec)
		v.applyStopBefore(v.stopBefore)
	}
}

func (v *chatView) startGeneration(gen uint64) {
	if gen == v.Gen && v.Started {
		return
	}
	if gen > v.Gen {
		v.retireQuestion(v.Gen)
	}
	v.Gen = gen
	v.Started = false
	v.Ended = false
	v.InitSent = false
	v.InitDone = false
	v.CanResume = false
	v.SessionSent = false
	v.SessionReady = false
	v.SessionFailed = false
	v.SessionMethod = ""
	v.SessionFallback = false
	v.Inflight = nil
	v.Permission = nil
	v.outBuf = nil
}

func (v *chatView) observeIn(rec streamLogRecord) {
	v.LastSeq, v.LastSeqGen = rec.Offset, rec.Gen
	line := bytes.TrimSpace(rec.Data)
	if len(line) == 0 {
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return
	}
	id := rawID(msg.ID)
	if msg.Method == "" {
		v.observeResponse(id, msg)
		return
	}
	switch {
	case msg.Method == "initialize":
		v.InitSent = true
	case msg.Method == "session/new", msg.Method == "session/resume", msg.Method == "session/load":
		v.SessionSent = true
		v.SessionMethod = msg.Method
		if msg.Method == "session/new" && v.SessionFailed {
			v.SessionFallback = true
		}
	case msg.Method == "session/cancel":
		v.LastCancelIn = rec.Offset
	case msg.Method == "session/prompt":
		v.Reply = ""
		promptID := promptIDFromPrompt(msg.Params)
		if promptID == "" {
			promptID = strings.TrimPrefix(id, "p-")
		}
		if strings.HasPrefix(promptID, "answer-") {
			// A stale answer delivered as its own turn. The user's text is
			// already in the transcript from the answer note.
			if !v.Done[promptID] {
				for i := range v.Answers {
					if fmt.Sprintf("answer-%d", v.Answers[i].Offset) == promptID {
						a := v.Answers[i]
						v.Inflight = &promptRef{ID: promptID, Text: a.Text, Original: a.Text, Sender: a.Sender, Offset: a.Offset}
						break
					}
				}
			}
		} else if promptID != "" && !v.noteIDs[promptID] {
			// A log written before note records existed: show the prompt the
			// agent received as the user's message.
			if text, sender := userTextFromPrompt(msg.Params); text != "" {
				v.appendTranscript(userFrame(text, sender, promptID))
			}
		} else if promptID != "" && !v.Done[promptID] {
			for i := range v.Queued {
				if v.Queued[i].ID == promptID {
					// Copy rather than point into Queued: removing a prompt
					// reuses the slice's backing array, which would silently
					// change an aliased Inflight to a different prompt.
					ref := v.Queued[i]
					ref.Sent = rec.Offset
					v.Inflight = &ref
					break
				}
			}
		}
	case msg.Method == "session/request_permission":
		// blipchat answering the agent, never written by blipchat as a request.
	}
}

func (v *chatView) observeOut(rec streamLogRecord) {
	v.outOffset = rec.Offset
	v.outBuf = append(v.outBuf, rec.Data...)
	for {
		i := bytes.IndexByte(v.outBuf, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimSpace(v.outBuf[:i])
		v.outBuf = v.outBuf[i+1:]
		v.observeLine(line)
	}
	if len(v.outBuf) > acpMaxLine {
		v.outBuf = nil
	}
}

func (v *chatView) observeLine(line []byte) {
	if len(line) == 0 {
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		v.appendTranscript(outputLineFrame(line))
		return
	}
	if msg.Method == "" {
		v.observeResponse(rawID(msg.ID), msg)
		// Responses carry stop reasons and similar turn metadata the UI uses
		// to separate bubbles. Old replays kept them too.
		v.appendTranscript(line)
		return
	}
	switch msg.Method {
	case "session/update":
		v.observeUpdate(line, msg.Params)
	case "session/request_permission":
		v.Permission = &permissionRef{ID: msg.ID, Method: msg.Method, Params: msg.Params}
	default:
		if len(bytes.TrimSpace(msg.ID)) > 0 {
			v.Permission = &permissionRef{ID: msg.ID, Method: msg.Method, Params: msg.Params}
		} else {
			v.appendTranscript(line)
		}
	}
}

func (v *chatView) observeUpdate(line []byte, params json.RawMessage) {
	var p struct {
		Update struct {
			SessionUpdate string          `json:"sessionUpdate"`
			Content       json.RawMessage `json:"content"`
			Title         json.RawMessage `json:"title"`
		} `json:"update"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		v.appendTranscript(line)
		return
	}
	switch p.Update.SessionUpdate {
	case "agent_message_chunk":
		text := contentText(p.Update.Content)
		if len(v.Reply) < maxReplyBytes {
			v.Reply += text
			if len(v.Reply) > maxReplyBytes {
				v.Reply = v.Reply[:maxReplyBytes]
			}
		}
		v.appendTranscript(line)
	case "user_message_chunk":
		// Rendered from notes, or from in/session/prompt for old logs.
	case "session_info_update":
		if len(p.Update.Title) > 0 {
			v.TitleSeq = v.outOffset
			v.HasTitle = true
			if string(p.Update.Title) == "null" {
				v.Title = ""
			} else {
				var title string
				if json.Unmarshal(p.Update.Title, &title) == nil {
					v.Title = shorten(strings.TrimSpace(title), 200)
				}
			}
		}
		v.appendTranscript(line)
	default:
		v.appendTranscript(line)
	}
}

func (v *chatView) observeResponse(id string, msg rpcMessage) {
	if v.Permission != nil && rawID(v.Permission.ID) == id {
		v.Permission = nil
	}
	switch {
	case id == fmt.Sprintf("g%d-init", v.Gen):
		v.InitDone = true
		if msg.Error == nil {
			var caps struct {
				LoadSession         bool `json:"loadSession"`
				SessionCapabilities struct {
					Resume json.RawMessage `json:"resume"`
				} `json:"sessionCapabilities"`
			}
			if json.Unmarshal(msg.Result, &caps) == nil {
				v.CanResume = caps.LoadSession || len(bytes.TrimSpace(caps.SessionCapabilities.Resume)) > 0
			}
		}
	case id == fmt.Sprintf("g%d-session", v.Gen), id == fmt.Sprintf("g%d-session-new", v.Gen):
		if msg.Error != nil {
			v.SessionFailed = true
			return
		}
		v.SessionFailed = false
		v.SessionReady = true
		var result struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(msg.Result, &result) == nil && result.SessionID != "" {
			v.SessionID = result.SessionID
		}
	case strings.HasPrefix(id, "p-answer-"):
		key := strings.TrimPrefix(id, "p-")
		v.Done[key] = true
		v.removeAnswer(key)
		if v.Inflight != nil && v.Inflight.ID == key {
			v.Inflight = nil
		}
	case strings.HasPrefix(id, "p-"):
		promptID := strings.TrimPrefix(id, "p-")
		v.Done[promptID] = true
		v.removePrompt(promptID)
		if v.Inflight != nil && v.Inflight.ID == promptID {
			v.Inflight = nil
		}
	}
}

func (v *chatView) removePrompt(id string) {
	kept := v.Queued[:0]
	for _, ref := range v.Queued {
		if ref.ID == id {
			continue
		}
		kept = append(kept, ref)
	}
	v.Queued = kept
}

func (v *chatView) removeAnswer(key string) {
	kept := v.Answers[:0]
	for _, a := range v.Answers {
		if fmt.Sprintf("answer-%d", a.Offset) == key {
			continue
		}
		kept = append(kept, a)
	}
	v.Answers = kept
}

func (v *chatView) observeNote(rec streamLogRecord) {
	v.LastSeq, v.LastSeqGen = rec.Offset, rec.Gen
	var note noteRecord
	if err := json.Unmarshal(bytes.TrimSpace(rec.Data), &note); err != nil {
		return
	}
	switch note.Type {
	case notePrompt:
		if note.ID == "" {
			note.ID = fmt.Sprintf("n%d", rec.Offset)
		}
		v.noteIDs[note.ID] = true
		ref := promptRef{ID: note.ID, Text: note.Text, Original: note.Original, Sender: note.Sender, Offset: rec.Offset}
		if !v.Done[note.ID] {
			v.Queued = append(v.Queued, ref)
		}
		v.appendTranscript(userFrame(promptDisplayText(note), note.Sender, note.ID))
	case noteAnswer:
		qid := note.QID
		if note.QID == "" {
			qid = fmt.Sprintf("q%d", rec.Offset)
		}
		if q := v.Questions[qid]; q != nil && v.Question != nil && v.Question.ID == qid {
			v.Question = nil
		}
		if !v.Consumed[qid] {
			v.Answers = append(v.Answers, answerRef{QID: qid, Text: note.Text, Sender: note.Sender, Offset: rec.Offset, Gen: note.Gen})
		}
		v.appendTranscript(userFrame(note.Text, note.Sender, ""))
	case noteQuestion:
		q := &Question{ID: note.ID, Text: shorten(note.Text, maxQuestionBytes), Options: cleanOptions(note.Options), AskedAt: time.Time{}}
		if q.ID == "" {
			q.ID = fmt.Sprintf("q%d", rec.Offset)
		}
		v.Questions[q.ID] = q
		v.Question = q
		v.QuestionGen = rec.Gen
		v.Expired[q.ID] = false
	case noteConsumed:
		v.Consumed[note.QID] = true
		v.dropAnswers(note.QID)
		if v.Question != nil && v.Question.ID == note.QID {
			v.Question = nil
		}
	case noteExpire:
		v.Expired[note.QID] = true
		if v.Question != nil && v.Question.ID == note.QID {
			v.Question = nil
		}
	case noteCancel:
		v.retireQuestion(rec.Gen)
		if rec.Offset > v.CancelSeq {
			v.CancelSeq = rec.Offset
		}
		// The prompt that was in flight when the user cancelled is abandoned,
		// even if the agent never confirms the cancellation.
		if v.Inflight != nil && v.Inflight.Sent != 0 && v.Inflight.Sent < rec.Offset {
			v.Done[v.Inflight.ID] = true
			v.removePrompt(v.Inflight.ID)
		}
		// Prompts submitted before the cancel but not started yet are dropped
		// too. Keep Inflight: the agent still owns that turn until it answers
		// or exits, and the engine must not start the next prompt early.
		kept := v.Queued[:0]
		for _, ref := range v.Queued {
			if ref.Offset >= rec.Offset {
				kept = append(kept, ref)
			}
		}
		v.Queued = kept
	case noteStop:
		v.retireQuestion(rec.Gen)
		if rec.Offset > v.StopSeq {
			v.StopSeq = rec.Offset
		}
		v.dropPrompts(func(ref promptRef) bool { return ref.Offset < rec.Offset })
	}
}

// retireQuestion closes a question whose waiting turn has gone away. Keep its
// history and answers for replay, and never close a newer generation's question.
func (v *chatView) retireQuestion(gen uint64) {
	if v.Question != nil && v.QuestionGen <= gen {
		v.Expired[v.Question.ID] = true
		v.Question = nil
	}
}

// applyStopBefore also applies to records replayed after the boundary was
// loaded. A stopped queue must not reappear when an engine catches up or moves
// to another replica. A new prompt exactly at the boundary remains eligible.
func (v *chatView) applyStopBefore(before uint64) {
	if before > v.stopBefore {
		v.stopBefore = before
	}
	if v.stopBefore == 0 {
		return
	}
	if v.stopBefore > v.StopSeq {
		v.StopSeq = v.stopBefore
	}
	v.dropPrompts(func(ref promptRef) bool { return ref.Offset < v.stopBefore })
	kept := v.Answers[:0]
	for _, answer := range v.Answers {
		if answer.Offset >= v.stopBefore {
			kept = append(kept, answer)
		}
	}
	v.Answers = kept
}

func (v *chatView) dropPrompts(drop func(promptRef) bool) {
	kept := v.Queued[:0]
	for _, ref := range v.Queued {
		if drop(ref) {
			continue
		}
		kept = append(kept, ref)
	}
	v.Queued = kept
	if v.Inflight != nil && drop(*v.Inflight) {
		v.Inflight = nil
	}
}

func (v *chatView) dropAnswers(qid string) {
	kept := v.Answers[:0]
	for _, a := range v.Answers {
		if a.QID == qid {
			continue
		}
		kept = append(kept, a)
	}
	v.Answers = kept
}

func (v *chatView) appendTranscript(message json.RawMessage) {
	if len(message) == 0 {
		return
	}
	v.emitted = append(v.emitted, message)
	v.Transcript = append(v.Transcript, message)
	v.TranscriptBytes += len(message)
	// Keep the newest history: the UI says it shows the most recent messages.
	for (len(v.Transcript) > maxTranscriptMessages || v.TranscriptBytes > maxTranscriptBytes) && len(v.Transcript) > 1 {
		v.TranscriptBytes -= len(v.Transcript[0])
		v.Transcript = v.Transcript[1:]
		v.Truncated = true
	}
	if v.TranscriptBytes > maxTranscriptBytes {
		// A single message larger than the cap is kept so the chat is never
		// completely empty, but the transcript is still marked truncated.
		v.Truncated = true
	}
}

// queuedPrompts returns prompts that still need a session/prompt turn, oldest
// first. A prompt whose turn is in flight is skipped.
func (v *chatView) queuedPrompts() []promptRef {
	if v.Inflight != nil {
		return nil
	}
	return v.Queued
}

// canWrite reports whether a conditional append can use LastSeq.
func (v *chatView) canWrite() (uint64, bool) {
	if v.LastSeq == 0 || v.LastSeqGen != v.Gen {
		return 0, false
	}
	return v.LastSeq, true
}

// busy reports whether the agent has a turn in flight.
func (v *chatView) busy() bool { return v.Inflight != nil }

// pendingAnswer returns the next answer that should be delivered as a prompt.
// An answer is stale when the generation that asked the question is over, or
// when ask_user already gave up on it. A live turn answers are left for the
// ask_user call that is still waiting for them.
func (v *chatView) pendingAnswer() (answerRef, bool) {
	if v.busy() {
		return answerRef{}, false
	}
	for _, a := range v.Answers {
		if v.Consumed[a.QID] {
			continue
		}
		if v.Done[fmt.Sprintf("answer-%d", a.Offset)] {
			continue
		}
		if a.Gen < v.Gen || v.Ended || v.Expired[a.QID] {
			return a, true
		}
	}
	return answerRef{}, false
}

// questionGen returns the generation that asked a question. Answers are
// stamped with it so a turn that ends, or a replica that dies, still delivers
// the answer on the next generation.
func (v *chatView) questionGen(qid string) uint64 {
	if gen, ok := v.QuestionGens[qid]; ok {
		return gen
	}
	return v.Gen
}

// nextTurn returns the oldest thing the agent should be asked to do: a queued
// prompt note or an answer whose asker is gone.
func (v *chatView) nextTurn() (promptRef, bool) {
	if v.busy() {
		return promptRef{}, false
	}
	var best promptRef
	found := false
	if len(v.Queued) > 0 {
		best, found = v.Queued[0], true
	}
	if a, ok := v.pendingAnswer(); ok && (!found || a.Offset < best.Offset) {
		question := ""
		if q := v.Questions[a.QID]; q != nil {
			question = q.Text
		}
		text := a.Text
		if question != "" {
			text = fmt.Sprintf("Answer to your question %q: %s", shorten(question, 200), a.Text)
		}
		best = promptRef{
			ID:       fmt.Sprintf("answer-%d", a.Offset),
			Text:     shorten(text, maxPromptBytes),
			Original: a.Text,
			Sender:   a.Sender,
			Offset:   a.Offset,
		}
		found = true
	}
	return best, found
}

// hasWork reports whether the chat still has something for the agent to do in
// a new generation.
func (v *chatView) hasWork() bool {
	if v.busy() {
		return true
	}
	if len(v.Queued) > 0 {
		return true
	}
	_, answer := v.pendingAnswer()
	return answer
}

func promptDisplayText(note noteRecord) string {
	if note.Original != "" {
		return note.Original
	}
	return note.Text
}

func promptIDFromPrompt(params json.RawMessage) string {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return ""
	}
	var id string
	if raw, ok := p.Meta["blip.dev/promptID"]; ok {
		_ = json.Unmarshal(raw, &id)
	}
	return id
}

func userTextFromPrompt(params json.RawMessage) (string, string) {
	var p struct {
		Prompt []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"prompt"`
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return "", ""
	}
	var text string
	if raw, ok := p.Meta["blip.dev/text"]; ok {
		_ = json.Unmarshal(raw, &text)
	}
	if text == "" {
		var parts []string
		for _, part := range p.Prompt {
			if part.Type == "text" {
				parts = append(parts, part.Text)
			}
		}
		text = strings.Join(parts, "\n")
	}
	var sender string
	if raw, ok := p.Meta["blip.dev/sender"]; ok {
		_ = json.Unmarshal(raw, &sender)
	}
	return text, sender
}

func userFrame(text, sender, promptID string) json.RawMessage {
	update := map[string]any{
		"sessionUpdate": "user_message_chunk",
		"content":       []any{map[string]any{"type": "text", "text": text}},
		"blipUser":      true,
	}
	if sender != "" {
		update["sender"] = sender
	}
	if promptID != "" {
		update["promptID"] = promptID
	}
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params":  map[string]any{"update": update},
	}
	data, _ := json.Marshal(msg)
	return data
}

func outputFrame(stream, text string) json.RawMessage {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "blip/output",
		"params":  map[string]any{"stream": stream, "text": text},
	}
	data, _ := json.Marshal(msg)
	return data
}

// outputLineFrame keeps structured agent output as JSON and wraps anything
// else as plain stdout text.
func outputLineFrame(line []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var anyJSON json.RawMessage
		if json.Unmarshal(trimmed, &anyJSON) == nil {
			return append(json.RawMessage(nil), trimmed...)
		}
	}
	return outputFrame("stdout", string(line))
}

func contentText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var item struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &item) == nil && item.Text != "" {
		return item.Text
	}
	var items []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &items) == nil {
		var b strings.Builder
		for _, it := range items {
			if it.Type == "" || it.Type == "text" {
				b.WriteString(it.Text)
			}
		}
		return b.String()
	}
	return ""
}

func rawID(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return string(raw)
}

// recordFromLine parses one NDJSON log line.
func recordFromLine(line []byte) (streamLogRecord, error) {
	var rec streamLogRecord
	err := json.Unmarshal(bytes.TrimSpace(line), &rec)
	return rec, err
}
