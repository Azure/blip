// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// A client that connects after the prompt note was recorded already shows the
// user's message from its snapshot. The event stream must not treat the later
// session/prompt as a legacy prompt and render the same message a second time.
func TestEventsResumeAfterNoteDoesNotRepeatPrompt(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	g.wire.note(noteRecord{Type: noteAdmission})
	noteOff := g.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello", Original: "hello", Sender: "bob"})

	resp := g.request(t, http.MethodGet, "/api/sessions/"+name, nil, "alice", nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("detail: status %d", resp.StatusCode)
	}
	detail := decodeBody[sessionDetail](t, resp)
	if detail.Offset != noteOff {
		t.Fatalf("detail offset = %d, want note offset %d", detail.Offset, noteOff)
	}
	if n := countUserMessageChunks(t, detail.Transcript); n != 1 {
		t.Fatalf("detail transcript has %d user_message_chunk frames, want 1: %s", n, detail.Transcript)
	}

	events, readErr := openLifecycleEvents(t, g, name, detail.Offset)
	initial := nextLifecycleEvent(t, events, readErr)
	if initial.Type != "status" {
		t.Fatalf("initial event = %+v, want a status frame", initial)
	}

	prompt := map[string]any{
		"jsonrpc": "2.0",
		"id":      "p-n1",
		"method":  "session/prompt",
		"params": map[string]any{
			"sessionId": "acp-session-1",
			"prompt":    []map[string]any{{"type": "text", "text": "hello"}},
			"_meta": map[string]any{
				"blip.dev/promptID": "n1",
				"blip.dev/text":     "hello",
				"blip.dev/sender":   "bob",
			},
		},
	}
	g.wire.appendRecord(1, recordIn, mustJSON(prompt))

	// The marker makes the follow stream's progress observable: when it
	// arrives, every record before it has been handled.
	line, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params": map[string]any{
			"sessionId": "acp-session-1",
			"update": map[string]any{
				"sessionUpdate": "agent_message_chunk",
				"content":       map[string]string{"type": "text", "text": "marker"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.wire.appendRecord(1, recordOut, append(line, '\n'))

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev, open := <-events:
			if !open {
				t.Fatalf("SSE closed before the marker: %v", <-readErr)
			}
			if ev.Type != "acp" {
				continue
			}
			kind, text := chatChunkKind(t, ev.Message)
			if kind == "agent_message_chunk" && text == "marker" {
				return
			}
			if kind == "user_message_chunk" {
				t.Fatalf("event stream repeated the user message before the marker: %s", ev.Message)
			}
		case <-deadline:
			t.Fatal("timed out waiting for the marker agent_message_chunk")
		}
	}
}

// chatChunkKind returns the sessionUpdate kind and text of one transcript
// frame, or empty strings for frames that are not session/update chunks.
func chatChunkKind(t *testing.T, frame json.RawMessage) (string, string) {
	t.Helper()
	var msg struct {
		Params struct {
			Update struct {
				SessionUpdate string          `json:"sessionUpdate"`
				Content       json.RawMessage `json:"content"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatalf("decode chat chunk: %v", err)
	}
	return msg.Params.Update.SessionUpdate, contentText(msg.Params.Update.Content)
}

func countUserMessageChunks(t *testing.T, frames []json.RawMessage) int {
	t.Helper()
	n := 0
	for _, frame := range frames {
		if kind, _ := chatChunkKind(t, frame); kind == "user_message_chunk" {
			n++
		}
	}
	return n
}
