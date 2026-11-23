// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sseFrame is one server-sent event with the id line the browser would keep as
// Last-Event-ID.
type sseFrame struct {
	id string
	ev Event
}

// openEventFrames opens the chat's event stream at query (for example
// "?offset=12.1") with an optional Last-Event-ID header.
func openEventFrames(t *testing.T, g *testGateway, name, query, lastEventID string) <-chan sseFrame {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.ts.URL+"/api/sessions/"+name+"/events"+query, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", "alice")
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if stream.StatusCode != http.StatusOK {
		cancel()
		stream.Body.Close()
		t.Fatalf("events: status %d", stream.StatusCode)
	}
	t.Cleanup(func() {
		cancel()
		stream.Body.Close()
	})
	frames := make(chan sseFrame, 64)
	go func() {
		defer close(frames)
		scanner := bufio.NewScanner(stream.Body)
		var id string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "id: "):
				id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				var ev Event
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
					return
				}
				select {
				case frames <- sseFrame{id: id, ev: ev}:
				case <-ctx.Done():
					return
				}
				id = ""
			}
		}
	}()
	return frames
}

// collectACPUntil reads transcript events until the marker chunk arrives, so a
// resume's exact frame set is known without probing the stream for silence.
func collectACPUntilMarker(t *testing.T, frames <-chan sseFrame, marker string) []sseFrame {
	t.Helper()
	var out []sseFrame
	deadline := time.After(3 * time.Second)
	for {
		select {
		case frame, open := <-frames:
			if !open {
				t.Fatal("SSE closed before the marker")
			}
			if frame.ev.Type != "acp" {
				continue
			}
			if kind, text := chatChunkKind(t, frame.ev.Message); kind == "agent_message_chunk" && text == marker {
				return out
			}
			out = append(out, frame)
		case <-deadline:
			t.Fatalf("timed out waiting for marker %q; got %d frames", marker, len(out))
		}
	}
}

func agentUpdate(text string) map[string]any {
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

func acpTexts(t *testing.T, frames []sseFrame) []string {
	t.Helper()
	out := make([]string, 0, len(frames))
	for _, frame := range frames {
		_, text := chatChunkKind(t, frame.ev.Message)
		out = append(out, text)
	}
	return out
}

// A record that carries several transcript frames must be resumable between
// them. Every frame gets a unique id; a reconnect resumes at the frame after
// the one the client acknowledged, dropping and duplicating nothing.
func TestServerEventsResumeInsideRecord(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	// Start the ring above zero: "?offset=0" is the historical no-cursor form.
	g.wire.appendRecord(1, recordStart, nil)
	var record []byte
	for _, text := range []string{"a", "b", "c"} {
		line, err := json.Marshal(agentUpdate(text))
		if err != nil {
			t.Fatal(err)
		}
		record = append(record, line...)
		record = append(record, '\n')
	}
	off := g.wire.appendRecord(1, recordOut, record)
	g.wire.emitACP(1, agentUpdate("marker"))

	first := collectACPUntilMarker(t, openEventFrames(t, g, name, "?offset=0", ""), "marker")
	if got := acpTexts(t, first); strings.Join(got, "") != "abc" {
		t.Fatalf("first connection frames = %v, want a b c", got)
	}
	for i, frame := range first {
		want := eventID(off, i)
		if frame.id != want || frame.ev.Cursor != want {
			t.Fatalf("frame %d id = %q cursor = %q, want %q", i, frame.id, frame.ev.Cursor, want)
		}
		if frame.ev.Offset != off {
			t.Fatalf("frame %d offset = %d, want record offset %d", i, frame.ev.Offset, off)
		}
	}
	if first[0].id == first[1].id || first[1].id == first[2].id {
		t.Fatalf("frames of one record share an id: %q %q %q", first[0].id, first[1].id, first[2].id)
	}

	for _, tc := range []struct {
		name        string
		query       string
		lastEventID string
		want        string
	}{
		// The browser's own auto-retry sends the SSE id.
		{name: "after first frame", lastEventID: first[0].id, want: "bc"},
		{name: "after second frame via url", query: "?offset=" + first[1].id, want: "c"},
		{name: "after last frame", lastEventID: first[2].id, want: ""},
		// A plain numeric offset still means the whole record was delivered.
		{name: "numeric offset", query: "?offset=" + strconv.FormatUint(off, 10), want: ""},
		// The historical ?offset=0 form still replays from the chat start.
		{name: "no cursor", query: "?offset=0", want: "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := collectACPUntilMarker(t, openEventFrames(t, g, name, tc.query, tc.lastEventID), "marker")
			if got := strings.Join(acpTexts(t, frames), ""); got != tc.want {
				t.Fatalf("resumed frames = %q, want %q", got, tc.want)
			}
		})
	}
}

// A record with a transcript frame and a status frame is also resumable: the
// status is recomputed, and the transcript frame is never re-sent.
func TestServerEventsResumeInsideNoteRecord(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	// An answer note is stored with a user transcript frame plus a status
	// frame, so both frames share one record offset.
	off := g.wire.note(noteRecord{Type: noteAnswer, QID: "q1", Text: "yes"})
	g.wire.emitACP(1, agentUpdate("marker"))

	first := collectACPUntilMarker(t, openEventFrames(t, g, name, "?offset=0", ""), "marker")
	if len(first) != 1 || first[0].id != eventID(off, 0) {
		t.Fatalf("note record frames = %+v, want one user frame at %s", first, eventID(off, 0))
	}

	resumed := collectACPUntilMarker(t, openEventFrames(t, g, name, "", first[0].id), "marker")
	if len(resumed) != 0 {
		t.Fatalf("resume inside a note record replayed %v", acpTexts(t, resumed))
	}
}

func TestEventCursorParsing(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		seen   bool
		offset uint64
		skip   int
		bad    bool
	}{
		{raw: "", seen: false},
		{raw: "0", seen: false, skip: -1},
		{raw: "42", seen: true, offset: 42, skip: -1},
		{raw: "42.0", seen: true, offset: 42, skip: 1},
		{raw: "42.7", seen: true, offset: 42, skip: 8},
		{raw: "0.2", seen: true, skip: 3},
		{raw: "42.", bad: true},
		{raw: ".2", bad: true},
		{raw: "42.x", bad: true},
		{raw: "x.2", bad: true},
		{raw: "-1", bad: true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/events?offset="+tc.raw, nil)
			if tc.raw == "" {
				req = httptest.NewRequest(http.MethodGet, "/events", nil)
			}
			cur, seen, err := eventOffset(req)
			if tc.bad {
				if err == nil {
					t.Fatalf("offset %q was accepted", tc.raw)
				}
				return
			}
			if err != nil || seen != tc.seen || cur.offset != tc.offset || cur.skip != tc.skip {
				t.Fatalf("offset %q = (%+v, %t, %v), want offset=%d skip=%d seen=%t",
					tc.raw, cur, seen, err, tc.offset, tc.skip, tc.seen)
			}
		})
	}
}
