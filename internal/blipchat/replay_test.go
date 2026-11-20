// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
)

type replayWire struct {
	Wire
	log []byte
}

func (w *replayWire) ReadLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(w.log)), nil
}

func replayLogRecord(t *testing.T, offset uint64, typ streamRecordType, data string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"o": offset,
		"g": 1,
		"t": int(typ),
		"d": base64.StdEncoding.EncodeToString([]byte(data)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestReplayTranscript(t *testing.T) {
	const sessionUpdate = `{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}}`
	split := len(sessionUpdate) / 2
	var log []byte
	log = append(log, replayLogRecord(t, 1, recordIn, `{"jsonrpc":"2.0","id":"1","method":"session/prompt","params":{"prompt":[{"type":"text","text":"wrapped"}],"_meta":{"blip.dev/sender":"alice","blip.dev/text":"hello"}}}`)...)
	log = append(log, replayLogRecord(t, 2, recordOut, sessionUpdate[:split])...)
	log = append(log, replayLogRecord(t, 3, recordOut, sessionUpdate[split:]+"\nnot json\n")...)
	log = append(log, replayLogRecord(t, 4, recordErr, "boom")...)

	got, truncated := replayTranscript(context.Background(), &replayWire{log: log}, "default", "chat-1")
	if truncated {
		t.Fatal("short transcript reported truncated")
	}
	if len(got) != 4 {
		var b bytes.Buffer
		for _, raw := range got {
			b.Write(raw)
			b.WriteByte('\n')
		}
		t.Fatalf("transcript has %d entries, want 4: %s", len(got), b.String())
	}

	var user struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				Kind    string `json:"sessionUpdate"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				BlipUser bool   `json:"blipUser"`
				Sender   string `json:"sender"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(got[0], &user); err != nil {
		t.Fatal(err)
	}
	if user.Method != "session/update" || user.Params.Update.Kind != "user_message_chunk" ||
		!user.Params.Update.BlipUser || len(user.Params.Update.Content) != 1 ||
		user.Params.Update.Content[0].Text != "hello" || user.Params.Update.Sender != "alice" {
		t.Fatalf("user message = %s", got[0])
	}
	if string(got[1]) != sessionUpdate {
		t.Fatalf("agent update = %s", got[1])
	}

	var stdout, stderr struct {
		Method string `json:"method"`
		Params struct {
			Stream string `json:"stream"`
			Text   string `json:"text"`
		} `json:"params"`
	}
	if err := json.Unmarshal(got[2], &stdout); err != nil {
		t.Fatal(err)
	}
	if stdout.Method != "blip/output" || stdout.Params.Stream != "stdout" || stdout.Params.Text != "not json" {
		t.Fatalf("stdout message = %s", got[2])
	}
	if err := json.Unmarshal(got[3], &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.Method != "blip/output" || stderr.Params.Stream != "stderr" || stderr.Params.Text != "boom" {
		t.Fatalf("stderr message = %s", got[3])
	}
}

func TestReplayTranscriptWithoutLogReader(t *testing.T) {
	if got, truncated := replayTranscript(context.Background(), &fakeWire{}, "default", "chat-1"); got != nil || truncated {
		t.Fatalf("transcript = %v, truncated = %v, want nil/false", got, truncated)
	}
}

func TestReplayTranscriptReportsTruncation(t *testing.T) {
	var log []byte
	for i := 0; i <= maxTranscriptMessages; i++ {
		log = append(log, replayLogRecord(t, uint64(i+1), recordErr, "x")...)
	}
	got, truncated := replayTranscript(context.Background(), &replayWire{log: log}, "default", "chat-1")
	if !truncated {
		t.Fatal("replay did not report truncation")
	}
	if len(got) != maxTranscriptMessages {
		t.Fatalf("transcript has %d entries, want cap %d", len(got), maxTranscriptMessages)
	}
}
