// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"
)

// logReader is implemented by wires that can read a state's retained
// trajectory log without following new records. It is optional so test wires
// and older substitutes keep working.
type logReader interface {
	ReadLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error)
}

const replayTimeout = 5 * time.Second

// replayTranscript rebuilds the visible ACP transcript from a state's durable
// trajectory log. It is used when no driver is live, for example after a
// blipchat restart, so opening an old chat still shows its conversation.
func replayTranscript(ctx context.Context, wire Wire, namespace, state string) ([]json.RawMessage, bool) {
	lr, ok := wire.(logReader)
	if !ok {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, replayTimeout)
	defer cancel()
	rc, err := lr.ReadLog(ctx, namespace, state, 0)
	if err != nil {
		return nil, false
	}
	defer rc.Close()

	var out []json.RawMessage
	var total int
	var truncated bool
	var pending []byte
	appendRaw := func(raw []byte) {
		if len(bytes.TrimSpace(raw)) == 0 {
			return
		}
		raw = append([]byte(nil), raw...)
		out = append(out, raw)
		total += len(raw)
		for len(out) > maxTranscriptMessages || (total > maxTranscriptBytes && len(out) > 1) {
			total -= len(out[0])
			out = out[1:]
			truncated = true
		}
	}

	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64<<10), acpMaxLine)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec streamLogRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		switch rec.Type {
		case recordIn:
			if raw := userMessageFromPrompt(rec.Data); raw != nil {
				appendRaw(raw)
			}
		case recordOut:
			pending = append(pending, rec.Data...)
			for {
				i := bytes.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				appendOutputLine(appendRaw, pending[:i])
				pending = pending[i+1:]
			}
		case recordErr:
			raw, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"method":  "blip/output",
				"params":  map[string]string{"stream": "stderr", "text": string(rec.Data)},
			})
			if err == nil {
				appendRaw(raw)
			}
		}
	}
	return out, truncated
}

// appendOutputLine mirrors acpAgent.handleLine: JSON frames are transcript
// entries, while plain stdout is wrapped so the UI can display it.
func appendOutputLine(appendRaw func([]byte), line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err == nil {
		appendRaw(line)
		return
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "blip/output",
		"params":  map[string]string{"stream": "stdout", "text": string(line)},
	})
	if err == nil {
		appendRaw(raw)
	}
}

// userMessageFromPrompt turns a logged session/prompt request into the same
// synthetic user_message_chunk the live driver records.
func userMessageFromPrompt(data []byte) json.RawMessage {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Prompt []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"prompt"`
			Meta struct {
				Sender string `json:"blip.dev/sender"`
				Text   string `json:"blip.dev/text"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &msg); err != nil || msg.Method != "session/prompt" {
		return nil
	}
	var text string
	for _, part := range msg.Params.Prompt {
		if part.Type == "" || part.Type == "text" {
			text += part.Text
		}
	}
	if msg.Params.Meta.Text != "" {
		text = msg.Params.Meta.Text
	}
	if text == "" {
		return nil
	}
	update := map[string]any{
		"sessionUpdate": "user_message_chunk",
		"content":       []map[string]string{{"type": "text", "text": text}},
		"blipUser":      true,
	}
	if msg.Params.Meta.Sender != "" {
		update["sender"] = msg.Params.Meta.Sender
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params":  map[string]any{"update": update},
	})
	if err != nil {
		return nil
	}
	return raw
}
