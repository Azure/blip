// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"encoding/json"
	"fmt"

	"time"
)

// ACP is JSON-RPC 2.0 over newline-delimited stdin/stdout. Blipchat builds
// frames and derives all conversation state from the stream; it does not keep
// a live agent object in memory.
const (
	acpProtocolVersion = 1
	acpCallTimeout     = 90 * time.Second
	acpMaxLine         = 4 << 20
)

type rpcMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("agent error %d: %s", e.Code, e.Message)
}

func initRequestID(gen uint64) string      { return fmt.Sprintf("g%d-init", gen) }
func sessionRequestID(gen uint64) string   { return fmt.Sprintf("g%d-session", gen) }
func promptRequestID(noteID string) string { return "p-" + noteID }
func answerRequestID(offset uint64) string { return fmt.Sprintf("p-answer-%d", offset) }

// sendLine writes one newline-delimited JSON frame. ACP is NDJSON, and some
// agents (notably opencode) do not dispatch a request until they see the
// terminating newline. Every frame written to the agent's stdin must pass
// through this helper.
func sendLine(frame []byte) []byte {
	if len(frame) == 0 || frame[len(frame)-1] == '\n' {
		return frame
	}
	out := make([]byte, len(frame)+1)
	copy(out, frame)
	out[len(frame)] = '\n'
	return out
}

func acpFrame(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return data
}

func initializeFrame(gen uint64) json.RawMessage {
	return acpFrame(map[string]any{
		"jsonrpc": "2.0",
		"id":      initRequestID(gen),
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": acpProtocolVersion,
			"clientCapabilities": map[string]any{
				"fs":       map[string]bool{"readTextFile": false, "writeTextFile": false},
				"terminal": false,
			},
			"clientInfo": map[string]any{"name": "blipchat", "version": "1"},
		},
	})
}

func sessionSetupFrame(gen uint64, method, sessionID, cwd string, mcpServers []any) json.RawMessage {
	return acpFrame(map[string]any{
		"jsonrpc": "2.0",
		"id":      sessionRequestID(gen),
		"method":  method,
		"params":  map[string]any{"sessionId": sessionID, "cwd": cwd, "mcpServers": mcpServers},
	})
}

func newSessionFrame(gen uint64, cwd string, mcpServers []any) json.RawMessage {
	return acpFrame(map[string]any{
		"jsonrpc": "2.0",
		"id":      sessionRequestID(gen),
		"method":  "session/new",
		"params":  map[string]any{"cwd": cwd, "mcpServers": mcpServers},
	})
}

func promptFrame(noteID, sessionID, text, original, sender string) json.RawMessage {
	meta := map[string]any{"blip.dev/promptID": noteID}
	if original != "" {
		meta["blip.dev/text"] = original
	}
	if sender != "" {
		meta["blip.dev/sender"] = sender
	}
	return acpFrame(map[string]any{
		"jsonrpc": "2.0",
		"id":      promptRequestID(noteID),
		"method":  "session/prompt",
		"params": map[string]any{
			"sessionId": sessionID,
			"prompt":    []any{map[string]string{"type": "text", "text": text}},
			"_meta":     meta,
		},
	})
}

func cancelFrame(sessionID string) json.RawMessage {
	return acpFrame(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/cancel",
		"params":  map[string]any{"sessionId": sessionID},
	})
}

// permissionReply answers an agent request. Unknown methods get -32601.
func permissionReply(id json.RawMessage, method string, params json.RawMessage, mode string) json.RawMessage {
	if method != "session/request_permission" {
		return acpFrame(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"error":   &rpcError{Code: -32601, Message: "method not found: " + method},
		})
	}
	var reply any
	if option := choosePermission(params, mode); option == "" {
		reply = map[string]any{"outcome": map[string]string{"outcome": "cancelled"}}
	} else {
		reply = map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": option}}
	}
	return acpFrame(map[string]any{"jsonrpc": "2.0", "id": id, "result": reply})
}

func choosePermission(params json.RawMessage, mode string) string {
	var p struct {
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	pick := func(kinds ...string) string {
		for _, want := range kinds {
			for _, opt := range p.Options {
				if opt.Kind == want {
					return opt.OptionID
				}
			}
		}
		return ""
	}
	if mode == "never" {
		return pick("reject_once", "reject_always")
	}
	if id := pick("allow_once", "allow_always"); id != "" {
		return id
	}
	for _, opt := range p.Options {
		if len(opt.Kind) >= 5 && opt.Kind[:5] == "allow" {
			return opt.OptionID
		}
	}
	if len(p.Options) > 0 {
		return p.Options[0].OptionID
	}
	return ""
}
