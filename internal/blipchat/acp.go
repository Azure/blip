// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ACP is JSON-RPC 2.0 over newline-delimited stdin/stdout. The agent is a
// child of the blip's primary command; blipchat is the client.
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

type pendingCall struct {
	kind string
	ch   chan rpcResponse
}

type rpcResponse struct {
	result json.RawMessage
	err    error
}

// acpAgent owns the framing, pending requests, and agent-to-client requests
// for one agent process.
type acpAgent struct {
	send          func(ctx context.Context, data []byte, eof bool) error
	onMessage     func(json.RawMessage)
	onPromptDone  func(error)
	onSessionID   func(string)
	autoApprove   string
	idPrefix      string
	idSeq         int64
	mu            sync.Mutex
	pending       map[string]*pendingCall
	buf           []byte
	sessionID     string
	replaying     bool
	loadSession   bool
	resumeSession bool
	mcpServers    []any
}

func newACPAgent(send func(context.Context, []byte, bool) error, onMessage func(json.RawMessage), onPromptDone func(error), onSessionID func(string), autoApprove string) *acpAgent {
	var prefix [4]byte
	_, _ = rand.Read(prefix[:])
	return &acpAgent{
		send:         send,
		onMessage:    onMessage,
		onPromptDone: onPromptDone,
		onSessionID:  onSessionID,
		autoApprove:  autoApprove,
		idPrefix:     "blipchat-" + hex.EncodeToString(prefix[:]),
		pending:      make(map[string]*pendingCall),
	}
}

func (a *acpAgent) SessionID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionID
}

func (a *acpAgent) SetSessionID(id string) {
	a.mu.Lock()
	a.sessionID = id
	a.mu.Unlock()
}

// SetMCPServers sets the servers offered to the agent in session/new and
// session/load. They are sent as-is, in ACP's mcpServers format.
func (a *acpAgent) SetMCPServers(servers []any) {
	a.mu.Lock()
	a.mcpServers = servers
	a.mu.Unlock()
}

func (a *acpAgent) servers() []any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mcpServers == nil {
		return []any{}
	}
	return a.mcpServers
}

func (a *acpAgent) Pending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

func (a *acpAgent) newID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.idSeq++
	return a.idPrefix + "-" + strconv.FormatInt(a.idSeq, 10)
}

func idKey(raw json.RawMessage) string { return string(bytes.TrimSpace(raw)) }

func (a *acpAgent) register(id string, p *pendingCall) string {
	key := strconv.Quote(id)
	a.mu.Lock()
	a.pending[key] = p
	a.mu.Unlock()
	return key
}

func (a *acpAgent) forget(key string) {
	a.mu.Lock()
	delete(a.pending, key)
	a.mu.Unlock()
}

// Feed appends stdout bytes and dispatches every complete newline-delimited
// message. A partial line stays buffered until the next record.
func (a *acpAgent) Feed(data []byte) {
	a.mu.Lock()
	a.buf = append(a.buf, data...)
	if len(a.buf) > acpMaxLine {
		a.buf = nil
	}
	var lines [][]byte
	for {
		i := bytes.IndexByte(a.buf, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimSpace(a.buf[:i])
		if len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
		a.buf = a.buf[i+1:]
	}
	a.mu.Unlock()
	for _, line := range lines {
		a.handleLine(line)
	}
}

func (a *acpAgent) handleLine(line []byte) {
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		a.emit(map[string]any{
			"jsonrpc": "2.0",
			"method":  "blip/output",
			"params":  map[string]string{"stream": "stdout", "text": string(line)},
		})
		return
	}
	if msg.Method != "" {
		raw := append([]byte(nil), line...)
		a.mu.Lock()
		replaying := a.replaying
		a.mu.Unlock()
		if !(replaying && msg.Method == "session/update") {
			a.onMessage(raw)
		}
		if len(msg.ID) != 0 && string(msg.ID) != "null" {
			a.handleRequest(msg.ID, msg.Method, msg.Params)
		}
		return
	}
	// A response to one of our requests. Forward it so the UI sees turn
	// results, then complete the pending call.
	raw := append([]byte(nil), line...)
	key := idKey(msg.ID)
	a.mu.Lock()
	p := a.pending[key]
	delete(a.pending, key)
	replaying := a.replaying
	a.mu.Unlock()
	// An asynchronous prompt rejection is an internal retry signal: the
	// driver stops the failed generation and retries the prompt. Do not show
	// that transient error as a chat message when the retry may succeed; a
	// permanent failure is reported through the driver's terminal status.
	suppress := p != nil && p.ch == nil && p.kind == "session/prompt" && msg.Error != nil
	if !replaying && !suppress {
		a.onMessage(raw)
	}
	if p == nil {
		return
	}
	if p.ch != nil {
		if msg.Error != nil {
			p.ch <- rpcResponse{err: msg.Error}
		} else {
			p.ch <- rpcResponse{result: msg.Result}
		}
		return
	}
	if p.kind == "session/prompt" && a.onPromptDone != nil {
		var promptErr error
		if msg.Error != nil {
			promptErr = msg.Error
		}
		a.onPromptDone(promptErr)
	}
}

func (a *acpAgent) emit(v any) {
	raw, err := json.Marshal(v)
	if err == nil {
		a.onMessage(raw)
	}
}

func (a *acpAgent) handleRequest(id json.RawMessage, method string, params json.RawMessage) {
	var reply any
	switch method {
	case "session/request_permission":
		option := choosePermission(params, a.autoApprove)
		if option == "" {
			reply = map[string]any{"outcome": map[string]string{"outcome": "cancelled"}}
		} else {
			reply = map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": option}}
		}
	default:
		a.reply(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"error":   &rpcError{Code: -32601, Message: "method not found: " + method},
		})
		return
	}
	a.reply(map[string]any{"jsonrpc": "2.0", "id": id, "result": reply})
}

// sendLine writes one newline-delimited JSON frame. ACP is NDJSON, and some
// agents (notably opencode) do not dispatch a request until they see the
// terminating newline.
func (a *acpAgent) sendLine(ctx context.Context, data []byte, eof bool) error {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		return a.send(ctx, data, eof)
	}
	frame := make([]byte, len(data)+1)
	copy(frame, data)
	frame[len(data)] = '\n'
	return a.send(ctx, frame, eof)
}

func (a *acpAgent) reply(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.sendLine(ctx, data, false)
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

func (a *acpAgent) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := a.newID()
	p := &pendingCall{kind: method, ch: make(chan rpcResponse, 1)}
	key := a.register(id, p)
	data, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		a.forget(key)
		return nil, err
	}
	if err := a.sendLine(ctx, data, false); err != nil {
		a.forget(key)
		return nil, err
	}
	timer := time.NewTimer(acpCallTimeout)
	defer timer.Stop()
	select {
	case resp := <-p.ch:
		if resp.err != nil {
			return nil, resp.err
		}
		return resp.result, nil
	case <-ctx.Done():
		a.forget(key)
		return nil, ctx.Err()
	case <-timer.C:
		a.forget(key)
		return nil, fmt.Errorf("%s: timed out", method)
	}
}

// Start sends initialize and then resumes, loads, or creates a session.
func (a *acpAgent) Start(ctx context.Context) (string, error) {
	res, err := a.call(ctx, "initialize", map[string]any{
		"protocolVersion": acpProtocolVersion,
		"clientCapabilities": map[string]any{
			"fs":       map[string]bool{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
		"clientInfo": map[string]any{"name": "blipchat", "version": "1"},
	})
	if err != nil {
		return "", err
	}
	var init struct {
		AgentCapabilities struct {
			LoadSession         bool                       `json:"loadSession"`
			SessionCapabilities map[string]json.RawMessage `json:"sessionCapabilities"`
		} `json:"agentCapabilities"`
	}
	_ = json.Unmarshal(res, &init)
	a.loadSession = init.AgentCapabilities.LoadSession
	if raw, ok := init.AgentCapabilities.SessionCapabilities["resume"]; ok && string(raw) != "null" {
		a.resumeSession = true
	}

	a.mu.Lock()
	sessionID := a.sessionID
	a.mu.Unlock()
	if sessionID != "" {
		params := map[string]any{"sessionId": sessionID, "cwd": "/", "mcpServers": a.servers()}
		a.mu.Lock()
		a.replaying = true
		a.mu.Unlock()
		if a.resumeSession {
			if _, err := a.call(ctx, "session/resume", params); err == nil {
				a.finishReplay()
				return sessionID, nil
			}
		}
		if a.loadSession {
			if _, err := a.call(ctx, "session/load", params); err == nil {
				a.finishReplay()
				return sessionID, nil
			}
		}
		a.finishReplay()
	}
	res, err = a.call(ctx, "session/new", map[string]any{"cwd": "/", "mcpServers": a.servers()})
	if err != nil {
		return "", err
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(res, &created); err != nil {
		return "", err
	}
	if created.SessionID == "" {
		return "", errors.New("session/new returned no sessionId")
	}
	a.SetSessionID(created.SessionID)
	if a.onSessionID != nil {
		a.onSessionID(created.SessionID)
	}
	return created.SessionID, nil
}

// Prompt registers a session/prompt request. Its response ends the turn.
func (a *acpAgent) finishReplay() {
	a.mu.Lock()
	a.replaying = false
	a.mu.Unlock()
}

func (a *acpAgent) Prompt(ctx context.Context, text string, meta map[string]any) error {
	sessionID := a.SessionID()
	if sessionID == "" {
		return errors.New("no ACP session")
	}
	id := a.newID()
	p := &pendingCall{kind: "session/prompt"}
	key := a.register(id, p)
	params := map[string]any{
		"sessionId": sessionID,
		"prompt":    []any{map[string]string{"type": "text", "text": text}},
	}
	if len(meta) > 0 {
		params["_meta"] = meta
	}
	data, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "session/prompt",
		"params":  params,
	})
	if err != nil {
		a.forget(key)
		return err
	}
	if err := a.sendLine(ctx, data, false); err != nil {
		a.forget(key)
		return err
	}
	return nil
}

func (a *acpAgent) Cancel(ctx context.Context) error {
	sessionID := a.SessionID()
	if sessionID == "" {
		return nil
	}
	data, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/cancel",
		"params":  map[string]any{"sessionId": sessionID},
	})
	if err != nil {
		return err
	}
	return a.sendLine(ctx, data, false)
}

// Reset drops state that belonged to a dead agent process. The session id and
// capabilities survive so the next process can load the conversation.
func (a *acpAgent) Reset() {
	a.mu.Lock()
	a.pending = make(map[string]*pendingCall)
	a.buf = nil
	a.mu.Unlock()
}
