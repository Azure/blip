// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Caller is the chat that sent an MCP request.
type Caller struct {
	Namespace string
	Session   *v1.BlipState
	Blip      *v1.Blip
}

// Callers resolves a bearer token to the chat that sent an MCP request. The
// real implementation is a token review; tests use a fake.
type Callers interface {
	Identify(ctx context.Context, namespace, token string) (*Caller, error)
}

func agentSender(caller *Caller) string {
	if caller.Session == nil {
		return "agent"
	}
	return "agent:" + caller.Session.Name
}

const mcpProtocolVersion = "2025-06-18"

// maxAgentWait bounds a get_agent long poll so the agent can call again
// instead of holding one request open indefinitely.
const maxAgentWait = 120 * time.Second

// mcpServers is the ACP server list offered to an agent. Admission policy,
// not the profile, decides which profiles a chat may actually spawn.
func (s *Server) mcpServers() []any {
	if s.mcpURL == "" {
		return nil
	}
	return []any{map[string]any{
		"type":    "http",
		"name":    "blipchat",
		"url":     s.mcpURL,
		"headers": []any{},
	}}
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mcpResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func mcpFailure(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": mcpError{Code: code, Message: message}}
}

// handleMCP serves the Model Context Protocol over plain HTTP. It implements
// initialize, ping, tools/list and tools/call; that is all an ACP agent uses.
// Requests are authenticated by the caller's projected service-account token,
// which the pool sidecar adds and the guest never holds.
func (s *Server) handleMCP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.callers == nil {
			writeError(w, http.StatusServiceUnavailable, "agent tools are not configured")
			return
		}
		token := bearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="blipchat"`)
			writeError(w, http.StatusUnauthorized, "a bearer token is required")
			return
		}
		// The namespace is fixed at deployment time; a stale ?namespace= query
		// parameter is ignored rather than rejected.
		caller, err := s.callers.Identify(r.Context(), s.namespace, token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		if caller.Session.Labels[v1.LabelOwner] == "" || caller.Session.Annotations[AnnotationProfile] == "" {
			s.backfillChat(r.Context(), caller.Session)
		}
		var req mcpRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if len(req.ID) == 0 {
			// A notification has no response. Accept it so clients that send
			// notifications/initialized do not see an error.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var out map[string]any
		switch req.Method {
		case "initialize":
			version := mcpProtocolVersion
			var params struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if json.Unmarshal(req.Params, &params) == nil && params.ProtocolVersion != "" {
				version = params.ProtocolVersion
			}
			out = mcpResult(req.ID, map[string]any{
				"protocolVersion": version,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "blipchat", "version": "1"},
			})
		case "ping":
			out = mcpResult(req.ID, map[string]any{})
		case "tools/list":
			out = mcpResult(req.ID, map[string]any{"tools": mcpTools()})
		case "tools/call":
			out = s.callTool(r.Context(), caller, req)
		default:
			out = mcpFailure(req.ID, -32601, "method not found: "+req.Method)
		}
		writeJSON(w, http.StatusOK, out)
	})
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func mcpTools() []map[string]any {
	tool := func(name, description string, properties map[string]any, required ...string) map[string]any {
		schema := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			schema["required"] = required
		}
		return map[string]any{"name": name, "description": description, "inputSchema": schema}
	}
	text := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	id := text("The child chat name returned by spawn_agent or list_agents.")
	return []map[string]any{
		tool("list_profiles", "List the available agent profiles, with their descriptions and workspace mode.", map[string]any{}),
		tool("spawn_agent", "Start a child chat and send it a prompt. It runs in its own blip workspace. Returns the child's chat name; use get_agent to read its answer.", map[string]any{
			"profile": text("One of the profiles list_profiles returns."),
			"prompt":  text("The task for the child agent."),
			"title":   text("Optional short display name for the child chat."),
		}, "profile", "prompt"),
		tool("list_agents", "List the child chats this chat has started, with their status.", map[string]any{}),
		tool("get_agent", "Read a child chat's status and its latest answer. With waitSeconds it waits for the current turn to finish first.", map[string]any{
			"id":          id,
			"waitSeconds": map[string]any{"type": "integer", "description": "Wait up to this many seconds (0-120) for the turn to finish.", "minimum": 0, "maximum": 120},
		}, "id"),
		tool("send_agent", "Send another prompt to a child chat, continuing its conversation.", map[string]any{
			"id":     id,
			"prompt": text("The follow-up prompt."),
		}, "id", "prompt"),
		tool("stop_agent", "Stop a child chat's running turn so its workspace is saved.", map[string]any{"id": id}, "id"),
		tool("ask_user", "Ask the user a question and wait for their answer. Use it when only the user can decide. If they do not answer within the time limit, it returns and their answer arrives as your next message.", map[string]any{
			"question": text("The question for the user."),
			"options":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional short choices the user can click."},
		}, "question"),
	}
}

func (s *Server) callTool(ctx context.Context, caller *Caller, req mcpRequest) map[string]any {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return mcpFailure(req.ID, -32602, "invalid tools/call params")
	}
	var args struct {
		Profile     string   `json:"profile"`
		Prompt      string   `json:"prompt"`
		Title       string   `json:"title"`
		ID          string   `json:"id"`
		WaitSeconds int      `json:"waitSeconds"`
		Question    string   `json:"question"`
		Options     []string `json:"options"`
	}
	if len(params.Arguments) > 0 {
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolFailure(req.ID, "invalid arguments: "+err.Error())
		}
	}
	var (
		text string
		err  error
	)
	switch params.Name {
	case "list_profiles":
		text, err = s.toolListProfiles()
	case "spawn_agent":
		text, err = s.toolSpawnAgent(ctx, caller, args.Profile, args.Prompt, args.Title)
	case "list_agents":
		text, err = s.toolListAgents(ctx, caller)
	case "get_agent":
		text, err = s.toolGetAgent(ctx, caller, args.ID, args.WaitSeconds)
	case "send_agent":
		text, err = s.toolSendAgent(ctx, caller, args.ID, args.Prompt)
	case "stop_agent":
		text, err = s.toolStopAgent(ctx, caller, args.ID)
	case "ask_user":
		text, err = s.toolAskUser(ctx, caller, args.Question, args.Options)
	default:
		return mcpFailure(req.ID, -32602, "unknown tool: "+params.Name)
	}
	if err != nil {
		return toolFailure(req.ID, err.Error())
	}
	return toolResult(req.ID, text)
}

func toolResult(id json.RawMessage, text string) map[string]any {
	return mcpResult(id, map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
	})
}

func toolFailure(id json.RawMessage, message string) map[string]any {
	return mcpResult(id, map[string]any{
		"content": []map[string]string{{"type": "text", "text": message}},
		"isError": true,
	})
}

func jsonText(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

// toolListProfiles lists every configured profile. The admission policies
// decide which of them this chat is allowed to spawn.
func (s *Server) toolListProfiles() (string, error) {
	type info struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description,omitempty"`
		Workspace   string `json:"workspace"`
	}
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]info, 0, len(names))
	for _, name := range names {
		p := s.profiles[name]
		out = append(out, info{Name: name, Title: p.Title, Description: p.Description, Workspace: p.Workspace})
	}
	return jsonText(map[string]any{"profiles": out}), nil
}

// child returns a child chat of the caller, refusing any other session.
func (s *Server) child(ctx context.Context, caller *Caller, id string) (*v1.BlipState, error) {
	if !validDNSLabel(id) {
		return nil, errors.New("id must be a chat name")
	}
	st, err := s.chatState(ctx, caller.Namespace, id)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("no child chat named %q", id)
		}
		return nil, err
	}
	if st.Annotations[AnnotationParent] != caller.Session.Name {
		return nil, fmt.Errorf("chat %q was not started by this chat", id)
	}
	return st, nil
}

func (s *Server) toolSpawnAgent(ctx context.Context, caller *Caller, profileName, prompt, title string) (string, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return "", errors.New("prompt is required")
	}
	if len(prompt) > 32000 {
		return "", errors.New("prompt is too long")
	}
	if _, ok := s.profiles[profileName]; !ok {
		return "", fmt.Errorf("unknown profile %q", profileName)
	}

	// createChat inherits the parent's scope and owner from the reviewed
	// parent state, so a child can never widen its own access.
	created, err := s.createChat(ctx, chatRequest{
		Profile: profileName,
		Parent:  caller.Session,
		Title:   strings.TrimSpace(title),
	})
	if err != nil {
		return "", err
	}
	if err := s.waitStateReady(ctx, caller.Namespace, created.Name); err != nil {
		return "", err
	}
	st, err := s.chatState(ctx, caller.Namespace, created.Name)
	if err != nil {
		return "", err
	}
	profile, err := s.profileFor(st)
	if err != nil {
		return "", err
	}
	note, err := s.promptNote(st, profile, agentSender(caller), prompt)
	if err != nil {
		return "", fmt.Errorf("could not send the prompt: %w", err)
	}
	if err := s.appendNote(ctx, st, profile, note); err != nil {
		return "", fmt.Errorf("could not send the prompt: %w", err)
	}
	s.ensureEngine(created.Name)
	return jsonText(map[string]any{"id": created.Name, "profile": profileName, "workspace": s.profiles[profileName].Workspace}), nil
}

// waitStateReady waits for a copied chat to finish its copy so its inherited
// log offset is final and its first turn can start.
func (s *Server) waitStateReady(ctx context.Context, ns, name string) error {
	deadline := time.Now().Add(startTimeout)
	for {
		st, err := s.cluster.GetSession(ctx, ns, name)
		if err == nil && st.Status.Phase == v1.StateReady {
			return nil
		}
		if err == nil && st.Status.Phase == v1.StateFailed {
			return fmt.Errorf("child chat %s could not start: %s", name, st.Status.Message)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for child chat %s", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(statusPoll):
		}
	}
}

func (s *Server) toolListAgents(ctx context.Context, caller *Caller) (string, error) {
	children, err := s.cluster.ListChildSessions(ctx, caller.Namespace, caller.Session.Name)
	if err != nil {
		return "", err
	}
	type info struct {
		Name     string    `json:"id"`
		Title    string    `json:"title,omitempty"`
		Profile  string    `json:"profile"`
		Phase    string    `json:"phase"`
		Running  bool      `json:"running"`
		Waiting  bool      `json:"waiting,omitempty"`
		Question *Question `json:"question,omitempty"`
	}
	out := make([]info, 0, len(children))
	for i := range children {
		blips, err := s.cluster.ListStateBlips(ctx, caller.Namespace, children[i].Name)
		if err != nil {
			return "", err
		}
		summary := summarize(&children[i], blips)
		view := s.readView(ctx, &children[i])
		phase, running := summary.Phase, view.busy()
		if running && phase != string(v1.BlipRunning) {
			phase = string(v1.BlipPending)
		}
		if !running && phase == string(v1.BlipRunning) {
			phase = string(v1.BlipSaving)
		}
		out = append(out, info{
			Name: summary.Name, Title: summary.Title, Profile: summary.Profile, Phase: phase,
			Running: running, Waiting: view.Question != nil, Question: view.Question,
		})
	}
	return jsonText(map[string]any{"agents": out}), nil
}

func (s *Server) toolGetAgent(ctx context.Context, caller *Caller, id string, waitSeconds int) (string, error) {
	st, err := s.child(ctx, caller, id)
	if err != nil {
		return "", err
	}
	wait := time.Duration(waitSeconds) * time.Second
	if wait > maxAgentWait {
		wait = maxAgentWait
	}
	deadline := time.Now().Add(wait)
	for {
		view := s.readView(ctx, st)
		// A prompt can be queued before the engine has sent it, so "busy"
		// alone reports a child idle while it still has work to do.
		if !view.hasWork() || view.Question != nil || wait == 0 || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(statusPoll):
		}
	}
	blips, err := s.cluster.ListStateBlips(ctx, caller.Namespace, id)
	if err != nil {
		return "", err
	}
	view := s.readView(ctx, st)
	summary := summarize(st, blips)
	running := view.busy()
	phase := summary.Phase
	if running && phase != string(v1.BlipRunning) {
		phase = string(v1.BlipPending)
	}
	if !running && phase == string(v1.BlipRunning) {
		phase = string(v1.BlipSaving)
	}
	out := map[string]any{
		"id":      summary.Name,
		"title":   summary.Title,
		"profile": summary.Profile,
		"phase":   phase,
		"running": running,
		"idle":    !running,
		"reply":   view.Reply,
	}
	if view.Question != nil {
		out["question"] = view.Question
		out["note"] = "the child is waiting for the user's answer; send_agent answers it"
	} else if running {
		out["note"] = "the child is still working; call get_agent again with waitSeconds"
	}
	return jsonText(out), nil
}

// toolAskUser asks the user a question and waits for the answer. A timeout is
// reported as normal text that tells the agent to end its turn.
func (s *Server) toolAskUser(ctx context.Context, caller *Caller, question string, options []string) (string, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		return "", errors.New("question is required")
	}
	st := caller.Session
	profile, err := s.profileFor(st)
	if err != nil {
		return "", err
	}
	view := s.readView(ctx, st)
	if view.Question != nil {
		return "", errors.New("another question is already waiting for an answer")
	}
	q := Question{
		ID:      "q" + strconv.FormatInt(time.Now().UnixNano(), 36) + randomSuffix(),
		Text:    shorten(question, maxQuestionBytes),
		Options: cleanOptions(options),
		AskedAt: time.Now(),
	}
	note := noteRecord{Type: noteQuestion, ID: q.ID, Text: q.Text, Options: q.Options}
	if err := s.appendNote(ctx, st, profile, note); err != nil {
		return "", fmt.Errorf("could not ask the question: %w", err)
	}
	s.ensureEngine(st.Name)
	deadline := time.Now().Add(s.questionTTL)
	for {
		select {
		case <-ctx.Done():
			// The request is already cancelled, but its question must not
			// capture the next user message. Only expire this call's QID.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
			_, _ = s.writeNote(cleanupCtx, st.Name, noteRecord{Type: noteExpire, QID: q.ID})
			cancel()
			return "", ctx.Err()
		case <-time.After(statusPoll):
		}
		view = s.readView(ctx, st)
		for _, answer := range view.Answers {
			if answer.QID == q.ID {
				// Tell the driver this answer was delivered in-band so it is
				// not replayed as a separate turn.
				_, _ = s.writeNote(ctx, st.Name, noteRecord{Type: noteConsumed, QID: q.ID})
				return answer.Text, nil
			}
		}
		if time.Now().After(deadline) {
			_, _ = s.writeNote(ctx, st.Name, noteRecord{Type: noteExpire, QID: q.ID})
			return "The user hasn't answered yet. End your turn now; their answer will arrive as your next message.", nil
		}
	}
}

func (s *Server) toolSendAgent(ctx context.Context, caller *Caller, id, prompt string) (string, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return "", errors.New("prompt is required")
	}
	if len(prompt) > 32000 {
		return "", errors.New("prompt is too long")
	}
	st, err := s.child(ctx, caller, id)
	if err != nil {
		return "", err
	}
	profile, err := s.profileFor(st)
	if err != nil {
		return "", err
	}
	view := s.readView(ctx, st)
	if view.Question != nil {
		note := noteRecord{Type: noteAnswer, QID: view.Question.ID, Text: prompt, Sender: agentSender(caller), Gen: view.questionGen(view.Question.ID)}
		if err := s.appendNote(ctx, st, profile, note); err != nil {
			return "", fmt.Errorf("could not answer the question: %w", err)
		}
		s.ensureEngine(id)
		return jsonText(map[string]any{"id": id, "answered": true}), nil
	}
	note, err := s.promptNote(st, profile, agentSender(caller), prompt)
	if err != nil {
		return "", fmt.Errorf("could not send the prompt: %w", err)
	}
	if err := s.appendNote(ctx, st, profile, note); err != nil {
		return "", fmt.Errorf("could not send the prompt: %w", err)
	}
	s.ensureEngine(id)
	return jsonText(map[string]any{"id": id, "sent": true}), nil
}

func (s *Server) toolStopAgent(ctx context.Context, caller *Caller, id string) (string, error) {
	if _, err := s.child(ctx, caller, id); err != nil {
		return "", err
	}
	if _, err := s.writeNote(ctx, id, noteRecord{Type: noteStop}); err != nil && !errors.Is(err, ErrNotRunning) {
		return "", fmt.Errorf("could not stop the child chat: %w", err)
	}
	if err := s.stopBlip(ctx, id); err != nil {
		return "", err
	}
	return jsonText(map[string]any{"id": id, "stopping": true}), nil
}
