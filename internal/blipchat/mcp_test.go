// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// mcpCallers is a Callers implementation for tests: a token maps directly to
// the chat a real token review would have proven.
type mcpCallers struct {
	byToken map[string]*Caller
}

func (f mcpCallers) Identify(_ context.Context, namespace, token string) (*Caller, error) {
	caller, ok := f.byToken[token]
	if !ok || caller.Namespace != namespace {
		return nil, errors.New("unknown token")
	}
	return caller, nil
}

func mcpProfiles() Profiles {
	return Profiles{
		DefaultProfileName: {Command: []string{"agent"}, Title: "Parent"},
		"worker": {
			Command:     []string{"agent"},
			Title:       "Worker",
			Description: "Does the work",
			Workspace:   WorkspaceBase,
		},
	}
}

func newMCPGateway(t *testing.T, timeout time.Duration) (*testGateway, *httptest.Server, *v1.BlipState) {
	t.Helper()
	fc := newFakeCluster()
	caller := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-root",
			Namespace: "team",
			UID:       "uid-root",
			Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: "chat-root"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationRoot:    "chat-root",
				AnnotationDepth:   "0",
			},
		},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	if err := fc.CreateSession(context.Background(), "team", caller); err != nil {
		t.Fatal(err)
	}
	g := newGatewayWithCluster(t, fc, Options{
		Profiles:        mcpProfiles(),
		MCPURL:          "http://blipchat/mcp",
		QuestionTimeout: timeout,
		Callers: mcpCallers{byToken: map[string]*Caller{
			"token-root": {Namespace: "team", Session: caller},
		}},
	})
	mcp := httptest.NewServer(g.srv.MCPHandler())
	t.Cleanup(mcp.Close)
	return g, mcp, caller
}

type mcpReply struct {
	Result json.RawMessage `json:"result"`
	Error  *mcpError       `json:"error"`
}

func (g *testGateway) mcpRequest(t *testing.T, base, token, method string, params any) mcpReply {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", base+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", method, resp.StatusCode)
	}
	var out mcpReply
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

type mcpToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func (g *testGateway) mcpTool(t *testing.T, base, token, name string, args map[string]any) (string, bool) {
	t.Helper()
	reply := g.mcpRequest(t, base, token, "tools/call", map[string]any{"name": name, "arguments": args})
	if reply.Error != nil {
		t.Fatalf("%s: rpc error %d: %s", name, reply.Error.Code, reply.Error.Message)
	}
	var result mcpToolResult
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Content) == 0 {
		return "", result.IsError
	}
	return result.Content[0].Text, result.IsError
}

func TestMCPToolsList(t *testing.T) {
	gw, mcp, _ := newMCPGateway(t, 200*time.Millisecond)

	reply := gw.mcpRequest(t, mcp.URL, "token-root", "tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(reply.Result, &list); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"list_profiles", "spawn_agent", "list_agents", "get_agent", "send_agent", "stop_agent", "ask_user"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tools %v do not contain %q", names, want)
		}
	}

	reply = gw.mcpRequest(t, mcp.URL, "token-root", "ping", nil)
	if reply.Error != nil {
		t.Fatalf("ping: %+v", reply.Error)
	}
}

func TestMCPSpawnListAndGet(t *testing.T) {
	gw, mcp, caller := newMCPGateway(t, 200*time.Millisecond)

	text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "spawn_agent", map[string]any{
		"profile": "worker",
		"prompt":  "review the change",
		"title":   "Reviewer",
	})
	if isErr {
		t.Fatalf("spawn_agent: %s", text)
	}
	var spawned struct {
		ID        string `json:"id"`
		Profile   string `json:"profile"`
		Workspace string `json:"workspace"`
	}
	if err := json.Unmarshal([]byte(text), &spawned); err != nil {
		t.Fatalf("spawn_agent result %q: %v", text, err)
	}
	if spawned.ID == "" || spawned.Profile != "worker" || spawned.Workspace != WorkspaceBase {
		t.Fatalf("spawn_agent = %+v", spawned)
	}

	child, err := gw.cluster.GetSession(context.Background(), "team", spawned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if child.Annotations[AnnotationParent] != caller.Name {
		t.Fatalf("parent annotation = %q, want %q", child.Annotations[AnnotationParent], caller.Name)
	}
	if child.Labels[LabelParent] != caller.Name || child.Labels[v1.LabelOwner] != caller.Name {
		t.Fatalf("child labels = %v", child.Labels)
	}
	if child.Annotations[AnnotationTitle] != "Reviewer" || child.Annotations[AnnotationProfile] != "worker" {
		t.Fatalf("child annotations = %v", child.Annotations)
	}
	if !hasNote(gw.wire.notes(), notePrompt, func(n noteRecord) bool {
		return n.Original == "review the change" && strings.HasPrefix(n.Sender, "agent:")
	}) {
		t.Fatalf("child prompt notes = %+v", gw.wire.notes())
	}

	text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "list_agents", map[string]any{})
	if isErr {
		t.Fatalf("list_agents: %s", text)
	}
	var listed struct {
		Agents []struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Profile string `json:"profile"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(text), &listed); err != nil {
		t.Fatalf("list_agents result %q: %v", text, err)
	}
	if len(listed.Agents) != 1 || listed.Agents[0].ID != spawned.ID ||
		listed.Agents[0].Title != "Reviewer" || listed.Agents[0].Profile != "worker" {
		t.Fatalf("list_agents = %+v", listed.Agents)
	}

	text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "get_agent", map[string]any{
		"id":          spawned.ID,
		"waitSeconds": 5,
	})
	if isErr {
		t.Fatalf("get_agent: %s", text)
	}
	var got struct {
		ID      string `json:"id"`
		Running bool   `json:"running"`
		Idle    bool   `json:"idle"`
		Reply   string `json:"reply"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("get_agent result %q: %v", text, err)
	}
	if got.ID != spawned.ID || !got.Idle || got.Running {
		t.Fatalf("get_agent = %+v", got)
	}
	if !strings.Contains(got.Reply, "done: review the change") {
		t.Fatalf("get_agent reply = %q", got.Reply)
	}
}

func TestMCPSendAgent(t *testing.T) {
	gw, mcp, _ := newMCPGateway(t, 200*time.Millisecond)

	text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "spawn_agent", map[string]any{
		"profile": "worker",
		"prompt":  "first task",
	})
	if isErr {
		t.Fatalf("spawn_agent: %s", text)
	}
	var spawned struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(text), &spawned); err != nil {
		t.Fatal(err)
	}

	// Wait for the first turn so the child is idle before the follow-up.
	if text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "get_agent", map[string]any{"id": spawned.ID, "waitSeconds": 5}); isErr {
		t.Fatalf("get_agent: %s", text)
	}

	text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "send_agent", map[string]any{
		"id":     spawned.ID,
		"prompt": "carry on",
	})
	if isErr {
		t.Fatalf("send_agent: %s", text)
	}
	var sent struct {
		ID   string `json:"id"`
		Sent bool   `json:"sent"`
	}
	if err := json.Unmarshal([]byte(text), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.ID != spawned.ID || !sent.Sent {
		t.Fatalf("send_agent = %+v", sent)
	}
	if !hasNote(gw.wire.notes(), notePrompt, func(n noteRecord) bool { return n.Original == "carry on" }) {
		t.Fatalf("second prompt note missing: %+v", gw.wire.notes())
	}

	text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "get_agent", map[string]any{"id": spawned.ID, "waitSeconds": 5})
	if isErr || !strings.Contains(text, "done: carry on") {
		t.Fatalf("get_agent after send = %s / %t", text, isErr)
	}

	// While a question is open, send_agent answers it instead of prompting.
	gw.wire.note(noteRecord{Type: noteQuestion, ID: "q-child", Text: "Approve?", Options: []string{"yes", "no"}})
	// The fake writes straight to the ring, bypassing the server's view cache.
	gw.srv.invalidateView(spawned.ID)
	text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "send_agent", map[string]any{
		"id":     spawned.ID,
		"prompt": "yes",
	})
	if isErr {
		t.Fatalf("send_agent answer: %s", text)
	}
	var answered struct {
		ID       string `json:"id"`
		Answered bool   `json:"answered"`
	}
	if err := json.Unmarshal([]byte(text), &answered); err != nil {
		t.Fatal(err)
	}
	if answered.ID != spawned.ID || !answered.Answered {
		t.Fatalf("send_agent answer = %+v", answered)
	}
	if !hasNote(gw.wire.notes(), noteAnswer, func(n noteRecord) bool {
		return n.QID == "q-child" && n.Text == "yes"
	}) {
		t.Fatalf("answer note = %+v", gw.wire.notes())
	}
}

func TestMCPStopAgent(t *testing.T) {
	gw, mcp, caller := newMCPGateway(t, 200*time.Millisecond)

	child := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-child",
			Namespace: "team",
			Labels: map[string]string{
				LabelSession:  "true",
				LabelParent:   caller.Name,
				v1.LabelOwner: caller.Name,
			},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationParent:  caller.Name,
				AnnotationRoot:    caller.Name,
				AnnotationDepth:   "1",
			},
		},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	if err := gw.cluster.CreateSession(context.Background(), "team", child); err != nil {
		t.Fatal(err)
	}
	gw.addRunningBlip(t, child.Name)

	text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "stop_agent", map[string]any{"id": child.Name})
	if isErr {
		t.Fatalf("stop_agent: %s", text)
	}
	var stopped struct {
		ID       string `json:"id"`
		Stopping bool   `json:"stopping"`
	}
	if err := json.Unmarshal([]byte(text), &stopped); err != nil {
		t.Fatal(err)
	}
	if stopped.ID != child.Name || !stopped.Stopping {
		t.Fatalf("stop_agent = %+v", stopped)
	}
	if !hasNote(gw.wire.notes(), noteStop, nil) {
		t.Fatalf("stop note = %+v", gw.wire.notes())
	}
	blips, err := gw.cluster.ListStateBlips(context.Background(), "team", child.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(blips) != 1 || blips[0].Status.Phase != v1.BlipSucceeded {
		t.Fatalf("blips after stop = %+v", blips)
	}
}

func TestMCPAskUser(t *testing.T) {
	t.Run("second question while one is open", func(t *testing.T) {
		gw, mcp, _ := newMCPGateway(t, 200*time.Millisecond)
		gw.wire.note(noteRecord{Type: noteQuestion, ID: "q-open", Text: "Already?"})

		text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "ask_user", map[string]any{"question": "Second?"})
		if !isErr || !strings.Contains(text, "another question") {
			t.Fatalf("ask_user = %q / %t", text, isErr)
		}
	})

	t.Run("timely answer", func(t *testing.T) {
		gw, mcp, caller := newMCPGateway(t, time.Second)

		answered := make(chan error, 1)
		go func() {
			ctx := context.Background()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				view := gw.srv.readView(ctx, caller)
				if q := view.Question; q != nil {
					_, err := gw.srv.writeNote(ctx, caller.Name, noteRecord{
						Type: noteAnswer, QID: q.ID, Text: "Yes", Sender: "browser", Gen: view.Gen,
					})
					answered <- err
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			answered <- errors.New("ask_user did not open a question")
		}()

		text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "ask_user", map[string]any{
			"question": "Ship it?",
			"options":  []string{"Yes", "No"},
		})
		if err := <-answered; err != nil {
			t.Fatal(err)
		}
		if isErr || text != "Yes" {
			t.Fatalf("ask_user = %q / %t", text, isErr)
		}

		var qid string
		for _, note := range gw.wire.notes() {
			if note.Type == noteQuestion {
				qid = note.ID
			}
		}
		if qid == "" {
			t.Fatalf("question note = %+v", gw.wire.notes())
		}
		if !hasNote(gw.wire.notes(), noteConsumed, func(n noteRecord) bool { return n.QID == qid }) {
			t.Fatalf("consumed note = %+v", gw.wire.notes())
		}
	})

	t.Run("timeout", func(t *testing.T) {
		gw, mcp, _ := newMCPGateway(t, 200*time.Millisecond)

		start := time.Now()
		text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "ask_user", map[string]any{"question": "Still there?"})
		if isErr {
			t.Fatalf("timeout returned an error: %s", text)
		}
		if !strings.Contains(text, "hasn't answered") || !strings.Contains(text, "End your turn") {
			t.Fatalf("timeout text = %q", text)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("ask_user timeout took %v", elapsed)
		}

		var qid string
		for _, note := range gw.wire.notes() {
			if note.Type == noteQuestion {
				qid = note.ID
			}
		}
		if qid == "" {
			t.Fatalf("question note = %+v", gw.wire.notes())
		}
		if !hasNote(gw.wire.notes(), noteExpire, func(n noteRecord) bool { return n.QID == qid }) {
			t.Fatalf("expire note = %+v", gw.wire.notes())
		}
	})

	t.Run("non-child ids", func(t *testing.T) {
		gw, mcp, _ := newMCPGateway(t, 200*time.Millisecond)
		stranger := &v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "chat-stranger",
				Namespace: "team",
				Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: "chat-stranger"},
				Annotations: map[string]string{
					AnnotationProfile: DefaultProfileName,
					AnnotationParent:  "chat-someone-else",
					AnnotationRoot:    "chat-someone-else",
					AnnotationDepth:   "1",
				},
			},
			Status: v1.BlipStateStatus{Phase: v1.StateReady},
		}
		if err := gw.cluster.CreateSession(context.Background(), "team", stranger); err != nil {
			t.Fatal(err)
		}

		for _, tc := range []struct {
			id   string
			want string
		}{
			{"chat-stranger", "was not started by this chat"},
			{"chat-missing", "no child chat"},
		} {
			text, isErr := gw.mcpTool(t, mcp.URL, "token-root", "get_agent", map[string]any{"id": tc.id})
			if !isErr || !strings.Contains(text, tc.want) {
				t.Fatalf("get_agent %s = %q / %t, want %q", tc.id, text, isErr, tc.want)
			}
			text, isErr = gw.mcpTool(t, mcp.URL, "token-root", "stop_agent", map[string]any{"id": tc.id})
			if !isErr || !strings.Contains(text, tc.want) {
				t.Fatalf("stop_agent %s = %q / %t, want %q", tc.id, text, isErr, tc.want)
			}
		}
	})
}
