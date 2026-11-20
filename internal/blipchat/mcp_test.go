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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

type fakeCallers struct{ byToken map[string]*Caller }

func (f fakeCallers) Identify(_ context.Context, ns, token string) (*Caller, error) {
	c, ok := f.byToken[token]
	if !ok || c.Namespace != ns {
		return nil, errors.New("unknown token")
	}
	return c, nil
}

func agentProfiles() Profiles {
	return Profiles{
		DefaultProfileName: {
			Command:   []string{"agent"},
			Title:     "Parent",
			Workspace: WorkspaceBase,
		},
		"worker": {
			Command:     []string{"agent"},
			Description: "Does the work",
			Title:       "Worker",
			Workspace:   WorkspaceBase,
		},
	}
}

func testMCP(t *testing.T, profiles Profiles) (*Server, *fakeCluster, *fakeWire, *httptest.Server, *v1.BlipState) {
	t.Helper()
	fc := newFakeCluster()
	fw := newFakeWire()
	fw.autoRespond = true
	caller := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-root",
			Namespace: "team",
			UID:       "uid-root",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationDepth:   "0",
			},
		},
	}
	if err := fc.CreateSession(context.Background(), "team", caller); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Namespace: "team",
		Profiles:  profiles,
		Cluster:   fc,
		Wire:      fw,
		Log:       testLogger(),
		Callers:   fakeCallers{byToken: map[string]*Caller{"token-root": {Namespace: "team", Session: caller}}},
		MCPURL:    "http://blipchat/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.MCPHandler())
	t.Cleanup(func() {
		fw.closeLog()
		ts.Close()
		s.Close()
	})
	return s, fc, fw, ts, caller
}

type rpcReply struct {
	Result json.RawMessage `json:"result"`
	Error  *mcpError       `json:"error"`
}

func rpcDo(t *testing.T, url, token, method string, params any) rpcReply {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest("POST", url+"/mcp", bytes.NewReader(body))
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
	if resp.StatusCode == http.StatusUnauthorized {
		return rpcReply{}
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", method, resp.StatusCode)
	}
	var out rpcReply
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func callTool(t *testing.T, url, token, name string, args map[string]any) (string, bool) {
	t.Helper()
	reply := rpcDo(t, url, token, "tools/call", map[string]any{"name": name, "arguments": args})
	if reply.Error != nil {
		t.Fatalf("%s: rpc error %s", name, reply.Error.Message)
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Content) == 0 {
		return "", result.IsError
	}
	return result.Content[0].Text, result.IsError
}

func TestMCPRequiresCaller(t *testing.T) {
	_, _, _, ts, _ := testMCP(t, agentProfiles())

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d", resp.StatusCode)
	}
	if reply := rpcDo(t, ts.URL, "bogus", "ping", nil); reply.Error != nil || len(reply.Result) != 0 {
		t.Fatalf("bogus token: %+v", reply)
	}
}

func TestMCPInitializeAndTools(t *testing.T) {
	_, _, _, ts, _ := testMCP(t, agentProfiles())

	init := rpcDo(t, ts.URL, "token-root", "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(init.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.ProtocolVersion != "2025-06-18" || result.ServerInfo.Name != "blipchat" {
		t.Fatalf("initialize = %+v", result)
	}

	list := rpcDo(t, ts.URL, "token-root", "tools/list", map[string]any{})
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(list.Result, &tools); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"list_profiles", "spawn_agent", "list_agents", "get_agent", "send_agent", "stop_agent", "ask_user"} {
		if !strings.Contains(strings.Join(names, ","), want) {
			t.Fatalf("tools %v do not contain %q", names, want)
		}
	}
}

func TestMCPListProfilesListsAll(t *testing.T) {
	profiles := agentProfiles()
	profiles["secret"] = Profile{Command: []string{"agent"}}
	_, _, _, ts, _ := testMCP(t, profiles)

	text, isErr := callTool(t, ts.URL, "token-root", "list_profiles", map[string]any{})
	if isErr {
		t.Fatal(text)
	}
	for _, want := range []string{"worker", "Does the work", "secret"} {
		if !strings.Contains(text, want) {
			t.Fatalf("list_profiles = %s, want %q", text, want)
		}
	}
	if strings.Contains(text, "maxChildren") || strings.Contains(text, "maxDepth") {
		t.Fatalf("list_profiles still reports policy limits: %s", text)
	}
}

func TestMCPSpawnAgentTree(t *testing.T) {
	_, fc, fw, ts, caller := testMCP(t, agentProfiles())

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{
		"profile": "worker",
		"prompt":  "review the change",
		"title":   "Reviewer",
	})
	if isErr {
		t.Fatal(text)
	}
	var spawned struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(text), &spawned); err != nil {
		t.Fatal(err)
	}
	child, err := fc.GetSession(context.Background(), "team", spawned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if child.Labels[LabelSession] != "true" || child.Labels[LabelParent] != caller.Name || child.Labels[v1.LabelOwner] != caller.Name {
		t.Fatalf("labels = %v", child.Labels)
	}
	if child.Annotations[AnnotationParent] != caller.Name || child.Annotations[AnnotationRoot] != caller.Name || child.Annotations[AnnotationDepth] != "1" {
		t.Fatalf("tree annotations = %v", child.Annotations)
	}
	if child.Annotations[AnnotationParentProfile] != DefaultProfileName || child.Annotations[AnnotationParentDepth] != "0" {
		t.Fatalf("parent policy annotations = %v", child.Annotations)
	}
	if child.Annotations[AnnotationTitle] != "Reviewer" || child.Annotations[AnnotationProfile] != "worker" {
		t.Fatalf("annotations = %v", child.Annotations)
	}
	if len(child.OwnerReferences) != 1 || child.OwnerReferences[0].Name != caller.Name {
		t.Fatalf("ownerReferences = %v", child.OwnerReferences)
	}
	// The MCP server is offered to the child agent in session/new.
	waitFor(t, "the child agent to start", func() bool {
		for _, m := range fw.messages() {
			if m.method == "session/new" {
				return true
			}
		}
		return false
	})
	joined := ""
	for _, m := range fw.messages() {
		joined += string(m.raw)
	}
	if !strings.Contains(joined, `"blipchat"`) || !strings.Contains(joined, `"mcpServers"`) {
		t.Fatalf("session/new did not offer the MCP server: %s", joined)
	}

	text, isErr = callTool(t, ts.URL, "token-root", "get_agent", map[string]any{"id": spawned.ID, "waitSeconds": 5})
	if isErr {
		t.Fatal(text)
	}
	var got struct {
		Idle    bool   `json:"idle"`
		Running bool   `json:"running"`
		Phase   string `json:"phase"`
		Reply   string `json:"reply"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Idle || !strings.Contains(got.Reply, "review the change") {
		t.Fatalf("get_agent = %s", text)
	}
	// The Blip can still report Running while the driver has already received
	// the reply. get_agent must not return idle:true together with a running or
	// Running-phase child.
	if got.Running || strings.EqualFold(got.Phase, "Running") {
		t.Fatalf("get_agent contradictory idle state = %s", text)
	}

	text, isErr = callTool(t, ts.URL, "token-root", "list_agents", map[string]any{})
	if isErr || !strings.Contains(text, spawned.ID) {
		t.Fatalf("list_agents = %s", text)
	}
	var listed struct {
		Agents []struct {
			ID      string `json:"id"`
			Phase   string `json:"phase"`
			Running bool   `json:"running"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(text), &listed); err != nil {
		t.Fatal(err)
	}
	if got.Idle {
		for _, agent := range listed.Agents {
			if agent.ID == spawned.ID && (agent.Running || strings.EqualFold(agent.Phase, "Running")) {
				t.Fatalf("list_agents contradicts get_agent idle state: %s", text)
			}
		}
	}

	text, isErr = callTool(t, ts.URL, "token-root", "send_agent", map[string]any{"id": spawned.ID, "prompt": "carry on"})
	if isErr {
		t.Fatal(text)
	}
	text, isErr = callTool(t, ts.URL, "token-root", "get_agent", map[string]any{"id": spawned.ID, "waitSeconds": 5})
	if isErr || !strings.Contains(text, "carry on") {
		t.Fatalf("get_agent after send = %s", text)
	}

	text, isErr = callTool(t, ts.URL, "token-root", "stop_agent", map[string]any{"id": spawned.ID})
	if isErr {
		t.Fatal(text)
	}
}

func TestMCPChildUsesMessageTemplate(t *testing.T) {
	profiles := agentProfiles()
	worker := profiles["worker"]
	worker.MessageTemplate = "parent={{.Parent}} root={{.Root}} depth={{.Depth}} text={{.Text}}"
	profiles["worker"] = worker
	_, _, fw, ts, caller := testMCP(t, profiles)

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{
		"profile": "worker",
		"prompt":  "work",
	})
	if isErr {
		t.Fatal(text)
	}
	want := "parent=" + caller.Name + " root=" + caller.Name + " depth=1 text=work"
	waitFor(t, "the templated child prompt", func() bool {
		for _, m := range fw.messages() {
			if m.method == "session/prompt" && strings.Contains(string(m.raw), want) {
				return true
			}
		}
		return false
	})
}

func TestMCPWorkspaceForkCopiesParent(t *testing.T) {
	profiles := agentProfiles()
	worker := profiles["worker"]
	worker.Workspace = WorkspaceFork
	profiles["worker"] = worker
	_, fc, _, ts, caller := testMCP(t, profiles)

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{"profile": "worker", "prompt": "work"})
	if isErr {
		t.Fatal(text)
	}
	var spawned struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(text), &spawned); err != nil {
		t.Fatal(err)
	}
	child, err := fc.GetSession(context.Background(), "team", spawned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if child.Spec.CopyFrom != caller.Name {
		t.Fatalf("copyFrom = %q, want %q", child.Spec.CopyFrom, caller.Name)
	}
}

func TestMCPSpawnRejectsUnknownProfile(t *testing.T) {
	_, _, _, ts, _ := testMCP(t, agentProfiles())

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{"profile": "missing", "prompt": "x"})
	if !isErr || !strings.Contains(text, "unknown profile") {
		t.Fatalf("unknown profile = %s/%t", text, isErr)
	}
}

func TestMCPSpawnPropagatesAdmissionError(t *testing.T) {
	_, fc, _, ts, _ := testMCP(t, agentProfiles())
	fc.mu.Lock()
	fc.createSessionErr = apierrors.NewForbidden(
		schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, "chat",
		errors.New(`admission webhook "chat-policy" denied the request`))
	fc.mu.Unlock()

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{"profile": "worker", "prompt": "x"})
	if !isErr || !strings.Contains(text, "denied the request") {
		t.Fatalf("admission denial = %s/%t", text, isErr)
	}
}

func TestMCPRejectsForeignChat(t *testing.T) {
	_, fc, _, ts, _ := testMCP(t, agentProfiles())
	if err := fc.CreateSession(context.Background(), "team", &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-other", Namespace: "team", Labels: map[string]string{LabelSession: "true"},
		Annotations: map[string]string{AnnotationProfile: DefaultProfileName, AnnotationParent: "chat-someone-else"},
	}}); err != nil {
		t.Fatal(err)
	}
	text, isErr := callTool(t, ts.URL, "token-root", "get_agent", map[string]any{"id": "chat-other"})
	if !isErr || !strings.Contains(text, "not started by this chat") {
		t.Fatalf("foreign chat = %s/%t", text, isErr)
	}
}

func TestMCPAskUserAnsweredInTurn(t *testing.T) {
	s, _, _, ts, caller := testMCP(t, agentProfiles())
	ctx := context.Background()
	d, err := s.driverFor(ctx, caller.Name)
	if err != nil {
		t.Fatal(err)
	}
	answerErr := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && d.Question() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		if d.Question() == nil {
			answerErr <- errors.New("ask_user did not open a question")
			return
		}
		answerErr <- d.Answer("browser", "Yes")
	}()
	text, isErr := callTool(t, ts.URL, "token-root", "ask_user", map[string]any{
		"question": "Ship it?",
		"options":  []string{"Yes", "No"},
	})
	if err := <-answerErr; err != nil {
		t.Fatal(err)
	}
	if isErr || text != "Yes" {
		t.Fatalf("ask_user = %q, isError=%v", text, isErr)
	}
	if d.Question() != nil {
		t.Fatal("question still open after the answer")
	}
}

func TestMCPAskUserTimesOut(t *testing.T) {
	s, fc, _, ts, caller := testMCP(t, agentProfiles())
	s.questionTTL = 25 * time.Millisecond
	text, isErr := callTool(t, ts.URL, "token-root", "ask_user", map[string]any{"question": "Still there?"})
	if isErr {
		t.Fatalf("timeout returned an error: %s", text)
	}
	if !strings.Contains(text, "hasn't answered") || !strings.Contains(text, "End your turn") {
		t.Fatalf("timeout text = %q", text)
	}
	d, err := s.driverFor(context.Background(), caller.Name)
	if err != nil {
		t.Fatal(err)
	}
	if d.Question() == nil {
		t.Fatal("question was cleared on timeout")
	}
	st, err := fc.GetSession(context.Background(), "team", caller.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Annotations[AnnotationQuestion] == "" {
		t.Fatal("question annotation was not persisted on timeout")
	}
	if err := d.Answer("browser", "Yes"); err != nil {
		t.Fatalf("late answer: %v", err)
	}
}

func TestMCPAskUserRejectsSecondQuestion(t *testing.T) {
	s, _, _, ts, caller := testMCP(t, agentProfiles())
	d, err := s.driverFor(context.Background(), caller.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.startQuestion("first", nil); err != nil {
		t.Fatal(err)
	}
	text, isErr := callTool(t, ts.URL, "token-root", "ask_user", map[string]any{"question": "second"})
	if !isErr || !strings.Contains(text, "another question") {
		t.Fatalf("second question = %q, isError=%v", text, isErr)
	}
	if err := d.Answer("browser", "one"); err != nil {
		t.Fatal(err)
	}
}

func TestMCPChildQuestionIsVisibleAndAnswerable(t *testing.T) {
	s, _, _, ts, _ := testMCP(t, agentProfiles())
	ctx := context.Background()

	text, isErr := callTool(t, ts.URL, "token-root", "spawn_agent", map[string]any{
		"profile": "worker",
		"prompt":  "review the change",
	})
	if isErr {
		t.Fatal(text)
	}
	var spawned struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(text), &spawned); err != nil {
		t.Fatal(err)
	}
	d, err := s.driverFor(ctx, spawned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.startQuestion("Approve the change?", []string{"Approve", "Reject"}); err != nil {
		t.Fatal(err)
	}

	list, isErr := callTool(t, ts.URL, "token-root", "list_agents", map[string]any{})
	if isErr {
		t.Fatal(list)
	}
	if !strings.Contains(list, `"waiting": true`) || !strings.Contains(list, "Approve the change?") {
		t.Fatalf("list_agents = %s", list)
	}

	reply, isErr := callTool(t, ts.URL, "token-root", "get_agent", map[string]any{"id": spawned.ID, "waitSeconds": 5})
	if isErr {
		t.Fatal(reply)
	}
	if !strings.Contains(reply, "Approve the change?") || !strings.Contains(reply, "send_agent") {
		t.Fatalf("get_agent = %s", reply)
	}

	sent, isErr := callTool(t, ts.URL, "token-root", "send_agent", map[string]any{"id": spawned.ID, "prompt": "Approve"})
	if isErr {
		t.Fatal(sent)
	}
	if !strings.Contains(sent, `"answered": true`) {
		t.Fatalf("send_agent = %s", sent)
	}
	if d.Question() != nil {
		t.Fatal("send_agent did not answer the child's question")
	}
}
