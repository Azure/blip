// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// runningWire makes fakeWire behave like the node's stdin endpoint: a state
// with no running blip rejects writes with ErrNotRunning. That is what makes
// appendNote start a generation, as it does in a real deployment.
type runningWire struct {
	*fakeWire
	cluster *fakeCluster
}

func (w *runningWire) Send(ctx context.Context, ns, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	blips, err := w.cluster.ListStateBlips(ctx, ns, state)
	if err != nil {
		return 0, err
	}
	if runningBlip(blips) == nil {
		return 0, ErrNotRunning
	}
	return w.fakeWire.Send(ctx, ns, state, data, eof, note, after)
}

// The ring is NDJSON in the node's short wire form. Encode it here rather than
// relying on encoding/json's default field names so the fake round-trips
// through streamLogRecord.UnmarshalJSON exactly like the real endpoint.
func encodeLogRecord(rec streamLogRecord) []byte {
	line, _ := json.Marshal(struct {
		O uint64 `json:"o"`
		G uint64 `json:"g"`
		T int    `json:"t"`
		D string `json:"d"`
	}{
		O: rec.Offset,
		G: rec.Gen,
		T: int(rec.Type),
		D: base64.StdEncoding.EncodeToString(rec.Data),
	})
	return append(line, '\n')
}

func (w *runningWire) ReadLog(ctx context.Context, _, _ string, offset uint64) (io.ReadCloser, error) {
	w.fakeWire.mu.Lock()
	var buf bytes.Buffer
	for _, rec := range w.fakeWire.records {
		if rec.Offset < offset {
			continue
		}
		buf.Write(encodeLogRecord(rec))
	}
	w.fakeWire.mu.Unlock()
	return io.NopCloser(&buf), nil
}

func (w *runningWire) OpenLog(ctx context.Context, _, _ string, offset uint64) (io.ReadCloser, error) {
	return &followLogReader{wire: w.fakeWire, ctx: ctx, after: offset}, nil
}

// followLogReader replays recorded lines from the requested offset and then
// follows new ones until the context ends.
type followLogReader struct {
	wire  *fakeWire
	ctx   context.Context
	after uint64
	idx   int
	buf   []byte
}

func (r *followLogReader) Read(p []byte) (int, error) {
	for {
		if len(r.buf) > 0 {
			n := copy(p, r.buf)
			r.buf = r.buf[n:]
			return n, nil
		}
		if r.ctx.Err() != nil {
			return 0, io.EOF
		}
		r.wire.mu.Lock()
		if r.idx >= len(r.wire.records) {
			r.wire.mu.Unlock()
			select {
			case <-r.ctx.Done():
				return 0, io.EOF
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		rec := r.wire.records[r.idx]
		r.idx++
		r.wire.mu.Unlock()
		if rec.Offset < r.after {
			continue
		}
		r.buf = encodeLogRecord(rec)
	}
}

func (r *followLogReader) Close() error { return nil }

type testGateway struct {
	srv     *Server
	cluster *fakeCluster
	wire    *fakeWire
	ts      *httptest.Server
}

func newGateway(t *testing.T, opts Options) *testGateway {
	t.Helper()
	return newGatewayWithCluster(t, newFakeCluster(), opts)
}

func newGatewayWithCluster(t *testing.T, fc *fakeCluster, opts Options) *testGateway {
	t.Helper()
	fw := newFakeWire()
	fw.autoRespond = true
	// The node emits a start record and resets the generation sequence when
	// the guest connects, which happens right after a blip starts running.
	fc.onCreateBlip = func(b *v1.Blip) {
		fw.start(uint64(generationOf(b)))
	}
	if opts.Namespace == "" {
		opts.Namespace = "team"
	}
	if opts.DefaultPool == "" {
		opts.DefaultPool = "default"
	}
	if opts.AutoApprove == "" {
		opts.AutoApprove = "always"
	}
	if opts.Profiles == nil {
		opts.Profiles = Profiles{DefaultProfileName: {}}
	}
	opts.Cluster = fc
	opts.Wire = &runningWire{fakeWire: fw, cluster: fc}
	if opts.Log == nil {
		opts.Log = testLogger()
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		cancel()
		s.Close()
		fw.closeLog()
	})
	return &testGateway{srv: s, cluster: fc, wire: fw, ts: ts}
}

func (g *testGateway) request(t *testing.T, method, path string, body any, user string, headers map[string]string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, g.ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.Header.Set("X-Forwarded-User", user)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func (g *testGateway) createChat(t *testing.T, body map[string]any, user string) string {
	t.Helper()
	resp := g.request(t, "POST", "/api/sessions", body, user, nil)
	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create chat: status %d: %s", resp.StatusCode, raw)
	}
	created := decodeBody[struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}](t, resp)
	if created.Name == "" {
		t.Fatal("create chat returned an empty name")
	}
	return created.Name
}

func (g *testGateway) chatState(t *testing.T, name string) *v1.BlipState {
	t.Helper()
	st, err := g.cluster.GetSession(context.Background(), g.srv.namespace, name)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// addRunningBlip creates a Running blip for the chat without driving an
// engine. It lets handler tests inspect notes without waiting for a turn.
func (g *testGateway) addRunningBlip(t *testing.T, state string) *v1.Blip {
	t.Helper()
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s-g1", state),
			Namespace:   g.srv.namespace,
			Labels:      map[string]string{LabelSession: state},
			Annotations: map[string]string{AnnotationGeneration: "1"},
		},
	}
	if err := g.cluster.CreateBlip(context.Background(), g.srv.namespace, blip); err != nil {
		t.Fatal(err)
	}
	return blip
}

func (g *testGateway) promptFrames() []string {
	var out []string
	for _, m := range g.wire.messages() {
		if m.method == "session/prompt" {
			out = append(out, promptText(m.raw))
		}
	}
	return out
}

func (g *testGateway) waitPrompt(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, text := range g.promptFrames() {
			if strings.Contains(text, substr) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var sent []string
	for _, m := range g.wire.messages() {
		label := m.method
		if m.note {
			label = "note"
		}
		if label == "" {
			label = "eof"
		}
		sent = append(sent, fmt.Sprintf("%s(%s:after=%d)", label, m.id, m.after))
	}
	g.srv.mu.Lock()
	engines := len(g.srv.engines)
	g.srv.mu.Unlock()
	t.Fatalf("timed out waiting for session/prompt containing %q; engines=%d sent=%v prompts=%v notes=%+v",
		substr, engines, sent, g.promptFrames(), g.wire.notes())
}

func (g *testGateway) waitReply(t *testing.T, name, substr string) {
	t.Helper()
	waitFor(t, "agent reply containing "+substr, func() bool {
		st, err := g.cluster.GetSession(context.Background(), g.srv.namespace, name)
		if err != nil {
			return false
		}
		return strings.Contains(g.srv.readView(context.Background(), st).Reply, substr)
	})
}

func hasNote(notes []noteRecord, typ string, match func(noteRecord) bool) bool {
	for _, note := range notes {
		if note.Type == typ && (match == nil || match(note)) {
			return true
		}
	}
	return false
}

func TestServerListHidesPrivateChats(t *testing.T) {
	g := newGateway(t, Options{})

	team := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	private := g.createChat(t, map[string]any{"profile": DefaultProfileName, "scope": scopeUser}, "alice")

	resp := g.request(t, "GET", "/api/sessions", nil, "alice", nil)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("list as alice: status %d", resp.StatusCode)
	}
	alice := decodeBody[[]sessionSummary](t, resp)
	got := map[string]sessionSummary{}
	for _, s := range alice {
		got[s.Name] = s
	}
	if len(alice) != 2 {
		t.Fatalf("alice sessions = %+v, want 2", alice)
	}
	if got[team].Scope != scopeTeam {
		t.Fatalf("team scope = %q", got[team].Scope)
	}
	if got[private].Scope != scopeUser {
		t.Fatalf("private scope = %q", got[private].Scope)
	}

	resp = g.request(t, "GET", "/api/sessions", nil, "bob", nil)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("list as bob: status %d", resp.StatusCode)
	}
	bob := decodeBody[[]sessionSummary](t, resp)
	if len(bob) != 1 || bob[0].Name != team {
		t.Fatalf("bob sessions = %+v, want only %s", bob, team)
	}

	resp = g.request(t, "GET", "/api/sessions/"+private, nil, "bob", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob private detail: status %d, want 404", resp.StatusCode)
	}

	resp = g.request(t, "GET", "/api/sessions/"+private, nil, "alice", nil)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("owner private detail: status %d", resp.StatusCode)
	}
	detail := decodeBody[sessionDetail](t, resp)
	if detail.Name != private || detail.Scope != scopeUser {
		t.Fatalf("private detail = %+v", detail)
	}

	resp = g.request(t, "GET", "/api/sessions/"+team, nil, "bob", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob team detail: status %d", resp.StatusCode)
	}
}

func TestServerCreateSessionMetadata(t *testing.T) {
	g := newGateway(t, Options{Profiles: Profiles{
		DefaultProfileName: {},
		"worker":           {Command: []string{"agent"}, Title: "Worker"},
	}})

	name := g.createChat(t, map[string]any{
		"profile": "worker",
		"scope":   scopeUser,
		"title":   "  Fix the build  ",
	}, "alice")

	st := g.chatState(t, name)
	if st.Namespace != "team" {
		t.Fatalf("namespace = %q", st.Namespace)
	}
	if st.Annotations[AnnotationProfile] != "worker" {
		t.Fatalf("profile = %q", st.Annotations[AnnotationProfile])
	}
	if st.Annotations[AnnotationScope] != scopeUser || st.Annotations[AnnotationUser] != "alice" {
		t.Fatalf("scope annotations = %v", st.Annotations)
	}
	if st.Annotations[AnnotationTitle] != "Fix the build" {
		t.Fatalf("title = %q", st.Annotations[AnnotationTitle])
	}
	// Creating a chat must not consume a pool slot before it has a turn.
	if names := g.cluster.blipNames(); len(names) != 0 {
		t.Fatalf("create started blips: %v", names)
	}

	resp := g.request(t, "POST", "/api/sessions", map[string]any{"profile": "missing"}, "alice", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown profile: status %d, want 400", resp.StatusCode)
	}

	resp = g.request(t, "POST", "/api/sessions", map[string]any{"profile": DefaultProfileName, "scope": "everyone"}, "alice", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scope: status %d, want 400", resp.StatusCode)
	}
}

func TestServerMessageValidation(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	for _, tc := range []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"whitespace", "   \n\t "},
		{"too long", strings.Repeat("a", 32001)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": tc.text}, "alice", nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
	if names := g.cluster.blipNames(); len(names) != 0 {
		t.Fatalf("invalid messages started blips: %v", names)
	}
	if notes := g.wire.notes(); len(notes) != 0 {
		t.Fatalf("invalid messages wrote notes: %+v", notes)
	}
}

func TestServerMessageStartsAgentAndWritesNote(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": "hello"}, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("message: status %d: %s", resp.StatusCode, raw)
	}
	accepted := decodeBody[map[string]bool](t, resp)
	if !accepted["accepted"] {
		t.Fatalf("message response = %v", accepted)
	}

	// The handler ensures a running blip before the note lands.
	blips, err := g.cluster.ListStateBlips(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if len(blips) == 0 {
		t.Fatal("message did not start a blip")
	}

	waitFor(t, "the prompt note", func() bool {
		return hasNote(g.wire.notes(), notePrompt, func(n noteRecord) bool {
			return n.Original == "hello" && n.Sender == "alice"
		})
	})
	g.waitPrompt(t, "hello")
}

func TestServerMessagesKeepOrder(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	for _, text := range []string{"first", "second"} {
		resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": text}, "alice", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("message %q: status %d", text, resp.StatusCode)
		}
	}
	g.waitPrompt(t, "first")
	g.waitPrompt(t, "second")

	frames := g.promptFrames()
	first, second := -1, -1
	for i, text := range frames {
		if strings.Contains(text, "first") && first < 0 {
			first = i
		}
		if strings.Contains(text, "second") && second < 0 {
			second = i
		}
	}
	if first < 0 || second < 0 || first > second {
		t.Fatalf("prompt order = %v; notes=%+v; messages=%+v", frames, g.wire.notes(), g.wire.messages())
	}
}

func TestServerMessageAnswersOpenQuestion(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	g.wire.note(noteRecord{Type: noteQuestion, ID: "q-open", Text: "Ship it?", Options: []string{"Yes", "No"}})

	resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": "Yes"}, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("answer message: status %d: %s", resp.StatusCode, raw)
	}
	resp.Body.Close()

	if !hasNote(g.wire.notes(), noteAnswer, func(n noteRecord) bool {
		return n.QID == "q-open" && n.Text == "Yes" && n.Sender == "alice"
	}) {
		t.Fatalf("answer note = %+v", g.wire.notes())
	}
	if hasNote(g.wire.notes(), notePrompt, nil) {
		t.Fatalf("message while a question was open became a prompt: %+v", g.wire.notes())
	}
}

func TestServerCancelAndStop(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	g.addRunningBlip(t, name)

	resp := g.request(t, "POST", "/api/sessions/"+name+"/cancel", nil, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		defer resp.Body.Close()
		t.Fatalf("cancel: status %d", resp.StatusCode)
	}
	if accepted := decodeBody[map[string]bool](t, resp); !accepted["accepted"] {
		t.Fatalf("cancel response = %v", accepted)
	}
	if !hasNote(g.wire.notes(), noteCancel, nil) {
		t.Fatalf("cancel note = %+v", g.wire.notes())
	}

	resp = g.request(t, "POST", "/api/sessions/"+name+"/stop", nil, "alice", nil)
	if resp.StatusCode != http.StatusAccepted {
		defer resp.Body.Close()
		t.Fatalf("stop: status %d", resp.StatusCode)
	}
	if accepted := decodeBody[map[string]bool](t, resp); !accepted["accepted"] {
		t.Fatalf("stop response = %v", accepted)
	}
	if !hasNote(g.wire.notes(), noteStop, nil) {
		t.Fatalf("stop note = %+v", g.wire.notes())
	}

	blips, err := g.cluster.ListStateBlips(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if len(blips) != 1 {
		t.Fatalf("blips = %+v", blips)
	}
	if blips[0].Status.Phase != v1.BlipSucceeded || !blips[0].Spec.Stop {
		t.Fatalf("stop did not stop the blip: %+v", blips[0])
	}
}

func TestServerDetailAndEvents(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName, "title": "Fix the bug"}, "alice")

	resp := g.request(t, "POST", "/api/sessions/"+name+"/message", map[string]string{"text": "hello"}, "alice", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("message: status %d", resp.StatusCode)
	}
	g.waitReply(t, name, "done: hello")

	resp = g.request(t, "GET", "/api/sessions/"+name, nil, "alice", nil)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("detail: status %d", resp.StatusCode)
	}
	detail := decodeBody[sessionDetail](t, resp)
	if detail.Name != name || detail.Profile != DefaultProfileName || detail.Title != "Fix the bug" {
		t.Fatalf("detail = %+v", detail)
	}
	if detail.Offset == 0 {
		t.Fatal("detail offset = 0")
	}
	if detail.TranscriptTruncated {
		t.Fatal("fresh transcript is truncated")
	}
	if len(detail.Transcript) < 2 {
		t.Fatalf("transcript = %s", detail.Transcript)
	}

	var user struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				Kind     string `json:"sessionUpdate"`
				Sender   string `json:"sender"`
				BlipUser bool   `json:"blipUser"`
				Content  []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(detail.Transcript[0], &user); err != nil {
		t.Fatal(err)
	}
	if user.Method != "session/update" || user.Params.Update.Kind != "user_message_chunk" ||
		user.Params.Update.Sender != "alice" || !user.Params.Update.BlipUser {
		t.Fatalf("transcript[0] = %s", detail.Transcript[0])
	}
	if len(user.Params.Update.Content) != 1 || user.Params.Update.Content[0].Text != "hello" {
		t.Fatalf("transcript[0] content = %s", detail.Transcript[0])
	}
	var found bool
	for _, frame := range detail.Transcript[1:] {
		if strings.Contains(string(frame), "done: hello") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("transcript has no agent reply: %s", detail.Transcript)
	}

	// The event stream replays the same ring from the requested offset.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", g.ts.URL+"/api/sessions/"+name+"/events?offset=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", "alice")
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("events: status %d", stream.StatusCode)
	}

	scanner := bufio.NewScanner(stream.Body)
	var sawRunning, sawReply bool
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
			t.Fatalf("event %q: %v", line, err)
		}
		if ev.Type == "status" && ev.Status != nil && ev.Status.Running {
			sawRunning = true
		}
		if ev.Type == "acp" && strings.Contains(string(ev.Message), "done: hello") {
			sawReply = true
		}
		if sawRunning && sawReply {
			break
		}
	}
	if !sawRunning || !sawReply {
		t.Fatalf("events: running=%t reply=%t (scanner error %v)", sawRunning, sawReply, scanner.Err())
	}
}

func TestServerMethodsNotFoundAndProbes(t *testing.T) {
	g := newGateway(t, Options{})

	for _, tc := range []struct{ method, path, allow string }{
		{"DELETE", "/api/sessions", "GET, POST, HEAD"},
		{"GET", "/api/sessions/chat-any/message", "POST"},
		{"POST", "/api/sessions/chat-any/events", "GET, HEAD"},
		{"PUT", "/api/me", "GET, HEAD"},
		{"POST", "/healthz", "GET, HEAD"},
		{"POST", "/readyz", "GET, HEAD"},
	} {
		resp := g.request(t, tc.method, tc.path, nil, "alice", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: status %d, want 405", tc.method, tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != tc.allow {
			t.Fatalf("%s %s: Allow = %q, want %q", tc.method, tc.path, got, tc.allow)
		}
	}

	for _, path := range []string{"/api/sessions/chat-nope", "/api/sessions/chat-nope/events"} {
		resp := g.request(t, "GET", path, nil, "alice", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404", path, resp.StatusCode)
		}
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp := g.request(t, "GET", path, nil, "", nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		status := decodeBody[map[string]string](t, resp)
		if status["status"] != "ok" {
			t.Fatalf("%s = %v", path, status)
		}
	}
}

func TestCreateChatForkStartsAfterParent(t *testing.T) {
	fc := newFakeCluster()
	profiles := Profiles{
		DefaultProfileName: {Command: []string{"agent"}},
		"forked":           {Command: []string{"agent"}, Workspace: WorkspaceFork},
	}
	g := newGatewayWithCluster(t, fc, Options{Profiles: profiles})
	ctx := context.Background()

	parent := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-parent",
			Namespace: "team",
			UID:       "uid-parent",
			Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: "chat-parent"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationRoot:    "chat-parent",
				AnnotationDepth:   "0",
			},
		},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	if err := fc.CreateSession(ctx, "team", parent); err != nil {
		t.Fatal(err)
	}
	// The parent's ring already contains a turn. A fork inherits these
	// records, but must not treat them as its own work.
	g.wire.start(1)
	g.wire.note(noteRecord{Type: notePrompt, ID: "old", Text: "old", Original: "old"})
	g.wire.end(1)
	tail := g.wire.offset

	created, err := g.srv.createChat(ctx, chatRequest{Profile: "forked", Parent: parent})
	if err != nil {
		t.Fatal(err)
	}
	start, err := strconv.ParseUint(created.Annotations[AnnotationStart], 10, 64)
	if err != nil {
		t.Fatalf("start annotation = %q: %v", created.Annotations[AnnotationStart], err)
	}
	if start != tail {
		t.Fatalf("start = %d, want parent tail %d", start, tail)
	}
	view := g.srv.readView(ctx, created)
	if len(view.Transcript) != 0 || view.Newest != 0 {
		t.Fatalf("fork replayed parent history: transcript=%d newest=%d", len(view.Transcript), view.Newest)
	}
}
