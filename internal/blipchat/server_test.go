// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func testServer(t *testing.T) (*Server, *fakeCluster, *httptest.Server) {
	t.Helper()
	return testServerWithProfiles(t, Profiles{DefaultProfileName: {}})
}

func testServerWithProfiles(t *testing.T, profiles Profiles) (*Server, *fakeCluster, *httptest.Server) {
	t.Helper()
	return testServerWithOptions(t, Options{Profiles: profiles})
}

func testServerWithOptions(t *testing.T, opts Options) (*Server, *fakeCluster, *httptest.Server) {
	t.Helper()
	fc := newFakeCluster()
	if opts.Namespace == "" {
		opts.Namespace = "team"
	}
	if opts.DefaultPool == "" {
		opts.DefaultPool = "default"
	}
	if opts.AutoApprove == "" {
		opts.AutoApprove = "always"
	}
	if opts.Cluster == nil {
		opts.Cluster = fc
	}
	if opts.Wire == nil {
		opts.Wire = &noLogWire{}
	}
	if opts.Log == nil {
		opts.Log = testLogger()
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		s.Close()
	})
	return s, fc, ts
}

type noLogWire struct{}

func (noLogWire) Send(context.Context, string, string, []byte, bool) error { return nil }
func (noLogWire) OpenLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return nil, apierrors.NewServiceUnavailable("not ready")
}
func (noLogWire) LogEnd(context.Context, string, string) (uint64, error) { return 0, nil }

func do(t *testing.T, method, url string, body any, users ...string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		req.Header.Add("X-Forwarded-User", u)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestServerIdentityAndIgnoredNamespace(t *testing.T) {
	_, _, ts := testServer(t)

	resp := do(t, "GET", ts.URL+"/api/sessions", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no user: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions", nil, "alice", "bob")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("two users: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"create session", "POST", "/api/sessions", map[string]any{"profile": DefaultProfileName}},
		{"me", "GET", "/api/me", nil},
	} {
		t.Run(tc.name+" invalid UTF-8 user", func(t *testing.T) {
			resp := do(t, tc.method, ts.URL+tc.path, tc.body, "\xff")
			if resp.StatusCode != http.StatusBadRequest {
				resp.Body.Close()
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			var body map[string]string
			decodeBody(t, resp, &body)
			if body["error"] != "X-Forwarded-User must be valid UTF-8" {
				t.Fatalf("error = %q", body["error"])
			}
		})
	}

	for _, user := range []string{"   ", "alice,bob"} {
		resp := do(t, "GET", ts.URL+"/api/me", nil, user)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("user %q: status %d, want 401", user, resp.StatusCode)
		}
		resp.Body.Close()
	}

	const unicodeUser = "r1-07-üser"
	resp = do(t, "GET", ts.URL+"/api/me", nil, unicodeUser)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unicode me: status %d", resp.StatusCode)
	}
	var me map[string]string
	decodeBody(t, resp, &me)
	if me["user"] != unicodeUser {
		t.Fatalf("unicode user = %q, want %q", me["user"], unicodeUser)
	}

	resp = do(t, "POST", ts.URL+"/api/sessions", map[string]any{"profile": DefaultProfileName}, unicodeUser)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unicode create: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The namespace is fixed at deployment time. An old client or bookmark
	// that still sends one is served from the configured namespace.
	resp = do(t, "GET", ts.URL+"/api/sessions?namespace=Not_A_Label", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stale namespace: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestNormalizeBasePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{" /blipchat ", "/blipchat"},
		{"/blipchat", "/blipchat"},
		{"/apps/chat", "/apps/chat"},
	} {
		got, err := normalizeBasePath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalizeBasePath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{
		"blipchat", "/blipchat/", "/a//b", "/a/../b", "/a/./b",
		"/api", "/api/v1", "/mcp", "/healthz", "/readyz",
		"/a?b", "/a#b", "/a b", "/a{b}", "/a}b", "/a%20b", "/a\\b",
	} {
		if _, err := normalizeBasePath(in); err == nil {
			t.Errorf("normalizeBasePath(%q) succeeded", in)
		}
	}
}

func TestServerUIBasePathDefault(t *testing.T) {
	_, _, ts := testServer(t)
	resp := do(t, "GET", ts.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UI: status %d", resp.StatusCode)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(page), uiBasePathPlaceholder) || !strings.Contains(string(page), `content=""`) {
		t.Fatalf("default UI does not carry an empty base path")
	}
}

func TestServerBasePath(t *testing.T) {
	_, _, ts := testServerWithOptions(t, Options{BasePath: "/blipchat"})

	resp := do(t, "GET", ts.URL+"/blipchat/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("base path UI: status %d", resp.StatusCode)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), `content="/blipchat"`) {
		t.Fatalf("base path UI does not carry the configured path")
	}

	// A proxy that strips the prefix forwards "/" to blipchat. The UI must
	// still build its requests from the configured base path.
	resp = do(t, "GET", ts.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("root UI: status %d", resp.StatusCode)
	}
	page, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), `content="/blipchat"`) {
		t.Fatalf("root UI does not carry the configured path")
	}

	resp = do(t, "GET", ts.URL+"/blipchat/api/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("base path without user: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/blipchat/api", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("base path API root without user: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/blipchat/api/me", nil, "alice")
	var me map[string]string
	decodeBody(t, resp, &me)
	if me["user"] != "alice" {
		t.Fatalf("base path user = %q", me["user"])
	}

	resp = do(t, "POST", ts.URL+"/blipchat/api/sessions", map[string]any{"profile": "default"}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("base path create: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/blipchat/api/sessions", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("base path list: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/blipchat/api/sessions/chat-missing/events", nil, "alice")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("base path events: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The root API stays available for a proxy that strips the prefix.
	resp = do(t, "GET", ts.URL+"/api/me", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("root API: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	for _, p := range []string{"/healthz", "/blipchat/healthz"} {
		resp = do(t, "GET", ts.URL+p, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
		resp.Body.Close()
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, tc := range []struct{ target, location string }{
		{"/blipchat", "/blipchat/"},
		{"/blipchat?x=1", "/blipchat/?x=1"},
	} {
		req, err := http.NewRequest("GET", ts.URL+tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != tc.location {
			t.Fatalf("%s redirect: status %d, location %q", tc.target, resp.StatusCode, resp.Header.Get("Location"))
		}
		resp.Body.Close()
	}
}

func TestServerCreateListAndMessage(t *testing.T) {
	_, fc, ts := testServer(t)

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{
		"profile": "default",
	}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)
	if !strings.HasPrefix(created.Name, "chat-") || len(created.Name) != len("chat-")+6 {
		t.Fatalf("name = %q", created.Name)
	}
	if len(fc.blipNames()) != 0 {
		// The driver starts asynchronously; zero here is fine, the message
		// below proves the pipeline works.
	}

	resp = do(t, "POST", ts.URL+"/api/sessions", map[string]any{
		"profile": "missing",
	}, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown profile: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", resp.StatusCode)
	}
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	if len(sessions) != 1 || sessions[0].Name != created.Name || sessions[0].Title != "" {
		t.Fatalf("sessions = %+v", sessions)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions/"+created.Name+"", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail: status %d", resp.StatusCode)
	}
	var detail sessionDetail
	decodeBody(t, resp, &detail)
	if detail.Name != created.Name {
		t.Fatalf("detail = %+v", detail)
	}

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message", map[string]string{"text": ""}, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty message: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message", map[string]string{"text": "hello"}, "alice")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("message: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerCreateDoesNotStartAgent(t *testing.T) {
	_, fc, ts := testServer(t)

	name := createSession(t, ts.URL, DefaultProfileName)
	if names := fc.blipNames(); len(names) != 0 {
		t.Fatalf("create started blips: %v", names)
	}

	// Opening or cancelling an empty chat must not pretend a turn is running.
	resp := do(t, "POST", ts.URL+"/api/sessions/"+name+"/cancel", nil, "alice")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions/"+name, nil, "alice")
	var detail sessionDetail
	decodeBody(t, resp, &detail)
	if detail.Running || strings.EqualFold(detail.Phase, "cancelling") {
		t.Fatalf("empty chat after cancel = %+v", detail)
	}
	if names := fc.blipNames(); len(names) != 0 {
		t.Fatalf("cancel started blips: %v", names)
	}
}

func TestServerMissingProfileDoesNotFallback(t *testing.T) {
	// A chat keeps its profile annotation, but if that profile is removed the
	// driver must not silently run the default profile on the next turn.
	s, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {},
		"agent":            {Command: []string{"agent"}},
	})

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{"profile": "agent"}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)

	delete(s.profiles, "agent")

	// History remains readable; the chat is not hidden by the missing profile.
	resp = do(t, "GET", ts.URL+"/api/sessions/"+created.Name, nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail after profile removal: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message", map[string]string{"text": "hello"}, "alice")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("message with removed profile: status %d, want %d", resp.StatusCode, http.StatusConflict)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "profile is not configured") || !strings.Contains(string(body), "agent") {
		t.Fatalf("message error = %q", body)
	}
	if names := fc.blipNames(); len(names) != 0 {
		t.Fatalf("missing profile started blips: %v", names)
	}
}

func TestServerRejectsRenderedMessageTooLong(t *testing.T) {
	_, _, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {
			Description:     strings.Repeat("d", maxPromptBytes+1),
			MessageTemplate: "{{.Description}}{{.Text}}",
		},
	})

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{
		"profile": DefaultProfileName,
	}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message", map[string]string{"text": "hello"}, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("message: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerMe(t *testing.T) {
	_, _, ts := testServer(t)

	resp := do(t, "GET", ts.URL+"/api/me", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: status %d", resp.StatusCode)
	}
	var me map[string]string
	decodeBody(t, resp, &me)
	if me["user"] != "alice" {
		t.Fatalf("user = %q", me["user"])
	}

	resp = do(t, "GET", ts.URL+"/api/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous me: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/me", nil, "alice,bob")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ambiguous me: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerMessageRecordsSender(t *testing.T) {
	_, _, ts := testServer(t)
	name := createSession(t, ts.URL, DefaultProfileName)

	resp := do(t, "POST", ts.URL+"/api/sessions/"+name+"/message",
		map[string]string{"text": "steer left"}, "alice")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("message: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		resp = do(t, "GET", ts.URL+"/api/sessions/"+name+"", nil, "alice")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("detail: status %d", resp.StatusCode)
		}
		var detail sessionDetail
		decodeBody(t, resp, &detail)
		if len(detail.Transcript) > 0 {
			var msg struct {
				Method string `json:"method"`
				Params struct {
					Update struct {
						Kind     string          `json:"sessionUpdate"`
						Sender   string          `json:"sender"`
						BlipUser bool            `json:"blipUser"`
						Text     json.RawMessage `json:"content"`
					} `json:"update"`
				} `json:"params"`
			}
			if err := json.Unmarshal(detail.Transcript[0], &msg); err != nil {
				t.Fatal(err)
			}
			if msg.Method != "session/update" || msg.Params.Update.Kind != "user_message_chunk" {
				t.Fatalf("transcript[0] = %s", detail.Transcript[0])
			}
			if msg.Params.Update.Sender != "alice" {
				t.Fatalf("sender = %q, want alice", msg.Params.Update.Sender)
			}
			if !msg.Params.Update.BlipUser {
				t.Fatalf("transcript[0] is not marked as a blip user message: %s", detail.Transcript[0])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("user message was not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerNotFound(t *testing.T) {
	_, _, ts := testServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/sessions/not-a-chat", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func rawDo(t *testing.T, method, url, body, contentType string, headers map[string]string, users ...string) *http.Response {
	t.Helper()
	return rawDoHost(t, "", method, url, body, contentType, headers, users...)
}

func rawDoHost(t *testing.T, host, method, url, body, contentType string, headers map[string]string, users ...string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, u := range users {
		req.Header.Add("X-Forwarded-User", u)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestServerRejectsUnsafePosts(t *testing.T) {
	s, _, ts := testServer(t)
	url := ts.URL + "/api/sessions"

	resp := rawDo(t, "POST", url, `{"profile":"default"}`, "text/plain", nil, "alice")
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: status %d, want 415", resp.StatusCode)
	}
	resp.Body.Close()

	resp = rawDo(t, "POST", url, `{"profile":"default"}`, "application/json",
		map[string]string{"Sec-Fetch-Site": "cross-site"}, "alice")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	resp = rawDo(t, "POST", url, `{"profile":"default"}`, "application/json",
		map[string]string{"Origin": "https://evil.example"}, "alice")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	for _, origin := range []string{
		"https://user@evil.example",
		"ftp://evil.example",
		"null",
	} {
		resp = rawDo(t, "POST", url, `{"profile":"default"}`, "application/json",
			map[string]string{"Origin": origin}, "alice")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: status %d, want 403", origin, resp.StatusCode)
		}
		resp.Body.Close()
	}

	resp = rawDo(t, "POST", url, `{"profile":"default"}`, "application/json",
		map[string]string{"Origin": ts.URL, "Sec-Fetch-Site": "same-origin"}, "alice")
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("same-origin request with Origin was rejected")
	}
	resp.Body.Close()

	addr := ts.Listener.Addr().String()
	bareHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	siblingOrigin := "http://" + net.JoinHostPort(bareHost, "1")
	proxyCases := []struct {
		name    string
		host    string
		headers map[string]string
		want    int
	}{
		{
			name: "port-stripped host same-origin",
			host: bareHost,
			headers: map[string]string{
				"Origin":         ts.URL,
				"Sec-Fetch-Site": "same-origin",
			},
			want: http.StatusCreated,
		},
		{
			name: "port-stripped host same-site sibling port",
			host: bareHost,
			headers: map[string]string{
				"Origin":         siblingOrigin,
				"Sec-Fetch-Site": "same-site",
			},
			want: http.StatusForbidden,
		},
		{
			name: "explicit mismatched port",
			host: addr,
			headers: map[string]string{
				"Origin":         siblingOrigin,
				"Sec-Fetch-Site": "same-origin",
			},
			want: http.StatusForbidden,
		},
		{
			name: "forwarded external authority overrides stripped host",
			host: "blipchat",
			headers: map[string]string{
				"Origin":           ts.URL,
				"X-Forwarded-Host": addr,
				"Sec-Fetch-Site":   "same-origin",
			},
			want: http.StatusCreated,
		},
		{
			name: "forwarded port-stripped authority same-origin",
			host: "blipchat",
			headers: map[string]string{
				"Origin":           ts.URL,
				"X-Forwarded-Host": bareHost,
				"Sec-Fetch-Site":   "same-origin",
			},
			want: http.StatusCreated,
		},
		{
			name: "foreign host",
			host: bareHost,
			headers: map[string]string{
				"Origin":         "https://evil.example",
				"Sec-Fetch-Site": "same-origin",
			},
			want: http.StatusForbidden,
		},
		{
			name: "comma-separated forwarded host",
			host: "blipchat",
			headers: map[string]string{
				"Origin":           ts.URL,
				"X-Forwarded-Host": addr + ", evil.example",
				"Sec-Fetch-Site":   "same-origin",
			},
			want: http.StatusForbidden,
		},
	}
	for _, tc := range proxyCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := rawDoHost(t, tc.host, "POST", url, `{"profile":"default"}`, "application/json", tc.headers, "alice")
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	t.Run("duplicate forwarded host", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://blipchat/api/sessions", strings.NewReader(`{"profile":"default"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", ts.URL)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-Forwarded-User", "alice")
		req.Header.Add("X-Forwarded-Host", addr)
		req.Header.Add("X-Forwarded-Host", "evil.example")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}

func TestServerRejectsMalformedJSON(t *testing.T) {
	_, _, ts := testServer(t)
	url := ts.URL + "/api/sessions"

	for _, body := range []string{"null", "{} {}", "{} trailing", "{", "[]"} {
		resp := rawDo(t, "POST", url, body, "application/json", nil, "alice")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%q: status %d, want 400", body, resp.StatusCode)
		}
		resp.Body.Close()
	}

	huge := `{"text":"` + strings.Repeat("a", 130<<10) + `"}`
	resp := rawDo(t, "POST", url, huge, "application/json", nil, "alice")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d, want 413", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerSecurityHeaders(t *testing.T) {
	_, _, ts := testServer(t)

	resp := do(t, "GET", ts.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ui: status %d", resp.StatusCode)
	}
	headers := resp.Header
	if !strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", headers.Get("Content-Security-Policy"))
	}
	if headers.Get("X-Frame-Options") != "DENY" || headers.Get("X-Content-Type-Options") != "nosniff" ||
		headers.Get("Referrer-Policy") != "no-referrer" || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("UI security headers = %v", headers)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/me", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: status %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.Header.Get("Vary"), "X-Forwarded-User") {
		t.Fatalf("API cache headers = %v", resp.Header)
	}
	resp.Body.Close()
}

func TestServerUnknownAPIIsJSON(t *testing.T) {
	_, _, ts := testServer(t)
	resp := do(t, "GET", ts.URL+"/api/nope", nil, "alice")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	var body map[string]string
	decodeBody(t, resp, &body)
	if body["error"] == "" {
		t.Fatalf("error body = %v", body)
	}
}

func TestServerMCPListenerServesOnlyMCP(t *testing.T) {
	s, _, ts := testServer(t)
	mcp := httptest.NewServer(s.MCPHandler())
	defer mcp.Close()

	resp := do(t, "GET", mcp.URL+"/api/me", nil, "alice")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("MCP listener /api/me: status %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "POST", ts.URL+"/mcp", map[string]any{}, "alice")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("browser listener /mcp: status %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", mcp.URL+"/mcp", nil, "alice")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("MCP listener GET /mcp: status %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "POST" {
		t.Fatalf("MCP listener GET /mcp: Allow = %q, want POST", got)
	}
	resp.Body.Close()
}

func TestServerStatusMessage(t *testing.T) {
	_, fc, ts := testServer(t)
	name := createSession(t, ts.URL, DefaultProfileName)
	if err := fc.CreateBlip(context.Background(), "team", &v1.Blip{ObjectMeta: metav1.ObjectMeta{
		Name:      name + "-g1",
		Namespace: "team",
		Labels:    map[string]string{LabelSession: name},
	}}); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	fc.blips[key("team", name+"-g1")].Status = v1.BlipStatus{
		Phase:   v1.BlipFailed,
		Reason:  "no space",
		Message: "no eligible node has enough space",
	}
	fc.mu.Unlock()

	resp := do(t, "GET", ts.URL+"/api/sessions", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", resp.StatusCode)
	}
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	for _, session := range sessions {
		if session.Name == name {
			if session.StatusMessage != "no eligible node has enough space" {
				t.Fatalf("statusMessage = %q", session.StatusMessage)
			}
			return
		}
	}
	t.Fatal("created session not listed")
}

func TestServerStatusMessageOnlyOnFailure(t *testing.T) {
	_, fc, ts := testServer(t)
	name := createSession(t, ts.URL, DefaultProfileName)
	if err := fc.CreateBlip(context.Background(), "team", &v1.Blip{ObjectMeta: metav1.ObjectMeta{
		Name:      name + "-g1",
		Namespace: "team",
		Labels:    map[string]string{LabelSession: name},
	}}); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	fc.blips[key("team", name+"-g1")].Status = v1.BlipStatus{
		Phase:   v1.BlipSucceeded,
		Message: "Completed",
	}
	fc.mu.Unlock()

	resp := do(t, "GET", ts.URL+"/api/sessions", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", resp.StatusCode)
	}
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	for _, session := range sessions {
		if session.Name == name {
			if session.StatusMessage != "" {
				t.Fatalf("statusMessage on completed chat = %q, want empty", session.StatusMessage)
			}
			return
		}
	}
	t.Fatal("created session not listed")
}

func TestServerMethodNotAllowed(t *testing.T) {
	_, _, ts := testServer(t)
	for _, tc := range []struct{ method, path, allow string }{
		{"DELETE", "/api/sessions", "GET, POST, HEAD"},
		{"PUT", "/api/me", "GET, HEAD"},
		{"GET", "/api/sessions/chat-any/message", "POST"},
		{"POST", "/api/sessions/chat-any/events", "GET, HEAD"},
		{"POST", "/healthz", "GET, HEAD"},
		{"POST", "/readyz", "GET, HEAD"},
		{"POST", "/", "GET, HEAD"},
	} {
		resp := do(t, tc.method, ts.URL+tc.path, nil, "alice")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			resp.Body.Close()
			t.Fatalf("%s %s: status %d, want 405", tc.method, tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != tc.allow {
			resp.Body.Close()
			t.Fatalf("%s %s: Allow = %q, want %q", tc.method, tc.path, got, tc.allow)
		}
		resp.Body.Close()
	}
}

func TestServerDetailCreatesDriverForCoherentOffset(t *testing.T) {
	s, fc, ts := testServer(t)
	name := createSession(t, ts.URL, DefaultProfileName)

	resp := do(t, "GET", ts.URL+"/api/sessions/"+name, nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail: status %d", resp.StatusCode)
	}
	var detail struct {
		Phase   string `json:"phase"`
		Running bool   `json:"running"`
	}
	decodeBody(t, resp, &detail)
	if detail.Running || detail.Phase == string(v1.BlipPending) || detail.Phase == string(v1.BlipRunning) {
		t.Fatalf("fresh idle detail = %+v, want idle phase", detail)
	}
	if d := s.lookupDriver(name); d == nil {
		t.Fatal("detail did not create a driver; SSE would start at an incoherent offset")
	}
	if names := fc.blipNames(); len(names) != 0 {
		t.Fatalf("detail started blips: %v", names)
	}

	// A fresh chat's latest Blip can still be Pending while the state is Ready
	// and no turn is in flight. The detail must not tell the UI to show a
	// pending turn with a Stop button.
	fc.mu.Lock()
	fc.blips[key("team", name+"-g1")] = &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-g1",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: name},
		},
		Status: v1.BlipStatus{Phase: v1.BlipPending},
	}
	fc.mu.Unlock()
	resp = do(t, "GET", ts.URL+"/api/sessions/"+name, nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail with pending blip: status %d", resp.StatusCode)
	}
	decodeBody(t, resp, &detail)
	if detail.Running || detail.Phase == string(v1.BlipPending) || detail.Phase == string(v1.BlipRunning) {
		t.Fatalf("idle detail with Pending blip = %+v, want idle phase", detail)
	}
}

func TestSummarizeIgnoresOlderRunningBlip(t *testing.T) {
	st := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "chat-old", Namespace: "team", Labels: map[string]string{LabelSession: "true"}}}
	blips := []v1.Blip{
		{ObjectMeta: metav1.ObjectMeta{Name: "chat-old-g1", Annotations: map[string]string{AnnotationGeneration: "1"}}, Status: v1.BlipStatus{Phase: v1.BlipRunning}},
		{ObjectMeta: metav1.ObjectMeta{Name: "chat-old-g2", Annotations: map[string]string{AnnotationGeneration: "2"}}, Status: v1.BlipStatus{Phase: v1.BlipSucceeded}},
	}
	got := summarize(st, blips)
	if got.Running {
		t.Fatalf("summary reports running for an older orphan generation: %+v", got)
	}
	if got.Phase != v1.BlipSucceeded {
		t.Fatalf("phase = %q, want %q", got.Phase, v1.BlipSucceeded)
	}
}

func addState(t *testing.T, fc *fakeCluster, name string, labels map[string]string, phase string, created time.Time) {
	t.Helper()
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "team",
			Labels:            labels,
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: v1.BlipStateStatus{Phase: phase},
	}
	if err := fc.CreateSession(context.Background(), "team", st); err != nil {
		t.Fatal(err)
	}
}

func createSession(t *testing.T, url, profile string) string {
	t.Helper()
	resp := do(t, "POST", url+"/api/sessions", map[string]any{"profile": profile}, "alice")
	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: status %d: %s", resp.StatusCode, body)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)
	return created.Name
}

func TestServerCreateUsesNewestReadyBase(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}
	_, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {},
		"agent":            {Command: []string{"agent"}, BaseSelector: selector},
	})
	now := time.Now()
	match := map[string]string{"app": "agent"}
	addState(t, fc, "old-base", match, v1.StateReady, now.Add(-3*time.Minute))
	addState(t, fc, "new-base", match, v1.StateReady, now.Add(-time.Minute))
	addState(t, fc, "pending-base", match, v1.StatePending, now)
	addState(t, fc, "old-chat", map[string]string{"app": "agent", LabelSession: "true"}, v1.StateReady, now.Add(time.Minute))

	name := createSession(t, ts.URL, "agent")
	st, err := fc.GetSession(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.CopyFrom != "new-base" {
		t.Fatalf("copyFrom = %q, want new-base", st.Spec.CopyFrom)
	}
	if st.Annotations[AnnotationBase] != "new-base" {
		t.Fatalf("base annotation = %q", st.Annotations[AnnotationBase])
	}
	if _, ok := st.Annotations[AnnotationTitle]; ok {
		t.Fatalf("new chat has a title annotation: %v", st.Annotations)
	}
}

func TestServerCreateFailsWithoutReadyBase(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}
	_, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {},
		"agent":            {Command: []string{"agent"}, BaseSelector: selector},
	})
	now := time.Now()
	match := map[string]string{"app": "agent"}
	addState(t, fc, "pending-base", match, v1.StatePending, now)
	addState(t, fc, "old-chat", map[string]string{"app": "agent", LabelSession: "true"}, v1.StateReady, now)

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{"profile": "agent"}, "alice")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	var body map[string]string
	decodeBody(t, resp, &body)
	if !strings.Contains(body["error"], "no Ready BlipState") {
		t.Fatalf("error = %q", body["error"])
	}
	if len(fc.blipNames()) != 0 {
		t.Fatalf("a failed create started a blip: %v", fc.blipNames())
	}
}

func TestServerCreateWithoutSelectorStartsEmpty(t *testing.T) {
	_, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {Command: []string{"agent"}},
	})

	name := createSession(t, ts.URL, DefaultProfileName)
	st, err := fc.GetSession(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.CopyFrom != "" {
		t.Fatalf("copyFrom = %q, want empty", st.Spec.CopyFrom)
	}
	if _, ok := st.Annotations[AnnotationBase]; ok {
		t.Fatalf("base annotation on an empty chat: %v", st.Annotations)
	}
}

func TestServerCreateWritesRootChatMetadata(t *testing.T) {
	_, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {Command: []string{"agent"}},
	})

	name := createSession(t, ts.URL, DefaultProfileName)
	st, err := fc.GetSession(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Labels[LabelSession] != "true" {
		t.Fatalf("session label = %q", st.Labels[LabelSession])
	}
	if st.Labels[v1.LabelOwner] != name {
		t.Fatalf("owner label = %q, want %q", st.Labels[v1.LabelOwner], name)
	}
	if st.Annotations[AnnotationProfile] != DefaultProfileName || st.Annotations[AnnotationRoot] != name || st.Annotations[AnnotationDepth] != "0" {
		t.Fatalf("root annotations = %v", st.Annotations)
	}
	for _, absent := range []string{AnnotationParent, AnnotationParentProfile, AnnotationParentDepth} {
		if _, ok := st.Annotations[absent]; ok {
			t.Fatalf("root has %s = %q", absent, st.Annotations[absent])
		}
	}
}

func TestNewRejectsInvalidBaseSelector(t *testing.T) {
	_, err := New(Options{
		Profiles: Profiles{"bad": {BaseSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Bogus"}},
		}}},
		Cluster: newFakeCluster(),
		Wire:    noLogWire{},
		Log:     testLogger(),
	})
	if err == nil {
		t.Fatal("New accepted an invalid baseSelector")
	}
}

func TestServerListShowsChatTree(t *testing.T) {
	_, fc, ts := testServerWithProfiles(t, Profiles{
		DefaultProfileName: {Command: []string{"agent"}},
	})
	now := time.Now()
	parent := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-parent", Namespace: "team",
		Labels:            map[string]string{LabelSession: "true", v1.LabelOwner: "chat-parent"},
		Annotations:       map[string]string{AnnotationProfile: DefaultProfileName, AnnotationRoot: "chat-parent", AnnotationDepth: "0"},
		CreationTimestamp: metav1.NewTime(now.Add(-time.Minute)),
	}}
	child := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-child", Namespace: "team",
		Labels:            map[string]string{LabelSession: "true", LabelParent: "chat-parent", v1.LabelOwner: "chat-parent"},
		Annotations:       map[string]string{AnnotationProfile: DefaultProfileName, AnnotationParent: "chat-parent", AnnotationParentProfile: DefaultProfileName, AnnotationRoot: "chat-parent", AnnotationDepth: "1", AnnotationParentDepth: "0"},
		CreationTimestamp: metav1.NewTime(now),
	}}
	// A fork copies the session label onto its per-mount states but not the
	// chat annotations; those copies are not chats.
	hidden := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-mount", Namespace: "team",
		Labels:            map[string]string{LabelSession: "true", v1.LabelOwner: "chat-parent"},
		CreationTimestamp: metav1.NewTime(now.Add(time.Minute)),
	}}
	for _, st := range []*v1.BlipState{parent, child, hidden} {
		if err := fc.CreateSession(context.Background(), "team", st); err != nil {
			t.Fatal(err)
		}
	}

	resp := do(t, "GET", ts.URL+"/api/sessions", nil, "alice")
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	got := sessions[0]
	if got.Name != "chat-child" || got.Parent != "chat-parent" || got.Root != "chat-parent" || got.Depth != 1 {
		t.Fatalf("child summary = %+v", got)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions/chat-mount", nil, "alice")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("hidden mount detail: status %d", resp.StatusCode)
	}
}

func TestServerForkedChatSkipsInheritedLog(t *testing.T) {
	fc := newFakeCluster()
	fw := newFakeWire()
	fw.offset = 4096
	defer fw.closeLog()
	state := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-child", Namespace: "team", Labels: map[string]string{LabelSession: "true"},
		Annotations: map[string]string{AnnotationProfile: DefaultProfileName, AnnotationParent: "chat-parent"},
	}}
	if err := fc.CreateSession(context.Background(), "team", state); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Namespace: "team", Profiles: Profiles{DefaultProfileName: {}},
		Cluster: fc, Wire: fw, Log: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := s.driverFor(context.Background(), "chat-child")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st, err := fc.GetSession(context.Background(), "team", "chat-child")
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Annotations[AnnotationOffset]; got != "4096" {
		t.Fatalf("inherited offset annotation = %q", got)
	}
}

type forkLogWire struct {
	*fakeWire
	log []byte
}

func (w *forkLogWire) ReadLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(w.log)), nil
}

func TestServerForkedChatReplaysLog(t *testing.T) {
	fw := newFakeWire()
	fw.offset = 4096
	defer fw.closeLog()
	const sessionUpdate = `{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"inherited"}}}}`
	var log []byte
	log = append(log, replayLogRecord(t, 1, recordIn, `{"jsonrpc":"2.0","id":"1","method":"session/prompt","params":{"prompt":[{"type":"text","text":"wrapped"}],"_meta":{"blip.dev/sender":"alice","blip.dev/text":"before restart"}}}`)...)
	log = append(log, replayLogRecord(t, 2, recordOut, sessionUpdate+"\n")...)
	fc := newFakeCluster()
	state := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-child", Namespace: "team", Labels: map[string]string{LabelSession: "true"},
		Annotations: map[string]string{
			AnnotationProfile: DefaultProfileName,
			AnnotationParent:  "chat-parent",
			AnnotationOffset:  "4096",
		},
	}}
	if err := fc.CreateSession(context.Background(), "team", state); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Namespace: "team", Profiles: Profiles{DefaultProfileName: {}},
		Cluster: fc, Wire: &forkLogWire{fakeWire: fw, log: log}, Log: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := s.driverFor(context.Background(), "chat-child")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	transcript, _, _ := d.Snapshot()
	if len(transcript) != 2 {
		t.Fatalf("forked chat transcript has %d entries, want 2", len(transcript))
	}
}

func TestNewRejectsInvalidProfileName(t *testing.T) {
	for _, name := range []string{"bad profile", "bad*profile"} {
		_, err := New(Options{
			Profiles: Profiles{DefaultProfileName: {}, name: {}},
			Cluster:  newFakeCluster(),
			Wire:     noLogWire{},
			Log:      testLogger(),
		})
		if err == nil {
			t.Fatalf("New accepted the profile name %q", name)
		}
	}
}

func TestServerCreateChildFallsBackForLegacyParent(t *testing.T) {
	s, fc, _ := testServer(t)
	parent := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-legacy", Namespace: "team",
		Labels:      map[string]string{LabelSession: "true"},
		Annotations: map[string]string{AnnotationTitle: "Legacy"},
	}}
	if err := fc.CreateSession(context.Background(), "team", parent); err != nil {
		t.Fatal(err)
	}

	created, err := s.createChat(context.Background(), chatRequest{
		Profile: DefaultProfileName,
		Owner:   "alice",
		Parent:  parent,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := fc.GetSession(context.Background(), "team", created.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations[AnnotationParentProfile] != DefaultProfileName || got.Annotations[AnnotationParentDepth] != "0" {
		t.Fatalf("legacy parent annotations = %v", got.Annotations)
	}
	if got.Annotations[AnnotationRoot] != "chat-legacy" || got.Annotations[AnnotationDepth] != "1" {
		t.Fatalf("tree annotations = %v", got.Annotations)
	}
	if got.Labels[v1.LabelOwner] != "chat-legacy" {
		t.Fatalf("owner label = %q", got.Labels[v1.LabelOwner])
	}
}

func TestBackfillLegacyChatMetadata(t *testing.T) {
	s, fc, _ := testServer(t)
	st := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name:        "chat-old",
		Namespace:   "team",
		Labels:      map[string]string{LabelSession: "true"},
		Annotations: map[string]string{AnnotationProfile: "default", AnnotationTitle: "old"},
	}}
	fc.states[key("team", "chat-old")] = st
	if err := fc.CreateBlip(context.Background(), "team", &v1.Blip{ObjectMeta: metav1.ObjectMeta{
		Name:      "chat-old-g1",
		Namespace: "team",
		Labels:    map[string]string{LabelSession: "chat-old"},
	}}); err != nil {
		t.Fatal(err)
	}

	s.backfillChat(context.Background(), st.DeepCopy())

	got, err := fc.GetSession(context.Background(), "team", "chat-old")
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels[v1.LabelOwner] != "chat-old" ||
		got.Annotations[AnnotationRoot] != "chat-old" ||
		got.Annotations[AnnotationDepth] != "0" {
		t.Fatalf("backfilled state = %+v", got.ObjectMeta)
	}
	blip, err := fc.GetBlip(context.Background(), "team", "chat-old-g1")
	if err != nil {
		t.Fatal(err)
	}
	if blip.Labels[v1.LabelOwner] != "chat-old" {
		t.Fatalf("backfilled blip = %+v", blip.ObjectMeta)
	}
}

func TestServerCreateTeamChatByDefault(t *testing.T) {
	s, fc, ts := testServer(t)

	name := createSession(t, ts.URL, DefaultProfileName)
	st, err := fc.GetSession(context.Background(), "team", name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Annotations[AnnotationScope] != scopeTeam || st.Annotations[AnnotationUser] != "" {
		t.Fatalf("scope annotations = %v", st.Annotations)
	}
	if st.Namespace != s.namespace {
		t.Fatalf("chat namespace = %q, want %q", st.Namespace, s.namespace)
	}

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{"profile": DefaultProfileName, "scope": "everyone"}, "alice")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scope: status %d", resp.StatusCode)
	}
}

func TestServerPrivateChatIsOnlyVisibleToItsOwner(t *testing.T) {
	_, fc, ts := testServer(t)

	resp := do(t, "POST", ts.URL+"/api/sessions", map[string]any{"profile": DefaultProfileName, "scope": "user"}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)
	st, err := fc.GetSession(context.Background(), "team", created.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Annotations[AnnotationScope] != scopeUser || st.Annotations[AnnotationUser] != "alice" {
		t.Fatalf("scope annotations = %v", st.Annotations)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions", nil, "alice")
	var mine []sessionSummary
	decodeBody(t, resp, &mine)
	if len(mine) != 1 || mine[0].Name != created.Name || mine[0].Scope != scopeUser {
		t.Fatalf("alice sessions = %+v", mine)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions", nil, "bob")
	var theirs []sessionSummary
	decodeBody(t, resp, &theirs)
	if len(theirs) != 0 {
		t.Fatalf("bob sees private chats: %+v", theirs)
	}

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/sessions/" + created.Name},
		{"GET", "/api/sessions/" + created.Name + "/events"},
		{"POST", "/api/sessions/" + created.Name + "/message"},
		{"POST", "/api/sessions/" + created.Name + "/cancel"},
		{"POST", "/api/sessions/" + created.Name + "/stop"},
	} {
		var body any
		if tc.method == "POST" {
			body = map[string]string{"text": "hello"}
		}
		resp := do(t, tc.method, ts.URL+tc.path, body, "bob")
		if resp.StatusCode != http.StatusNotFound {
			resp.Body.Close()
			t.Fatalf("%s %s as bob: status %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// The owner keeps full access.
	resp = do(t, "GET", ts.URL+"/api/sessions/"+created.Name, nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner detail: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerNonOwnerCannotStartPrivateChatDriver(t *testing.T) {
	s, fc, ts := testServer(t)
	st := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-private", Namespace: "team",
		Labels: map[string]string{LabelSession: "true"},
		Annotations: map[string]string{
			AnnotationProfile: DefaultProfileName, AnnotationScope: scopeUser, AnnotationUser: "alice",
			AnnotationRoot: "chat-private", AnnotationDepth: "0",
		},
	}}
	if err := fc.CreateSession(context.Background(), "team", st); err != nil {
		t.Fatal(err)
	}

	resp := do(t, "GET", ts.URL+"/api/sessions/chat-private/events", nil, "bob")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("events as bob: status %d, want 404", resp.StatusCode)
	}
	if d := s.lookupDriver("chat-private"); d != nil {
		t.Fatal("a denied request started the private chat's driver")
	}
}

func TestServerLegacyChatWithoutScopeIsTeam(t *testing.T) {
	_, fc, ts := testServer(t)
	addState(t, fc, "chat-old", map[string]string{LabelSession: "true"}, v1.StateReady, time.Now())
	if err := fc.PatchSession(context.Background(), "team", "chat-old", nil, map[string]string{
		AnnotationProfile: DefaultProfileName, AnnotationRoot: "chat-old", AnnotationDepth: "0",
	}); err != nil {
		t.Fatal(err)
	}

	resp := do(t, "GET", ts.URL+"/api/sessions", nil, "bob")
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	if len(sessions) != 1 || sessions[0].Name != "chat-old" || sessions[0].Scope != scopeTeam {
		t.Fatalf("sessions = %+v", sessions)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions/chat-old", nil, "bob")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy chat detail: status %d", resp.StatusCode)
	}
}

func TestServerChildInheritsPrivateScope(t *testing.T) {
	s, fc, _ := testServer(t)
	parent := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "chat-private", Namespace: "team",
		UID:         "uid-private",
		Labels:      map[string]string{LabelSession: "true"},
		Annotations: map[string]string{AnnotationProfile: DefaultProfileName, AnnotationScope: scopeUser, AnnotationUser: "alice"},
	}}
	if err := fc.CreateSession(context.Background(), "team", parent); err != nil {
		t.Fatal(err)
	}

	// A caller cannot choose a different scope for a child.
	created, err := s.createChat(context.Background(), chatRequest{
		Profile: DefaultProfileName,
		Scope:   scopeTeam,
		Owner:   "bob",
		Parent:  parent,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := fc.GetSession(context.Background(), "team", created.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations[AnnotationScope] != scopeUser || got.Annotations[AnnotationUser] != "alice" {
		t.Fatalf("child scope annotations = %v", got.Annotations)
	}
}

func TestServerPrivateCreateRequiresOwner(t *testing.T) {
	s, _, _ := testServer(t)
	if _, err := s.createChat(context.Background(), chatRequest{Profile: DefaultProfileName, Scope: scopeUser}); err == nil {
		t.Fatal("a private chat was created without an owner")
	}
}
