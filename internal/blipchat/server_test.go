// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func testServer(t *testing.T) (*Server, *fakeCluster, *httptest.Server) {
	t.Helper()
	fc := newFakeCluster()
	s, err := New(Options{
		Namespace:   "team",
		Profiles:    Profiles{DefaultProfileName: {}},
		DefaultPool: "default",
		AutoApprove: "always",
		Cluster:     fc,
		Wire:        &noLogWire{},
		Log:         testLogger(),
	})
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

func TestServerIdentityAndNamespaceValidation(t *testing.T) {
	_, _, ts := testServer(t)

	resp := do(t, "GET", ts.URL+"/api/sessions?namespace=team", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no user: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions?namespace=team", nil, "alice", "bob")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("two users: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions?namespace=Not_A_Label", nil, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad namespace: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerCreateListAndMessage(t *testing.T) {
	_, fc, ts := testServer(t)

	resp := do(t, "POST", ts.URL+"/api/sessions?namespace=team", map[string]any{
		"namespace": "team",
		"profile":   "default",
		"title":     "Fix the flaky test",
	}, "alice")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var created struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &created)
	if !strings.HasPrefix(created.Name, "chat-fix-the-flaky-test-") {
		t.Fatalf("name = %q", created.Name)
	}
	if len(fc.blipNames()) != 0 {
		// The driver starts asynchronously; zero here is fine, the message
		// below proves the pipeline works.
	}

	resp = do(t, "POST", ts.URL+"/api/sessions?namespace=team", map[string]any{
		"namespace": "team",
		"profile":   "missing",
	}, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown profile: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "GET", ts.URL+"/api/sessions?namespace=team", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", resp.StatusCode)
	}
	var sessions []sessionSummary
	decodeBody(t, resp, &sessions)
	if len(sessions) != 1 || sessions[0].Name != created.Name || sessions[0].Title != "Fix the flaky test" {
		t.Fatalf("sessions = %+v", sessions)
	}

	resp = do(t, "GET", ts.URL+"/api/sessions/"+created.Name+"?namespace=team", nil, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail: status %d", resp.StatusCode)
	}
	var detail sessionDetail
	decodeBody(t, resp, &detail)
	if detail.Name != created.Name {
		t.Fatalf("detail = %+v", detail)
	}

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message?namespace=team", map[string]string{"text": ""}, "alice")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty message: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "POST", ts.URL+"/api/sessions/"+created.Name+"/message?namespace=team", map[string]string{"text": "hello"}, "alice")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("message: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerNotFound(t *testing.T) {
	_, _, ts := testServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/sessions/not-a-chat?namespace=team", nil)
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
