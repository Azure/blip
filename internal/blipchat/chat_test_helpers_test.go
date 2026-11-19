package blipchat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// chatRequestFor runs one chat request against a fake client and a test
// upstream, returning the recorded response.
func chatRequestFor(t *testing.T, c client.Client, upstream *httptest.Server, user, namespace, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()}}
	path := "/chat"
	if namespace != "" {
		path += "?namespace=" + url.QueryEscape(namespace)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("X-Forwarded-User", user)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	(&Chat{Server: s}).ServeHTTP(rec, req)
	return rec
}

func chatTurns(t *testing.T, c client.Client) []v1.BlipTurn {
	t.Helper()
	var turns v1.BlipTurnList
	if err := c.List(context.Background(), &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	return turns.Items
}
