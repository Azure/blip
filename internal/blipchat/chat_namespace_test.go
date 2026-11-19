package blipchat

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestChatNamespaceValidation(t *testing.T) {
	invalid := []string{"..", "UPPER", "ns/other", "ns name", strings.Repeat("a", 64), "-leading", "trailing-", "a_b", "nul\x00"}
	for _, namespace := range invalid {
		t.Run(fmt.Sprintf("%q", namespace), func(t *testing.T) {
			upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
			c := testClient(t, testThread())
			rec := chatRequestFor(t, c, upstream, "alice", namespace, `{"thread":"proj","message":"hi"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if len(*requests) != 0 {
				t.Errorf("invalid namespace reached the model (%d requests)", len(*requests))
			}
		})
	}
	for _, namespace := range []string{"ns", "a-b1"} {
		t.Run("valid "+namespace, func(t *testing.T) {
			upstream := llmServer(t, Message{Role: "assistant", Content: "ok"})
			thread := testThread()
			thread.Namespace = namespace
			c := testClient(t, thread)
			rec := chatRequestFor(t, c, upstream, "alice", namespace, `{"thread":"proj","message":"hi"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
		})
	}
	// A valid but missing namespace is a 404, not a validation error.
	upstream := llmServer(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread())
	rec := chatRequestFor(t, c, upstream, "alice", "other", `{"thread":"proj","message":"hi"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing thread status = %d, want 404", rec.Code)
	}
}
