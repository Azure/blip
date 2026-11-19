package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// send must be pinned to the incarnation the handler looked up. If the name
// now belongs to a recreated thread, the turn is not created at all rather
// than being owned by the new incarnation.
func TestChatSendPinsTurnToLookedUpThreadIncarnation(t *testing.T) {
	old := testThread()
	old.UID = types.UID("old-incarnation")
	replaced := testThread()
	replaced.UID = types.UID("new-incarnation")
	c := testClient(t, replaced)

	step := &chatStep{s: &Server{Client: c}, thread: old, user: "alice"}
	_, err := step.call(context.Background(), "send", `{"topic":"chat.propose","text":"do work"}`)
	if !errors.Is(err, errStaleIncarnation) {
		t.Fatalf("err = %v, want errStaleIncarnation", err)
	}
	if turns := chatTurns(t, c); len(turns) != 0 {
		t.Errorf("stale chat created turns %v", names(turns))
	}
}

// A request that outlives a thread delete/recreate must abandon instead of
// carrying the old project's directive into the new coordinator.
func TestChatSendAbandonsRecreatedThread(t *testing.T) {
	old := testThread()
	old.UID = types.UID("old-incarnation")
	c := testClient(t, old)

	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() {
			ctx := context.Background()
			var live v1.BlipThread
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &live); err != nil {
				t.Error(err)
				return
			}
			if err := c.Delete(ctx, &live); err != nil {
				t.Error(err)
				return
			}
			recreated := testThread()
			recreated.UID = types.UID("new-incarnation")
			if err := c.Create(ctx, recreated); err != nil {
				t.Error(err)
			}
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": Message{Role: "assistant", ToolCalls: []ToolCall{
				toolCall("send", `{"topic":"chat.propose","text":"old project work"}`),
			}}}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer upstream.Close()

	rec := chatRequestFor(t, c, upstream, "alice", "ns", `{"thread":"proj","message":"do work"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if turns := chatTurns(t, c); len(turns) != 0 {
		t.Errorf("stale chat created turns %v", names(turns))
	}
}

// A deleted thread must not leave an unowned turn that a later thread of the
// same name could adopt.
func TestChatSendAbandonsDeletedThread(t *testing.T) {
	old := testThread()
	old.UID = types.UID("old-incarnation")
	c := testClient(t, old)

	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() {
			ctx := context.Background()
			var live v1.BlipThread
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &live); err != nil {
				t.Error(err)
				return
			}
			if err := c.Delete(ctx, &live); err != nil {
				t.Error(err)
			}
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": Message{Role: "assistant", ToolCalls: []ToolCall{
				toolCall("send", `{"topic":"chat.propose","text":"orphan work"}`),
			}}}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer upstream.Close()

	rec := chatRequestFor(t, c, upstream, "alice", "ns", `{"thread":"proj","message":"do work"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if turns := chatTurns(t, c); len(turns) != 0 {
		t.Errorf("deleted thread's chat left turns %v", names(turns))
	}
}

type contextRecordingClient struct {
	client.Client
	listCtx context.Context
}

func (c *contextRecordingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	c.listCtx = ctx
	return c.Client.List(ctx, list, opts...)
}

// system reads turns while building the prompt. That read must use the
// request context so a canceled or expired chat stops promptly.
func TestChatSystemUsesRequestContext(t *testing.T) {
	thread := testThread()
	recorder := &contextRecordingClient{Client: testClient(t, thread)}
	ctx := context.WithValue(context.Background(), struct{}{}, "request")
	step := &chatStep{s: &Server{Client: recorder}, thread: thread}
	step.system(ctx)
	if recorder.listCtx != ctx {
		t.Error("system listed turns with a context other than the request's")
	}
}
