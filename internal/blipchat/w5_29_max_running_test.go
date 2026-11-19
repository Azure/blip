package blipchat

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// The client List is served from the informer cache in production. A Blip
// created by an earlier start_task in the same step may not be visible yet, so
// the admission check must count the step's own starts too. With maxRunning=1
// the second start_task in one step must be rejected.
func TestStartTaskCountsStepStartsAgainstMaxRunning(t *testing.T) {
	thread := testThread()
	thread.Spec.MaxRunning = 1
	thread.Spec.Base = "base"
	thread.Status.Tasks = []v1.ThreadTask{
		{ID: "one", Title: "one", Open: true},
		{ID: "two", Title: "two", Open: true},
	}
	base := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "ns"}}

	// Model the cache lag: hide Blips whose status has not been observed yet.
	// The just-created Blip has no phase, so a List served this way misses it.
	hideUnstarted := true
	c := testClientWith(t, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := cl.List(ctx, list, opts...); err != nil {
				return err
			}
			blips, ok := list.(*v1.BlipList)
			if !ok || !hideUnstarted {
				return nil
			}
			kept := blips.Items[:0]
			for _, b := range blips.Items {
				if b.Status.Phase != "" {
					kept = append(kept, b)
				}
			}
			blips.Items = kept
			return nil
		},
	}, thread, base)

	server, requests := llmServerWithRequests(t,
		Message{Role: "assistant", ToolCalls: []ToolCall{
			toolCall("start_task", `{"task":"one","prompt":"do one"}`),
			toolCall("start_task", `{"task":"two","prompt":"do two"}`),
		}},
		Message{Role: "assistant", Content: "done"},
	)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}

	hideUnstarted = false
	var blips v1.BlipList
	if err := c.List(ctx, &blips, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(blips.Items) != 1 {
		t.Errorf("started %d blips with maxRunning=1: %v", len(blips.Items), blipNames(blips.Items))
	}
	if len(*requests) < 2 {
		t.Fatalf("made %d LLM requests, want a follow-up with the tool results", len(*requests))
	}
	found := false
	for _, message := range (*requests)[len(*requests)-1]["messages"].([]any) {
		m, _ := message.(map[string]any)
		content, _ := m["content"].(string)
		if m["role"] == "tool" && strings.Contains(content, "thread already runs 1 blips") {
			found = true
		}
	}
	if !found {
		t.Errorf("second start_task was not rejected with the maxRunning error")
	}
}
