package blipchat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A Blip belongs to the incarnation of the thread that created it. Labels are
// name-derived and survive a delete/recreate, so the thread UID annotation
// decides; a legacy Blip without it belongs only when it was created at or
// after this thread incarnation.
func TestBelongsToThreadScopesToIncarnation(t *testing.T) {
	created := metav1.NewTime(timeNow())
	older := metav1.NewTime(created.Add(-time.Hour))
	thread := testThread()
	thread.UID = types.UID("new-incarnation")
	thread.CreationTimestamp = created
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	blip := func(annotations map[string]string, at metav1.Time) *v1.Blip {
		return &v1.Blip{ObjectMeta: metav1.ObjectMeta{
			Name: "worker", Namespace: "ns",
			Labels:            map[string]string{v1.LabelThread: v1.ThreadLabel("proj"), v1.LabelOwner: owner},
			Annotations:       annotations,
			CreationTimestamp: at,
		}}
	}
	tests := []struct {
		name string
		b    *v1.Blip
		want bool
	}{
		{"tagged for this incarnation", blip(map[string]string{v1.AnnotationThreadUID: "new-incarnation"}, older), true},
		{"tagged for a previous incarnation", blip(map[string]string{v1.AnnotationThreadUID: "old-incarnation"}, created), false},
		{"legacy created with the thread", blip(nil, created), true},
		{"legacy created after the thread", blip(nil, metav1.NewTime(created.Add(time.Minute))), true},
		{"legacy created before the thread", blip(nil, older), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := belongsToThread(tt.b, thread); got != tt.want {
				t.Errorf("belongsToThread = %v, want %v", got, tt.want)
			}
		})
	}
}

// A report from a Blip of a previous incarnation must not become a turn of the
// recreated thread, even though its name-derived labels still match.
func TestWatcherIgnoresPreviousIncarnationReport(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("new-incarnation")
	old := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker", Namespace: "ns", UID: types.UID("blip-uid"),
			Labels: map[string]string{
				v1.LabelThread: v1.ThreadLabel("proj"),
				v1.LabelOwner:  v1.ThreadOwner("ns", "proj"),
			},
			Annotations: map[string]string{v1.AnnotationThreadUID: "old-incarnation"},
		},
		Status: v1.BlipStatus{Report: &v1.BlipReport{Seq: 1, Text: "stale report"}},
	}
	c := testClient(t, thread, old)
	w := &Watcher{Client: c}
	ctx := context.Background()
	if _, err := w.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "worker"}}); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(ctx, &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(turns.Items) != 0 {
		t.Errorf("previous incarnation's report became turns %v", names(turns.Items))
	}
}

// A step abandoned as a stale incarnation must remove the Blips and states its
// start_task calls created; they were started for a thread that no longer
// exists.
func TestStaleStepStartTaskRollsBackCreatedWork(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("old-incarnation")
	thread.Spec.Base = "base"
	thread.Status.Tasks = []v1.ThreadTask{{ID: "work", Title: "work", Open: true}}
	base := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "ns"}}
	c := testClient(t, thread, base)

	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			ctx := context.Background()
			old := &v1.BlipThread{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, old); err != nil {
				t.Error(err)
				return
			}
			if err := c.Delete(ctx, old); err != nil {
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
				toolCall("start_task", `{"task":"work","prompt":"do it"}`),
			}}}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer server.Close()
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatalf("the stale step should be abandoned, not fail: %v", err)
	}
	var blips v1.BlipList
	if err := c.List(ctx, &blips, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(blips.Items) != 0 {
		t.Errorf("stale step left blips behind: %v", blipNames(blips.Items))
	}
	var states v1.BlipStateList
	if err := c.List(ctx, &states, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(states.Items) != 1 || states.Items[0].Name != "base" {
		t.Errorf("stale step left states behind: %v", stateNames(states.Items))
	}
}

func blipNames(blips []v1.Blip) []string {
	out := make([]string, len(blips))
	for i := range blips {
		out[i] = blips[i].Name
	}
	return out
}

func stateNames(states []v1.BlipState) []string {
	out := make([]string, len(states))
	for i := range states {
		out[i] = states[i].Name
	}
	return out
}
