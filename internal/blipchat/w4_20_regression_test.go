package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Thread lookup failures must not reflect API details, internal URLs, or the
// caller-supplied name (which can contain NUL bytes) back to the browser.
func TestChatHidesThreadLookupErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "not found",
			err:        apierrors.NewNotFound(k8sschema.GroupResource{Group: "blip.dev", Resource: "BlipThread"}, "bad\x00name"),
			wantStatus: http.StatusNotFound,
			wantBody:   "thread not found",
		},
		{
			name:       "transport",
			err:        fmt.Errorf(`Get "https://10.0.0.5:6443/api/v1/namespaces/ns": dial tcp 10.0.0.5:6443: i/o timeout`),
			wantStatus: http.StatusBadGateway,
			wantBody:   "chat backend unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClientWith(t, interceptor.Funcs{
				Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*v1.BlipThread); ok {
						return tt.err
					}
					return cl.Get(ctx, key, obj, opts...)
				},
			}, testThread())
			rec := chatRequestFor(t, c, llmServer(t, Message{Role: "assistant", Content: "ok"}), "alice", "ns",
				`{"thread":"proj","message":"hi"}`)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			body := rec.Body.String()
			for _, leak := range []string{"BlipThread", "blip.dev", "bad", "10.0.0.5", "6443", "i/o timeout", "thread:"} {
				if strings.Contains(body, leak) {
					t.Errorf("response leaks %q: %s", leak, body)
				}
			}
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("response = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

// A Blip whose owner label is not the thread's derived owner must be neither
// listed to the model nor counted against maxRunning, even when it carries the
// thread's label.
func TestBlipListAndMaxRunningIgnoreForeignOwner(t *testing.T) {
	thread := testThread()
	thread.Spec.MaxRunning = 1
	thread.Status.Tasks = []v1.ThreadTask{{ID: "work", Title: "work", Open: true}}
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	owned := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "ns", Labels: map[string]string{
			v1.LabelThread: v1.ThreadLabel("proj"), v1.LabelOwner: owner,
		}},
		Status: v1.BlipStatus{Phase: v1.BlipSucceeded},
	}
	foreign := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "ns", Labels: map[string]string{
			v1.LabelThread: v1.ThreadLabel("proj"), v1.LabelOwner: "u-evil",
		}},
		Status: v1.BlipStatus{Report: &v1.BlipReport{Seq: 1, Text: "INJECTED attacker text"}},
	}
	c := testClient(t, thread, owned, foreign)
	s := &Server{Client: c}
	ctx := context.Background()
	list, err := s.blipList(ctx, thread)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, "owned") {
		t.Errorf("blipList omitted the thread's own blip:\n%s", list)
	}
	if strings.Contains(list, "foreign") || strings.Contains(list, "INJECTED") {
		t.Errorf("blipList exposed a foreign-owner blip:\n%s", list)
	}
	st := &step{s: s, thread: thread, tasks: append([]v1.ThreadTask{}, thread.Status.Tasks...)}
	_, err = st.call(ctx, "start_task", `{"task":"work","prompt":"do it"}`)
	if err == nil {
		t.Fatal("start_task succeeded without a base state")
	}
	if strings.Contains(err.Error(), "maxRunning") {
		t.Errorf("foreign-owner blip consumed the thread's running budget: %v", err)
	}
	if !strings.Contains(err.Error(), "spec.base") {
		t.Errorf("start_task error = %v, want the base-state error after the budget check", err)
	}
}

// Coordinator notes and replies are never pending input (pendingTurns
// excludes them), so retention must be able to age them out even though their
// sequence is above consumedSeq.
func TestPruneBoundsOldCoordinatorTurns(t *testing.T) {
	old := metav1.NewTime(timeNow().Add(-48 * time.Hour))
	fresh := metav1.NewTime(timeNow())
	thread := testThread()
	thread.Spec.Retention.Turns = &metav1.Duration{Duration: time.Hour}
	thread.Spec.Retention.KeepTurns = 1
	thread.Status.ConsumedSeq = 5
	objs := []client.Object{thread}
	user := testTurn("user-old", "proj")
	user.Status = v1.BlipTurnStatus{Seq: 1, AcceptedTime: &old}
	objs = append(objs, user)
	// The shape produced by successive timer-driven steps: coordinator turns
	// created after the last user turn, all above consumedSeq.
	for i := 0; i < 100; i++ {
		turn := testTurn(fmt.Sprintf("coord-%03d", i), "proj")
		turn.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorCoordinator, Name: "proj"}
		turn.Status = v1.BlipTurnStatus{Seq: int64(6 + i), AcceptedTime: &old}
		objs = append(objs, turn)
	}
	pending := testTurn("pending", "proj")
	pending.Status = v1.BlipTurnStatus{Seq: 106, AcceptedTime: &fresh}
	objs = append(objs, pending)

	c := testClient(t, objs...)
	s := &Server{Client: c}
	ctx := context.Background()
	if err := s.prune(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(ctx, &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if got := names(turns.Items); len(got) != 1 || got[0] != "pending" {
		t.Errorf("turns after prune = %v, want only the pending user turn", got)
	}
}

// cleanAttributes must select the same subset of oversized attribute maps on
// every call: a random subset makes an idempotent turn re-create itself.
// A prompt that cannot fit every turn must not advance consumedSeq past a
// turn it neither rendered nor summarized: that permanently loses input.
func TestPromptOverflowDoesNotConsumeUnshownTurns(t *testing.T) {
	const count = 30
	fresh := metav1.NewTime(timeNow())
	thread := testThread()
	objs := []client.Object{thread}
	for i := 1; i <= count; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 1900))
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	upstream, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: upstream.URL, HTTP: upstream.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	prompt := requestPrompt(t, (*requests)[0])
	if !strings.Contains(prompt, "TURN30-MARKER") {
		t.Errorf("prompt omitted the newest turn")
	}
	for i := 1; i <= count; i++ {
		if strings.Contains(prompt, fmt.Sprintf("TURN%02d-MARKER", i)) {
			continue
		}
		if updated.Status.ConsumedSeq >= int64(i) {
			t.Errorf("turn %d was neither rendered nor summarized, but consumedSeq = %d passed it", i, updated.Status.ConsumedSeq)
		}
	}
}

// When even compact summaries of the older turns cannot fit, the renderer
// must consume a prefix it rendered and leave the newer turns pending.
func TestBoardTurnsLeavesNewestPendingWithoutRoomToSummarize(t *testing.T) {
	fresh := metav1.NewTime(timeNow())
	turns := make([]v1.BlipTurn, 0, 20)
	for i := 1; i <= 20; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 400))
		turns = append(turns, *turn)
	}
	var b strings.Builder
	last := boardTurns(&b, turns, 200)
	out := b.String()
	if !strings.Contains(out, "TURN01-MARKER") {
		t.Errorf("oldest turn was not rendered:\n%s", out)
	}
	if strings.Contains(out, "TURN20-MARKER") {
		t.Errorf("newest turn was rendered although consuming it would skip older ones:\n%s", out)
	}
	if last != 1 {
		t.Errorf("highest shown seq = %d, want the rendered prefix ending at 1", last)
	}
	if !strings.Contains(out, "newer turns left for a later step") {
		t.Errorf("missing notice about the pending newer turns:\n%s", out)
	}
}

func TestCleanAttributesUsesStableSubset(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < 20; i++ {
		in[fmt.Sprintf("key-%02d", i)] = fmt.Sprintf("value-%02d", i)
	}
	want := cleanAttributes(in)
	if len(want) != 16 {
		t.Fatalf("cleanAttributes kept %d attributes, want the 16-attribute cap", len(want))
	}
	for i := 0; i < 50; i++ {
		if got := cleanAttributes(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("cleanAttributes changed between calls:\nfirst %v\nnow   %v", want, got)
		}
	}
}

// A report turn has a deterministic name. Reconciles triggered by unrelated
// Blip metadata updates must not replace it and reset the sequencer state that
// decides whether the report was already consumed.
func TestWatcherKeepsReportTurnOnMetadataUpdates(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	report := map[string]string{}
	for i := 0; i < 20; i++ {
		report[fmt.Sprintf("field-%02d", i)] = fmt.Sprintf("value-%02d", i)
	}
	text, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reporter",
			Namespace: "ns",
			UID:       types.UID("blip-uid"),
			Labels: map[string]string{
				v1.LabelThread: v1.ThreadLabel("proj"),
				v1.LabelOwner:  v1.ThreadOwner("ns", "proj"),
			},
		},
		Status: v1.BlipStatus{
			Report: &v1.BlipReport{Seq: 1, Text: string(text)},
		},
	}
	c := testClient(t, thread, blip)
	w := &Watcher{Client: c}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "reporter"}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	name := "blip-blip-uid-r1"
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
		t.Fatal(err)
	}
	turn.Status = v1.BlipTurnStatus{Seq: 7, ThreadUID: "thread-uid"}
	if err := c.Status().Update(ctx, &turn); err != nil {
		t.Fatal(err)
	}

	// An annotation change is what makes the watcher reconcile a Blip whose
	// report has not changed.
	for i := 0; i < 20; i++ {
		var current v1.Blip
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "reporter"}, &current); err != nil {
			t.Fatal(err)
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations["probe"] = fmt.Sprint(i)
		if err := c.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
		var got v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &got); err != nil {
			t.Fatalf("reconcile %d: report turn was replaced: %v", i, err)
		}
		if got.Status.Seq != 7 || got.Status.ThreadUID != "thread-uid" {
			t.Fatalf("reconcile %d: turn status = %+v, want the original seq and incarnation", i, got.Status)
		}
		var turns v1.BlipTurnList
		if err := c.List(ctx, &turns, client.InNamespace("ns"), client.MatchingFields{turnField: "proj"}); err != nil {
			t.Fatal(err)
		}
		if len(turns.Items) != 1 {
			t.Fatalf("reconcile %d: %d report turns survive, want 1", i, len(turns.Items))
		}
	}
}
