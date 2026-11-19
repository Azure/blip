package blipchat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func testClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&v1.BlipThread{}, &v1.BlipTurn{}).
		WithIndex(&v1.BlipTurn{}, turnField, func(o client.Object) []string {
			return []string{o.(*v1.BlipTurn).Spec.Thread}
		}).
		Build()
}

func testThread() *v1.BlipThread {
	return &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: "proj", Namespace: "ns"},
		Spec:       v1.BlipThreadSpec{Pool: "default", MaxRunning: 2, DailyTokens: 1000},
	}
}

func testTurn(name, thread string) *v1.BlipTurn {
	return &v1.BlipTurn{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: v1.BlipTurnSpec{
			Thread: thread,
			Author: v1.TurnAuthor{Kind: v1.TurnAuthorUser, Name: "alice"},
			Topic:  "chat.propose",
			Text:   "please fix it",
		},
	}
}

func TestSequencerOrdersTurns(t *testing.T) {
	c := testClient(t, testThread(), testTurn("one", "proj"), testTurn("two", "proj"))
	s := &Sequencer{Client: c}
	ctx := context.Background()
	for _, name := range []string{"one", "two"} {
		if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	var thread v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.LastSeq != 2 {
		t.Fatalf("lastSeq = %d, want 2", thread.Status.LastSeq)
	}
	for i, name := range []string{"one", "two"} {
		var turn v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
			t.Fatal(err)
		}
		if turn.Status.Seq != int64(i+1) {
			t.Errorf("turn %s seq = %d, want %d", name, turn.Status.Seq, i+1)
		}
	}
	// Re-reconciling a sequenced turn must not consume another number.
	if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.LastSeq != 2 {
		t.Errorf("lastSeq after repeat = %d, want 2", thread.Status.LastSeq)
	}
}

func TestWatcherTurnsReportsIntoMessages(t *testing.T) {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns", UID: types.UID("uid-a"),
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelTask: "t1"},
		},
		Spec:   v1.BlipSpec{Pool: "default", State: "s", Command: []string{"true"}},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Report: &v1.BlipReport{Seq: 2, Text: `{"outcome":"success","summary":"tests pass"}`}},
	}
	c := testClient(t, testThread(), b)
	w := &Watcher{Client: c}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "blip-a"}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "blip-uid-a-r2"}, &turn); err != nil {
		t.Fatalf("report turn: %v", err)
	}
	if turn.Spec.Text != "tests pass" || turn.Spec.Attributes["outcome"] != "success" {
		t.Errorf("report turn = %+v", turn.Spec)
	}
	if turn.Spec.Author.Kind != v1.TurnAuthorBlip || turn.Spec.Topic != "blip.report" {
		t.Errorf("report author/topic = %s/%s", turn.Spec.Author.Kind, turn.Spec.Topic)
	}
	if turn.Spec.Wake != v1.WakeBatch {
		t.Errorf("report wake = %q", turn.Spec.Wake)
	}

	var current v1.Blip
	if err := c.Get(ctx, req.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	current.Status.Phase = v1.BlipSucceeded
	if err := c.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "blip-uid-a-fin"}, &turn); err != nil {
		t.Fatalf("finished turn: %v", err)
	}
	if turn.Spec.Attributes["phase"] != v1.BlipSucceeded {
		t.Errorf("finished attributes = %v", turn.Spec.Attributes)
	}
	// Idempotent.
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(ctx, &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(turns.Items) != 2 {
		t.Errorf("got %d turns, want 2", len(turns.Items))
	}
}

// llmServer replies with the given messages in order and records requests.
func llmServer(t *testing.T, replies ...Message) *httptest.Server {
	t.Helper()
	var requests []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requests = append(requests, body)
		reply := replies[0]
		if len(replies) > 1 {
			replies = replies[1:]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": reply}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func toolCall(name, arguments string) ToolCall {
	var call ToolCall
	call.ID = "call-" + name
	call.Type = "function"
	call.Function.Name = name
	call.Function.Arguments = arguments
	return call
}

func TestStepUpdatesBoardAndConsumesTurns(t *testing.T) {
	ttl := metav1.NewTime(time.Now().Add(-time.Minute))
	thread := testThread()
	thread.Status.NextWake = &ttl
	turn := testTurn("one", "proj")
	turn.Status.Seq = 1
	turn.Status.AcceptedTime = &ttl
	server := llmServer(t,
		Message{Role: "assistant", ToolCalls: []ToolCall{
			toolCall("task_create", `{"id":"t1","title":"Fix login"}`),
			toolCall("note", `{"text":"starting with the login bug"}`),
			toolCall("idle", `{}`),
		}},
		Message{Role: "assistant", Content: "nothing more"},
	)
	c := testClient(t, thread, turn)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	if err := s.step(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != 1 {
		t.Errorf("consumedSeq = %d, want 1", updated.Status.ConsumedSeq)
	}
	if len(updated.Status.Tasks) != 1 || updated.Status.Tasks[0].ID != "t1" || !updated.Status.Tasks[0].Open {
		t.Errorf("tasks = %+v", updated.Status.Tasks)
	}
	if updated.Status.TokensToday != 30 {
		t.Errorf("tokensToday = %d, want 30", updated.Status.TokensToday)
	}
	if updated.Status.NextWake == nil || updated.Status.NextWake.Time.Before(time.Now().Add(29*time.Minute)) {
		t.Errorf("open task did not schedule the heartbeat: %v", updated.Status.NextWake)
	}
	var note v1.BlipTurnList
	if err := c.List(context.Background(), &note, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range note.Items {
		if x.Spec.Author.Kind == v1.TurnAuthorCoordinator && x.Spec.Topic == "coordinator.note" {
			found = true
		}
	}
	if !found {
		t.Error("coordinator note turn was not created")
	}
}

func TestChatSendCreatesUserTurn(t *testing.T) {
	server := llmServer(t,
		Message{Role: "assistant", ToolCalls: []ToolCall{toolCall("send", `{"topic":"chat.propose","text":"please add tests"}`)}},
		Message{Role: "assistant", Content: "I sent that to the coordinator."},
	)
	thread := testThread()
	c := testClient(t, thread)
	s := &Server{Client: c, Config: Config{Model: "test"}, LLM: &LLM{BaseURL: server.URL, HTTP: server.Client()}}
	body := `{"thread":"proj","message":"can you add tests?"}`
	req := httptest.NewRequest(http.MethodPost, "/chat?namespace=ns", strings.NewReader(body))
	req.Header.Set("X-Forwarded-User", "bob@example.com")
	rec := httptest.NewRecorder()
	(&Chat{Server: s}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var response chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Reply != "I sent that to the coordinator." {
		t.Errorf("reply = %q", response.Reply)
	}
	var turns v1.BlipTurnList
	if err := c.List(context.Background(), &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(turns.Items) != 1 {
		t.Fatalf("got %d turns", len(turns.Items))
	}
	turn := turns.Items[0]
	if turn.Spec.Author.Kind != v1.TurnAuthorUser || turn.Spec.Author.Name != "bob@example.com" || turn.Spec.Topic != "chat.propose" {
		t.Errorf("turn = %+v", turn.Spec)
	}
}

func TestReportFields(t *testing.T) {
	attrs, summary := reportFields(`{"outcome":"success","tests":"pass","summary":"all good"}`)
	if summary != "all good" || attrs["outcome"] != "success" || attrs["tests"] != "pass" {
		t.Errorf("attrs=%v summary=%q", attrs, summary)
	}
	if _, ok := attrs["summary"]; ok {
		t.Error("summary leaked into attributes")
	}
	attrs, summary = reportFields("plain text")
	if attrs != nil || summary != "plain text" {
		t.Errorf("plain: attrs=%v summary=%q", attrs, summary)
	}
}

func TestReadOnlyInspect(t *testing.T) {
	for _, ok := range [][]string{{"git", "status"}, {"ls", "-la"}, {"cat", "README.md"}} {
		if err := readOnly(ok); err != nil {
			t.Errorf("%v rejected: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"rm", "-rf", "/"}, {"git", "push"}, {"sh", "-c", "echo"}} {
		if err := readOnly(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestReportReachesCoordinator wires the watcher, sequencer, and one step
// together: a workload report becomes a turn, the turn is sequenced, and the
// step consumes it.
func TestReportReachesCoordinator(t *testing.T) {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns", UID: types.UID("uid-a"),
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelTask: "t1"},
		},
		Spec:   v1.BlipSpec{Pool: "default", State: "s", Command: []string{"true"}},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Report: &v1.BlipReport{Seq: 1, Text: `{"outcome":"success","summary":"done"}`}},
	}
	server := llmServer(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, testThread(), b)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "blip-a"}}
	if _, err := (&Watcher{Client: c}).Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Sequencer{Client: c}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "blip-uid-a-r1"}}); err != nil {
		t.Fatal(err)
	}
	var thread v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Millisecond, Heartbeat: time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	time.Sleep(5 * time.Millisecond)
	if !s.shouldStep(ctx, &thread) {
		t.Fatal("thread with a new turn should step")
	}
	if err := s.step(ctx, &thread); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.ConsumedSeq != 1 {
		t.Errorf("consumedSeq = %d, want 1", thread.Status.ConsumedSeq)
	}
}

// A turn that does not ask to wake the coordinator is context only: it is
// consumed by the next step, but on its own it must not start one.
func TestWakeNoneDoesNotStep(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	turn := &v1.BlipTurn{
		ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: "ns"},
		Spec: v1.BlipTurnSpec{
			Thread: "proj",
			Author: v1.TurnAuthor{Kind: v1.TurnAuthorBlip, Name: "blip-a"},
			Topic:  "blip.report",
			Wake:   v1.WakeNone,
		},
		Status: v1.BlipTurnStatus{Seq: 1, AcceptedTime: &old},
	}
	c := testClient(t, testThread(), turn)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Millisecond, Heartbeat: time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
	}
	var thread v1.BlipThread
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if s.shouldStep(context.Background(), &thread) {
		t.Fatal("a WakeNone turn alone should not trigger a step")
	}
}
