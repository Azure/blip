package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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
	return testClientWith(t, interceptor.Funcs{}, objs...)
}

func testClientWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&v1.BlipThread{}, &v1.BlipTurn{}).
		WithIndex(&v1.BlipTurn{}, turnField, func(o client.Object) []string {
			return []string{o.(*v1.BlipTurn).Spec.Thread}
		}).
		WithInterceptorFuncs(funcs).
		Build()
}

// conflictTurns makes the next n turn status updates fail the way the API
// server does when a producer updates the turn between our read and write.
func conflictTurns(n *int) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if _, ok := obj.(*v1.BlipTurn); ok && *n > 0 {
				*n--
				return apierrors.NewConflict(k8sschema.GroupResource{Group: "blip.dev", Resource: "blipturns"}, obj.GetName(), errors.New("the object has been modified"))
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}
}

func testThread() *v1.BlipThread {
	return &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: "proj", Namespace: "ns"},
		Spec:       v1.BlipThreadSpec{Pool: "default", MaxRunning: 2, DailyTokens: 1000},
	}
}

func TestSystemPromptDefault(t *testing.T) {
	thread := testThread()
	thread.Spec.Charter = "Use state:ready for ready tasks."
	prompt := systemPrompt(thread)
	for _, want := range []string{
		`You are the coordinator for the Blip project "ns/proj".`,
		"You own the task board",
		"Charter:\nUse state:ready for ready tasks.",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestSystemPromptFromThread(t *testing.T) {
	thread := testThread()
	thread.Spec.SystemPrompt = "Custom coordinator prompt: spend 100% of the budget."
	thread.Spec.Charter = "Project conventions."
	prompt := systemPrompt(thread)
	if !strings.HasPrefix(prompt, thread.Spec.SystemPrompt) {
		t.Errorf("prompt does not start with spec.systemPrompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Charter:\nProject conventions.") {
		t.Errorf("prompt missing charter:\n%s", prompt)
	}
	if strings.Contains(prompt, "You own the task board") {
		t.Errorf("custom prompt still contains the built-in text:\n%s", prompt)
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

// A thread that is deleted and recreated reuses its name but gets a new UID.
// Turns sequenced by the old incarnation must not be adopted by the new one.
func TestSequencerScopesTurnsToThreadIncarnation(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("new-incarnation")
	old := testTurn("old", "proj")
	old.Status = v1.BlipTurnStatus{Seq: 7, ThreadUID: "old-incarnation"}
	fresh := testTurn("fresh", "proj")
	c := testClient(t, thread, old, fresh)
	ctx := context.Background()
	if _, err := (&Sequencer{Client: c}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "fresh"}}); err != nil {
		t.Fatal(err)
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "fresh"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.Seq != 1 || turn.Status.ThreadUID != "new-incarnation" {
		t.Errorf("fresh turn status = %+v, want seq 1 for the new incarnation", turn.Status)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.LastSeq != 1 {
		t.Errorf("lastSeq = %d, want 1", updated.Status.LastSeq)
	}
	s := &Server{Client: c}
	pending, err := s.pendingTurns(ctx, &updated)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Name != "fresh" {
		t.Errorf("pending turns = %v, want only fresh", names(pending))
	}
}

func names(turns []v1.BlipTurn) []string {
	out := make([]string, len(turns))
	for i := range turns {
		out[i] = turns[i].Name
	}
	return out
}

// Pruning deletes turns left behind by a previous thread incarnation even when
// their sequence is higher than the current thread's consumed sequence.
func TestPruneDeletesStaleIncarnationTurns(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("new-incarnation")
	old := testTurn("old", "proj")
	old.Status = v1.BlipTurnStatus{Seq: 99, ThreadUID: "old-incarnation"}
	current := testTurn("current", "proj")
	current.Status = v1.BlipTurnStatus{Seq: 1, ThreadUID: "new-incarnation"}
	c := testClient(t, thread, old, current)
	s := &Server{Client: c}
	if err := s.prune(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(context.Background(), &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if got := names(turns.Items); len(got) != 1 || got[0] != "current" {
		t.Errorf("turns after prune = %v, want only current", got)
	}
}

// A turn created while its thread exists is owned by that thread, so deleting
// the thread cascades instead of leaving an orphan behind.
func TestCreateTurnInOwnsTurn(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	c := testClient(t, thread)
	ctx := context.Background()
	if err := createTurnIn(ctx, c, "ns", "turn", turnSpec{Thread: "proj", AuthorKind: v1.TurnAuthorUser, AuthorName: "alice"}); err != nil {
		t.Fatal(err)
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "turn"}, &turn); err != nil {
		t.Fatal(err)
	}
	if len(turn.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %v, want one", turn.OwnerReferences)
	}
	ref := turn.OwnerReferences[0]
	if ref.Kind != "BlipThread" || ref.Name != "proj" || ref.UID != "thread-uid" {
		t.Errorf("owner reference = %+v", ref)
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

// Turns that arrive before their thread are numbered by creation time when
// the thread appears, not by the arbitrary order their requeues fire.
func TestSequencerOrdersWaitingTurnsByCreationTime(t *testing.T) {
	base := metav1.NewTime(time.Now().Add(-time.Minute))
	at := func(name string, offset time.Duration) *v1.BlipTurn {
		turn := testTurn(name, "proj")
		turn.CreationTimestamp = metav1.NewTime(base.Add(offset))
		return turn
	}
	oldest := at("oldest", 0)
	middle := at("middle", time.Second)
	newest := at("newest", 2*time.Second)
	c := testClient(t, newest, oldest, middle)
	s := &Sequencer{Client: c}
	ctx := context.Background()
	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}
	}
	// No thread yet: every turn waits.
	for _, name := range []string{"oldest", "middle", "newest"} {
		if result, err := s.Reconcile(ctx, req(name)); err != nil || result.RequeueAfter == 0 {
			t.Fatalf("%s: result %+v err %v, want a requeue", name, result, err)
		}
	}
	if err := c.Create(ctx, testThread()); err != nil {
		t.Fatal(err)
	}
	// Any single turn event must sequence the whole backlog in order.
	if _, err := s.Reconcile(ctx, req("newest")); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"oldest": 1, "middle": 2, "newest": 3}
	for name, seq := range want {
		var turn v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
			t.Fatal(err)
		}
		if turn.Status.Seq != seq {
			t.Errorf("%s seq = %d, want %d", name, turn.Status.Seq, seq)
		}
	}
}

// Equal creation timestamps fall back to name order.
func TestSequencerOrdersTiedTurnsByName(t *testing.T) {
	ts := metav1.NewTime(time.Now())
	b := testTurn("b", "proj")
	b.CreationTimestamp = ts
	a := testTurn("a", "proj")
	a.CreationTimestamp = ts
	c := testClient(t, testThread(), b, a)
	s := &Sequencer{Client: c}
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "b"}}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"a": 1, "b": 2}
	for name, seq := range want {
		var turn v1.BlipTurn
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
			t.Fatal(err)
		}
		if turn.Status.Seq != seq {
			t.Errorf("%s seq = %d, want %d", name, turn.Status.Seq, seq)
		}
	}
}

// A conflict while writing the turn status must not consume a sequence
// number: the old code advanced lastSeq first, leaving a permanent hole.
func TestSequencerConflictDoesNotBurnSeq(t *testing.T) {
	conflicts := 1
	c := testClientWith(t, conflictTurns(&conflicts), testThread(), testTurn("one", "proj"))
	s := &Sequencer{Client: c}
	ctx := context.Background()
	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}
	}
	if _, err := s.Reconcile(ctx, req("one")); err != nil {
		t.Fatal(err)
	}
	if conflicts != 0 {
		t.Fatalf("test did not exercise a conflict")
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "one"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.Seq != 1 {
		t.Errorf("turn seq = %d, want 1", turn.Status.Seq)
	}
	var thread v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.LastSeq != 1 {
		t.Errorf("lastSeq = %d, want 1", thread.Status.LastSeq)
	}
}

// Persistent conflicts leave the counter untouched instead of burning one
// number per reconcile, so sequencing cannot starve under update churn.
func TestSequencerFailedWritesDoNotAdvanceLastSeq(t *testing.T) {
	conflicts := seqRetries
	c := testClientWith(t, conflictTurns(&conflicts), testThread(), testTurn("one", "proj"))
	s := &Sequencer{Client: c}
	ctx := context.Background()
	if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err == nil {
		t.Fatal("expected a conflict error")
	}
	var thread v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.LastSeq != 0 {
		t.Errorf("lastSeq = %d, want 0 after only conflicts", thread.Status.LastSeq)
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "one"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.Seq != 0 {
		t.Errorf("turn seq = %d, want 0", turn.Status.Seq)
	}
}

// If the counter write fails after the turn was numbered, the next reconcile
// repairs lastSeq instead of handing out the same number again.
func TestSequencerRepairsLaggingLastSeq(t *testing.T) {
	turn := testTurn("one", "proj")
	turn.Status = v1.BlipTurnStatus{Seq: 4}
	c := testClient(t, testThread(), turn)
	s := &Sequencer{Client: c}
	ctx := context.Background()
	if _, err := s.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "one"}}); err != nil {
		t.Fatal(err)
	}
	var thread v1.BlipThread
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "proj"}, &thread); err != nil {
		t.Fatal(err)
	}
	if thread.Status.LastSeq != 4 {
		t.Errorf("lastSeq = %d, want 4", thread.Status.LastSeq)
	}
}

// A turn whose thread can never exist is terminal immediately instead of
// being requeued every two seconds forever. A turn racing a valid thread name
// is given a grace period.
func TestSequencerOrphanHandling(t *testing.T) {
	ctx := context.Background()
	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}
	}

	invalid := testTurn("invalid", "proj ")
	invalid.CreationTimestamp = metav1.NewTime(time.Now())
	young := testTurn("young", "proj")
	young.CreationTimestamp = metav1.NewTime(time.Now())
	old := testTurn("old", "proj")
	old.CreationTimestamp = metav1.NewTime(time.Now().Add(-orphanGrace - time.Minute))
	c := testClient(t, invalid, young, old)
	s := &Sequencer{Client: c}

	if result, err := s.Reconcile(ctx, req("invalid")); err != nil || result.RequeueAfter != 0 {
		t.Fatalf("invalid thread result %+v err %v, want no requeue", result, err)
	}
	var turn v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "invalid"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.OrphanedAt == nil || turn.Status.Seq != 0 {
		t.Errorf("invalid turn status = %+v, want orphaned and unsequenced", turn.Status)
	}
	if result, err := s.Reconcile(ctx, req("invalid")); err != nil || result.RequeueAfter != 0 {
		t.Fatalf("orphaned turn requeued: %+v %v", result, err)
	}

	if result, err := s.Reconcile(ctx, req("young")); err != nil || result.RequeueAfter != requeueDelay {
		t.Fatalf("young turn result %+v err %v, want requeue after %v", result, err, requeueDelay)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "young"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.OrphanedAt != nil {
		t.Error("a turn racing a valid thread name was orphaned too early")
	}

	if result, err := s.Reconcile(ctx, req("old")); err != nil || result.RequeueAfter != 0 {
		t.Fatalf("old turn result %+v err %v, want no requeue", result, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "old"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.OrphanedAt == nil {
		t.Error("turn past the grace period was not marked orphaned")
	}
}

// An orphaned turn is sequenced when its thread appears (the thread create
// watch enqueues it), and the terminal marker is cleared.
func TestSequencerAdoptsOrphanWhenThreadAppears(t *testing.T) {
	orphaned := testTurn("waiting", "proj")
	orphaned.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	orphaned.Status.OrphanedAt = &metav1.Time{Time: time.Now()}
	thread := testThread()
	c := testClient(t, thread, orphaned)
	s := &Sequencer{Client: c}
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "waiting"}}); err != nil {
		t.Fatal(err)
	}
	var turn v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "waiting"}, &turn); err != nil {
		t.Fatal(err)
	}
	if turn.Status.Seq != 1 || turn.Status.OrphanedAt != nil {
		t.Errorf("turn status = %+v, want sequenced without an orphan marker", turn.Status)
	}
}

// Turns with no thread are garbage-collected after the default retention.
func TestPruneOrphanTurns(t *testing.T) {
	thread := testThread()
	old := func(t *v1.BlipTurn) *v1.BlipTurn {
		t.CreationTimestamp = metav1.NewTime(time.Now().Add(-defaultTurnAge - time.Hour))
		return t
	}
	orphan := old(testTurn("orphan", "deleted-thread"))
	young := testTurn("young", "deleted-thread")
	young.CreationTimestamp = metav1.NewTime(time.Now())
	live := testTurn("live", "proj")
	live.CreationTimestamp = metav1.NewTime(time.Now())
	live.Status.Seq = 1
	c := testClient(t, thread, orphan, young, live)
	s := &Server{Client: c}
	if err := s.pruneOrphanTurns(context.Background(), []v1.BlipThread{*thread}); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(context.Background(), &turns, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	got := names(turns.Items)
	want := map[string]bool{"young": true, "live": true}
	if len(got) != len(want) {
		t.Fatalf("turns after sweep = %v, want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected surviving turn %q", name)
		}
	}
}

func TestWatcherTurnsReportsIntoMessages(t *testing.T) {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns", UID: types.UID("uid-a"),
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelTask: "t1", v1.LabelOwner: Owner(&ThreadKey{Namespace: "ns", Name: "proj"})},
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

// llmServer replies with the given messages in order.
func llmServer(t *testing.T, replies ...Message) *httptest.Server {
	t.Helper()
	server, _ := llmServerWithRequests(t, replies...)
	return server
}

// llmServerWithRequests also records the request bodies.
func llmServerWithRequests(t *testing.T, replies ...Message) (*httptest.Server, *[]map[string]any) {
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
	return server, &requests
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

func TestStepUsesSystemPromptFromThread(t *testing.T) {
	thread := testThread()
	thread.Spec.SystemPrompt = "Custom coordinator prompt."
	thread.Spec.Charter = "Project conventions."
	turn := testTurn("one", "proj")
	turn.Status.Seq = 1
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	c := testClient(t, thread, turn)
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 1000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	if err := s.step(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	messages, ok := (*requests)[0]["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatalf("request messages = %#v", (*requests)[0]["messages"])
	}
	first, ok := messages[0].(map[string]any)
	if !ok {
		t.Fatalf("first message = %#v", messages[0])
	}
	if first["role"] != "system" {
		t.Errorf("first message role = %v", first["role"])
	}
	content, _ := first["content"].(string)
	if !strings.Contains(content, thread.Spec.SystemPrompt) {
		t.Errorf("system message missing spec.systemPrompt:\n%s", content)
	}
	if !strings.Contains(content, thread.Spec.Charter) {
		t.Errorf("system message missing spec.charter:\n%s", content)
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
	tests := []struct {
		name string
		argv []string
		ok   bool
	}{
		// Benign inspection.
		{name: "git status", argv: []string{"git", "status"}, ok: true},
		{name: "git log", argv: []string{"git", "log", "--oneline", "-n", "5"}, ok: true},
		{name: "git diff", argv: []string{"git", "diff", "--stat"}, ok: true},
		{name: "git show", argv: []string{"git", "show", "HEAD:README.md"}, ok: true},
		{name: "git rev-parse", argv: []string{"git", "rev-parse", "HEAD"}, ok: true},
		{name: "git branch list", argv: []string{"git", "branch"}, ok: true},
		{name: "git branch all", argv: []string{"git", "branch", "-a"}, ok: true},
		{name: "git branch merged", argv: []string{"git", "branch", "--merged=main"}, ok: true},
		{name: "ls", argv: []string{"ls", "-la"}, ok: true},
		{name: "cat", argv: []string{"cat", "README.md"}, ok: true},
		{name: "head", argv: []string{"head", "-n", "20", "README.md"}, ok: true},
		{name: "tail", argv: []string{"tail", "-n", "20", "README.md"}, ok: true},
		{name: "wc", argv: []string{"wc", "-l", "README.md"}, ok: true},
		{name: "grep", argv: []string{"grep", "-n", "func", "main.go"}, ok: true},
		{name: "rg", argv: []string{"rg", "-n", "--glob", "*.go", "func"}, ok: true},
		{name: "rg pretty", argv: []string{"rg", "--pretty", "func"}, ok: true},
		{name: "find", argv: []string{"find", ".", "-name", "*.go", "-type", "f"}, ok: true},
		{name: "find printable", argv: []string{"find", ".", "-maxdepth", "2", "-print"}, ok: true},
		{name: "pwd", argv: []string{"pwd"}, ok: true},

		// Options that execute commands or write files.
		{name: "find exec", argv: []string{"find", "/", "-exec", "sh", "-c", "id", ";"}},
		{name: "find execdir", argv: []string{"find", ".", "-execdir", "rm", "{}", ";"}},
		{name: "find delete", argv: []string{"find", "/tmp", "-delete"}},
		{name: "find ok", argv: []string{"find", ".", "-ok", "rm", "{}", ";"}},
		{name: "find okdir", argv: []string{"find", ".", "-okdir", "rm", "{}", ";"}},
		{name: "find fprint", argv: []string{"find", ".", "-fprint", "/tmp/pwn"}},
		{name: "find fprintf", argv: []string{"find", ".", "-fprintf", "/tmp/pwn", "%p"}},
		{name: "find fls", argv: []string{"find", ".", "-fls", "/tmp/pwn"}},
		{name: "rg pre", argv: []string{"rg", "--pre", "id", "x", "."}},
		{name: "rg pre equals", argv: []string{"rg", "--pre=id", "x", "."}},
		{name: "rg pre glob", argv: []string{"rg", "--pre-glob", "*.pdf", "--pre", "id", "x", "."}},
		{name: "git output", argv: []string{"git", "log", "--output=/tmp/pwn"}},
		{name: "git output separate", argv: []string{"git", "log", "--output", "/tmp/pwn"}},
		{name: "git order file", argv: []string{"git", "log", "-O", "/tmp/pwn"}},
		{name: "git ext diff", argv: []string{"git", "diff", "--ext-diff"}},
		{name: "git textconv", argv: []string{"git", "show", "--textconv", "HEAD"}},
		{name: "git branch delete", argv: []string{"git", "branch", "-D", "main"}},
		{name: "git branch create", argv: []string{"git", "branch", "newbranch"}},
		{name: "git push", argv: []string{"git", "push"}},
		{name: "rm", argv: []string{"rm", "-rf", "/"}},
		{name: "sh", argv: []string{"sh", "-c", "echo"}},
		{name: "empty", argv: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readOnly(tt.argv)
			if tt.ok && err != nil {
				t.Errorf("%v rejected: %v", tt.argv, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("%v accepted", tt.argv)
			}
		})
	}
}

func TestInspectRequiresThreadOwnedBlip(t *testing.T) {
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	tests := []struct {
		name   string
		labels map[string]string
	}{
		{name: "other thread", labels: map[string]string{v1.LabelThread: "other", v1.LabelOwner: owner}},
		{name: "other owner", labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: "p-other"}},
		{name: "no labels", labels: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &v1.Blip{
				ObjectMeta: metav1.ObjectMeta{Name: "blip-a", Namespace: "ns", Labels: tt.labels},
				Status:     v1.BlipStatus{Phase: v1.BlipSucceeded},
			}
			c := testClient(t, testThread(), b)
			chat := &chatStep{s: &Server{Client: c}, thread: testThread()}
			if _, err := chat.inspect(context.Background(), "blip-a", nil); err == nil {
				t.Fatal("inspect accepted a blip outside the thread")
			}
		})
	}
}

func TestInspectAcceptsThreadOwnedBlip(t *testing.T) {
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{
			Phase:  v1.BlipSucceeded,
			Report: &v1.BlipReport{Text: `{"summary":"done"}`},
		},
	}
	c := testClient(t, testThread(), b)
	chat := &chatStep{s: &Server{Client: c}, thread: testThread()}
	got, err := chat.inspect(context.Background(), "blip-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "done") {
		t.Errorf("inspect result = %q", got)
	}
}

// TestReportReachesCoordinator wires the watcher, sequencer, and one step
// together: a workload report becomes a turn, the turn is sequenced, and the
// step consumes it.
func TestReportReachesCoordinator(t *testing.T) {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns", UID: types.UID("uid-a"),
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelTask: "t1", v1.LabelOwner: Owner(&ThreadKey{Namespace: "ns", Name: "proj"})},
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

// A blip may only report into a thread its owner owns. A restricted VM can
// relabel its own Blip with another project's blip.dev/thread, so the watcher
// must verify the thread exists and its derived owner matches the Blip owner
// before appending attacker-controlled text to the victim's history.
func TestWatcherIgnoresForeignThreadLabel(t *testing.T) {
	project := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	victimThread := &v1.BlipThread{ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "ns"}}
	report := func(labels map[string]string) *v1.Blip {
		return &v1.Blip{
			ObjectMeta: metav1.ObjectMeta{Name: "blip-a", Namespace: "ns", UID: types.UID("uid-a"), Labels: labels},
			Status: v1.BlipStatus{
				Phase:  v1.BlipSucceeded,
				Report: &v1.BlipReport{Seq: 1, Text: "CROSS-PROJECT-INJECTION"},
			},
		}
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "blip-a"}}

	for _, tc := range []struct {
		name   string
		labels map[string]string
	}{
		{"foreign thread label", map[string]string{v1.LabelThread: "victim", v1.LabelOwner: project}},
		{"missing thread", map[string]string{v1.LabelThread: "missing", v1.LabelOwner: project}},
		{"missing owner label", map[string]string{v1.LabelThread: "proj"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, testThread(), victimThread, report(tc.labels))
			if _, err := (&Watcher{Client: c}).Reconcile(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			var turns v1.BlipTurnList
			if err := c.List(context.Background(), &turns, client.InNamespace("ns")); err != nil {
				t.Fatal(err)
			}
			if len(turns.Items) != 0 {
				t.Fatalf("created turns outside the blip's thread: %v", names(turns.Items))
			}
		})
	}

	// Same-owner reporting still becomes turns.
	labels := map[string]string{v1.LabelThread: "proj", v1.LabelOwner: project}
	c := testClient(t, testThread(), victimThread, report(labels))
	if _, err := (&Watcher{Client: c}).Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blip-uid-a-r1", "blip-uid-a-fin"} {
		var turn v1.BlipTurn
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
			t.Errorf("same-owner turn %s: %v", name, err)
		}
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

// Turns written by the coordinator carry their thread and derived owner so
// the in-guest API proxy can scope turn reads to one project.
func TestCreateTurnInLabelsScope(t *testing.T) {
	c := testClient(t, testThread())
	turn := turnSpec{Thread: "proj", AuthorKind: v1.TurnAuthorServiceAccount, AuthorName: "system:serviceaccount:ns:ci", Text: "hello"}
	if err := createTurnIn(context.Background(), c, "ns", "turn-a", turn); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "turn-a"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[v1.LabelThread] != "proj" {
		t.Errorf("thread label = %q", got.Labels[v1.LabelThread])
	}
	if want := v1.ThreadOwner("ns", "proj"); got.Labels[v1.LabelOwner] != want {
		t.Errorf("owner label = %q, want %q", got.Labels[v1.LabelOwner], want)
	}
}

// A deterministic watcher name is a retry only when the existing turn is the
// same turn. A squatted name must not suppress the real report or finish.
func TestCreateTurnInReplacesSquattedName(t *testing.T) {
	c := testClient(t, testThread())
	squat := &v1.BlipTurn{
		ObjectMeta: metav1.ObjectMeta{Name: "blip-uid-fin", Namespace: "ns"},
		Spec: v1.BlipTurnSpec{
			Thread: "proj",
			Author: v1.TurnAuthor{Kind: v1.TurnAuthorServiceAccount, Name: "system:serviceaccount:ns:ci"},
			Topic:  "blip.finished",
			Text:   "forged finish",
		},
	}
	if err := c.Create(context.Background(), squat); err != nil {
		t.Fatal(err)
	}
	want := turnSpec{
		Thread: "proj", AuthorKind: v1.TurnAuthorBlip, AuthorName: "blip-a",
		Topic: "blip.finished", Text: "Succeeded complete",
	}
	if err := createTurnIn(context.Background(), c, "ns", "blip-uid-fin", want); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "blip-uid-fin"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Text != want.Text || got.Spec.Author.Kind != v1.TurnAuthorBlip || got.Spec.Author.Name != "blip-a" {
		t.Fatalf("squatted turn survived: %+v", got.Spec)
	}
}

func TestCreateTurnInRetryIsIdempotent(t *testing.T) {
	c := testClient(t, testThread())
	spec := turnSpec{Thread: "proj", AuthorKind: v1.TurnAuthorBlip, AuthorName: "blip-a", Topic: "blip.report", Text: "done"}
	for i := 0; i < 2; i++ {
		if err := createTurnIn(context.Background(), c, "ns", "blip-uid-r1", spec); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "blip-uid-r1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Text != "done" {
		t.Fatalf("turn = %+v", got.Spec)
	}
}

// The coordinator's exec and stop tools are as strict as inspect: they may
// only act on blips labelled with this thread and its derived owner.
func TestExecAndStopRequireThreadOwnedBlip(t *testing.T) {
	thread := testThread()
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	foreign := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "other", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Pod: "pod-a"},
	}
	c := testClient(t, thread, foreign)
	s := &Server{Client: c}
	if _, err := s.execIn(context.Background(), thread, "blip-a", []string{"true"}, time.Second); err == nil {
		t.Fatal("exec accepted a blip outside the thread")
	}

	st := &step{s: s, thread: thread}
	if _, err := st.call(context.Background(), "stop", `{"blip":"blip-a"}`); err == nil {
		t.Fatal("stop accepted a blip outside the thread")
	}
	var got v1.Blip
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "blip-a"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Stop {
		t.Fatal("foreign blip was stopped")
	}

	own := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-b", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Pod: "pod-b"},
	}
	c = testClient(t, thread, own)
	st = &step{s: &Server{Client: c}, thread: thread}
	if _, err := st.call(context.Background(), "stop", `{"blip":"blip-b"}`); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "blip-b"}, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Spec.Stop {
		t.Fatal("own blip was not stopped")
	}
}
