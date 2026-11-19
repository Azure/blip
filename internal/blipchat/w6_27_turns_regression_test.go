package blipchat

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A turn-status write can land on the API server while its response is lost
// (deadline, connection reset, 5xx). The sequencer must not release a number
// that the turn already carries: doing so rewinds lastSeq and lets the next
// turn reuse the same status.seq.
func TestLostTurnStatusWriteDoesNotReuseSeq(t *testing.T) {
	thread := testThread()
	thread.UID = types.UID("inc")
	one := testTurn("a-one", "proj")
	two := testTurn("b-two", "proj")

	var mu sync.Mutex
	injected := false
	funcs := interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			// Apply the write first, then lose the response for one turn.
			if err := c.SubResource(sub).Update(ctx, obj, opts...); err != nil {
				return err
			}
			turn, ok := obj.(*v1.BlipTurn)
			if !ok || sub != "status" {
				return nil
			}
			mu.Lock()
			first := !injected && turn.Name == "a-one"
			if first {
				injected = true
			}
			mu.Unlock()
			if first {
				return errors.New("simulated lost response after apply")
			}
			return nil
		},
	}
	c := testClientWith(t, funcs, thread, one, two)
	s := &Sequencer{Client: c}
	ctx := context.Background()
	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}}
	}

	// The write persisted, so the reconcile is effectively complete; it must
	// not surface an error that makes the caller retry and re-release the
	// number.
	if _, err := s.Reconcile(ctx, req("a-one")); err != nil {
		t.Fatalf("reconcile after a persisted write returned %v", err)
	}
	seqOne := turnStatusSeq(t, c, "a-one")
	seqTwo := turnStatusSeq(t, c, "b-two")
	if seqOne != 1 || seqTwo != 2 {
		t.Fatalf("seqs = %d/%d, want distinct 1/2", seqOne, seqTwo)
	}

	// A later turn must not reuse a number that is already on a turn.
	three := testTurn("c-three", "proj")
	if err := c.Create(ctx, three); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reconcile(ctx, req("c-three")); err != nil {
		t.Fatal(err)
	}
	if seq := turnStatusSeq(t, c, "c-three"); seq != 3 {
		t.Errorf("c-three seq = %d, want 3 after the persisted write kept the counter", seq)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.LastSeq != 3 {
		t.Errorf("lastSeq = %d, want 3", updated.Status.LastSeq)
	}
}

// A backlog far larger than the turn budget must not make renderWakePrefix
// emit every wake turn in full. It renders a bounded prefix instead, and the
// consumed sequence still advances over exactly that prefix.
func TestPromptBudgetBoundsLargeBatchBacklog(t *testing.T) {
	now := timeNow()
	fresh := metav1.NewTime(now)
	thread := testThread()
	objs := []client.Object{thread}
	const turns = 2600
	for i := 1; i <= turns; i++ {
		turn := testTurn(fmt.Sprintf("turn-%04d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", i, strings.Repeat("x", 1900))
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("made %d LLM requests, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "older turns summarized") || !strings.Contains(prompt, "newer turns omitted") {
		t.Errorf("prompt does not disclose the bounded prefix:\n%s", prompt)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	t.Logf("turns=%d prompt bytes=%d budget=%d consumedSeq=%d", turns, len(prompt), promptBudget, updated.Status.ConsumedSeq)
	if updated.Status.ConsumedSeq <= 0 || updated.Status.ConsumedSeq >= turns {
		t.Errorf("consumedSeq = %d, want a bounded prefix of %d pending turns", updated.Status.ConsumedSeq, turns)
	}
}

// Report-shaped turns (blip author, blip.report topic, 2 KiB summaries) are
// the ordinary large backlog. They must stay within the prompt budget too.
func TestPromptBudgetBoundsReportBacklog(t *testing.T) {
	now := timeNow()
	fresh := metav1.NewTime(now)
	thread := testThread()
	objs := []client.Object{thread}
	const turns = 1000
	name := "p-0123456789abcdef.job-123456789-3"
	for i := 1; i <= turns; i++ {
		turn := testTurn(fmt.Sprintf("blip-%04d-r1", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorBlip, Name: name}
		turn.Spec.Topic = "blip.report"
		turn.Spec.Text = strings.Repeat("y", 2048)
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("made %d LLM requests, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "older turns summarized") || !strings.Contains(prompt, "newer turns omitted") {
		t.Errorf("prompt does not disclose the bounded prefix:\n%s", prompt)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	t.Logf("report turns=%d prompt bytes=%d budget=%d consumedSeq=%d", turns, len(prompt), promptBudget, updated.Status.ConsumedSeq)
	if updated.Status.ConsumedSeq <= 0 || updated.Status.ConsumedSeq >= turns {
		t.Errorf("consumedSeq = %d, want the report backlog to advance", updated.Status.ConsumedSeq)
	}
}

// A single non-wake turn at the head of an otherwise wake-turn backlog used to
// leave index 0 unrendered forever: the step deferred on every tick without
// calling the model. The bounded fallback must consume the leading turn.
func TestWakePrefixAdvancesPastLeadingNonWakeTurn(t *testing.T) {
	now := timeNow()
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }
	fresh := metav1.NewTime(now)
	thread := testThread()
	thread.Status.Timers = []v1.ThreadTimer{{
		ID: "t1", At: metav1.NewTime(now.Add(-time.Hour)), Note: "retry deploy",
	}}
	objs := []client.Object{thread}
	const turns = 2600
	for i := 1; i <= turns; i++ {
		turn := testTurn(fmt.Sprintf("turn-%04d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeBatch
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", i, strings.Repeat("x", 200))
		if i == 1 {
			turn.Spec.Wake = v1.WakeNone
		}
		objs = append(objs, turn)
	}
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	ctx := context.Background()
	if err := s.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("the step made no LLM request; the leading non-wake turn stalled the backlog")
	}
	prompt := requestPrompt(t, (*requests)[0])
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "older turns summarized") || !strings.Contains(prompt, "newer turns omitted") {
		t.Errorf("prompt does not disclose the bounded prefix:\n%s", prompt)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	first := updated.Status.ConsumedSeq
	if first < 1 {
		t.Fatalf("consumedSeq = %d, want the leading turn consumed", first)
	}
	// The next tick must keep moving rather than stalling on the same head.
	if err := s.step(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	t.Logf("mirror turns=%d prompt bytes=%d consumedSeq=%d then=%d", turns, len(prompt), first, updated.Status.ConsumedSeq)
	if updated.Status.ConsumedSeq <= first {
		t.Errorf("consumedSeq stayed at %d; the backlog stopped progressing", first)
	}
}

func turnStatusSeq(t *testing.T, c client.Client, name string) int64 {
	t.Helper()
	var turn v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: name}, &turn); err != nil {
		t.Fatal(err)
	}
	return turn.Status.Seq
}

// A long non-wake prefix followed by a wake suffix that does not fit as full
// lines reaches the oldest-prefix fallback. That fallback must disclose the
// pending suffix with a count, not one unbounded summary per wake turn.
func TestPromptBudgetBoundsNonWakePrefixWithWakeSuffix(t *testing.T) {
	now := timeNow()
	fresh := metav1.NewTime(now)
	thread := testThread()
	objs := []client.Object{thread}
	seq := int64(0)
	add := func(n int, wake string) {
		for i := 0; i < n; i++ {
			seq++
			turn := testTurn(fmt.Sprintf("turn-%05d", seq), "proj")
			turn.Status.Seq = seq
			turn.Status.AcceptedTime = &fresh
			turn.Spec.Wake = wake
			turn.Spec.Text = "x"
			objs = append(objs, turn)
		}
	}
	add(2000, v1.WakeNone)
	add(1000, v1.WakeBatch)
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	s := &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
	if err := s.step(context.Background(), thread); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("made %d LLM requests, want 1", len(*requests))
	}
	prompt := requestPrompt(t, (*requests)[0])
	if len(prompt) > promptBudget {
		t.Errorf("prompt = %d bytes, want at most the %d-byte budget", len(prompt), promptBudget)
	}
	if !strings.Contains(prompt, "newer turns left for a later step") {
		t.Errorf("prompt does not disclose the pending suffix:\n%s", prompt)
	}
	var updated v1.BlipThread
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(thread), &updated); err != nil {
		t.Fatal(err)
	}
	t.Logf("none+wake turns=%d prompt bytes=%d consumedSeq=%d", seq, len(prompt), updated.Status.ConsumedSeq)
	if updated.Status.ConsumedSeq <= 0 {
		t.Errorf("consumedSeq = %d, want the prefix consumed", updated.Status.ConsumedSeq)
	}
}
