package blipchat

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// deferredBacklog seeds the wave-5 unrenderable shape: a long Wake=None
// backlog whose only wake turn lies beyond what even compact summaries can
// show. addDueTimer also seeds an already-due timer, which shouldStep treats
// as a pending wake.
func deferredBacklog(t *testing.T, now time.Time, addDueTimer bool) (*v1.BlipThread, []client.Object) {
	t.Helper()
	fresh := metav1.NewTime(now)
	thread := testThread()
	thread.Spec.DailyTokens = 0
	if addDueTimer {
		thread.Status.Timers = []v1.ThreadTimer{{
			ID: "t1", At: metav1.NewTime(now.Add(-time.Minute)), Note: "retry deploy",
		}}
	}
	objs := []client.Object{thread}
	for i := 1; i <= 2600; i++ {
		turn := testTurn(fmt.Sprintf("turn-%04d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%04d-MARKER %s", i, strings.Repeat("x", 200))
		if i == 2000 {
			turn.Spec.Wake = v1.WakeNow
		}
		objs = append(objs, turn)
	}
	return thread, objs
}

func newDeferredServer(c client.Client, server *httptest.Server) *Server {
	return &Server{
		Client: c,
		Config: Config{Model: "test", Debounce: time.Second, Heartbeat: 30 * time.Minute, StepTokenLimit: 100000, MaxToolCalls: 20},
		LLM:    &LLM{BaseURL: server.URL, HTTP: server.Client()},
	}
}

// A restarted or newly elected leader must honour the deferred retry that the
// previous leader persisted. The pending Wake=Now turn is exactly the input
// that caused the deferral, so it must not bypass the backoff.
func TestRestartedLeaderHonorsDeferredPromptBackoff(t *testing.T) {
	now := timeNow()
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }

	thread, objs := deferredBacklog(t, now, false)
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	ctx := context.Background()

	leader1 := newDeferredServer(c, server)
	if err := leader1.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 0 {
		t.Fatalf("deferred step made %d LLM requests, want 0", len(*requests))
	}
	if live.Status.NextWake == nil || !live.Status.NextWake.After(now) {
		t.Fatalf("nextWake = %v, want a future deferred wake", live.Status.NextWake)
	}
	if leader1.shouldStep(ctx, &live) {
		t.Fatal("the leader that deferred ignored its own in-process backoff")
	}

	// A fresh process has an empty in-memory backoff map; the durable thread
	// status must still hold the retry.
	leader2 := newDeferredServer(c, server)
	if leader2.shouldStep(ctx, &live) {
		t.Fatalf("a restarted leader ignored the deferred backoff in nextWake=%v and re-entered the stalled prompt", live.Status.NextWake)
	}

	// Even halfway through the backoff the pending Wake=Now turn must wait.
	timeNow = func() time.Time { return now.Add(stalledPromptBackoff / 2) }
	if leader2.shouldStep(ctx, &live) {
		t.Fatal("the deferred backoff was cut short by a pending Wake=Now turn")
	}
	// After the bounded backoff the thread may retry and make progress.
	timeNow = func() time.Time { return now.Add(stalledPromptBackoff + time.Second) }
	if !leader2.shouldStep(ctx, &live) {
		t.Fatal("a deferred thread never retried after the backoff expired")
	}
}

// The same restart/failover case with a due timer instead of a Wake=Now turn.
// The timer was deliberately kept pending by the deferred step, so it is the
// pending input that used to bypass NextWake on a new leader.
func TestRestartedLeaderHonorsDeferredPromptBackoffWithDueTimer(t *testing.T) {
	now := timeNow()
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }

	thread, objs := deferredBacklog(t, now, true)
	c := testClient(t, objs...)
	server, requests := llmServerWithRequests(t, Message{Role: "assistant", Content: "ok"})
	ctx := context.Background()

	leader1 := newDeferredServer(c, server)
	if err := leader1.step(ctx, thread); err != nil {
		t.Fatal(err)
	}
	var live v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(thread), &live); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 0 {
		t.Fatalf("deferred step made %d LLM requests, want 0", len(*requests))
	}
	if len(live.Status.Timers) != 1 {
		t.Fatalf("timers = %+v, want the unprocessed due timer kept", live.Status.Timers)
	}
	if live.Status.NextWake == nil || !live.Status.NextWake.After(now) {
		t.Fatalf("nextWake = %v, want a future deferred wake", live.Status.NextWake)
	}

	leader2 := newDeferredServer(c, server)
	if leader2.shouldStep(ctx, &live) {
		t.Fatalf("a restarted leader re-entered the stalled prompt from the kept due timer (nextWake=%v)", live.Status.NextWake)
	}
	timeNow = func() time.Time { return now.Add(stalledPromptBackoff + time.Second) }
	if !leader2.shouldStep(ctx, &live) {
		t.Fatal("the kept due timer was never retried after the backoff expired")
	}
}
