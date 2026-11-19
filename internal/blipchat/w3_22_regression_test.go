package blipchat

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A prompt over budget must keep the newest turns (the actionable ones) and
// report exactly how many older turns it left out. ConsumedSeq must never
// advance past the last turn the prompt actually rendered.
func TestBoardPromptTruncatesOldestTurnsNotNewest(t *testing.T) {
	const count = 30
	fresh := metav1.NewTime(timeNow())
	objs := []client.Object{testThread()}
	for i := 1; i <= count; i++ {
		turn := testTurn(fmt.Sprintf("turn-%02d", i), "proj")
		turn.Status.Seq = int64(i)
		turn.Status.AcceptedTime = &fresh
		turn.Spec.Wake = v1.WakeNone
		turn.Spec.Text = fmt.Sprintf("TURN%02d-MARKER %s", i, strings.Repeat("x", 1900))
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
	if err := s.step(ctx, objs[0].(*v1.BlipThread)); err != nil {
		t.Fatal(err)
	}
	var updated v1.BlipThread
	if err := c.Get(ctx, client.ObjectKeyFromObject(objs[0]), &updated); err != nil {
		t.Fatal(err)
	}
	if len(*requests) == 0 {
		t.Fatal("no LLM request recorded")
	}
	prompt := requestPrompt(t, (*requests)[0])

	if !strings.Contains(prompt, "TURN30-MARKER") {
		t.Errorf("prompt omitted the newest turn:\n%s", prompt)
	}
	shown, highest := 0, int64(0)
	for i := 1; i <= count; i++ {
		if strings.Contains(prompt, fmt.Sprintf("TURN%02d-MARKER", i)) {
			shown++
			highest = int64(i)
		}
	}
	if shown == count {
		t.Fatalf("test did not exceed the prompt budget: all %d turns fit", count)
	}
	notice := regexp.MustCompile(`\((\d+) older turns omitted\)`).FindStringSubmatch(prompt)
	if notice == nil {
		t.Fatalf("prompt kept %d/%d turns without an accurate omission notice:\n%s", shown, count, prompt)
	}
	omitted, err := strconv.Atoi(notice[1])
	if err != nil {
		t.Fatal(err)
	}
	if want := count - shown; omitted != want {
		t.Errorf("omission notice says %d older turns omitted, want %d:\n%s", omitted, want, prompt)
	}
	if updated.Status.ConsumedSeq != highest {
		t.Errorf("consumedSeq = %d, want the highest rendered seq %d", updated.Status.ConsumedSeq, highest)
	}
	if updated.Status.ConsumedSeq > int64(count) {
		t.Errorf("consumedSeq = %d passed the newest pending turn %d", updated.Status.ConsumedSeq, count)
	}

	// The newest pending turn must still be able to step after the truncated
	// step consumed the rendered suffix.
	freshPtr := metav1.NewTime(timeNow())
	next := testTurn("turn-next", "proj")
	next.Status.Seq = count + 1
	next.Status.AcceptedTime = &freshPtr
	next.Spec.Wake = v1.WakeNone
	next.Spec.Text = "TURN31-MARKER"
	if err := c.Create(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := s.step(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(objs[0]), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ConsumedSeq != count+1 {
		t.Errorf("second step consumedSeq = %d, want %d", updated.Status.ConsumedSeq, count+1)
	}
	last := requestPrompt(t, (*requests)[len(*requests)-1])
	if !strings.Contains(last, "TURN31-MARKER") {
		t.Errorf("second step prompt omitted the newest turn:\n%s", last)
	}
}

// requestPrompt returns the user message content from a recorded request.
func requestPrompt(t *testing.T, request map[string]any) string {
	t.Helper()
	messages, ok := request["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("request messages = %#v", request["messages"])
	}
	user, ok := messages[1].(map[string]any)
	if !ok {
		t.Fatalf("user message = %#v", messages[1])
	}
	content, _ := user["content"].(string)
	return content
}
