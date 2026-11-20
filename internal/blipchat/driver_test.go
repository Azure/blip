// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestDriverAppliesMessageTemplate(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-test",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationTitle:   "Worker",
				AnnotationProfile: "reviewer",
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	profiles := Profiles{"reviewer": {
		Description:     "reviews changes",
		MessageTemplate: "session={{.Session}} ns={{.Namespace}} profile={{.Profile}} title={{.Title}} description={{.Description}} base={{.Base}} parent={{.Parent}} root={{.Root}} depth={{.Depth}} created={{.Created}} text={{.Text}}",
	}}
	profile := profiles.get("reviewer", "default")
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-test",
		ProfileName: "reviewer",
		Profile:     profile,
		Base:        "base-state",
		Parent:      "chat-parent",
		Root:        "chat-root",
		Depth:       2,
		Created:     "2026-01-02T03:04:05Z",
		Title:       "Worker",
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("hello"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "prompt", func() bool { return len(fw.promptIDs()) >= 1 })
	text := lastPromptText(t, fw)
	for _, want := range []string{
		"session=chat-test",
		"ns=team",
		"profile=reviewer",
		"title=Worker",
		"description=reviews changes",
		"base=base-state",
		"parent=chat-parent",
		"root=chat-root",
		"depth=2",
		"created=2026-01-02T03:04:05Z",
		"text=hello",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("prompt %q does not contain %q", text, want)
		}
	}
	d.mu.Lock()
	transcript := ""
	for _, raw := range d.transcript {
		transcript += string(raw)
	}
	d.mu.Unlock()
	if !strings.Contains(transcript, `"text":"hello"`) || strings.Contains(transcript, "session=chat-test") {
		t.Fatalf("transcript = %s, want the original message", transcript)
	}
}

func TestDriverRejectsRenderedMessageTooLong(t *testing.T) {
	fc := newFakeCluster()
	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:   fc,
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   profile,
	})
	defer d.Close()

	err := d.Submit(strings.Repeat("x", maxPromptBytes+1))
	if !errors.Is(err, errMessageTooLong) {
		t.Fatalf("submit error = %v, want %v", err, errMessageTooLong)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) != 0 || d.submitted != 0 {
		t.Fatalf("queue = %d, submitted = %d", len(d.queue), d.submitted)
	}
}

func TestDriverTranscriptTruncationFlag(t *testing.T) {
	d := newDriver(driverOptions{
		Cluster:   newFakeCluster(),
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
	})
	defer d.Close()
	for i := 0; i <= maxTranscriptMessages; i++ {
		d.acpMessage(json.RawMessage(`{"i":1}`))
	}
	if !d.TranscriptTruncated() {
		t.Fatal("transcript trim did not set the truncation flag")
	}
	transcript, _, _ := d.Snapshot()
	if len(transcript) != maxTranscriptMessages {
		t.Fatalf("transcript has %d records, want %d", len(transcript), maxTranscriptMessages)
	}
}

func TestDriverRejectsWhenQueueIsFull(t *testing.T) {
	fc := newFakeCluster()
	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:   fc,
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   profile,
	})
	defer d.Close()

	for i := 0; i < maxQueue; i++ {
		if err := d.Submit("hello"); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	if err := d.Submit("hello"); !errors.Is(err, errSessionBusy) {
		t.Fatalf("submit error = %v, want %v", err, errSessionBusy)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) != maxQueue || d.submitted != maxQueue {
		t.Fatalf("queue = %d, submitted = %d", len(d.queue), d.submitted)
	}
}

func TestDriverStopAcceptedWhenQueueIsFull(t *testing.T) {
	fc := newFakeCluster()
	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:   fc,
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   profile,
	})
	defer d.Close()

	for i := 0; i < maxQueue; i++ {
		if err := d.Submit("hello"); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	d.mu.Lock()
	full := len(d.queue)
	d.mu.Unlock()
	if full != maxQueue {
		t.Fatalf("queue = %d, want %d", full, maxQueue)
	}
	// Prompt notifications must not consume the slots needed to stop a busy
	// chat. At the queue limit, Stop and Cancel still have to be accepted.
	if !d.Stop() {
		t.Fatal("Stop returned false with a full prompt queue")
	}
}

func lastPromptText(t *testing.T, fw *fakeWire) string {
	t.Helper()
	var text string
	for _, m := range fw.messages() {
		if m.method != "session/prompt" {
			continue
		}
		var msg struct {
			Params struct {
				Prompt []struct {
					Text string `json:"text"`
				} `json:"prompt"`
			} `json:"params"`
		}
		if err := json.Unmarshal(m.raw, &msg); err != nil {
			t.Fatal(err)
		}
		if len(msg.Params.Prompt) > 0 {
			text = msg.Params.Prompt[0].Text
		}
	}
	return text
}

func TestDriverRestartsGenerationOnNotRunning(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-test",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationTitle:   "Test",
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	fw.failFirst = true
	defer fw.closeLog()

	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-test",
		Profile:     profile,
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("hello"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "two prompt attempts and two generations", func() bool {
		return len(fw.promptIDs()) >= 2 && len(fc.blipNames()) == 2
	})
	names := fc.blipNames()
	if names[0] != "chat-test-g1" || names[1] != "chat-test-g2" {
		t.Fatalf("generations = %v", names)
	}
	ids := fw.promptIDs()
	fw.emitRPC(ids[len(ids)-1], map[string]any{"stopReason": "end_turn"})
	waitFor(t, "stdin eof", func() bool {
		for _, m := range fw.messages() {
			if m.eof {
				return true
			}
		}
		return false
	})

	var methods []string
	for _, m := range fw.messages() {
		if m.method != "" {
			methods = append(methods, m.method)
		}
	}
	joined := strings.Join(methods, ",")
	for _, want := range []string{"initialize", "session/new", "session/load"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("methods %q do not contain %q", joined, want)
		}
	}
}

func TestDriverWaitRunningFailsFastWhenBlipDisappears(t *testing.T) {
	fc := newFakeCluster()
	d := newDriver(driverOptions{
		Cluster:   fc,
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-gone",
		Profile:   Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
	})
	defer d.Close()

	started := time.Now()
	_, err := d.waitRunning(context.Background(), "chat-gone-g1")
	if err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("waitRunning error = %v, want disappeared", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("waitRunning took %v after the blip disappeared", elapsed)
	}
}

func TestDriverRecoversWhenInflightBlipFails(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-watch",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-watch",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitFor(t, "first prompt in flight", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.inflight
	})

	fc.mu.Lock()
	fc.blips[key("team", "chat-watch-g1")].Status = v1.BlipStatus{Phase: v1.BlipFailed, Message: "VM disappeared"}
	fc.mu.Unlock()

	d.watchRunning()
	waitFor(t, "turn closed after failed blip", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.inflight && !d.initialized && d.ended && d.lastStatus.Phase == "Failed"
	})

	// The failure must not strand the queue: a new message starts a new
	// generation instead of waiting forever for the dead agent.
	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	// The fake cluster reports a new generation Running as soon as it is
	// created, before the ACP prompt is sent on the recovered agent. Wait for
	// the prompt itself, then confirm the generation is Running.
	waitFor(t, "second prompt sent", func() bool {
		return strings.Contains(lastPromptText(t, fw), "second")
	})
	b, err := fc.GetBlip(ctx, "team", "chat-watch-g2")
	if err != nil || b.Status.Phase != v1.BlipRunning {
		t.Fatalf("second generation: blip=%v err=%v", b, err)
	}
}

func TestDriverStopDuringStartIsImmediate(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	fc.pendingBlips = true
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-start",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-start",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitFor(t, "pending first generation", func() bool {
		b, err := fc.GetBlip(ctx, "team", "chat-start-g1")
		return err == nil && b.Status.Phase == v1.BlipPending
	})
	stopped := time.Now()
	if !d.Stop() {
		t.Fatal("stop was not accepted")
	}
	waitFor(t, "start canceled and turn closed", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.inflight && d.lastStatus.Phase == "Stopped" && len(d.queue) == 0
	})
	if elapsed := time.Since(stopped); elapsed > 3*time.Second {
		t.Fatalf("stop during start took %s, want immediate", elapsed)
	}
	// The canceled start must not leave a second generation behind.
	time.Sleep(300 * time.Millisecond)
	if names := fc.blipNames(); len(names) != 1 {
		t.Fatalf("generations after canceled start = %v, want one", names)
	}

	fc.pendingBlips = false
	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitFor(t, "second generation after stop", func() bool {
		b, err := fc.GetBlip(ctx, "team", "chat-start-g2")
		return err == nil && b.Status.Phase == v1.BlipRunning
	})
	waitFor(t, "second prompt", func() bool {
		return strings.Contains(lastPromptText(t, fw), "second")
	})
}

func TestDriverRecoversWhenInflightBlipIsSaving(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-saving",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-saving",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "turn in flight", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.inflight
	})

	fc.mu.Lock()
	fc.blips[key("team", "chat-saving-g1")].Status = v1.BlipStatus{
		Phase: v1.BlipSaving, Reason: "PodLost", Message: "the VM exited without an exit status",
	}
	fc.mu.Unlock()

	d.watchRunning()
	waitFor(t, "turn closed after PodLost", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.inflight && d.ended && d.lastStatus.Phase == "Failed" &&
			strings.Contains(d.lastStatus.Detail, "VM exited")
	})
}

func TestDriverStopsRetryWhenChatIsDeleted(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-deleted",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-deleted",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.retryDelay = 50 * time.Millisecond
	fc.createBlipErr = errors.New("state not found")
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("hello"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "first start failed", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.createBlipAttempt >= 1
	})

	fc.mu.Lock()
	delete(fc.states, key("team", "chat-deleted"))
	fc.mu.Unlock()

	waitFor(t, "retry stopped for deleted chat", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.lastStatus.Phase == "Stopped" && d.lastStatus.Detail == "chat removed"
	})
	time.Sleep(200 * time.Millisecond)
	fc.mu.Lock()
	attempts := fc.createBlipAttempt
	fc.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("start attempts after deletion = %d, want 1", attempts)
	}
}

func TestDriverMarkEndedClearsInFlightPending(t *testing.T) {
	store := &memPendingStore{}
	d := newDriver(driverOptions{
		Cluster:   newFakeCluster(),
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		Pending:   store,
	})
	defer d.Close()
	d.mu.Lock()
	d.current = &queuedPrompt{id: "p1", text: "hello"}
	d.pending = map[string]queuedPrompt{"p1": *d.current}
	d.inflight = true
	d.mu.Unlock()
	d.markEnded()
	d.promptDone(nil)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.saved) != 0 {
		t.Fatalf("pending store after turn end = %+v, want empty", store.saved)
	}
}

func TestDriverStopKeepsPromptAcceptedAfterStopRequest(t *testing.T) {
	d := newDriver(driverOptions{
		Cluster:   newFakeCluster(),
		Wire:      newFakeWire(),
		Hub:       NewHub(),
		Log:       testLogger(),
		Namespace: "team",
		State:     "chat-test",
		Profile:   Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
	})
	defer d.Close()
	now := time.Now()
	d.mu.Lock()
	d.queue = []queuedPrompt{
		{id: "before", text: "before", acceptedAt: now.Add(-time.Second)},
		{id: "after", text: "after", acceptedAt: now.Add(time.Second)},
	}
	d.pending = map[string]queuedPrompt{}
	for _, q := range d.queue {
		d.pending[q.id] = q
	}
	d.submitted = len(d.queue)
	dropped := d.dropQueuedOnStopLocked(now)
	d.mu.Unlock()
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) != 1 || d.queue[0].id != "after" {
		t.Fatalf("queue after stop = %+v, want only after", d.queue)
	}
	if _, ok := d.pending["before"]; ok {
		t.Fatal("pre-stop prompt stayed pending")
	}
	if _, ok := d.pending["after"]; !ok {
		t.Fatal("post-stop prompt was removed")
	}
	if d.submitted != 1 {
		t.Fatalf("submitted = %d, want 1", d.submitted)
	}
}

func TestDriverStopClosesTurnAndRunsQueuedPrompt(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-stop",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()
	store := &memPendingStore{}

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-stop",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
		Pending:     store,
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitFor(t, "first prompt in flight", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.inflight && len(d.queue) == 0
	})

	if !d.Stop() {
		t.Fatal("stop was not accepted")
	}
	waitFor(t, "blip stop requested", func() bool {
		b, err := fc.GetBlip(ctx, "team", "chat-stop-g1")
		return err == nil && b.Spec.Stop
	})
	waitFor(t, "turn closed after stop", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.inflight && !d.initialized && d.ended
	})
	waitFor(t, "pending store cleared after stop", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.saved) == 0
	})

	// A prompt sent after stop must start a new generation instead of
	// queueing behind the killed turn.
	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitFor(t, "second generation prompt", func() bool {
		names := fc.blipNames()
		return len(names) == 2 && names[1] == "chat-stop-g2" && len(fw.promptIDs()) == 2
	})
	if text := lastPromptText(t, fw); !strings.Contains(text, "second") {
		t.Fatalf("second prompt = %q", text)
	}
}

func TestDriverBacksOffAfterStartFailure(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	fc.createBlipErr = errors.New("no eligible node")
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-retry",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-retry",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.retryDelay = 250 * time.Millisecond
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("one"); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit("two"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "start failure", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.lastStatus.Phase == "Error"
	})
	fc.mu.Lock()
	created := fc.createBlipAttempt
	fc.mu.Unlock()
	if created != 1 {
		t.Fatalf("created %d blips for a burst of 2 prompts, want 1 before retry", created)
	}

	// A queued prompt must not immediately allocate another generation.
	time.Sleep(50 * time.Millisecond)
	fc.mu.Lock()
	created = fc.createBlipAttempt
	fc.mu.Unlock()
	if created != 1 {
		t.Fatalf("created %d blips during backoff, want 1", created)
	}

	waitFor(t, "retry attempt", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.createBlipAttempt == 2
	})

	d.mu.Lock()
	if len(d.transcript) == 0 {
		d.mu.Unlock()
		t.Fatal("user turn was not recorded")
	}
	transcript := string(d.transcript[0])
	d.mu.Unlock()
	if !strings.Contains(transcript, `"text":"one"`) {
		t.Fatalf("first user turn missing from transcript: %s", transcript)
	}
	if strings.Count(transcript, `"text":"one"`) != 1 {
		t.Fatalf("retry duplicated the user turn: %s", transcript)
	}
}

func TestDriverSavesAgentSessionTitle(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "chat-title",
			Namespace:   "team",
			Labels:      map[string]string{LabelSession: "true"},
			Annotations: map[string]string{AnnotationProfile: DefaultProfileName},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-title",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	titleUpdate := func(title any) map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"method":  "session/update",
			"params": map[string]any{
				"sessionId": "s1",
				"update":    map[string]any{"sessionUpdate": "session_info_update", "title": title},
			},
		}
	}

	fw.emitACP(titleUpdate("Fix the flaky test"))
	waitFor(t, "title annotation", func() bool {
		st, err := fc.GetSession(ctx, "team", "chat-title")
		return err == nil && st.Annotations[AnnotationTitle] == "Fix the flaky test"
	})

	fw.emitACP(titleUpdate(nil))
	waitFor(t, "cleared title annotation", func() bool {
		st, err := fc.GetSession(ctx, "team", "chat-title")
		return err == nil && st.Annotations[AnnotationTitle] == ""
	})
}

func TestDriverCopiesOwnerLabelToBlip(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-owner",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: "chat-owner"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationRoot:    "chat-owner",
				AnnotationDepth:   "0",
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        newFakeWire(),
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-owner",
		ProfileName: DefaultProfileName,
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	defer d.Close()

	if _, err := d.ensureRunning(ctx, false); err != nil {
		t.Fatal(err)
	}
	blips, err := fc.ListStateBlips(ctx, "team", "chat-owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(blips) != 1 {
		t.Fatalf("blips = %d, want 1", len(blips))
	}
	b := blips[0]
	if b.Labels[v1.LabelOwner] != "chat-owner" {
		t.Fatalf("owner label = %q, labels = %v", b.Labels[v1.LabelOwner], b.Labels)
	}
	if b.Labels[LabelSession] != "chat-owner" {
		t.Fatalf("session label = %q", b.Labels[LabelSession])
	}
	if b.Annotations[AnnotationGeneration] != "1" {
		t.Fatalf("generation = %q", b.Annotations[AnnotationGeneration])
	}
}

type memPendingStore struct {
	mu      sync.Mutex
	session string
	saved   []PendingPrompt
}

func (m *memPendingStore) LoadPending(_ context.Context, _, session string) ([]PendingPrompt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session != m.session {
		return nil, nil
	}
	return append([]PendingPrompt(nil), m.saved...), nil
}

func (m *memPendingStore) SavePending(_ context.Context, _, session string, prompts []PendingPrompt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = session
	m.saved = append([]PendingPrompt(nil), prompts...)
	return nil
}

func TestDriverPersistsAndResumesPendingPrompt(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-pending",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	store := &memPendingStore{}
	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster: fc, Wire: newFakeWire(), Hub: NewHub(), Log: testLogger(),
		Namespace: "team", State: "chat-pending", Profile: profile,
		Pending: store,
	})
	if err := d.SubmitAs("alice", "survive the restart"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	store.mu.Lock()
	saved := append([]PendingPrompt(nil), store.saved...)
	store.mu.Unlock()
	if len(saved) != 1 || saved[0].Original != "survive the restart" || saved[0].ID == "" {
		t.Fatalf("saved = %+v", saved)
	}
	d.Close()

	fw := newFakeWire()
	fw.autoRespond = true
	defer fw.closeLog()
	restarted := newDriver(driverOptions{
		Cluster: fc, Wire: fw, Hub: NewHub(), Log: testLogger(),
		Namespace: "team", State: "chat-pending", Profile: profile,
		Pending: store, PendingPrompts: saved,
	})
	restarted.start(ctx)
	defer restarted.Close()
	restarted.resume()
	waitFor(t, "resumed prompt", func() bool { return len(fw.promptIDs()) >= 1 })
	if got := lastPromptText(t, fw); !strings.Contains(got, "survive the restart") {
		t.Fatalf("prompt = %q", got)
	}
	waitFor(t, "pending cleared", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.saved) == 0
	})
}

func TestDriverCancelWithQueuedPromptStopsOldGeneration(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-cancel-queue",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-cancel-queue",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitFor(t, "first prompt in flight", func() bool {
		return len(fw.promptIDs()) == 1
	})
	firstID := fw.promptIDs()[0]

	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	if !d.Cancel() {
		t.Fatal("cancel was not accepted")
	}
	waitFor(t, "cancel sent to agent", func() bool {
		for _, m := range fw.messages() {
			if m.method == "session/cancel" {
				return true
			}
		}
		return false
	})

	// The agent completes the cancelled prompt while a follow-up is queued.
	// That turn must stop the old generation, or the new generation waits
	// forever on the state lease.
	fw.emitRPC(firstID, map[string]any{"stopReason": "cancelled"})

	waitFor(t, "cancelled generation stopped", func() bool {
		b, err := fc.GetBlip(ctx, "team", "chat-cancel-queue-g1")
		return err == nil && b.Spec.Stop
	})
	waitFor(t, "queued prompt on a fresh generation", func() bool {
		names := fc.blipNames()
		return len(names) == 2 && names[1] == "chat-cancel-queue-g2" && len(fw.promptIDs()) == 2
	})
	if got := lastPromptText(t, fw); !strings.Contains(got, "second") {
		t.Fatalf("second prompt = %q", got)
	}
}

func TestDriverBoundsStartRetries(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	fc.createBlipErr = errors.New("agent command not found")
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-bounded-retry",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-bounded-retry",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.retryDelay = 20 * time.Millisecond
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("hello"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// A second prompt accepted behind the failing one must not survive the
	// permanent failure as an orphaned queue entry.
	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitFor(t, "bounded retry gave up", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.lastStatus.Phase == "Error" &&
			strings.Contains(d.lastStatus.Detail, "after 4 attempts")
	})
	fc.mu.Lock()
	attempts := fc.createBlipAttempt
	fc.mu.Unlock()
	if attempts != maxStartAttempts {
		t.Fatalf("start attempts = %d, want %d", attempts, maxStartAttempts)
	}
	time.Sleep(150 * time.Millisecond)
	fc.mu.Lock()
	after := fc.createBlipAttempt
	fc.mu.Unlock()
	if after != attempts {
		t.Fatalf("start attempts continued after giving up: %d -> %d", attempts, after)
	}
	d.mu.Lock()
	queued := len(d.queue)
	submitted := d.submitted
	d.mu.Unlock()
	if queued != 0 || submitted != 0 || d.Busy() {
		t.Fatalf("queue=%d submitted=%d busy=%v after giving up", queued, submitted, d.Busy())
	}
	// The failed agent exits right after the terminal error. Its end record
	// must not replace the actionable start error with a generic stopped state.
	d.mu.Lock()
	gen := d.generation
	d.mu.Unlock()
	d.handleRecord(streamLogRecord{Offset: 1 << 20, Gen: gen, Type: recordEnd})
	d.mu.Lock()
	phase, detail := d.lastStatus.Phase, d.lastStatus.Detail
	d.mu.Unlock()
	if phase != "Error" || !strings.Contains(detail, "after 4 attempts") {
		t.Fatalf("status after end record = %q %q, want terminal Error", phase, detail)
	}
}

func TestDriverSnapshotIdleAfterCompletedTurn(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-snapshot-idle",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	fw.mu.Lock()
	fw.autoRespond = true
	fw.mu.Unlock()
	defer fw.closeLog()
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       state.Name,
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()
	if err := d.Submit("hello"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "snapshot idle", func() bool {
		_, _, idle := d.Snapshot()
		return idle
	})
	transcript, offset, idle := d.Snapshot()
	if !idle || len(transcript) == 0 || offset == 0 {
		t.Fatalf("snapshot idle=%v transcript=%d offset=%d", idle, len(transcript), offset)
	}
}

func TestDriverStopKeepsPromptAcceptedDuringStop(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-stop-race",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-stop-race",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("first"); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitFor(t, "first prompt in flight", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.inflight && len(d.queue) == 0
	})

	started := make(chan struct{})
	gate := make(chan struct{})
	fc.mu.Lock()
	fc.stopBlipStarted = started
	fc.stopBlipGate = gate
	fc.mu.Unlock()

	if !d.Stop() {
		t.Fatal("stop was not accepted")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not reach the cluster")
	}

	// This prompt is accepted while the stop is still winding down. It returned
	// success to the caller, so it must survive the queue drop and run on g2.
	if err := d.Submit("second"); err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitFor(t, "second prompt queued for after stop", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.queue) == 1 && d.queue[0].keepOnStop
	})
	close(gate)
	waitFor(t, "second generation prompt", func() bool {
		names := fc.blipNames()
		return len(names) == 2 && names[1] == "chat-stop-race-g2" && len(fw.promptIDs()) == 2
	})
	if text := lastPromptText(t, fw); !strings.Contains(text, "second") {
		t.Fatalf("second prompt = %q", text)
	}
	d.mu.Lock()
	queue, submitted := len(d.queue), d.submitted
	d.mu.Unlock()
	if queue != 0 {
		t.Fatalf("queue after stop = %d, want 0", queue)
	}
	if submitted != 2 {
		t.Fatalf("submitted after stop = %d, want 2", submitted)
	}
}

func TestDriverWatchStopsOrphanedRunningBlip(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-orphan",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	if err := fc.CreateBlip(ctx, "team", &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-orphan-g1",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "chat-orphan"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-orphan",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})

	// This is the state left behind when blipchat restarts mid-turn: the old
	// blip is Running but no prompt is in flight and no queued work exists.
	d.watchRunning()

	b, err := fc.GetBlip(ctx, "team", "chat-orphan-g1")
	if err != nil {
		t.Fatal(err)
	}
	if !b.Spec.Stop || b.Status.Phase != v1.BlipSucceeded {
		t.Fatalf("orphaned blip not stopped: spec.stop=%v phase=%s", b.Spec.Stop, b.Status.Phase)
	}
	d.mu.Lock()
	phase, detail, ended := d.lastStatus.Phase, d.lastStatus.Detail, d.ended
	d.mu.Unlock()
	if phase != "Stopped" || detail != "agent interrupted" || !ended {
		t.Fatalf("status after orphan stop = %q/%q ended=%v", phase, detail, ended)
	}
}

func TestDriverWatchStopsOlderRunningGeneration(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "chat-orphan2",
			Namespace:   "team",
			Labels:      map[string]string{LabelSession: "true"},
			Annotations: map[string]string{AnnotationProfile: DefaultProfileName},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"chat-orphan2-g1", "chat-orphan2-g2"} {
		if err := fc.CreateBlip(ctx, "team", &v1.Blip{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "team",
				Labels:    map[string]string{LabelSession: "chat-orphan2"},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	fw := newFakeWire()
	defer fw.closeLog()
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-orphan2",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})

	// Simulate a newer generation that already finished while an older one
	// from a timed-out start is still Running. If only the newest blip is
	// inspected, the older VM keeps the chat running forever.
	fc.mu.Lock()
	fc.blips[key("team", "chat-orphan2-g2")].Status.Phase = v1.BlipSucceeded
	fc.mu.Unlock()
	d.watchRunning()

	g1, err := fc.GetBlip(ctx, "team", "chat-orphan2-g1")
	if err != nil {
		t.Fatal(err)
	}
	if !g1.Spec.Stop || g1.Status.Phase != v1.BlipSucceeded {
		t.Fatalf("older running blip not stopped: spec.stop=%v phase=%s", g1.Spec.Stop, g1.Status.Phase)
	}
	d.mu.Lock()
	phase, ended := d.lastStatus.Phase, d.ended
	d.mu.Unlock()
	if phase != "Stopped" || !ended {
		t.Fatalf("status after older generation stop = %q ended=%v", phase, ended)
	}
}

func TestDriverStopsFailedGenerationBeforeRetry(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-init-timeout",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	fw.failInitialize = errors.New("initialize: timed out")
	defer fw.closeLog()

	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-init-timeout",
		Profile:     Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
		AutoApprove: "always",
	})
	d.retryDelay = 20 * time.Millisecond
	d.start(ctx)
	defer d.Close()

	if err := d.Submit("one"); err != nil {
		t.Fatal(err)
	}
	// The first generation is created Running, then initialize fails. It must
	// be stopped before the driver retries, otherwise every retry creates a
	// Blip that stays Pending on StateBusy behind the old lease.
	waitFor(t, "first generation stopped", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		if len(fc.blips) == 0 {
			return false
		}
		b := fc.blips[key("team", "chat-init-timeout-g1")]
		return b != nil && (b.Status.Phase == v1.BlipSucceeded || b.Spec.Stop)
	})
	waitFor(t, "bounded retry gave up", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.lastStatus.Phase == "Error" && strings.Contains(d.lastStatus.Detail, "after 4 attempts")
	})
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for name, b := range fc.blips {
		if b.Status.Phase == v1.BlipRunning || b.Status.Phase == v1.BlipPending {
			t.Fatalf("blip %s left %s after terminal start failure", name, b.Status.Phase)
		}
	}
}

func TestDriverRestoresPendingPromptsVisibleAndOrdered(t *testing.T) {
	d := newDriver(driverOptions{
		Log:       testLogger(),
		Hub:       NewHub(),
		Namespace: "team",
		State:     "chat-pending",
		PendingPrompts: []PendingPrompt{
			{ID: "p1", Text: "rendered one", Original: "one", User: "alice"},
			{ID: "p2", Text: "rendered two", Original: "two", User: "alice"},
		},
	})
	defer d.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) != 2 || d.queue[0].id != "p1" || d.queue[1].id != "p2" {
		t.Fatalf("restored queue order = %+v", d.queue)
	}
	if !d.queue[0].recorded || !d.queue[1].recorded {
		t.Fatalf("restored prompts would be recorded twice: %+v", d.queue)
	}
	ids := transcriptPromptIDs(d.transcript)
	if !ids["p1"] || !ids["p2"] {
		t.Fatalf("restored pending prompts missing from transcript: %v", ids)
	}
	var texts []string
	for _, raw := range d.transcript {
		var msg struct {
			Params struct {
				Update struct {
					Kind    string `json:"sessionUpdate"`
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"update"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &msg) == nil && msg.Params.Update.Kind == "user_message_chunk" && len(msg.Params.Update.Content) > 0 {
			texts = append(texts, msg.Params.Update.Content[0].Text)
		}
	}
	if strings.Join(texts, ",") != "one,two" {
		t.Fatalf("restored transcript = %v, want one,two", texts)
	}
	if got := d.pendingPromptsLocked(); len(got) != 2 || got[0].ID != "p1" || got[1].ID != "p2" {
		t.Fatalf("pending persistence order = %+v", got)
	}
}

func TestDriverDoesNotDuplicateReplayedPendingPrompt(t *testing.T) {
	user := json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"user_message_chunk","promptID":"p1","content":[{"type":"text","text":"one"}]}}}`)
	d := newDriver(driverOptions{
		Log:        testLogger(),
		Hub:        NewHub(),
		Namespace:  "team",
		State:      "chat-pending",
		Transcript: []json.RawMessage{user},
		PendingPrompts: []PendingPrompt{
			{ID: "p1", Text: "one", Original: "one"},
		},
	})
	defer d.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	if got := len(d.transcript); got != 1 {
		t.Fatalf("replayed transcript has %d rows, want 1 (no duplicate)", got)
	}
}

func TestDriverPromptRejectionStopsAndRequeues(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-reject",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	defer fw.closeLog()
	d := newDriver(driverOptions{
		Cluster: fc, Wire: fw, Hub: NewHub(), Log: testLogger(),
		Namespace: "team", State: "chat-reject",
		Profile: Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default"),
	})
	d.retryDelay = 30 * time.Millisecond
	d.start(ctx)
	defer d.Close()
	if err := d.Submit("one"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first prompt sent", func() bool { return len(fw.promptIDs()) >= 1 })
	// The agent accepted the request at the transport layer, then rejected it
	// asynchronously. The prompt must be kept pending and retried on a fresh
	// generation after the old lease is released.
	d.promptDone(errors.New("session already has an active ACP prompt"))
	waitFor(t, "rejected generation stopped", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		b := fc.blips[key("team", "chat-reject-g1")]
		return b != nil && b.Status.Phase == v1.BlipSucceeded
	})
	d.mu.Lock()
	queueLen, pendingLen := len(d.queue), len(d.pending)
	d.mu.Unlock()
	if queueLen != 1 || pendingLen != 1 {
		t.Fatalf("queue=%d pending=%d, want both 1 after rejection", queueLen, pendingLen)
	}
	waitFor(t, "retry on fresh generation", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.blips[key("team", "chat-reject-g2")] != nil
	})
}

func TestDriverPendingStoreExcludesInFlightPrompt(t *testing.T) {
	d := newDriver(driverOptions{
		Log: testLogger(), Hub: NewHub(), Namespace: "team", State: "chat-pending",
	})
	defer d.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	q1 := queuedPrompt{id: "p1", text: "one", original: "one"}
	q2 := queuedPrompt{id: "p2", text: "two", original: "two"}
	d.current = &q1
	d.queue = []queuedPrompt{q1, q2}
	d.pending = map[string]queuedPrompt{"p1": q1, "p2": q2}
	got := d.pendingPromptsLocked()
	if len(got) != 1 || got[0].ID != "p2" {
		t.Fatalf("pending store = %+v, want only p2", got)
	}
}
