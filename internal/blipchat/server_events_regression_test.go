// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Kubernetes continues to update the lifecycle after the guest's last ring
// record. An already-connected event stream must publish those updates without
// requiring another guest record or a browser reload.
func TestServerEventsPublishSavingAndTerminalPhases(t *testing.T) {
	for _, terminal := range []string{v1.BlipSucceeded, v1.BlipFailed} {
		t.Run(terminal, func(t *testing.T) {
			g := newGateway(t, Options{})
			name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
			if err := g.cluster.CreateBlip(context.Background(), "team", &v1.Blip{
				ObjectMeta: metav1.ObjectMeta{
					Name: name + "-g1", Labels: map[string]string{LabelSession: name},
				},
			}); err != nil {
				t.Fatal(err)
			}

			events, readErr := openLifecycleEvents(t, g, name, 0)

			var last Status
			var cursor uint64
			waitPhase := func(phase string, running bool) bool {
				t.Helper()
				timer := time.NewTimer(2 * time.Second)
				defer timer.Stop()
				for {
					select {
					case ev, open := <-events:
						if !open {
							t.Errorf("SSE closed before phase %q: %v", phase, <-readErr)
							return false
						}
						if ev.Offset < cursor {
							t.Fatalf("SSE cursor moved backward: %d -> %d", cursor, ev.Offset)
						}
						cursor = ev.Offset
						if ev.Type == "status" && ev.Status != nil {
							last = *ev.Status
							if last.Phase == phase && last.Running == running {
								return true
							}
						}
					case <-timer.C:
						t.Errorf("SSE did not publish phase %q (running=%t); last status: phase=%q running=%t", phase, running, last.Phase, last.Running)
						return false
					}
				}
			}
			assertDetail := func(phase string) {
				t.Helper()
				resp := g.request(t, http.MethodGet, "/api/sessions/"+name, nil, "alice", nil)
				if resp.StatusCode != http.StatusOK {
					resp.Body.Close()
					t.Fatalf("detail: status %d", resp.StatusCode)
				}
				detail := decodeBody[sessionDetail](t, resp)
				if detail.Phase != phase || detail.Running {
					t.Fatalf("GET detail: phase=%q running=%t; want phase=%q running=false", detail.Phase, detail.Running, phase)
				}
				t.Logf("GET detail: phase=%q running=%t", detail.Phase, detail.Running)
			}

			if !waitPhase(v1.BlipRunning, true) {
				t.Fatal("SSE never observed the running generation")
			}
			g.cluster.setActive("team", name, v1.BlipSaving)
			g.wire.end(1)
			assertDetail(v1.BlipSaving)
			waitPhase(v1.BlipSaving, false)

			// Saving completes only in Kubernetes. Deliberately append no more
			// records: the guest has already exited.
			g.cluster.setActive("team", name, terminal)
			assertDetail(terminal)
			waitPhase(terminal, false)
		})
	}
}

func openLifecycleEvents(t *testing.T, g *testGateway, name string, after uint64) (<-chan Event, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.ts.URL+"/api/sessions/"+name+"/events?offset="+strconv.FormatUint(after, 10), nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", "alice")
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		stream.Body.Close()
	})
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("events: status %d", stream.StatusCode)
	}
	events := make(chan Event, 32)
	readErr := make(chan error, 1)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(stream.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var ev Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
				readErr <- err
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
		readErr <- scanner.Err()
	}()
	return events, readErr
}

func nextLifecycleEvent(t *testing.T, events <-chan Event, readErr <-chan error) Event {
	t.Helper()
	select {
	case ev, open := <-events:
		if !open {
			t.Fatalf("SSE closed: %v", <-readErr)
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE event")
		return Event{}
	}
}

func TestServerEventsLifecyclePreservesCursorQuestionAndDetail(t *testing.T) {
	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	blipName := name + "-g1"
	if err := g.cluster.CreateBlip(context.Background(), "team", &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: blipName, Labels: map[string]string{LabelSession: name}},
	}); err != nil {
		t.Fatal(err)
	}
	after := g.wire.note(noteRecord{Type: noteQuestion, ID: "q1", Text: "Proceed?"})
	unread := g.wire.appendRecord(1, recordErr, []byte("unread stderr"))
	events, readErr := openLifecycleEvents(t, g, name, after)

	// The initial snapshot knows the question before the cursor, but must not
	// advance that cursor to the end of the snapshot and skip unread transcript.
	initial := nextLifecycleEvent(t, events, readErr)
	if initial.Type != "status" || initial.Offset != after || initial.Status == nil ||
		initial.Status.Phase != v1.BlipRunning || !initial.Status.Running ||
		initial.Status.Question == nil || initial.Status.Question.ID != "q1" {
		t.Fatalf("initial lifecycle = %+v (status %+v)", initial, initial.Status)
	}
	transcript := nextLifecycleEvent(t, events, readErr)
	if transcript.Type != "acp" || transcript.Offset != unread || !strings.Contains(string(transcript.Message), "unread stderr") {
		t.Fatalf("unread transcript = %+v", transcript)
	}

	g.cluster.mu.Lock()
	b := g.cluster.blips[key("team", blipName)]
	b.Status.Phase = v1.BlipFailed
	b.Status.Message = "save failed"
	g.cluster.mu.Unlock()
	failed := nextLifecycleEvent(t, events, readErr)
	if failed.Type != "status" || failed.Offset != unread || failed.Status == nil ||
		failed.Status.Phase != v1.BlipFailed || failed.Status.Running || failed.Status.Detail != "save failed" ||
		failed.Status.Question == nil || failed.Status.Question.ID != "q1" {
		t.Fatalf("failed lifecycle = %+v (status %+v)", failed, failed.Status)
	}

	// Repeated reads allocate fresh Question values. Deduplication must compare
	// their contents, not pointers, while preserving the original ring cursor.
	select {
	case duplicate := <-events:
		t.Fatalf("unchanged lifecycle emitted another event: %+v", duplicate)
	case <-time.After(viewCacheTTL + 2*statusPoll):
	}

	g.cluster.mu.Lock()
	b.Status.Message = "save retry failed"
	g.cluster.mu.Unlock()
	updated := nextLifecycleEvent(t, events, readErr)
	if updated.Type != "status" || updated.Offset != unread || updated.Status == nil ||
		updated.Status.Detail != "save retry failed" || updated.Status.Question == nil {
		t.Fatalf("updated failure detail = %+v (status %+v)", updated, updated.Status)
	}

	answer := g.wire.note(noteRecord{Type: noteAnswer, QID: "q1", Text: "yes", Gen: 1})
	for {
		ev := nextLifecycleEvent(t, events, readErr)
		if ev.Offset != answer {
			t.Fatalf("answer cursor = %d, want %d", ev.Offset, answer)
		}
		if ev.Type == "status" {
			if ev.Status == nil || ev.Status.Question != nil || ev.Status.Phase != v1.BlipFailed || ev.Status.Detail != "save retry failed" {
				t.Fatalf("answer lifecycle = %+v", ev.Status)
			}
			break
		}
	}
}

func TestServerEventsReconcileEndedGeneration(t *testing.T) {
	for _, generation := range []int{1, 2} {
		t.Run(strconv.Itoa(generation), func(t *testing.T) {
			g := newGateway(t, Options{})
			name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
			// Simulate controller status ahead of the next guest attachment:
			// the ring ends generation 1, but Kubernetes may already run 2.
			g.cluster.mu.Lock()
			blipName := name + "-g" + strconv.Itoa(generation)
			g.cluster.blips[key("team", blipName)] = &v1.Blip{
				ObjectMeta: metav1.ObjectMeta{Name: blipName, Namespace: "team", Labels: map[string]string{LabelSession: name}},
				Status:     v1.BlipStatus{Phase: v1.BlipRunning},
			}
			g.cluster.mu.Unlock()
			g.wire.start(1)
			g.wire.end(1)
			events, readErr := openLifecycleEvents(t, g, name, 0)
			ev := nextLifecycleEvent(t, events, readErr)
			wantPhase, wantRunning := v1.BlipSaving, false
			if generation == 2 {
				wantPhase, wantRunning = v1.BlipRunning, true
			}
			if ev.Type != "status" || ev.Status == nil || ev.Status.Phase != wantPhase || ev.Status.Running != wantRunning {
				t.Fatalf("generation %d lifecycle = %+v, want phase=%q running=%t", generation, ev.Status, wantPhase, wantRunning)
			}
		})
	}
}

type unavailableEventLog struct{ Wire }

func (w unavailableEventLog) OpenLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return nil, errors.New("follow endpoint unavailable")
}

type eventPollingCluster struct {
	Cluster
	fail     atomic.Bool
	attempts chan struct{}
}

func (c *eventPollingCluster) ListStateBlips(ctx context.Context, ns, state string) ([]v1.Blip, error) {
	if c.fail.Load() {
		select {
		case c.attempts <- struct{}{}:
		default:
		}
		return nil, errors.New("temporary cluster failure")
	}
	return c.Cluster.ListStateBlips(ctx, ns, state)
}

func TestServerEventsPollWithoutLogAndRecoverClusterErrors(t *testing.T) {
	fc, fw := newFakeCluster(), newFakeWire()
	cluster := &eventPollingCluster{Cluster: fc, attempts: make(chan struct{}, 1)}
	s, err := New(Options{
		Namespace: "team", DefaultPool: "default", Profiles: Profiles{DefaultProfileName: {}},
		Cluster: cluster, Wire: unavailableEventLog{&runningWire{fakeWire: fw, cluster: fc}}, Log: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Do not Start: lifecycle publication must not depend on a local engine.
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		s.Close()
		fw.closeLog()
	})
	g := &testGateway{srv: s, cluster: fc, wire: fw, ts: ts}
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")
	if err := fc.CreateBlip(context.Background(), "team", &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-g1", Labels: map[string]string{LabelSession: name}},
	}); err != nil {
		t.Fatal(err)
	}
	events, readErr := openLifecycleEvents(t, g, name, 0)
	initial := nextLifecycleEvent(t, events, readErr)
	if initial.Status == nil || initial.Status.Phase != v1.BlipRunning {
		t.Fatalf("initial lifecycle = %+v", initial)
	}
	cluster.fail.Store(true)
	fc.setActive("team", name, v1.BlipSaving)
	select {
	case <-cluster.attempts:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle was not polled while log endpoint was unavailable")
	}
	cluster.fail.Store(false)
	for _, phase := range []string{v1.BlipSaving, v1.BlipSucceeded} {
		fc.setActive("team", name, phase)
		ev := nextLifecycleEvent(t, events, readErr)
		if ev.Offset != 0 || ev.Status == nil || ev.Status.Phase != phase || ev.Status.Running {
			t.Fatalf("lifecycle after cluster recovery = %+v (status %+v), want %q at cursor 0", ev, ev.Status, phase)
		}
	}
}
