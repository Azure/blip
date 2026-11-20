// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// staleAllocationCluster models two replicas that both list before either
// creates g1. The losing replica's next list sees the winner's active blip.
type staleAllocationCluster struct {
	Cluster
	firstList bool
}

func (c *staleAllocationCluster) ListStateBlips(ctx context.Context, ns, state string) ([]v1.Blip, error) {
	if c.firstList {
		c.firstList = false
		return nil, nil
	}
	return c.Cluster.ListStateBlips(ctx, ns, state)
}

func TestIssue1EnsureRunningCreateConflictReusesActiveGeneration(t *testing.T) {
	for _, phase := range []string{v1.BlipPending, v1.BlipRunning} {
		t.Run(string(phase), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newEngineFixture(t)
				f.addBlip(t, 1)
				f.cluster.setActive("default", f.name, string(phase))
				f.srv.cluster = &staleAllocationCluster{Cluster: f.cluster, firstList: true}
				started := make(chan struct{})
				if phase == v1.BlipPending {
					go func() {
						time.Sleep(time.Second)
						f.cluster.setActive("default", f.name, string(v1.BlipRunning))
						close(started)
					}()
				} else {
					close(started)
				}
				ctx := context.Background()
				st, err := f.cluster.GetSession(ctx, "default", f.name)
				if err != nil {
					t.Fatal(err)
				}
				profile, err := f.srv.profileFor(st)
				if err != nil {
					t.Fatal(err)
				}
				got, err := f.srv.ensureRunning(ctx, st, profile)
				<-started
				if err != nil {
					t.Fatalf("ensureRunning: %v", err)
				}
				if got.Name != f.name+"-g1" {
					t.Fatalf("ensureRunning returned %s; want the existing %s g1, not a phantom generation; blips=%v", got.Name, phase, f.cluster.blipNames())
				}
				if names := f.cluster.blipNames(); len(names) != 1 {
					t.Fatalf("allocation created an extra generation: %v", names)
				}
			})
		})
	}
}

// A start timeout alone must not make a late, still-active g1 invisible to the
// next allocation. This characterization distinguishes current behavior from
// the old driver-based smoke report without waiting two real minutes.
func TestIssue1EnsureRunningTimeoutReusesLateGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t)
		f.cluster.pendingBlips = true
		ctx := context.Background()
		st, err := f.cluster.GetSession(ctx, "default", f.name)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := f.srv.profileFor(st)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.srv.ensureRunning(ctx, st, profile)
		if err == nil || !strings.Contains(err.Error(), "timed out waiting for "+f.name+"-g1") {
			t.Fatalf("ensureRunning error = %v, want the actual start timeout", err)
		}
		t.Logf("first allocation: %v", err)
		f.cluster.setActive("default", f.name, string(v1.BlipRunning))
		got, err := f.srv.ensureRunning(ctx, st, profile)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != f.name+"-g1" || len(f.cluster.blipNames()) != 1 {
			t.Fatalf("late start returned %s, blips=%v; want only g1", got.Name, f.cluster.blipNames())
		}
		t.Logf("late g1 reused: %s; blips=%v", got.Name, f.cluster.blipNames())
		// Once that generation completes its only prompt, a caught-up engine
		// has no reason to create g2 just because startup previously timed out.
		f.wire.start(1)
		f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "hello"})
		f.wire.emitACP(1, map[string]any{"jsonrpc": "2.0", "id": "p-n1", "result": map[string]any{"stopReason": "end_turn"}})
		f.wire.end(1)
		f.cluster.setActive("default", f.name, string(v1.BlipSucceeded))
		e := &chatEngine{s: f.srv, name: f.name, view: f.srv.readView(ctx, st)}
		if err := e.converge(ctx); err != errEngineIdle {
			t.Fatalf("completed g1 converge = %v, want idle", err)
		}
		if len(f.cluster.blipNames()) != 1 {
			t.Fatalf("completed g1 spawned an extra generation: %v", f.cluster.blipNames())
		}
		t.Log("g1 succeeded with its prompt complete; caught-up engine exited idle without g2")
	})
}

func TestIssue1EngineStopBeforeSessionReady(t *testing.T) {
	for _, stage := range []string{"pending", "initialize", "session"} {
		t.Run(stage, func(t *testing.T) {
			f := newEngineFixture(t)
			f.startGeneration(t, 2)
			view := newChatView("")
			view.observe(streamLogRecord{Type: recordStart, Gen: 2, Offset: 1})
			view.observe(streamLogRecord{Type: recordNote, Gen: 2, Offset: 2, Data: mustJSON(noteRecord{Type: noteStop})})
			if stage == "pending" {
				f.cluster.setActive("default", f.name, string(v1.BlipPending))
			}
			if stage == "session" {
				view.InitDone, view.SessionSent = true, true
			}
			e := &chatEngine{s: f.srv, name: f.name, view: view}
			if err := e.converge(context.Background()); err != nil {
				t.Fatal(err)
			}
			blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g2")
			if err != nil {
				t.Fatal(err)
			}
			if !blip.Spec.Stop {
				t.Fatalf("stop note ignored during %s: phase=%s spec.stop=%v sent=%v", stage, blip.Status.Phase, blip.Spec.Stop, engineSentMethods(f.wire))
			}
		})
	}
}

func TestIssue1EngineSessionSetupWatchdog(t *testing.T) {
	for _, stage := range []string{"initialize", "session"} {
		t.Run(stage, func(t *testing.T) {
			f := newEngineFixture(t)
			f.startGeneration(t, 2)
			view := newChatView("")
			view.observe(streamLogRecord{Type: recordStart, Gen: 2, Offset: 1})
			view.InitSent = true
			if stage == "session" {
				view.InitDone, view.SessionSent = true, true
			}
			e := &chatEngine{s: f.srv, name: f.name, view: view, progressAt: time.Now().Add(-promptTimeout - time.Second)}
			if err := e.converge(context.Background()); err != nil {
				t.Fatal(err)
			}
			blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g2")
			if err != nil {
				t.Fatal(err)
			}
			if !blip.Spec.Stop {
				t.Fatalf("unanswered %s survived promptTimeout: spec.stop=%v stalled=%v", stage, blip.Spec.Stop, e.stalled)
			}
		})
	}
}

func TestIssue1OldStopDoesNotKillGenerationWhoseStartWasTruncated(t *testing.T) {
	f := newEngineFixture(t)
	f.startGeneration(t, 2)
	v := newChatView("")
	v.observe(streamLogRecord{Type: recordStart, Gen: 1, Offset: 1})
	v.observe(streamLogRecord{Type: recordNote, Gen: 1, Offset: 2, Data: mustJSON(noteRecord{Type: noteStop})})
	// The ring wrapped before the next start could be replayed. Its output
	// identifies g2, but the old generation's StartSeq is still in the view.
	v.observe(streamLogRecord{Type: recordOut, Gen: 2, Offset: 100})
	e := &chatEngine{s: f.srv, name: f.name, view: v}
	if err := e.converge(context.Background()); err != nil {
		t.Fatal(err)
	}
	blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g2")
	if err != nil {
		t.Fatal(err)
	}
	if blip.Spec.Stop {
		t.Fatal("an old stop killed a newer generation before its start was observed")
	}
}

func TestIssue1StopPendingGenerationDoesNotWaitForStartup(t *testing.T) {
	for _, phase := range []string{v1.BlipPending, v1.BlipSucceeded} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newEngineFixture(t)
				f.startGeneration(t, 2)
				f.wire.note(noteRecord{Type: notePrompt, ID: "n1", Text: "still queued"})
				f.cluster.setActive("default", f.name, phase)
				f.srv.wire = &runningWire{fakeWire: f.wire, cluster: f.cluster}
				oldST, err := f.cluster.GetSession(context.Background(), "default", f.name)
				if err != nil {
					t.Fatal(err)
				}
				stale := f.srv.readView(context.Background(), oldST)
				req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+f.name+"/stop", nil)
				req.Header.Set("X-Forwarded-User", "alice")
				resp := httptest.NewRecorder()
				before := time.Now()
				f.srv.Handler().ServeHTTP(resp, req)
				elapsed := time.Since(before)
				if resp.Code != http.StatusAccepted {
					t.Fatalf("stop status=%d body=%s", resp.Code, resp.Body.String())
				}
				blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g2")
				if err != nil {
					t.Fatal(err)
				}
				if phase == v1.BlipPending && !blip.Spec.Stop {
					t.Fatal("stop handler did not stop pending g2")
				}
				if elapsed > 5*time.Second {
					t.Fatalf("stop waited %s for the pending generation to start before setting spec.stop; stop must not depend on successful startup", elapsed)
				}
				st, err := f.cluster.GetSession(context.Background(), "default", f.name)
				if err != nil {
					t.Fatal(err)
				}
				// Model a second replica whose cached view predates the stop. Fresh
				// state metadata must invalidate that view even before its TTL ends.
				f.srv.views[f.name] = cachedChatView{view: stale, at: time.Now()}
				view := f.srv.readView(context.Background(), st)
				if view.hasWork() || stopBefore(st) == 0 {
					t.Fatalf("pending queue was not durably cancelled: work=%v boundary=%d", view.hasWork(), stopBefore(st))
				}
				e := &chatEngine{s: f.srv, name: f.name, view: view}
				if err := e.converge(context.Background()); err != errEngineIdle {
					t.Fatalf("converge after stop = %v, want idle", err)
				}
				if names := f.cluster.blipNames(); len(names) != 1 {
					t.Fatalf("stop created a cancellation/retry VM: %v", names)
				}
			})
		})
	}
}

func TestIssue1StopBoundarySurvivesReplayAndAllowsNewWork(t *testing.T) {
	for _, loadBeforeReplay := range []bool{false, true} {
		t.Run(fmt.Sprint(loadBeforeReplay), func(t *testing.T) {
			v := newChatView("")
			if loadBeforeReplay {
				v.applyStopBefore(10)
			}
			v.observe(streamLogRecord{Type: recordNote, Gen: 1, Offset: 2, Data: mustJSON(noteRecord{Type: notePrompt, ID: "old", Text: "cancelled"})})
			v.observe(streamLogRecord{Type: recordNote, Gen: 1, Offset: 3, Data: mustJSON(noteRecord{Type: noteAnswer, QID: "q1", Text: "old answer"})})
			v.applyStopBefore(10)
			v.applyStopBefore(5) // A stale state read cannot undo a stop.
			if v.hasWork() {
				t.Fatal("cancelled work reappeared during replay")
			}
			v.observe(streamLogRecord{Type: recordStart, Gen: 2, Offset: 10})
			v.observe(streamLogRecord{Type: recordNote, Gen: 2, Offset: 42, Data: mustJSON(noteRecord{Type: notePrompt, ID: "new", Text: "keep"})})
			if turn, ok := v.nextTurn(); !ok || turn.ID != "new" {
				t.Fatalf("next turn = %+v, %v; want new prompt", turn, ok)
			}
			if v.StopSeq > v.StartSeq {
				t.Fatal("old stop would kill the new generation")
			}
		})
	}
}

type failedStopCluster struct {
	Cluster
	err error
}

func (c *failedStopCluster) StopBlip(ctx context.Context, ns, name string) error {
	if c.err != nil {
		return c.err
	}
	return c.Cluster.StopBlip(ctx, ns, name)
}

func (c *failedStopCluster) RecordStop(context.Context, string, string, uint64) error {
	return errors.New("cannot persist stop")
}

func TestIssue1WatchdogRetriesFailedStop(t *testing.T) {
	f := newEngineFixture(t)
	f.startGeneration(t, 2)
	c := &failedStopCluster{Cluster: f.cluster, err: errors.New("temporary stop failure")}
	f.srv.cluster = c
	v := newChatView("")
	v.observe(streamLogRecord{Type: recordStart, Gen: 2, Offset: 1})
	v.InitDone, v.SessionSent = true, true
	e := &chatEngine{s: f.srv, name: f.name, view: v, progressAt: time.Now().Add(-promptTimeout - time.Second)}
	if err := e.converge(context.Background()); !errors.Is(err, c.err) || e.stalled {
		t.Fatalf("failed stop: err=%v stalled=%v; want error and retry allowed", err, e.stalled)
	}
	c.err = nil
	if err := e.converge(context.Background()); err != nil || !e.stalled {
		t.Fatalf("retry: err=%v stalled=%v", err, e.stalled)
	}
}

func TestIssue1StopStillStopsWhenDurableRecordingFails(t *testing.T) {
	f := newEngineFixture(t)
	f.startGeneration(t, 2)
	f.cluster.setActive("default", f.name, string(v1.BlipPending))
	f.srv.wire = &runningWire{fakeWire: f.wire, cluster: f.cluster}
	f.srv.cluster = &failedStopCluster{Cluster: f.cluster}
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+f.name+"/stop", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	resp := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("recording failure hidden: status=%d body=%s", resp.Code, resp.Body.String())
	}
	blip, err := f.cluster.GetBlip(context.Background(), "default", f.name+"-g2")
	if err != nil || !blip.Spec.Stop {
		t.Fatalf("recording failure prevented stop: blip=%v err=%v", blip, err)
	}
}
