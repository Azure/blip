// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Canonical HTTP snapshots must agree for identical inputs. A retained end
// record only describes its own execution, not a newer generation or the
// workspace's readiness. In particular, a Ready workspace does not erase the
// last execution's failure.
func TestSessionSnapshotPhasePrecedence(t *testing.T) {
	for _, tt := range []struct {
		name       string
		blipPhase  string
		generation int64
		endedGen   uint64
		wantPhase  string
		wantRun    bool
		wantStatus string
	}{
		{name: "ready without execution", wantPhase: v1.StateReady},
		{name: "ready with retained end but no execution", endedGen: 1, wantPhase: v1.StateReady},
		{name: "ready with failed execution", blipPhase: v1.BlipFailed, generation: 1, endedGen: 1, wantPhase: v1.BlipFailed, wantStatus: "agent exited with code 7"},
		{name: "ready with successful execution", blipPhase: v1.BlipSucceeded, generation: 1, endedGen: 1, wantPhase: v1.BlipSucceeded},
		{name: "running before trajectory is available", blipPhase: v1.BlipRunning, generation: 1, wantPhase: v1.BlipRunning, wantRun: true},
		{name: "current execution ended before controller update", blipPhase: v1.BlipRunning, generation: 1, endedGen: 1, wantPhase: v1.BlipSaving},
		{name: "older end cannot stop newer running execution", blipPhase: v1.BlipRunning, generation: 2, endedGen: 1, wantPhase: v1.BlipRunning, wantRun: true},
		{name: "older end cannot stop newer pending execution", blipPhase: v1.BlipPending, generation: 2, endedGen: 1, wantPhase: v1.BlipPending, wantRun: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const namespace, name = "team", "snapshot"
			cluster := newFakeCluster()
			st := &v1.BlipState{
				ObjectMeta: metav1.ObjectMeta{
					Name: name, Namespace: namespace,
					Labels:      map[string]string{LabelSession: "true"},
					Annotations: map[string]string{AnnotationProfile: DefaultProfileName},
				},
			}
			st.Status.Phase = v1.StateReady
			if err := cluster.CreateSession(context.Background(), namespace, st); err != nil {
				t.Fatal(err)
			}
			if tt.blipPhase != "" {
				b := &v1.Blip{ObjectMeta: metav1.ObjectMeta{
					Name: name + "-g" + strconv.FormatInt(tt.generation, 10), Namespace: namespace,
					Labels:      map[string]string{LabelSession: name},
					Annotations: map[string]string{AnnotationGeneration: strconv.FormatInt(tt.generation, 10)},
				}}
				b.Status.Phase = tt.blipPhase
				b.Status.Message = "agent exited with code 7"
				cluster.blips[key(namespace, b.Name)] = b
			}
			wire := newFakeWire()
			if tt.endedGen != 0 {
				wire.start(tt.endedGen)
				wire.end(tt.endedGen)
			}
			s, err := New(Options{Namespace: namespace, DefaultPool: "default", Cluster: cluster, Wire: wire, Profiles: Profiles{DefaultProfileName: {}}, Log: testLogger()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			// Do not start the supervisor: these fixed snapshots must not race
			// background execution or depend on elapsed time or a live cluster.
			handler := s.Handler()
			listResponse := httptest.NewRecorder()
			listRequest := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			listRequest.Header.Set("X-Forwarded-User", "alice")
			handler.ServeHTTP(listResponse, listRequest)
			if listResponse.Code != http.StatusOK {
				t.Fatalf("list: %d %s", listResponse.Code, listResponse.Body.String())
			}
			list := decodeBody[[]sessionSummary](t, listResponse.Result())
			if len(list) != 1 {
				t.Fatalf("list has %d sessions, want 1", len(list))
			}
			detailResponse := httptest.NewRecorder()
			detailRequest := httptest.NewRequest(http.MethodGet, "/api/sessions/"+name, nil)
			detailRequest.Header.Set("X-Forwarded-User", "alice")
			handler.ServeHTTP(detailResponse, detailRequest)
			if detailResponse.Code != http.StatusOK {
				t.Fatalf("detail: %d %s", detailResponse.Code, detailResponse.Body.String())
			}
			detail := decodeBody[sessionDetail](t, detailResponse.Result())
			for endpoint, got := range map[string]sessionSummary{"list": list[0], "detail": detail.sessionSummary} {
				if got.Phase != tt.wantPhase || got.Running != tt.wantRun || got.Generation != tt.generation || got.StatusMessage != tt.wantStatus {
					t.Errorf("%s: phase=%s running=%v generation=%d status=%q; want phase=%s running=%v generation=%d status=%q", endpoint, got.Phase, got.Running, got.Generation, got.StatusMessage, tt.wantPhase, tt.wantRun, tt.generation, tt.wantStatus)
				}
			}
		})
	}
}

func TestReconcileSessionSummary(t *testing.T) {
	for _, tt := range []struct {
		name string
		view *chatView
		end  bool
	}{
		{name: "unavailable trajectory"},
		{name: "empty trajectory", view: &chatView{}},
		{name: "live generation", view: &chatView{Gen: 2, Started: true}},
		{name: "matching end", view: &chatView{Gen: 2, Ended: true}, end: true},
		{name: "older end", view: &chatView{Gen: 1, Ended: true}},
		{name: "newer end", view: &chatView{Gen: 3, Ended: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			summary := sessionSummary{Phase: v1.BlipRunning, Running: true, Generation: 2}
			got := reconcileSessionSummary(summary, tt.view)
			want := summary
			if tt.end {
				want.Phase, want.Running = v1.BlipSaving, false
			}
			if got.Phase != want.Phase || got.Running != want.Running || got.Generation != want.Generation {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			if summary.Phase != v1.BlipRunning || !summary.Running {
				t.Fatal("reconciliation mutated the input summary")
			}
		})
	}
}
