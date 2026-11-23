// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"fmt"
	"slices"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// historyState creates name as a copy of src (a root when src is empty) and
// drives it through plan, hold, and commit to Ready.
func (e *env) historyState(name, src string, limit int32) {
	e.t.Helper()
	e.newState(name, func(st *v1.BlipState) {
		st.Spec.CopyFrom, st.Spec.Replicas, st.Spec.HistoryLimit = src, 1, limit
	})
	e.run(e.state, ns, name)
	p := e.getState(name).Status.Pending
	if p == nil {
		e.t.Fatalf("state %s has no pending version: %+v", name, e.getState(name).Status)
	}
	e.hold(name, p.CommitID, p.Replicas...)
	e.run(e.state, ns, name)
	if st := e.getState(name); st.Status.Phase != v1.StateReady {
		e.t.Fatalf("state %s not ready: %+v", name, st.Status)
	}
}

// historyChain builds names[0] <- names[1] <- ... as committed copies.
func (e *env) historyChain(limit int32, names ...string) {
	e.t.Helper()
	for i, n := range names {
		src := ""
		if i > 0 {
			src = names[i-1]
		}
		e.historyState(n, src, limit)
	}
}

// updateStates applies mutate to each named state.
func (e *env) updateStates(mutate func(*v1.BlipState), names ...string) {
	e.t.Helper()
	for _, n := range names {
		st := e.getState(n)
		mutate(st)
		e.must(e.c.Update(e.ctx, st))
	}
}

func withHistoryLimit(n int32) func(*v1.BlipState) {
	return func(st *v1.BlipState) { st.Spec.HistoryLimit = n }
}

// expectLive checks the sorted names of states that exist and are not being
// deleted.
func (e *env) expectLive(want ...string) {
	e.t.Helper()
	var sts v1.BlipStateList
	e.must(e.c.List(e.ctx, &sts))
	var got []string
	for _, st := range sts.Items {
		if st.DeletionTimestamp == nil {
			got = append(got, st.Name)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		e.t.Fatalf("live states = %v, want %v", got, want)
	}
}

// TestHistoryCompactsAsChainGrows refreshes a chain one copy at a time. Each
// ready copy keeps its nearest historyLimit ancestors and deletes older ones,
// whose finalizers then release because their copies committed.
func TestHistoryCompactsAsChainGrows(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}
	for _, limit := range []int{1, 2} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			for i, n := range names {
				src := ""
				if i > 0 {
					src = names[i-1]
				}
				e.historyState(n, src, int32(limit))
				e.expectLive(names[max(0, i-limit) : i+1]...)
			}
			e.settle()
			for _, n := range names[:len(names)-limit-1] {
				err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: n}, &v1.BlipState{})
				if !apierrors.IsNotFound(err) {
					t.Fatalf("superseded state %s not removed: %v", n, err)
				}
			}
		})
	}
}

// TestHistoryCompactsBacklog enables historyLimit on an existing chain: the
// newest ready state deletes every ancestor beyond the limit at once.
func TestHistoryCompactsBacklog(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.historyChain(0, "a", "b", "c", "d", "e")
	e.settle()
	e.expectLive("a", "b", "c", "d", "e")

	e.updateStates(withHistoryLimit(1), "a", "b", "c", "d", "e")
	e.run(e.state, ns, "e")
	e.expectLive("d", "e")
}

// TestHistoryWaitsForReady covers a newest state that is not Ready: neither
// a pending copy nor a ready state with a writer compacts its history.
func TestHistoryWaitsForReady(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.historyChain(1, "a", "b")

	e.newState("c", func(st *v1.BlipState) {
		st.Spec.CopyFrom, st.Spec.Replicas, st.Spec.HistoryLimit = "b", 1, 1
	})
	e.run(e.state, ns, "c")
	c := e.getState("c")
	if c.Status.Pending == nil || c.Status.Phase == v1.StateReady {
		t.Fatalf("copy not pending: %+v", c.Status)
	}
	e.expectLive("a", "b", "c")
	e.hold("c", c.Status.Pending.CommitID, c.Status.Pending.Replicas...)
	e.run(e.state, ns, "c")
	e.expectLive("b", "c")

	// A committed state that is in use is not compacted either.
	e = newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.historyChain(0, "a", "b", "c")
	e.startBlip("w", "n1", withRoot("c"))
	e.updateStates(withHistoryLimit(1), "a", "b", "c")
	e.run(e.state, ns, "c")
	if c := e.getState("c"); c.Status.Phase != v1.StateInUse {
		t.Fatalf("state with writer not in use: %+v", c.Status)
	}
	e.expectLive("a", "b", "c")
}

// TestHistoryStopsAtForeignAncestor covers ancestors outside the newest
// state's history: they are kept, and so is every older ancestor behind them.
func TestHistoryStopsAtForeignAncestor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(name string, st *v1.BlipState)
		want   []string
	}{
		{"same history", func(string, *v1.BlipState) {}, []string{"c", "d"}},
		{"same owner", func(_ string, st *v1.BlipState) {
			st.Labels = map[string]string{v1.LabelOwner: "alice"}
		}, []string{"c", "d"}},
		{"historyLimit 0", func(_ string, st *v1.BlipState) {
			st.Spec.HistoryLimit = 0
		}, []string{"a", "b", "c", "d"}},
		{"newest without historyLimit", func(n string, st *v1.BlipState) {
			if n == "d" {
				st.Spec.HistoryLimit = 0
			}
		}, []string{"a", "b", "c", "d"}},
		{"owner differs", func(n string, st *v1.BlipState) {
			if n == "b" {
				st.Labels = map[string]string{v1.LabelOwner: "bob"}
			}
		}, []string{"a", "b", "c", "d"}},
		{"ancestor without historyLimit", func(n string, st *v1.BlipState) {
			if n == "b" {
				st.Spec.HistoryLimit = 0
			}
		}, []string{"a", "b", "c", "d"}},
		{"owner reference", func(n string, st *v1.BlipState) {
			if n == "b" {
				st.OwnerReferences = []metav1.OwnerReference{{APIVersion: "blip.dev/v1alpha1", Kind: "Blip", Name: "x", UID: "uid-x"}}
			}
		}, []string{"a", "b", "c", "d"}},
		{"chat session", func(n string, st *v1.BlipState) {
			if n == "b" {
				st.Labels = map[string]string{v1.LabelChatSession: "s1"}
			}
		}, []string{"a", "b", "c", "d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.historyChain(0, "a", "b", "c", "d")
			for _, n := range []string{"a", "b", "c", "d"} {
				e.updateStates(func(st *v1.BlipState) {
					st.Spec.HistoryLimit = 1
					tc.mutate(n, st)
				}, n)
			}
			e.run(e.state, ns, "d")
			e.expectLive(tc.want...)
		})
	}
}

// TestHistoryStopsAtReusedName covers an ancestor deleted and recreated under
// the same name: its UID no longer matches the copy's recorded source, so
// neither it nor anything older is deleted.
func TestHistoryStopsAtReusedName(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.historyChain(0, "a", "b", "c", "d")
	old := e.getState("b")
	e.must(e.c.Delete(e.ctx, old))
	e.run(e.state, ns, "b")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, &v1.BlipState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old b not removed: %v", err)
	}
	e.historyState("b", "", 1)
	if e.getState("b").UID == old.UID {
		t.Fatal("recreated b reused the old UID")
	}
	e.updateStates(withHistoryLimit(1), "a", "c", "d")

	e.run(e.state, ns, "d")
	e.expectLive("a", "b", "c", "d")
}

// TestHistorySkipsAncestorInUse covers an ancestor beyond the limit that a
// running Blip still writes: it is kept and retried, older ancestors are
// still deleted, and it goes once the Blip has saved and finished.
func TestHistorySkipsAncestorInUse(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.historyChain(0, "a", "b", "c", "d")
	b := e.startBlip("w", "n1", withRoot("b"))
	e.updateStates(withHistoryLimit(1), "a", "b", "c", "d")

	res := e.run(e.state, ns, "d")
	if res.RequeueAfter <= 0 || res.RequeueAfter > historyRetry {
		t.Fatalf("requeue after %v, want (0, %v]", res.RequeueAfter, historyRetry)
	}
	e.expectLive("b", "c", "d")
	expectPhase(t, e.getBlip("w"), v1.BlipRunning, "")
	w := e.getState("b").Status.Writer
	if w == nil || w.BlipUID != string(b.UID) {
		t.Fatalf("writer disrupted: %+v", w)
	}

	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 0, Reason: "Completed"}})
	e.run(e.blip, ns, "w")
	e.saveWriter("b", "b2b2b2b2b2b2b2b2")
	e.run(e.blip, ns, "w")
	if !v1.Finished(e.getBlip("w")) {
		t.Fatalf("blip not finished: %+v", e.getBlip("w").Status)
	}
	if res := e.run(e.state, ns, "d"); res.RequeueAfter == historyRetry {
		t.Fatalf("still retrying history: %+v", res)
	}
	e.expectLive("c", "d")
}

// TestHistoryLimitBeyondCopyChain checks that the walk reaches an ancestor
// beyond maxCopyChain when historyLimit is that large.
func TestHistoryLimitBeyondCopyChain(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	names := make([]string, maxCopyChain+2)
	for i := range names {
		names[i] = fmt.Sprintf("s%02d", i)
	}
	e.historyChain(maxCopyChain, names...)
	e.expectLive(names[1:]...)
}
