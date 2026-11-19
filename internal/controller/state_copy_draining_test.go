// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// readyPinnedSource creates a Ready source state on n1, pinned there by its
// selector so it cannot be repaired elsewhere.
func readyPinnedSource(t *testing.T) (*env, *v1.BlipState) {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.label("zone", "a", "n1")
	e.newState("src", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "src")
	src := e.getState("src")
	if src.Status.Pending == nil || !slices.Equal(src.Status.Pending.Replicas, []string{"n1"}) {
		t.Fatalf("source not pinned to n1: %+v", src.Status.Pending)
	}
	e.hold("src", src.Status.Pending.CommitID, "n1")
	e.run(e.state, ns, "src")
	src = e.getState("src")
	if src.Status.Phase != v1.StateReady || !slices.Equal(src.Status.Placements, []string{"n1"}) {
		t.Fatalf("source not ready on n1: %+v", src.Status)
	}
	return e, src
}

// TestCopyFromDrainingOnlySource: draining forbids new placements, not reading
// a version the node already sealed. A copy whose only source holder is a
// healthy draining node must pin that node and plan on a usable target, then
// commit once the target fetches the source commit.
func TestCopyFromDrainingOnlySource(t *testing.T) {
	e, _ := readyPinnedSource(t)
	e.setDrain("n1")
	e.run(e.state, ns, "src")

	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom == nil || !slices.Equal(cp.Status.CopiedFrom.Nodes, []string{"n1"}) {
		t.Fatalf("copy did not pin the draining holder: %+v", cp.Status.CopiedFrom)
	}
	if cp.Status.Pending == nil || cp.Status.Pending.SourceNode == "n1" {
		t.Fatalf("copy did not plan on a usable target: %+v", cp.Status.Pending)
	}
	if cp.Status.UnplaceableSince != nil {
		t.Fatalf("readable draining source marked the copy unplaceable: %+v", cp.Status)
	}

	// The target fetches and builds the copy commit from the draining source.
	p := cp.Status.Pending
	e.hold("cp", p.CommitID, p.Replicas...)
	e.run(e.state, ns, "cp")
	if cp = e.getState("cp"); cp.Status.Phase != v1.StateReady {
		t.Fatalf("copy did not commit: %+v", cp.Status)
	}
}

// TestCopyFromHealthySource: the non-draining control. A healthy source holder
// is still a valid copy source and is preferred for the build.
func TestCopyFromHealthySource(t *testing.T) {
	e, _ := readyPinnedSource(t)
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom == nil || !slices.Equal(cp.Status.CopiedFrom.Nodes, []string{"n1"}) {
		t.Fatalf("copy did not pin the healthy holder: %+v", cp.Status.CopiedFrom)
	}
	if cp.Status.Pending == nil || cp.Status.Pending.SourceNode != "n1" {
		t.Fatalf("copy did not prefer the healthy source: %+v", cp.Status.Pending)
	}
	if cp.Status.UnplaceableSince != nil {
		t.Fatalf("healthy source marked the copy unplaceable: %+v", cp.Status)
	}
}

// TestCopyFromUnavailableSourceIsBounded: when no current-incarnation holder
// is healthy enough to serve the committed source, the copy must not wait
// silently while pinning the source finalizer. It starts the unplaceable
// window and fails terminally after pendingTimeout.
func TestCopyFromUnavailableSourceIsBounded(t *testing.T) {
	e, _ := readyPinnedSource(t)
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, bn))
	old := metav1.NewTime(e.now.Add(-heartbeatTimeout - time.Second))
	bn.Status.Heartbeat = &old
	e.must(e.c.Status().Update(e.ctx, bn))

	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.Pending != nil || cp.Status.UnplaceableSince == nil {
		t.Fatalf("unavailable source did not start the retry window: %+v", cp.Status)
	}
	if !strings.Contains(cp.Status.Message, "no healthy holder") {
		t.Fatalf("unavailable source message: %q", cp.Status.Message)
	}

	e.now = e.now.Add(pendingTimeout + time.Second)
	e.heartbeat("n1")
	e.run(e.state, ns, "cp")
	cp = e.getState("cp")
	if cp.Status.Phase != v1.StateFailed || cp.Status.Pending != nil || cp.Status.UnplaceableSince != nil {
		t.Fatalf("unavailable source did not fail after the bound: %+v", cp.Status)
	}
	if !strings.Contains(cp.Status.Message, `copy source "src"`) || !strings.Contains(cp.Status.Message, "no healthy holder") {
		t.Fatalf("unavailable source failure message: %q", cp.Status.Message)
	}
}
