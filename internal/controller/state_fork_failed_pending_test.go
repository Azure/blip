// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestCopyOfFailedPendingSourceWaits covers workspace.CheckSource's rule: a
// failed state that still has a pending commit can recover, so a copy waits
// for it instead of failing immediately. A failed state without a pending
// commit is still terminal.
func TestCopyOfFailedPendingSourceWaits(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.create(&v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: ns, Generation: 1},
		Spec:       v1.BlipStateSpec{Replicas: 1},
		Status: v1.BlipStateStatus{
			Phase:   v1.StateFailed,
			Message: "initial version failed: fetch: device busy",
			Pending: &v1.PendingCommit{CommitID: "aaaaaaaabbbbbbbb", Generation: 1, SourceNode: "n1", Replicas: []string{"n1"}},
		},
	})
	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "src"; st.Spec.Replicas = 1 })

	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.Phase == v1.StateFailed || cp.Status.Pending != nil {
		t.Fatalf("copy of a failed-but-pending source failed: %+v", cp.Status)
	}
	if !strings.Contains(cp.Status.Message, `waiting for copy source "src" to commit`) {
		t.Fatalf("copy did not wait for the source's pending commit: %q", cp.Status.Message)
	}

	// The source's pending commit lands; the copy now plans normally.
	e.hold("src", "aaaaaaaabbbbbbbb", "n1")
	e.run(e.state, ns, "src")
	if st := e.getState("src"); st.Status.Committed == nil || st.Status.Committed.ID != "aaaaaaaabbbbbbbb" {
		t.Fatalf("source did not commit: %+v", st.Status)
	}
	e.run(e.state, ns, "cp")
	cp = e.getState("cp")
	if cp.Status.Phase != v1.StatePending || cp.Status.Pending == nil || cp.Status.CopiedFrom == nil {
		t.Fatalf("copy did not use the recovered source: %+v", cp.Status)
	}
}
