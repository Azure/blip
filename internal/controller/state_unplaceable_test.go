// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestUnplaceableStateFailsAfterBound covers image and empty states whose
// immutable nodeSelector matches no node. They can only commit if a node
// becomes eligible later, so they retry for the same bounded window as an
// unplaceable copy and then fail instead of leaving `pull`/`run --from`
// waiting forever.
func TestUnplaceableStateFailsAfterBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*v1.BlipState)
	}{
		{"image", func(st *v1.BlipState) {
			st.Spec.Image = "reg/img:v1"
			st.Spec.Replicas = 1
		}},
		{"empty", func(st *v1.BlipState) {
			st.Spec.Replicas = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newState("s", func(st *v1.BlipState) {
				st.Spec.NodeSelector = map[string]string{"zone": "none"}
				tc.mutate(st)
			})

			e.run(e.state, ns, "s")
			st := e.getState("s")
			if st.Status.Phase != v1.StatePending || st.Status.Pending != nil || st.Status.UnplaceableSince == nil {
				t.Fatalf("unplaceable state did not start its retry window: %+v", st.Status)
			}
			if !strings.Contains(st.Status.Message, "no eligible node can hold the state") {
				t.Fatalf("unplaceable state message: %q", st.Status.Message)
			}

			// Still inside the window: a node may recover or gain the label.
			e.now = e.now.Add(pendingTimeout - time.Second)
			e.run(e.state, ns, "s")
			st = e.getState("s")
			if st.Status.Phase != v1.StatePending || st.Status.UnplaceableSince == nil {
				t.Fatalf("state failed before the bound: %+v", st.Status)
			}

			e.now = e.now.Add(2 * time.Second)
			e.run(e.state, ns, "s")
			st = e.getState("s")
			if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil || st.Status.UnplaceableSince != nil {
				t.Fatalf("unplaceable state did not fail after the bound: %+v", st.Status)
			}
			if !strings.Contains(st.Status.Message, "no eligible node can hold the state") ||
				!strings.Contains(st.Status.Message, "nodeSelector") {
				t.Fatalf("unplaceable state failure message: %q", st.Status.Message)
			}
		})
	}
}

// TestUnplaceableStateCommitsWhenNodeBecomesEligible ensures the retry window
// does not falsely fail a state whose node appears (or gains the selector
// label) before the bound.
func TestUnplaceableStateCommitsWhenNodeBecomesEligible(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 1
		st.Spec.NodeSelector = map[string]string{"zone": "z1"}
	})

	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StatePending || st.Status.UnplaceableSince == nil {
		t.Fatalf("unplaceable state did not start its retry window: %+v", st.Status)
	}

	addNodeWithLabels(e, "n2", map[string]string{"zone": "z1"})
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Phase == v1.StateFailed || st.Status.Pending == nil || st.Status.UnplaceableSince != nil {
		t.Fatalf("state did not plan on the newly eligible node: %+v", st.Status)
	}
}

func addNodeWithLabels(e *env, name string, labels map[string]string) {
	e.t.Helper()
	l := map[string]string{
		v1.LabelEnrolled:                 "true",
		"blip.dev/node-pool":             "default",
		v1.LabelHypervisorPrefix + "kvm": "true",
	}
	for k, v := range labels {
		l[k] = v
	}
	e.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}})
	bn := &v1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: name}}
	e.create(bn)
	hb := metav1.NewTime(e.now)
	bn.Status = v1.BlipNodeStatus{
		Incarnation: "inc-" + name, Heartbeat: &hb, FreeBytes: 100 << 30,
		Hypervisors: []string{"kvm"},
	}
	e.must(e.c.Status().Update(e.ctx, bn))
}
