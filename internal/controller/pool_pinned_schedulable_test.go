// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// w622Cordon leaves node usable() for the pool's enrollment and health checks,
// but the scheduler can no longer place a VM there.
func w622Cordon(t *testing.T, e *env, node string) {
	t.Helper()
	n := &corev1.Node{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, n))
	n.Spec.Unschedulable = true
	e.must(e.c.Update(e.ctx, n))
}

func w622Taint(t *testing.T, e *env, node string) {
	t.Helper()
	n := &corev1.Node{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, n))
	n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: "w622/dedicated", Value: "yes", Effect: corev1.TaintEffectNoSchedule})
	e.must(e.c.Update(e.ctx, n))
}

// TestW622PinnedDemandSkipsUnschedulableHome covers a Blip waiting on a data
// node the scheduler cannot place a VM on, such as a cordoned or untolerated
// tainted node. Pinning a pod there guarantees FailedScheduling; the pool must
// use a generic placement instead.
func TestW622PinnedDemandSkipsUnschedulableHome(t *testing.T) {
	for _, tc := range []struct {
		name string
		mark func(*testing.T, *env, string)
	}{
		{"cordon", w622Cordon},
		{"taint", w622Taint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1", "n2")
			home := e.readyState("data", "n1").Status.Placements[0]
			e.newPool("default", 0, 2)
			e.newBlip("b", withRoot("data"))
			e.setBlipStatus("b", func(b *v1.Blip) {
				b.Status.Phase = v1.BlipPending
				b.Status.Locality = &v1.Locality{Node: home}
			})
			tc.mark(t, e, home)

			cl, err := loadCluster(e.ctx, e.c, e.now)
			e.must(err)
			if !cl.usable(home, nil) || cl.schedulable(home, poolSelector(e.getPool("default")), nil) {
				t.Fatalf("fixture: usable=%v schedulable=%v", cl.usable(home, nil), cl.schedulable(home, poolSelector(e.getPool("default")), nil))
			}

			e.run(e.pool, ns, "default")
			if n := len(pinnedPods(e, home)); n > 0 {
				t.Fatalf("pool pinned %d VM pod(s) to unschedulable node %s: %+v", n, home, e.pods())
			}
			if len(e.pods()) == 0 {
				t.Fatal("pool created no replacement at all")
			}
		})
	}
}

// TestW622LocalitySkipsUnschedulableHome covers the Blip side: homeNodes must
// not record a cordoned data node as the place to boot the Blip's VM.
func TestW622LocalitySkipsUnschedulableHome(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	home := e.readyState("data", "n1").Status.Placements[0]
	e.newPool("default", 0, 2)
	w622Cordon(t, e, home)
	e.newBlip("b", withRoot("data"))

	e.run(e.blip, ns, "b")
	loc := e.getBlip("b").Status.Locality
	if loc == nil || !loc.Fallback || loc.Node == home {
		t.Fatalf("locality %+v, want a fallback away from cordoned home %s", loc, home)
	}
}
