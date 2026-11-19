package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestW521UnreadyPinnedReplacementUsesFallbackNode covers a pinned spare on a
// node whose VMs never become ready. Retiring it must not immediately pin
// another replacement to the same failed node: a Blip that already fell back
// needs a generic placement on a healthy node instead of waiting out
// pendingTimeout.
func TestW521UnreadyPinnedReplacementUsesFallbackNode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	home := e.readyState("data", "n1").Status.Placements[0]
	e.newPool("default", 0, 2)
	e.newBlip("b", withRoot("data"))
	e.setBlipStatus("b", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipPending
		b.Status.Locality = &v1.Locality{Node: home, Fallback: true}
	})
	pool := e.getPool("default")

	stuck := e.pool.podFor(pool, "default-stuck")
	stuck.Spec.NodeName = home
	stuck.Status.Phase = corev1.PodPending
	stuck.Annotations[v1.AnnotationPinnedNode] = home
	stuck.CreationTimestamp = metav1.NewTime(e.now.Add(-warmTimeout - time.Minute))
	e.create(stuck)

	e.run(e.pool, ns, "default")
	if !e.podGone(stuck.Name) {
		t.Fatalf("unready pinned spare %s was not retired", stuck.Name)
	}
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one replacement: %+v", len(pods), pods)
	}
	if got := pods[0].Annotations[v1.AnnotationPinnedNode]; got == home {
		t.Fatalf("replacement re-pinned to the failed node %q", got)
	}
	if got := pods[0].Annotations[v1.AnnotationPinnedNode]; got != "" {
		t.Fatalf("replacement pinned to %q, want a generic placement", got)
	}
	if !unschedulableExcludes(&pods[0], home) {
		t.Fatalf("generic replacement does not avoid the failed node: %+v", pods[0].Spec.Affinity)
	}

	// The next pass must not add another pinned pod while the generic
	// replacement is still booting.
	e.run(e.pool, ns, "default")
	for _, p := range e.pods() {
		if p.Annotations[v1.AnnotationPinnedNode] == home {
			t.Fatalf("pinned replacement created on the failed node: %+v", p)
		}
	}
}
