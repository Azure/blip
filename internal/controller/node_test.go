package controller

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestNodeWatchWakesDrainingNodeForBlip checks the Blip watch mapping: a Blip
// that runs on a draining node must enqueue that node when it changes (for
// example when it finishes), while a Blip on a healthy node does not.
func TestNodeWatchWakesDrainingNodeForBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", withImage("reg/img:v1"))

	if got := e.node.blipNodes(e.ctx, b); len(got) != 0 {
		t.Fatalf("healthy node enqueued: %+v", got)
	}

	e.setDrain("n1")
	got := e.node.blipNodes(e.ctx, e.getBlip("b"))
	if len(got) != 1 || got[0].Name != "n1" {
		t.Fatalf("draining node not enqueued for its Blip: %+v", got)
	}

	// A Blip that lost its status node is mapped through its claimed pod.
	claimed := e.getBlip("b").DeepCopy()
	claimed.Status.Node = ""
	got = e.node.blipNodes(e.ctx, claimed)
	if len(got) != 1 || got[0].Name != "n1" {
		t.Fatalf("claimed pod node not enqueued: %+v", got)
	}

	// A draining node that is not safe is retried until it is, even if no
	// event wakes it.
	res := e.run(e.node, "", "n1")
	if res.RequeueAfter != drainRetry {
		t.Fatalf("unsafe draining node requeue %v, want %v", res.RequeueAfter, drainRetry)
	}
}

// TestSafeToRemoveRecomputedAfterBlipFinishes covers C8: the pod delete event
// arrived while the Blip was still running and NodeReconciler is not woken
// when the Blip finishes. The enrollment retry must recompute safety from the
// live objects and unenroll the node, instead of reading SafeToRemove forever.
func TestSafeToRemoveRecomputedAfterBlipFinishes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", withImage("reg/img:v1"))

	e.setDrain("n1")
	e.run(e.node, "", "n1")
	if !e.getBlip("b").Spec.Stop {
		t.Fatal("drain did not stop the running blip")
	}
	if e.getBlipNode("n1").Status.SafeToRemove {
		t.Fatal("safe before the blip finished")
	}

	// The VM pod disappears and the Blip finishes without any node reconcile:
	// this is the order real watches can produce (the pod delete arrives while
	// the Blip is still running; nothing wakes NodeReconciler when it
	// finishes).
	pod := e.getPod(b.Status.Pod)
	e.must(e.c.Delete(e.ctx, pod))
	e.run(e.blip, ns, "b")
	if !finished(e.getBlip("b")) {
		t.Fatalf("blip did not finish: %+v", e.getBlip("b").Status)
	}

	// No pool selects the node any more; only the enrollment retry runs.
	e.must(e.c.Delete(e.ctx, e.getPool("default")))
	node := e.getNode("n1")
	delete(node.Labels, "blip.dev/node-pool")
	e.must(e.c.Update(e.ctx, node))

	for range 2 {
		e.run(e.enroll, "", "n1")
	}
	bn := &v1.BlipNode{}
	err := e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, bn)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("node not unenrolled after the last blip finished: %v (SafeToRemove=%v)",
			err, bn.Status.SafeToRemove)
	}
	if l := e.getNode("n1").Labels; l[LabelEnrolled] != "" || l[LabelHypervisorPrefix+"kvm"] != "" {
		t.Fatalf("enrollment labels left on unenrolled node: %v", l)
	}
}
