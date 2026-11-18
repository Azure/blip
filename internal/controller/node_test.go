package controller

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestNodeWatchWakesDrainingNodeForBlip checks the Blip watch mapping: a Blip
// that runs on a draining node must enqueue that node when it changes (for
// example when it finishes), while a Blip on a healthy node does not.
func TestNodeWatchWakesDrainingNodeForBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

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
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

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
	e.saveWriter(b.Spec.State, newID())
	e.run(e.blip, ns, "b")
	if !finished(e.getBlip("b")) {
		t.Fatalf("blip did not finish: %+v", e.getBlip("b").Status)
	}
	// The saved root is the last durable placement on this one-node cluster.
	// Delete it before asking enrollment to prove the node empty.
	e.must(e.c.Delete(e.ctx, e.getState(b.Spec.State)))
	e.run(e.state, ns, b.Spec.State)

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

// TestUnenrollRechecksSafetyForANewDrain covers C9: after an undrain,
// SafeToRemove may still say true from the previous drain although a VM is
// running. The enrollment retry must reset the verdict for the drain it
// starts and prove safety from the live objects, so the labels and BlipNode
// stay while the VM runs and are removed only after a fresh drain completes.
func TestUnenrollRechecksSafetyForANewDrain(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	// Undrain race: the drain was cleared (or never observed) but the status
	// still carries the previous drain's safe verdict.
	bn := e.getBlipNode("n1")
	if bn.Spec.Drain {
		t.Fatal("unexpected drain")
	}
	bn.Status.SafeToRemove = true
	e.must(e.c.Status().Update(e.ctx, bn))

	// No pool selects the node any more; the enroll retry starts a new drain.
	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.NodeSelector = map[string]string{"blip.dev/node-pool": "other"}
	})

	res := e.run(e.enroll, "", "n1")
	bn = e.getBlipNode("n1")
	if !bn.Spec.Drain || bn.Annotations[AnnotationEnrollmentDrain] != "true" {
		t.Fatalf("new drain not recorded: %+v", bn)
	}
	if bn.Status.SafeToRemove {
		t.Fatal("stale SafeToRemove survived the new drain")
	}
	if res.RequeueAfter != enrollmentRetry {
		t.Fatalf("unsafe drain requeue %v, want %v", res.RequeueAfter, enrollmentRetry)
	}
	if l := e.getNode("n1").Labels; l[LabelEnrolled] != "true" || l[LabelHypervisorPrefix+"kvm"] != "" {
		t.Fatalf("node labels changed while the VM runs: %v", l)
	}
	expectPhase(t, e.getBlip("b"), v1.BlipRunning, "")

	// A retry still sees the running Blip and keeps the agent.
	e.run(e.enroll, "", "n1")
	if e.getNode("n1").Labels[LabelEnrolled] != "true" {
		t.Fatal("agent unenrolled while the VM still runs")
	}
	if err := e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, &v1.BlipNode{}); err != nil {
		t.Fatalf("BlipNode deleted while the VM still runs: %v", err)
	}

	// Finish the VM through the normal stop path; a fresh check now proves
	// the drain safe and unenrolls the node.
	e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(e.getBlip("b").Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	e.saveWriter(b.Spec.State, newID())
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	e.must(e.c.Delete(e.ctx, e.getState(b.Spec.State)))
	e.run(e.state, ns, b.Spec.State)
	e.run(e.enroll, "", "n1")

	if err := e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, &v1.BlipNode{}); !apierrors.IsNotFound(err) {
		t.Fatalf("node not unenrolled after the drain completed: %v", err)
	}
	if l := e.getNode("n1").Labels; l[LabelEnrolled] != "" || l[LabelHypervisorPrefix+"kvm"] != "" {
		t.Fatalf("enrollment labels left after unenroll: %v", l)
	}
}
