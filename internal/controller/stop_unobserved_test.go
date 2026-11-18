package controller

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// unobservedStopEnv claims a warm pod, clears its observed annotation, and
// then stops or deletes the Blip.
func unobservedStopEnv(t *testing.T, stop, deleteBlip bool) (*env, string) {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", withImage("reg/img:v1"))
	pod := e.getPod(b.Status.Pod)
	delete(pod.Annotations, AnnotationObserved)
	e.must(e.c.Update(e.ctx, pod))
	if stop {
		e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })
	}
	if deleteBlip {
		e.must(e.c.Delete(e.ctx, e.getBlip("b")))
	}
	e.now = e.now.Add(startTimeout + time.Minute)
	for range 3 {
		e.run(e.blip, ns, "b")
	}
	return e, pod.Name
}

// TestStopUnobservedVMFinishes covers C7: stopping a claimed Blip whose VM
// never reported an observation must not wait forever for that report.
func TestStopUnobservedVMFinishes(t *testing.T) {
	e, pod := unobservedStopEnv(t, true, false)
	b := e.getBlip("b")
	if b.Status.Phase != v1.BlipFailed && b.Status.Phase != v1.BlipSucceeded {
		t.Fatalf("stopped unobserved Blip phase %s", b.Status.Phase)
	}
	if !e.podGone(pod) {
		t.Fatal("stopped unobserved Blip kept its pod")
	}
}

// TestDeleteUnobservedVMFinishes covers C7: deleting a claimed Blip whose VM
// never reported an observation must clean up the pod and finalizer.
func TestDeleteUnobservedVMFinishes(t *testing.T) {
	e, pod := unobservedStopEnv(t, false, true)
	err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, &v1.Blip{})
	if err == nil {
		b := e.getBlip("b")
		t.Fatalf("deleted unobserved Blip still exists: phase=%s finalizers=%v", b.Status.Phase, b.Finalizers)
	}
	if !e.podGone(pod) {
		t.Fatal("deleted unobserved Blip kept its pod")
	}
}
