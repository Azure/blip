// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestStopBeforeStartSucceeds covers the case where a user stops a Blip before
// it is ever claimed. That is a requested stop, not a failure: the chat UI
// should return to idle instead of showing an error after a reload.
func TestStopBeforeStartSucceeds(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("b", e.withImage("reg/img:v1"))
	e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })

	e.run(e.blip, ns, "b")

	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if b.Status.Message != "stopped before start" {
		t.Fatalf("message %q", b.Status.Message)
	}
	if b.Status.Pod != "" {
		t.Fatalf("stopped before start kept pod %q", b.Status.Pod)
	}
	if b.Status.FinishTime == nil {
		t.Fatal("stopped before start has no finish time")
	}
}
