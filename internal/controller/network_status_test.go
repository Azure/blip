package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestRunningNetworkPolicyErrorIsSurfaced reproduces a live policy edit that
// compiles at admission but fails network.Compile on the node. The node
// replaces the grant with default deny and records the error on the pod; a
// Running Blip must mirror that error instead of looking healthy while all
// egress is blocked.
func TestRunningNetworkPolicyErrorIsSurfaced(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	const policyErr = "network policy: blip network: egress[0].to[0]: podSelector: selector.matchExpressions[0].operator: Invalid value: \"Bogus\": not a valid selector operator"
	e.annotatePod(b.Status.Pod, v1.AnnotationPrepareError, policyErr)
	e.run(e.blip, ns, "b")

	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Reason != ReasonNetworkFailed {
		t.Fatalf("reason = %q, want %q", b.Status.Reason, ReasonNetworkFailed)
	}
	if !strings.Contains(b.Status.Message, policyErr) {
		t.Fatalf("message = %q, want %q", b.Status.Message, policyErr)
	}

	// A repaired policy clears the node annotation and the Blip diagnostic.
	e.annotatePod(b.Status.Pod, v1.AnnotationPrepareError, "")
	e.run(e.blip, ns, "b")
	if b = e.getBlip("b"); b.Status.Reason != "" || b.Status.Message != "" {
		t.Fatalf("repaired policy still reports %q: %q", b.Status.Reason, b.Status.Message)
	}
}
