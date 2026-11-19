package controller

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

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

// TestInvalidStateRuntimeNetworkIsSurfaced covers the state-side half of the
// inherited network policy diagnostic. The node names "state network" on the
// Blip, but the invalid rules live on the BlipState. Without a state status
// and Event, an operator sees an InUse state with nothing to repair.
func TestInvalidStateRuntimeNetworkIsSurfaced(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	recorder := record.NewFakeRecorder(10)
	e.state.Recorder = recorder
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")

	bad := &v1.NetworkPolicy{Egress: []v1.NetworkEgressRule{{
		To: []v1.NetworkPeer{{IPBlock: &v1.NetworkIPBlock{CIDR: "invalid"}}},
	}}}
	st := e.getState("home")
	st.Spec.Runtime = &v1.RuntimeDefaults{Network: bad}
	st.Generation++
	e.must(e.c.Update(e.ctx, st))

	e.run(e.state, ns, "home")
	st = e.getState("home")
	if st.Status.Phase != v1.StateReady {
		t.Fatalf("invalid inherited policy changed the committed state phase: %+v", st.Status)
	}
	for _, field := range []struct{ name, value string }{
		{"message", st.Status.Message},
		{"lastError", st.Status.LastError},
	} {
		if !strings.Contains(field.value, "state network") || !strings.Contains(field.value, "invalid") {
			t.Errorf("state %s = %q, want the inherited network error", field.name, field.value)
		}
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "InvalidConfiguration") ||
			!strings.Contains(event, "state network") {
			t.Errorf("event = %q, want a Warning InvalidConfiguration naming the state network", event)
		}
	default:
		t.Fatal("no Warning Event for the invalid inherited network policy")
	}
	// The error is recorded once, not republished on every reconcile.
	e.run(e.state, ns, "home")
	select {
	case event := <-recorder.Events:
		t.Errorf("invalid policy republished an Event: %q", event)
	default:
	}

	// Repairing the state clears both diagnostics.
	st = e.getState("home")
	st.Spec.Runtime = nil
	st.Generation++
	e.must(e.c.Update(e.ctx, st))
	e.run(e.state, ns, "home")
	st = e.getState("home")
	if st.Status.Message != "" || st.Status.LastError != "" {
		t.Fatalf("repaired state still reports message=%q lastError=%q", st.Status.Message, st.Status.LastError)
	}

	// An invalid inherited policy must not keep a deleted state around.
	st = e.getState("home")
	st.Spec.Runtime = &v1.RuntimeDefaults{Network: bad}
	st.Generation++
	e.must(e.c.Update(e.ctx, st))
	e.must(e.c.Delete(e.ctx, st))
	e.run(e.state, ns, "home")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &v1.BlipState{}); err == nil {
		t.Fatal("invalid inherited network policy blocked state deletion")
	}
}
