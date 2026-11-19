// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"slices"
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// imageOnNode makes the image state "img" ready on the only node its selector
// matches, leaving every other eligible node without a placement.
func imageOnNode(e *env, node string) {
	e.t.Helper()
	e.label("zone", "a", node)
	e.newState("img", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 0
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "img")
	p := e.getState("img").Status.Pending
	if p == nil || !slices.Equal(p.Replicas, []string{node}) {
		e.t.Fatalf("pending %+v, want the image on %s", p, node)
	}
	e.hold("img", p.CommitID, node)
	e.run(e.state, ns, "img")
	if st := e.getState("img"); st.Status.Phase != v1.StateReady {
		e.t.Fatalf("state %+v, want ready", st.Status)
	}
}

// Imported states are immutable templates. Even an available warm VM cannot
// be claimed until the caller forks the template into a writable root.
func TestImportedRootRequiresForkBeforeClaimingWarmVM(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n2")
	imageOnNode(e, "n1")

	e.newBlip("b", withRoot("img"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipFailed, ReasonInvalidSpec)
	if b.Status.Pod != "" || b.Status.Node != "" || !strings.Contains(b.Status.Message, "fork") {
		t.Fatalf("imported root consumed a VM instead of requiring a fork: %+v", b.Status)
	}
	if e.getState("img").Status.Writer != nil {
		t.Fatal("imported template acquired a writer")
	}
	e.run(e.pool, ns, "default")
	if pods := e.pods(); len(pods) != 1 || !isVacant(&pods[0]) || pods[0].Spec.NodeName != "n2" {
		t.Fatalf("imported root consumed or replaced the warm VM: %+v", pods)
	}
}

// A forked root retains its data locality even with a shared image mounted
// read-only. It waits for a VM on the copy's node.
func TestCopiedStateStillWaitsForLocalVM(t *testing.T) {
	e, home, away := localSetup(t, 1, 0)
	imageOnNode(e, home)
	e.newState("copy", func(st *v1.BlipState) {
		st.Spec.CopyFrom, st.Spec.Replicas = "img", 1
		st.Spec.Mounts = []v1.Mount{{State: "img", Path: "/base"}}
	})
	e.run(e.state, ns, "copy")
	p := e.getState("copy").Status.Pending
	e.hold("copy", p.CommitID, p.Replicas...)
	e.run(e.state, ns, "copy")
	e.newBlip("b", withRoot("copy"))

	res := e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if loc := b.Status.Locality; loc == nil || loc.Node != home || loc.Fallback {
		t.Fatalf("locality %+v, want %s", loc, home)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > localWait {
		t.Fatalf("requeue after %v, want to wait for a VM on %s", res.RequeueAfter, home)
	}
	// The warm VM on the other node is not claimed while the local wait runs.
	if b.Status.Pod != "" || b.Status.Node != "" {
		t.Fatalf("claimed %s/%s away from the data on %s", b.Status.Node, b.Status.Pod, away)
	}
}

// An invalid direct-image execution must not create demand VMs, either before
// or after the Blip controller rejects its immutable root.
func TestImportedRootDoesNotCreatePoolDemand(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.newState("img", func(st *v1.BlipState) { st.Spec.Image, st.Spec.Replicas = "reg/img:v1", 0 })
	e.newBlip("b", withRoot("img"))

	e.run(e.pool, ns, "default")
	if pods := e.pods(); len(pods) != 0 {
		t.Fatalf("%d pods booted before validating the imported root", len(pods))
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonInvalidSpec)
	e.run(e.pool, ns, "default")
	if pods := e.pods(); len(pods) != 0 {
		t.Fatalf("%d pods booted for an invalid immutable root", len(pods))
	}
}
