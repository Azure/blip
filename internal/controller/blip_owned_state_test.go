package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// TestBorrowedStateDeletionFailsRunningBlip covers deleting the Blip that owns
// a workspace while another Blip runs in it via --state. The borrower must not
// report a successful save for data the owner's deletion is about to remove.
func TestBorrowedStateDeletionFailsRunningBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("owner", withRoot("home"))
	owner := e.getBlip("owner")
	st := e.getState("home")
	// The CLI's owner reference has no controller flag.
	st.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1.GroupVersion.String(),
		Kind:       "Blip",
		Name:       owner.Name,
		UID:        owner.UID,
	}}
	e.must(e.c.Update(e.ctx, st))

	bb := e.startBlip("bb", "n1", withRoot("home"))

	// The owner Blip's deletion (or TTL) removes its state through the owner
	// reference while bb is still writing.
	e.must(e.c.Delete(e.ctx, e.getState("home")))
	e.run(e.blip, ns, "bb")
	if bb = e.getBlip("bb"); !bb.Spec.Stop {
		t.Fatalf("borrower kept running for a deleted workspace: %+v", bb.Status)
	}
	if !strings.Contains(bb.Status.Message, "being deleted") {
		t.Fatalf("borrower has no deletion message: %+v", bb.Status)
	}

	e.observe(bb.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "bb")
	bb = e.getBlip("bb")
	if bb.Status.Phase != v1.BlipFailed || bb.Status.Reason != ReasonSaveFailed {
		t.Fatalf("borrower did not fail: %+v", bb.Status)
	}
	if !strings.Contains(bb.Status.Message, "deleted by its owner") {
		t.Fatalf("borrower has no clear failure message: %+v", bb.Status)
	}
}
