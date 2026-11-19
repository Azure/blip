package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// ownedBy makes state owned by the named Blip, like the CLI's --from fork.
func (e *env) ownedBy(state, blip string) {
	e.t.Helper()
	b := e.getBlip(blip)
	st := e.getState(state)
	st.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1.GroupVersion.String(),
		Kind:       "Blip",
		Name:       b.Name,
		UID:        b.UID,
	}}
	e.must(e.c.Update(e.ctx, st))
}

// TestDirectlyDeletedRootFailsRunningBlip covers deleting the workspace a
// running Blip writes to without deleting the Blip itself: an owner may remove
// its own root, a durable workspace has no owner at all, and kubectl can
// delete either directly. In every case the deletion removes the data the save
// would commit, so the Blip must stop and fail the save instead of reporting
// Succeeded for a discarded result.
func TestDirectlyDeletedRootFailsRunningBlip(t *testing.T) {
	for _, owned := range []bool{true, false} {
		name := "durable"
		if owned {
			name = "owned"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			e.readyState("home", "n1")
			b := e.startBlip("job", "n1", withRoot("home"))
			if owned {
				e.ownedBy("home", "job")
			}

			e.must(e.c.Delete(e.ctx, e.getState("home")))
			e.run(e.blip, ns, "job")
			b = e.getBlip("job")
			if !b.Spec.Stop {
				t.Fatalf("running Blip kept writing to a deleted workspace: %+v", b.Status)
			}
			if b.Annotations[v1.AnnotationStopReason] != reasonStateDeleting {
				t.Fatalf("stop reason %q, want %q", b.Annotations[v1.AnnotationStopReason], reasonStateDeleting)
			}
			if !strings.Contains(b.Status.Message, "being deleted") {
				t.Fatalf("no deletion message: %+v", b.Status)
			}

			// The node applies the stop and reports the exit.
			e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
			e.run(e.blip, ns, "job")
			b = e.getBlip("job")
			expectPhase(t, b, v1.BlipFailed, ReasonSaveFailed)
			if !strings.Contains(b.Status.Message, "save was discarded") {
				t.Fatalf("no discarded-save message: %q", b.Status.Message)
			}
		})
	}
}

// TestPendingVanishedRootFailsFast covers deleting the workspace of a Pending
// Blip that is waiting for a VM. Once the state is fully gone, the root cannot
// come back, so the Blip must fail at once instead of parking until the
// pending timeout with an unrelated StartTimeout.
func TestPendingVanishedRootFailsFast(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)

	// Remove the state completely: it has no writer or finalizer to keep it.
	st := e.getState("home")
	st.Finalizers = nil
	e.must(e.c.Update(e.ctx, st))
	e.must(e.c.Delete(e.ctx, st))

	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonStateNotFound)
	if !strings.Contains(b.Status.Message, "deleted") {
		t.Fatalf("no deletion message: %+v", b.Status)
	}
	if b.Status.RootStateUID == "" {
		t.Fatalf("pending Blip did not record its root: %+v", b.Status)
	}
}

// TestDirectlyDeletedWritableMountFailsRunningBlip mirrors the root case for a
// writable mount whose state is durable (no owner references). Saving must not
// mark the doomed mount Mounted and report success for its discarded save.
func TestDirectlyDeletedWritableMountFailsRunningBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("job", "n1", withRoot("home"), e.withMount("data", "/data", true))
	m := mountOf(b, "data")
	if m == nil || !m.Writable || m.AttachmentID == "" {
		t.Fatalf("no writable mount: %+v", b.Status.Mounts)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{
		ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted,
	}}})
	e.run(e.blip, ns, "job")
	if m = mountOf(e.getBlip("job"), "data"); m == nil || m.Phase != v1.MountMounted {
		t.Fatalf("writable mount did not attach: %+v", e.getBlip("job").Status.Mounts)
	}

	// The durable mount is deleted directly. Its data is gone even though this
	// Blip's root save can still commit.
	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	if !b.Spec.Stop {
		t.Fatalf("running Blip kept writing to a deleted mount: %+v", b.Status)
	}
	if !strings.Contains(b.Status.Message, "being deleted") {
		t.Fatalf("no mount deletion message: %+v", b.Status)
	}

	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.saveWriter("home", newID())
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonSaveFailed)
	if !strings.Contains(b.Status.Message, "save was discarded") {
		t.Fatalf("no discarded-save message: %q", b.Status.Message)
	}
	if m = mountOf(b, "data"); m == nil || m.Phase != v1.MountFailed {
		t.Fatalf("deleted mount not reported as failed: %+v", b.Status.Mounts)
	}
}
