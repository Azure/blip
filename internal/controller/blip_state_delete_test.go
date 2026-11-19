package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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

// TestPendingRecreatedRootFailsFast covers a root state deleted and recreated
// under the same name while the Blip is Pending. The new object is a different
// workspace: the Blip must fail instead of claiming a VM, running its command
// and committing into data it never saw.
func TestPendingRecreatedRootFailsFast(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	old := b.Status.RootStateUID
	if old == "" {
		t.Fatalf("pending Blip did not record its root: %+v", b.Status)
	}

	// Remove the original completely, then create a different state under the
	// same name before the next reconcile.
	st := e.getState("home")
	st.Finalizers = nil
	e.must(e.c.Update(e.ctx, st))
	e.must(e.c.Delete(e.ctx, st))
	e.readyState("home", "n1")
	recreated := string(e.getState("home").UID)
	if recreated == old {
		t.Fatalf("recreated state kept UID %q", old)
	}

	// A warm VM is now available, so only the UID check stands between this
	// Blip and running in the substituted workspace.
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "job")

	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonStateNotFound)
	if !strings.Contains(b.Status.Message, "replaced") || !strings.Contains(b.Status.Message, "substituted workspace") {
		t.Fatalf("unclear replacement message: %q", b.Status.Message)
	}
	if b.Status.RootStateUID != old {
		t.Fatalf("rootStateUID changed to %q, want the original %q", b.Status.RootStateUID, old)
	}
}

// TestPendingMatchingRootUIDStarts is the control for
// TestPendingRecreatedRootFailsFast: the same root object must still start the
// Blip normally.
func TestPendingMatchingRootUIDStarts(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	uid := b.Status.RootStateUID
	if uid == "" || uid != string(e.getState("home").UID) {
		t.Fatalf("rootStateUID %q does not name the live root %q", uid, e.getState("home").UID)
	}

	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "job")

	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Pod == "" {
		t.Fatalf("Blip did not claim a VM: %+v", b.Status)
	}
	if b.Status.RootStateUID != uid {
		t.Fatalf("rootStateUID changed from %q to %q", uid, b.Status.RootStateUID)
	}
}

// TestDirectlyDeletedWritableMountFailsRunningBlip mirrors the root case for a
// writable mount whose state is durable (no owner references). Saving must not
// mark the doomed mount Mounted and report success for its discarded save.
// TestDirectlyDeletedReadOnlyMountStopsRunningBlip covers a read-only
// attachment pinning a deleting state forever. The platform can hot-remove a
// read-only disk, so the reader must be stopped with a clear reason instead of
// silently staying Running while the state's finalizer waits for it.
func TestDirectlyDeletedReadOnlyMountStopsRunningBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("job", "n1", withRoot("home"), e.withMount("data", "/data", false))
	m := mountOf(b, "data")
	if m == nil || m.Writable || m.AttachmentID == "" {
		t.Fatalf("no attached read-only mount: %+v", b.Status.Mounts)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{
		ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted,
	}}})
	e.run(e.blip, ns, "job")
	if m = mountOf(e.getBlip("job"), "data"); m == nil || m.Phase != v1.MountMounted {
		t.Fatalf("read-only mount did not attach: %+v", e.getBlip("job").Status.Mounts)
	}

	// Deleting the source is blocked by the attachment until the reader
	// lets go.
	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.run(e.state, ns, "data")
	if st := e.getState("data"); !strings.Contains(st.Status.Message, "blip job") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked by the reader: %+v", st.Status)
	}

	// The reader is told and stopped instead of remaining silently Running.
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	if !b.Spec.Stop {
		t.Fatalf("reader kept a deleted read-only mount: %+v", b.Status)
	}
	if b.Annotations[v1.AnnotationStopReason] != reasonStateDeleting {
		t.Fatalf("stop reason %q, want %q", b.Annotations[v1.AnnotationStopReason], reasonStateDeleting)
	}
	if !strings.Contains(b.Status.Message, "being deleted") {
		t.Fatalf("no deletion message: %+v", b.Status)
	}

	// The node applies the stop; the read-only attachment no longer blocks
	// the state's finalizer.
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.saveWriter("home", newID())
	e.run(e.blip, ns, "job")
	expectPhase(t, e.getBlip("job"), v1.BlipSucceeded, ReasonStopped)
	e.run(e.state, ns, "data")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "data"}, &v1.BlipState{}); err == nil {
		t.Fatal("state not deleted after the read-only reader stopped")
	}
}

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
func TestPendingVanishedMountFailsFast(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data"}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	// The mount is fully gone before the Blip is created, as when a forked
	// root keeps a dangling read-only reference.
	st := e.getState("data")
	st.Finalizers = nil
	e.must(e.c.Update(e.ctx, st))
	e.must(e.c.Delete(e.ctx, st))

	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonStateNotFound)
	if !strings.Contains(b.Status.Message, "deleted") {
		t.Fatalf("no deletion message: %+v", b.Status)
	}
	if b.Status.RootStateUID == "" {
		t.Fatalf("pending Blip did not record its root: %+v", b.Status)
	}
}

// TestPendingValidMountWaitsForVM guards the reverse case: an existing mount
// must not be mistaken for a deletion and must keep the Blip pending normally.
func TestPendingValidMountWaitsForVM(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	e.newBlip("job", withRoot("home"), e.withMount("data", "/data", false))
	e.run(e.blip, ns, "job")
	expectPhase(t, e.getBlip("job"), v1.BlipPending, ReasonWaitingForVM)
}

// TestPendingForkMountLaunchWindowWaits covers the legitimate launch race: the
// CLI creates the Blip before workspace.Fork creates the workspace. Fork
// creates mount children before the root, so a missing root (and therefore a
// missing mount) still waits instead of failing as a deletion.
func TestPendingForkMountLaunchWindowWaits(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("job", withRoot("fork"))
	e.run(e.blip, ns, "job")
	expectPhase(t, e.getBlip("job"), v1.BlipPending, ReasonStateNotFound)

	// Fork's order: mount children first, root last.
	e.readyState("fork-m", "n1")
	e.newState("fork", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.Mounts = []v1.Mount{{State: "fork-m", Path: "/mnt"}}
	})
	e.run(e.state, ns, "fork")
	st := e.getState("fork")
	if st.Status.Pending == nil {
		t.Fatalf("fork root has no pending version: %+v", st.Status)
	}
	e.hold("fork", st.Status.Pending.CommitID, st.Status.Pending.Replicas...)
	e.run(e.state, ns, "fork")

	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	if b.Status.RootStateUID == "" {
		t.Fatalf("pending Blip did not record its root: %+v", b.Status)
	}
}

// TestDirectlyDeletedWritableMountFailsRunningBlip mirrors the root case for a
// writable mount whose state is durable (no owner references). Saving must not
// mark the doomed mount Mounted and report success for its discarded save.
