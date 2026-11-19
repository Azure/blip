// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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

// ownedMountBorrower sets up a durable root and a writable mount state owned by
// another Blip, then starts a borrower with the mount attached. It returns the
// borrower and the attachment ID of its writable mount.
func ownedMountBorrower(t *testing.T) (*env, *v1.Blip, string) {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	e.newBlip("owner", withRoot("home"))
	owner := e.getBlip("owner")
	st := e.getState("data")
	// The CLI's owner reference has no controller flag.
	st.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1.GroupVersion.String(),
		Kind:       "Blip",
		Name:       owner.Name,
		UID:        owner.UID,
	}}
	e.must(e.c.Update(e.ctx, st))

	bb := e.startBlip("bb", "n1", withRoot("home"), e.withMount("data", "/data", true))
	m := mountOf(bb, "data")
	if m == nil || !m.Writable || m.AttachmentID == "" {
		t.Fatalf("borrower has no writable mount: %+v", bb.Status.Mounts)
	}
	e.observe(bb.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{
		ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted,
	}}})
	e.run(e.blip, ns, "bb")
	bb = e.getBlip("bb")
	if m = mountOf(bb, "data"); m == nil || m.Phase != v1.MountMounted {
		t.Fatalf("writable mount did not attach: %+v", bb.Status.Mounts)
	}
	return e, bb, m.AttachmentID
}

// TestBorrowedWritableMountDeletionFailsRunningBlip mirrors the borrowed-root
// case for a writable mount. Deleting the mount's owner removes the data the
// borrower is writing, so the borrower must stop and fail the save instead of
// reporting Succeeded and leaving the mount marked Mounted.
func TestBorrowedWritableMountDeletionFailsRunningBlip(t *testing.T) {
	e, bb, mountID := ownedMountBorrower(t)

	// The owner Blip's deletion (or TTL) removes its mount state through the
	// owner reference while bb is still writing.
	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.run(e.blip, ns, "bb")
	if bb = e.getBlip("bb"); !bb.Spec.Stop {
		t.Fatalf("borrower kept running for a deleted mount: %+v", bb.Status)
	}
	if !strings.Contains(bb.Status.Message, "being deleted") {
		t.Fatalf("borrower has no mount deletion message: %+v", bb.Status)
	}

	e.observe(bb.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	// The root save still succeeds; only the owner-deleted mount is doomed.
	e.saveWriter("home", newID())
	e.run(e.blip, ns, "bb")
	bb = e.getBlip("bb")
	expectPhase(t, bb, v1.BlipFailed, ReasonSaveFailed)
	if !strings.Contains(bb.Status.Message, "deleted by its owner") {
		t.Fatalf("borrower has no clear failure message: %+v", bb.Status)
	}
	if m := mountOf(bb, "data"); m == nil || m.Phase != v1.MountFailed {
		t.Fatalf("deleted mount not reported as failed: %+v", bb.Status.Mounts)
	}

	// The node stops the VM and seals the doomed mount; once the root no
	// longer names the state, its finalizer must clear.
	e.seal("data", "n1", v1.SealResult{AttachmentID: mountID, CommitID: newID()})
	root := e.getState("home")
	root.Spec.Mounts = nil
	root.Generation++
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "data")
	st := &v1.BlipState{}
	err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "data"}, st)
	if err == nil && len(st.Finalizers) != 0 {
		t.Fatalf("terminating mount state still held: %v", st.Finalizers)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}

// TestTerminatingWritableMountDoesNotWedgeOwnerDeletion covers an idle borrower
// (for example sleep infinity). It must be stopped when its writable mount's
// owner deletes the state; otherwise the writer slot pins the state finalizer
// forever.
func TestTerminatingWritableMountDoesNotWedgeOwnerDeletion(t *testing.T) {
	e, bb, mountID := ownedMountBorrower(t)

	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.run(e.blip, ns, "bb")
	bb = e.getBlip("bb")
	if !bb.Spec.Stop {
		t.Fatalf("idle borrower kept the terminating mount open: %+v", bb.Status)
	}
	if bb.Annotations[v1.AnnotationStopReason] != reasonStateDeleting {
		t.Fatalf("borrower stop reason %q, want %q", bb.Annotations[v1.AnnotationStopReason], reasonStateDeleting)
	}

	// The idle command never ends on its own; the node applies the stop.
	e.observe(bb.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.saveWriter("home", newID())
	e.run(e.blip, ns, "bb")
	expectPhase(t, e.getBlip("bb"), v1.BlipFailed, ReasonSaveFailed)
	e.seal("data", "n1", v1.SealResult{AttachmentID: mountID, CommitID: newID()})
	root := e.getState("home")
	root.Spec.Mounts = nil
	root.Generation++
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "data")
	st := &v1.BlipState{}
	err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "data"}, st)
	if err == nil && len(st.Finalizers) != 0 {
		t.Fatalf("terminating mount state still wedged: %v", st.Finalizers)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}
