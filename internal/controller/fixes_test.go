package controller

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

func (e *env) annotatePod(name, key, value string) {
	e.t.Helper()
	p := e.getPod(name)
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[key] = value
	e.must(e.c.Update(e.ctx, p))
}

// storeSeal records a seal result in a state's status, like the controller
// does when it processes nodes[node].sealed.
func (e *env) storeSeal(state string, sr v1.SealResult) {
	e.t.Helper()
	st := e.getState(state)
	base := st.DeepCopy()
	e.must(e.state.recordSeal(e.ctx, st, sr))
	e.must(patchStatus(e.ctx, e.c, st, base))
}

// TestRemovedFailedMountIsForgotten covers a mount that failed before it
// attached: removing it from the spec drops its failed status entry so the
// Blip can mount the state again at another path.
func TestRemovedFailedMountIsForgotten(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1")
	e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	e.updateRoot("b", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "data"}}
	})
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	m := mountOf(b, "data")
	if m != nil || !strings.Contains(b.Status.Message, "not absolute") {
		t.Fatalf("failed attach %+v", m)
	}

	// Dropping the failed mount from the spec drops its status entry.
	e.updateRoot("b", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if m = mountOf(b, "data"); m != nil {
		t.Fatalf("removed failed mount stayed visible: %+v", m)
	}

	// The same state can be mounted at a different, valid path.
	e.updateRoot("b", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data"}}
	})
	e.run(e.blip, ns, "b")
	if m = mountOf(e.getBlip("b"), "data"); m == nil || m.Phase != v1.MountPending || m.Path != "/data" {
		t.Fatalf("remounted state %+v", m)
	}
}

// TestRemovedMountSaveFailureStaysVisible covers A: a save failure of a mount
// that was removed from the spec keeps its status entry and fails the Blip.
func TestRemovedMountSaveFailureStaysVisible(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1")
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	e.updateRoot("b", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	m := mountOf(b, "data")
	if m == nil || m.Phase != v1.MountPending {
		t.Fatalf("acquired mount %+v", m)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted},
	}})
	e.run(e.blip, ns, "b")
	if m = mountOf(e.getBlip("b"), "data"); m.Phase != v1.MountMounted {
		t.Fatalf("mounted mount %+v", m)
	}

	// Remove it: the mount is unmounted and then saved.
	e.updateRoot("b", func(b *v1.BlipState) { b.Spec.Mounts = nil })
	e.run(e.blip, ns, "b")
	if m = mountOf(e.getBlip("b"), "data"); m == nil || m.Phase != v1.MountUnmounting {
		t.Fatalf("after removal %+v", m)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{
		{ID: m.AttachmentID, State: "data", Phase: podapi.DiskDetached},
	}})
	e.run(e.blip, ns, "b")
	if m = mountOf(e.getBlip("b"), "data"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("after detach %+v", m)
	}

	e.seal("data", "n1", v1.SealResult{AttachmentID: m.AttachmentID, Error: "filesystem needs recovery"})
	e.run(e.state, ns, "data")
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipFailed, ReasonSaveFailed)
	if m = mountOf(b, "data"); m == nil || m.Phase != v1.MountFailed || !strings.Contains(m.Message, "save failed") {
		t.Fatalf("failed mount disappeared: %+v", m)
	}
}

// A failed root seal stays visible while every other attachment finishes its
// save. Deletion must not discard a still-saving execution's mount records.
func TestStopSaveErrorNotLostWhileOtherMountSaving(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("b", "n1", withRoot("home"), e.withMount("data", "/data", true))

	e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	expectPhase(t, b, v1.BlipSaving, "")

	e.seal("home", "n1", v1.SealResult{AttachmentID: b.Status.RootAttachmentID, Error: "unclean filesystem"})
	e.run(e.state, ns, "home")
	if w := e.getState("data").Status.Writer; w == nil {
		t.Fatal("mount writer cleared before the test seal")
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, ReasonSaveFailed)
	if m := mountOf(e.getBlip("b"), "data"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("saving attachment lost: %+v", m)
	}
	e.saveWriter("data", newID())
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonSaveFailed)
}

// TestSealHistoryPerAttachment covers B: a later seal of another attachment
// does not hide an earlier failure, and pruning keeps results a Blip still
// references.
func TestSealHistoryPerAttachment(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("s", "n1")
	const failed, ok = "1111111111111111", "2222222222222222"

	e.storeSeal("s", v1.SealResult{AttachmentID: failed, Error: "seal failed"})
	e.storeSeal("s", v1.SealResult{AttachmentID: ok, CommitID: "c2c2c2c2c2c2c2c2"})

	done, msg, err := e.blip.attachment(e.ctx, ns, "s", failed)
	if err != nil || !done || msg != "seal failed" {
		t.Fatalf("failed seal: done=%v msg=%q err=%v", done, msg, err)
	}
	done, msg, err = e.blip.attachment(e.ctx, ns, "s", ok)
	if err != nil || !done || msg != "" {
		t.Fatalf("successful seal: done=%v msg=%q err=%v", done, msg, err)
	}
	done, msg, err = e.blip.attachment(e.ctx, ns, "s", "3333333333333333")
	if err != nil || !done || msg == "" {
		t.Fatalf("unknown seal reported success: done=%v msg=%q err=%v", done, msg, err)
	}

	// A Blip referencing an old attachment keeps its seal result while
	// unrelated results are pruned.
	e.newBlip("old", withRoot("s"))
	e.updateBlipStatus("old", func(b *v1.Blip) { b.Status.RootAttachmentID = failed })
	for i := range 40 {
		e.storeSeal("s", v1.SealResult{AttachmentID: fmt.Sprintf("%016d", i), CommitID: fmt.Sprintf("%016d", i)})
	}
	st := e.getState("s")
	if !slices.ContainsFunc(st.Status.Seals, func(sr v1.SealResult) bool { return sr.AttachmentID == failed }) {
		t.Fatal("referenced seal was pruned")
	}
	if len(st.Status.Seals) > maxSeals || len(st.Status.Seals) > recentSeals+1 {
		t.Fatalf("pruned seals %d", len(st.Status.Seals))
	}
}

func (e *env) updateBlipStatus(name string, mutate func(*v1.Blip)) {
	e.t.Helper()
	b := e.getBlip(name)
	mutate(b)
	e.must(e.c.Status().Update(e.ctx, b))
}

// A live owner's serialized reconcile releases unused reservations. The state
// controller cannot distinguish these from acquire-to-publish work in flight.
func TestUnpublishedWriterReleased(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("data", "n1")
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	e.updateRoot("b", func(b *v1.BlipState) {
		b.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	})
	e.updateRoot("b", func(b *v1.BlipState) { b.Spec.Mounts = nil })

	st := e.getState("data")
	base := st.DeepCopy()
	st.Status.Writer = &v1.Writer{
		AttachmentID: "4444444444444444",
		BlipName:     b.Name,
		BlipUID:      string(b.UID),
		PodName:      b.Status.Pod,
		PodUID:       b.Status.PodUID,
		Node:         "n1",
		BaseCommit:   st.Status.Committed.ID,
	}
	e.must(patchStatus(e.ctx, e.c, st, base))

	e.run(e.state, ns, "data")
	st = e.getState("data")
	if st.Status.Writer == nil {
		t.Fatal("state controller released a possibly publishing writer")
	}
	e.run(e.blip, ns, "b")
	st = e.getState("data")
	if st.Status.Writer != nil {
		t.Fatalf("unpublished writer kept: %+v", st.Status.Writer)
	}
}

// TestPendingSourceFailover covers E: a pending version whose source lost the
// commit switches to a healthy replica that holds it.
func TestPendingSourceFailover(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.readyState("s", "n1", "n2")
	const pending = "c2c2c2c2c2c2c2c2"

	st := e.getState("s")
	base := st.DeepCopy()
	st.Status.Pending = &v1.PendingCommit{
		CommitID:     pending,
		Generation:   2,
		SourceNode:   "n1",
		AttachmentID: "5555555555555555",
		Replicas:     []string{"n1", "n2"},
	}
	e.must(patchStatus(e.ctx, e.c, st, base))
	e.hold("s", pending, "n2")
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending == nil || st.Status.Pending.SourceNode != "n2" {
		t.Fatalf("pending source did not fail over: %+v", st.Status.Pending)
	}
	if slices.Contains(st.Status.Pending.Replicas, "n1") {
		t.Errorf("deleted source still a replica: %v", st.Status.Pending.Replicas)
	}
}

func TestImagePendingSourceFailover(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1" })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || p.SourceNode != "n1" {
		t.Fatalf("initial pending %+v", p)
	}
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))
	e.run(e.state, ns, "s")
	p = e.getState("s").Status.Pending
	if p == nil || p.SourceNode == "n1" || slices.Contains(p.Replicas, "n1") {
		t.Fatalf("source failover %+v", p)
	}
}

// TestCopyResolvesRemoteAndKeepsImageConfig covers F: copies may be placed on
// nodes that do not hold the source, and carry its image config.
func TestCopyResolvesRemoteAndKeepsImageConfig(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.label("zone", "a", "n1")
	e.newState("src", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "src")
	src := e.getState("src")
	if src.Status.Pending == nil {
		t.Fatalf("source pending %+v", src.Status)
	}
	e.hold("src", src.Status.Pending.CommitID, src.Status.Pending.Replicas...)
	e.run(e.state, ns, "src")
	src = e.getState("src")
	if src.Status.ImageConfig == nil || src.Status.ImageConfig.WorkingDir != "/w" {
		t.Fatalf("image state config %+v", src.Status.ImageConfig)
	}

	// The only node holding the source cannot take the copy; a remote copy
	// must still be planned.
	e.setDrain("n1")
	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "src"; st.Spec.Replicas = 1 })
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.Pending == nil || cp.Status.Pending.SourceNode != "n2" {
		t.Fatalf("remote copy pending %+v", cp.Status)
	}
	if cp.Status.ImageConfig == nil || cp.Status.ImageConfig.WorkingDir != "/w" {
		t.Fatalf("copy did not keep image config: %+v", cp.Status.ImageConfig)
	}
	e.hold("cp", cp.Status.Pending.CommitID, cp.Status.Pending.Replicas...)
	e.run(e.state, ns, "cp")
	if cp = e.getState("cp"); cp.Status.Phase != v1.StateReady {
		t.Fatalf("remote copy not ready %+v", cp.Status)
	}
}

// TestDeletePendingInitialState covers G: deleting a pending initial version
// removes the finalizer instead of waiting for nodes forever.
func TestDeletePendingInitialState(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1" })
	e.run(e.state, ns, "s")
	if e.getState("s").Status.Pending == nil {
		t.Fatal("no pending initial version")
	}
	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	err := e.c.Get(e.ctx, req(ns, "s").NamespacedName, &v1.BlipState{})
	if err == nil {
		t.Fatal("state with a pending initial version was not deleted")
	}
}

func TestImageBuildErrorFailsStateAndDeletes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1" })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	e.report("s", "n1", func(o *v1.NodeObservation) {
		o.Error = "storage: image sha256:aaaa needs more bytes than the requested size"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || !strings.Contains(st.Status.Message, "needs more bytes") {
		t.Fatalf("node error not surfaced: %+v", st.Status)
	}
	if !strings.Contains(st.Status.LastError, "needs more bytes") {
		t.Errorf("lastError %q", st.Status.LastError)
	}
	e.must(e.c.Delete(e.ctx, st))
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, req(ns, "s").NamespacedName, &v1.BlipState{}); err == nil {
		t.Fatal("failed state not deleted")
	}
}

// TestWarmPodsSkipUnhealthyNodes covers H.
func TestWarmPodsSkipUnhealthyNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 2, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n2", "n1")

	e.now = e.now.Add(61 * time.Second)
	e.heartbeat("n2")
	e.newBlip("b", e.withImage("reg/img:v1"))

	pods := e.warmPods("b", nil)
	if len(pods) != 1 || pods[0].Spec.NodeName != "n1" {
		t.Fatalf("warm pods %+v", pods)
	}
	e.run(e.blip, ns, "b")
	if b := e.getBlip("b"); b.Status.Node != "n1" {
		t.Fatalf("claimed on %q", b.Status.Node)
	}
}

// TestStartingTimeouts covers I.
func TestStartingTimeouts(t *testing.T) {
	t.Run("prepare error", func(t *testing.T) {
		e := newEnv(t)
		e.addNodes("n1")
		e.newPool("default", 1, 0)
		e.run(e.pool, ns, "default")
		e.warmOn("n1")
		pod := e.pods()[0]
		e.observe(pod.Name, podapi.Observed{Phase: podapi.PhaseWarm})
		e.annotatePod(pod.Name, v1.AnnotationPrepareError, "disk resize failed")

		e.newBlip("b", e.withImage("reg/img:v1"))
		res := e.run(e.blip, ns, "b")
		if res.RequeueAfter <= 0 || res.RequeueAfter > startTimeout {
			t.Errorf("start deadline requeue %v", res.RequeueAfter)
		}
		b := e.getBlip("b")
		expectPhase(t, b, v1.BlipPending, ReasonPrepareFailed)
		if !strings.Contains(b.Status.Message, "disk resize failed") {
			t.Fatalf("message %q", b.Status.Message)
		}
		e.now = e.now.Add(startTimeout + time.Minute)
		e.run(e.blip, ns, "b")
		b = e.getBlip("b")
		expectPhase(t, b, v1.BlipFailed, ReasonPrepareFailed)
		if !strings.Contains(b.Status.Message, "timed out") {
			t.Fatalf("message %q", b.Status.Message)
		}
	})

	t.Run("claimed vm", func(t *testing.T) {
		e := newEnv(t)
		e.addNodes("n1")
		e.newPool("default", 1, 0)
		e.run(e.pool, ns, "default")
		e.warmOn("n1")
		e.observe(e.pods()[0].Name, podapi.Observed{Phase: podapi.PhaseWarm})
		e.newBlip("b", e.withImage("reg/img:v1"))
		res := e.run(e.blip, ns, "b")
		if res.RequeueAfter <= 0 || res.RequeueAfter > startTimeout {
			t.Errorf("start deadline requeue %v", res.RequeueAfter)
		}
		expectPhase(t, e.getBlip("b"), v1.BlipPending, ReasonStarting)
		e.now = e.now.Add(startTimeout + time.Minute)
		e.run(e.blip, ns, "b")
		expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonStartTimeout)
	})

	t.Run("no vm", func(t *testing.T) {
		e := newEnv(t)
		e.addNodes("n1")
		e.newPool("default", 0, 0)
		e.newBlip("b", e.withImage("reg/img:v1"))
		res := e.run(e.blip, ns, "b")
		if res.RequeueAfter <= 0 || res.RequeueAfter > pendingTimeout {
			t.Errorf("pending deadline requeue %v", res.RequeueAfter)
		}
		expectPhase(t, e.getBlip("b"), v1.BlipPending, ReasonWaitingForVM)
		e.now = e.now.Add(pendingTimeout + time.Minute)
		e.run(e.blip, ns, "b")
		expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonStartTimeout)
	})
}

// TestDrainStopsBlips covers J.
func TestDrainStopsBlips(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))

	e.setDrain("n1")
	e.run(e.node, "", "n1")
	if b = e.getBlip("b"); !b.Spec.Stop {
		t.Fatal("drain did not stop the running blip")
	}
	if e.safeToRemove("n1") {
		t.Fatal("node with a running claimed blip is safe to remove")
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, "")
	e.saveWriter(b.Spec.State, newID())
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	if e.safeToRemove("n1") {
		t.Fatal("node with the only durable root replica is safe to remove")
	}
	e.must(e.c.Delete(e.ctx, e.getState(b.Spec.State)))
	e.run(e.state, ns, b.Spec.State)
	if !e.safeToRemove("n1") {
		t.Fatal("drained node with no blip or state left is not safe to remove")
	}
}

// TestPendingCommitLostWhenSourceDeleted covers E's bounded failure: a
// pending save whose source node is gone and whose commit no replica holds
// is dropped with a seal error instead of waiting forever.
func TestPendingCommitLostWhenSourceDeleted(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	const pending = "c3c3c3c3c3c3c3c3"

	st := e.getState("s")
	base := st.DeepCopy()
	st.Status.Pending = &v1.PendingCommit{
		CommitID:     pending,
		Generation:   2,
		SourceNode:   "n1",
		AttachmentID: "6666666666666666",
		Replicas:     []string{"n1", "n2"},
	}
	e.must(patchStatus(e.ctx, e.c, st, base))
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil {
		t.Fatalf("lost pending version kept: %+v", st.Status.Pending)
	}
	if !strings.Contains(st.Status.Message, "lost") {
		t.Fatalf("message %q", st.Status.Message)
	}
	if !slices.ContainsFunc(st.Status.Seals, func(sr v1.SealResult) bool {
		return sr.AttachmentID == "6666666666666666" && sr.Error != ""
	}) {
		t.Fatalf("lost save has no failure seal: %+v", st.Status.Seals)
	}
}

// TestFinishedBlipClearsSavingMountPhase covers a finished Blip leaving its
// writable mounts marked Saving after their saves committed.
func TestFinishedBlipClearsSavingMountPhase(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("job", "n1", withRoot("home"), e.withMount("data", "/data", true))

	e.updateBlip("job", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSaving, ReasonStopped)
	if m := mountOf(b, "data"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("mount not saving after fencing: %+v", m)
	}

	e.saveWriter("home", newID())
	e.saveWriter("data", newID())
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if m := mountOf(b, "data"); m == nil || m.Phase != v1.MountMounted || m.Message != "" || m.Switching {
		t.Fatalf("finished Blip left mount in saving state: %+v", m)
	}
}

// TestFinishedBlipDropsRemovedWritableMount covers a mount removed while the
// Blip is stopping: its save resolves, but the finished Blip must not keep
// reporting the removed mount as Mounted with an attachment that was sealed.
func TestFinishedBlipDropsRemovedWritableMount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("job", "n1", withRoot("home"), e.withMount("data", "/data", true))

	e.updateBlip("job", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSaving, ReasonStopped)
	if m := mountOf(b, "data"); m == nil || m.Phase != v1.MountSaving {
		t.Fatalf("mount not saving after fencing: %+v", m)
	}

	// The removal lands while the writable mount is still saving.
	e.updateRoot("job", func(root *v1.BlipState) { root.Spec.Mounts = nil })
	e.saveWriter("home", newID())
	e.saveWriter("data", newID())
	e.run(e.blip, ns, "job")

	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if m := mountOf(b, "data"); m != nil {
		t.Fatalf("finished Blip keeps a removed mount: %+v", m)
	}
}

// TestFinishedBlipRetainsCommandOutput covers gather -f for a command that
// ended before the client attached: the tail of the guest-mirrored output is
// saved in status before the pod is deleted.
func TestFinishedBlipRetainsCommandOutput(t *testing.T) {
	e := newEnv(t)
	e.blip.Config.PodLogs = func(context.Context, string, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("boot noise\nblip: FASTOUT\nblip: LASTLINE\nmore noise\n")), nil
	}
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: "b", UID: types.UID("uid-b")},
		Status: v1.BlipStatus{
			Phase: v1.BlipSucceeded, Pod: "pod-b", PodUID: "uid-p",
		},
	}
	e.create(b)
	e.create(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-b", UID: types.UID("uid-p")}})
	b = e.getBlip("b")
	e.must(e.blip.cleanup(e.ctx, b))

	got := e.getBlip("b")
	if got.Status.Output != "FASTOUT\nLASTLINE\n" {
		t.Fatalf("output %q", got.Status.Output)
	}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "pod-b"}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod not deleted: %v", err)
	}
}

// Output beyond the retained bound keeps exactly the newest lines and says
// that earlier output was truncated. The marker is reserved inside the bound.
func TestPodOutputKeepsTailWithTruncationMarker(t *testing.T) {
	e := newEnv(t)
	const count = 65
	line := func(i int) string {
		return fmt.Sprintf("%04d:%s", i, strings.Repeat(string(rune('a'+i%26)), 1018))
	}
	var b strings.Builder
	for i := range count {
		b.WriteString("blip: " + line(i))
		b.WriteByte('\n')
	}
	e.blip.Config.PodLogs = func(context.Context, string, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(b.String())), nil
	}

	out, ok := e.blip.podOutput(e.ctx, ns, "pod")
	if !ok {
		t.Fatal("podOutput reported no output")
	}
	if !strings.HasPrefix(out, outputTruncated) {
		t.Fatalf("output does not start with the truncation marker: %q", out[:min(len(out), 80)])
	}
	if len(out) > maxRetainedOutput {
		t.Fatalf("output is %d bytes, want at most %d", len(out), maxRetainedOutput)
	}
	if !strings.HasSuffix(out, line(count-1)+"\n") {
		t.Fatalf("output does not end with the final line: %q", out[max(0, len(out)-80):])
	}
	body := strings.Split(strings.TrimSuffix(strings.TrimPrefix(out, outputTruncated), "\n"), "\n")
	if len(body) != count-2 {
		t.Fatalf("kept %d lines, want %d", len(body), count-2)
	}
	if body[0] != line(2) {
		t.Fatalf("tail starts at %q, want %q", body[0][:5], line(2)[:5])
	}
	for i, got := range body {
		if want := line(i + 2); got != want {
			t.Fatalf("line %d does not match the command's tail", i+2)
		}
	}
}

// A single line larger than the retained bound still keeps its newest bytes
// (and the truncation marker) instead of being dropped altogether.
func TestPodOutputKeepsTailOfOverlongLine(t *testing.T) {
	e := newEnv(t)
	body := strings.Repeat("x", 3*maxRetainedOutput)
	e.blip.Config.PodLogs = func(context.Context, string, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("blip: " + body + "\n")), nil
	}

	out, ok := e.blip.podOutput(e.ctx, ns, "pod")
	if !ok || out == "" {
		t.Fatal("podOutput dropped the only line")
	}
	if !strings.HasPrefix(out, outputTruncated) || len(out) > maxRetainedOutput {
		t.Fatalf("output is %d bytes with marker %t, want at most %d", len(out), strings.HasPrefix(out, outputTruncated), maxRetainedOutput)
	}
	if len(out) <= len(outputTruncated) {
		t.Fatalf("output kept no bytes of the overlong line: %q", out)
	}
	if rest := strings.Trim(out[len(outputTruncated):], "x\n"); rest != "" {
		t.Fatalf("overlong line kept unexpected bytes: %q", rest)
	}
}

// Output that fits is returned whole without a truncation marker.
func TestPodOutputDoesNotMarkOutputThatFits(t *testing.T) {
	e := newEnv(t)
	const count = 64 // exactly maxRetainedOutput bytes of 1024-byte lines
	line := func(i int) string {
		return fmt.Sprintf("%04d:%s", i, strings.Repeat(string(rune('a'+i%26)), 1018))
	}
	var b strings.Builder
	for i := range count {
		b.WriteString("blip: " + line(i))
		b.WriteByte('\n')
	}
	e.blip.Config.PodLogs = func(context.Context, string, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(b.String())), nil
	}

	out, ok := e.blip.podOutput(e.ctx, ns, "pod")
	if !ok {
		t.Fatal("podOutput reported no output")
	}
	if strings.Contains(out, outputTruncated) {
		t.Fatalf("output that fits was marked truncated: %q", out[:min(len(out), 80)])
	}
	if len(out) != maxRetainedOutput {
		t.Fatalf("output is %d bytes, want %d", len(out), maxRetainedOutput)
	}
	if !strings.HasPrefix(out, line(0)+"\n") || !strings.HasSuffix(out, line(count-1)+"\n") {
		t.Fatalf("output lost lines that fit: %q", out[:min(len(out), 80)])
	}
}
