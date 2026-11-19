package controller

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// deletionClient builds a client with the controller's field indexes.
func deletionClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
	for _, ix := range Indexes {
		b = b.WithIndex(ix.Obj, ix.Field, ix.Extract)
	}
	return b.Build()
}

// TestSourceDeletionSeesCopyOutsideCache covers the cache lag window between
// creating a copy and deleting its source: the finalizer must consult the live
// API, not a cache that can still be missing the copy.
func TestSourceDeletionSeesCopyOutsideCache(t *testing.T) {
	src := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: ns, UID: "uid-src"}}
	cp := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: ns},
		Spec:       v1.BlipStateSpec{CopyFrom: "src"},
	}
	r := &StateReconciler{
		Client: deletionClient(t, src),
		Live:   deletionClient(t, src, cp),
	}
	blockers, err := r.deletionBlockers(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(blockers) != 1 || blockers[0] != "copy cp" {
		t.Fatalf("blockers = %v, want [copy cp]", blockers)
	}
}

// TestLiveCopyCreatedBeforeSourceDeletionPinsIt covers deleting a live copy
// source before the copy had a chance to record status.copiedFrom: the source
// finalizer must wait for the copy, and the copy must still snapshot it.
func TestLiveCopyCreatedBeforeSourceDeletionPinsIt(t *testing.T) {
	e, w := liveSource(t)
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "repo"
		st.Spec.Replicas = 1
	})

	// Delete the source before the copy has ever been reconciled, so the
	// copy has no status.copiedFrom yet. Its writer then finishes and clears
	// the writer slot; only the unplanned copy can still pin the source.
	e.must(e.c.Delete(e.ctx, e.getState("repo")))
	src := e.getState("repo")
	w = src.Status.Writer
	if w == nil {
		t.Fatal("live source has no writer")
	}
	commit := newID()
	e.seal("repo", w.Node, v1.SealResult{AttachmentID: w.AttachmentID, CommitID: commit})
	e.hold("repo", commit, w.Node)
	e.updateBlipStatus("git", func(b *v1.Blip) { b.Status.Phase = v1.BlipSucceeded })
	e.run(e.state, ns, "repo")
	src = &v1.BlipState{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "repo"}, src); err != nil {
		t.Fatalf("source deleted before the unplanned copy could plan: %v", err)
	}
	if !strings.Contains(src.Status.Message, "copy cp") || len(src.Finalizers) == 0 {
		t.Fatalf("source deletion not blocked by the unplanned copy: %+v", src.Status)
	}

	// The copy can still plan from the source's committed version.
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom == nil || cp.Status.CopiedFrom.CommitID == "" || cp.Status.Pending == nil {
		t.Fatalf("copy did not plan from the pinned source: %+v", cp.Status)
	}
	p := cp.Status.Pending
	e.hold("cp", p.CommitID, p.Replicas...)
	e.run(e.state, ns, "cp")
	if cp = e.getState("cp"); cp.Status.Phase != v1.StateReady {
		t.Fatalf("copy did not commit: %+v", cp.Status)
	}

	// The committed copy releases the source finalizer.
	e.run(e.state, ns, "repo")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "repo"}, &v1.BlipState{}); err == nil {
		t.Fatal("source still exists after its copy committed")
	}
}
