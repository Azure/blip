package blipchat

import (
	"context"
	"fmt"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A retained Blip keeps its last status.report forever. Once retention prunes
// the deterministic report turn, a later reconcile of unchanged Blip metadata
// must not recreate it: the sequencer would give the stale report a new
// sequence above consumedSeq and the coordinator would process it again.
func TestPrunedReportTurnIsNotResurrected(t *testing.T) {
	old := metav1.NewTime(timeNow().Add(-3 * time.Hour))
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	thread.Spec.Retention.Turns = &metav1.Duration{Duration: time.Hour}
	thread.Spec.Retention.KeepTurns = 1
	thread.Status.ConsumedSeq = 4
	thread.Status.LastSeq = 4

	blip := testReportBlip("reporter", 1, "stale report")
	r1 := testTurn("blip-blip-uid-r1", "proj")
	r1.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorBlip, Name: "reporter"}
	r1.Spec.Topic = "blip.report"
	r1.Spec.Attributes = map[string]string{"seq": "1"}
	r1.Status = v1.BlipTurnStatus{Seq: 1, ThreadUID: "thread-uid", AcceptedTime: &old}
	objs := []client.Object{thread, blip, r1}
	for i := 2; i <= 4; i++ {
		note := testTurn(fmt.Sprintf("coord-note-%d", i), "proj")
		note.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorCoordinator, Name: "proj"}
		note.Status = v1.BlipTurnStatus{Seq: int64(i), ThreadUID: "thread-uid", AcceptedTime: &old}
		objs = append(objs, note)
	}
	c := testClient(t, objs...)
	s := &Server{Client: c}
	ctx := context.Background()
	if err := s.prune(ctx, thread); err != nil {
		t.Fatalf("prune: %v", err)
	}
	var pruned v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: r1.Name}, &pruned); !apierrors.IsNotFound(err) {
		t.Fatalf("setup: report turn was not pruned (err %v)", err)
	}

	w := &Watcher{Client: c}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: blip.Name}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatalf("watcher: %v", err)
	}
	var recreated v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: r1.Name}, &recreated); !apierrors.IsNotFound(err) {
		t.Fatalf("pruned report turn was recreated as pending input (seq %d, err %v)", recreated.Status.Seq, err)
	}

	// A genuinely new report for the same Blip must still be turned.
	var current v1.Blip
	if err := c.Get(ctx, client.ObjectKeyFromObject(blip), &current); err != nil {
		t.Fatal(err)
	}
	current.Status.Report = &v1.BlipReport{Seq: 2, Text: "fresh report"}
	if err := c.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatalf("watcher: %v", err)
	}
	var fresh v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "blip-blip-uid-r2"}, &fresh); err != nil {
		t.Fatalf("new report was not turned: %v", err)
	}
}

// The finished phase is emitted once and is terminal. If retention pruned the
// deterministic finish turn, a later reconcile must not deliver the same phase
// again.
func TestPrunedFinishedTurnIsNotResurrected(t *testing.T) {
	old := metav1.NewTime(timeNow().Add(-3 * time.Hour))
	thread := testThread()
	thread.UID = types.UID("thread-uid")
	thread.Spec.Retention.Turns = &metav1.Duration{Duration: time.Hour}
	thread.Spec.Retention.KeepTurns = 1
	thread.Status.ConsumedSeq = 2
	thread.Status.LastSeq = 3

	blip := testReportBlip("reporter", 0, "")
	blip.Status.Phase = v1.BlipSucceeded
	fin := testTurn("blip-blip-uid-fin", "proj")
	fin.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorBlip, Name: "reporter"}
	fin.Spec.Topic = "blip.finished"
	fin.Status = v1.BlipTurnStatus{Seq: 2, ThreadUID: "thread-uid", AcceptedTime: &old}
	fresh := metav1.NewTime(timeNow())
	newest := testTurn("coord-note", "proj")
	newest.Spec.Author = v1.TurnAuthor{Kind: v1.TurnAuthorCoordinator, Name: "proj"}
	newest.Status = v1.BlipTurnStatus{Seq: 3, ThreadUID: "thread-uid", AcceptedTime: &fresh}
	c := testClient(t, thread, blip, fin, newest)
	s := &Server{Client: c}
	ctx := context.Background()
	if err := s.prune(ctx, thread); err != nil {
		t.Fatalf("prune: %v", err)
	}
	var pruned v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: fin.Name}, &pruned); !apierrors.IsNotFound(err) {
		t.Fatalf("setup: finish turn was not pruned (err %v)", err)
	}

	w := &Watcher{Client: c}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: blip.Name}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatalf("watcher: %v", err)
	}
	var recreated v1.BlipTurn
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: fin.Name}, &recreated); !apierrors.IsNotFound(err) {
		t.Fatalf("pruned finish turn was recreated as pending input (seq %d, err %v)", recreated.Status.Seq, err)
	}
}

func testReportBlip(name string, seq int64, text string) *v1.Blip {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "ns",
			UID:       types.UID("blip-uid"),
			Labels: map[string]string{
				v1.LabelThread: v1.ThreadLabel("proj"),
				v1.LabelOwner:  v1.ThreadOwner("ns", "proj"),
			},
			Annotations: map[string]string{v1.AnnotationThreadUID: "thread-uid"},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning},
	}
	if seq > 0 {
		b.Status.Report = &v1.BlipReport{Seq: seq, Text: text}
	}
	return b
}
