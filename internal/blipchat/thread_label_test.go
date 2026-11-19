package blipchat

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func longThread() *v1.BlipThread {
	thread := testThread()
	thread.Name = "w3-23-" + strings.Repeat("x", 69)
	return thread
}

// A BlipThread name may be up to 253 characters, but a Kubernetes label value
// is at most 63. The turn must keep the full name in spec.thread and use a
// deterministic, valid label.
func TestCreateTurnInHashesLongThreadLabel(t *testing.T) {
	thread := longThread()
	c := testClient(t, thread)
	if err := createTurnIn(context.Background(), c, "ns", "turn-long", turnSpec{
		Thread: thread.Name, AuthorKind: v1.TurnAuthorCoordinator, AuthorName: thread.Name,
		Topic: "coordinator.note", Text: "hi",
	}); err != nil {
		t.Fatal(err)
	}
	var got v1.BlipTurn
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "turn-long"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Thread != thread.Name {
		t.Errorf("spec.thread = %q, want the full name %q", got.Spec.Thread, thread.Name)
	}
	if label := got.Labels[v1.LabelThread]; len(validation.IsValidLabelValue(label)) != 0 {
		t.Errorf("thread label %q is not a valid label value: %v", label, validation.IsValidLabelValue(label))
	}
}

// start_task labels the Blip and its state with the thread name. Long names
// must not produce labels the API server rejects, and the watcher must still
// recover the full name to attribute reports.
func TestStartTaskHashesLongThreadLabel(t *testing.T) {
	thread := longThread()
	thread.Spec.Base = "base"
	src := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "ns"}}
	c := testClient(t, thread, src)
	s := &Server{Client: c, Config: Config{AgentCommand: []string{"agent"}}}
	st := &step{s: s, thread: thread, tasks: thread.Status.Tasks}
	st.tasks = []v1.ThreadTask{{ID: "t1", Open: true}}
	if _, err := st.call(context.Background(), "start_task", `{"task":"t1","prompt":"work"}`); err != nil {
		t.Fatal(err)
	}
	var blips v1.BlipList
	if err := c.List(context.Background(), &blips, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(blips.Items) != 1 {
		t.Fatalf("blips = %d, want 1", len(blips.Items))
	}
	b := blips.Items[0]
	assertThreadLabels(t, b.Labels, b.Annotations, thread.Name)
	var state v1.BlipState
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: b.Name}, &state); err != nil {
		t.Fatal(err)
	}
	assertThreadLabels(t, state.Labels, state.Annotations, thread.Name)
}

func assertThreadLabels(t *testing.T, labels, annotations map[string]string, thread string) {
	t.Helper()
	label := labels[v1.LabelThread]
	if errs := validation.IsValidLabelValue(label); len(errs) != 0 {
		t.Errorf("thread label %q is not a valid label value: %v", label, errs)
	}
	if got := annotations[v1.AnnotationThread]; got != thread {
		t.Errorf("thread annotation = %q, want the full name %q", got, thread)
	}
}

// The watcher reads the thread name from a Blip to attribute its reports. A
// long name is only recoverable from the annotation, not the hashed label.
func TestWatcherUsesFullThreadNameForLongThread(t *testing.T) {
	thread := longThread()
	owner := v1.ThreadOwner("ns", thread.Name)
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns", UID: "uid-a",
			Labels: map[string]string{
				v1.LabelThread: v1.ThreadLabel(thread.Name),
				v1.LabelTask:   "t1",
				v1.LabelOwner:  owner,
			},
			Annotations: map[string]string{v1.AnnotationThread: thread.Name},
		},
		Status: v1.BlipStatus{
			Phase:  v1.BlipRunning,
			Report: &v1.BlipReport{Seq: 1, Text: `{"summary":"done"}`},
		},
	}
	c := testClient(t, thread, b)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "blip-a"}}
	if _, err := (&Watcher{Client: c}).Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var turns v1.BlipTurnList
	if err := c.List(context.Background(), &turns); err != nil {
		t.Fatal(err)
	}
	if len(turns.Items) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns.Items))
	}
	turn := turns.Items[0]
	if turn.Spec.Thread != thread.Name {
		t.Errorf("turn spec.thread = %q, want %q", turn.Spec.Thread, thread.Name)
	}
	if errs := validation.IsValidLabelValue(turn.Labels[v1.LabelThread]); len(errs) != 0 {
		t.Errorf("turn thread label %q: %v", turn.Labels[v1.LabelThread], errs)
	}
}
