package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func gcClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func gcBlip(name, phase string, finish *time.Time) *v1.Blip {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Status:     v1.BlipStatus{Phase: phase},
	}
	if finish != nil {
		t := metav1.NewTime(*finish)
		b.Status.FinishTime = &t
	}
	return b
}

func gcNames(t *testing.T, c client.Client) map[string]bool {
	t.Helper()
	var list v1.BlipList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(list.Items))
	for _, b := range list.Items {
		names[b.Name] = true
	}
	return names
}

func assertDeleted(t *testing.T, c client.Client, deleted, want int, names ...string) {
	t.Helper()
	if deleted != want {
		t.Fatalf("deleted = %d, want %d", deleted, want)
	}
	got := gcNames(t, c)
	if len(got) != len(names) {
		t.Fatalf("remaining = %v, want %v", got, names)
	}
	for _, name := range names {
		if !got[name] {
			t.Fatalf("remaining = %v, want %v", got, names)
		}
	}
}

func TestCollectTerminatedBlipsUnderThreshold(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c := gcClient(t,
		gcBlip("a", v1.BlipSucceeded, &t0),
		gcBlip("b", v1.BlipFailed, ptrTime(t0.Add(time.Minute))),
	)
	for _, threshold := range []int{2, 3} {
		deleted, err := CollectTerminatedBlips(context.Background(), c, threshold)
		if err != nil {
			t.Fatal(err)
		}
		assertDeleted(t, c, deleted, 0, "a", "b")
	}
}

func TestCollectTerminatedBlipsOldestFirst(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c := gcClient(t,
		gcBlip("b0", v1.BlipSucceeded, &t0),
		gcBlip("b1", v1.BlipFailed, ptrTime(t0.Add(1*time.Minute))),
		gcBlip("b2", v1.BlipSucceeded, ptrTime(t0.Add(2*time.Minute))),
		gcBlip("b3", v1.BlipFailed, ptrTime(t0.Add(3*time.Minute))),
		gcBlip("b4", v1.BlipSucceeded, ptrTime(t0.Add(4*time.Minute))),
	)
	deleted, err := CollectTerminatedBlips(context.Background(), c, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, c, deleted, 3, "b3", "b4")
}

func TestCollectTerminatedBlipsIgnoresUnfinishedAndDeleting(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	deleting := gcBlip("deleting", v1.BlipSucceeded, ptrTime(t0.Add(3*time.Minute)))
	now := metav1.NewTime(t0.Add(time.Hour))
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{v1.Finalizer}
	c := gcClient(t,
		gcBlip("old", v1.BlipSucceeded, &t0),
		gcBlip("new", v1.BlipFailed, ptrTime(t0.Add(1*time.Minute))),
		gcBlip("running", v1.BlipRunning, nil),
		gcBlip("pending", v1.BlipPending, nil),
		deleting,
	)
	deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, c, deleted, 1, "new", "running", "pending", "deleting")
}

func TestCollectTerminatedBlipsNilFinishTimeIsOldest(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c := gcClient(t,
		gcBlip("none", v1.BlipSucceeded, nil),
		gcBlip("later", v1.BlipFailed, &t0),
		gcBlip("latest", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute))),
	)
	deleted, err := CollectTerminatedBlips(context.Background(), c, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, c, deleted, 1, "later", "latest")
}

func TestCollectTerminatedBlipsDisabled(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c := gcClient(t,
		gcBlip("a", v1.BlipSucceeded, &t0),
		gcBlip("b", v1.BlipFailed, ptrTime(t0.Add(time.Minute))),
	)
	for _, threshold := range []int{0, -1} {
		deleted, err := CollectTerminatedBlips(context.Background(), c, threshold)
		if err != nil {
			t.Fatal(err)
		}
		assertDeleted(t, c, deleted, 0, "a", "b")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
