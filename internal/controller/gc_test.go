// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

func TestCollectTerminatedBlipsKeepsReplacement(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old := gcBlip("old", v1.BlipSucceeded, &t0)
	old.UID = "uid-old"
	fresh := gcBlip("new", v1.BlipFailed, ptrTime(t0.Add(time.Minute)))
	fresh.UID = "uid-new"
	base := gcClient(t, old, fresh)
	replaced := false
	var pinned types.UID
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			b, ok := obj.(*v1.Blip)
			if !ok || b.Name != "old" || replaced {
				return c.Delete(ctx, obj, opts...)
			}
			replaced = true
			// The finished Blip in the List snapshot is already gone; a
			// Running Blip has since been created under the same name.
			if err := c.Delete(ctx, &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old"}}); err != nil {
				return err
			}
			replacement := gcBlip("old", v1.BlipRunning, nil)
			replacement.UID = "uid-replacement"
			if err := c.Create(ctx, replacement); err != nil {
				return err
			}
			var do client.DeleteOptions
			do.ApplyOptions(opts)
			if do.Preconditions != nil && do.Preconditions.UID != nil {
				pinned = *do.Preconditions.UID
			}
			return deleteLikeAPI(ctx, c, obj, "uid-replacement", opts...)
		},
	})
	deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("GC did not attempt to delete the oldest finished Blip")
	}
	if pinned != "uid-old" {
		t.Fatalf("GC delete precondition UID = %q, want the observed uid-old", pinned)
	}
	if deleted != 0 {
		t.Fatalf("deleted = %d, want 0 because the observed Blip was already gone", deleted)
	}
	if got := gcNames(t, c); !got["old"] || !got["new"] {
		t.Fatalf("remaining = %v, want the replacement old and new", got)
	}
	got := &v1.Blip{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "old"}, got); err != nil {
		t.Fatal(err)
	}
	if got.UID != "uid-replacement" || got.Status.Phase != v1.BlipRunning {
		t.Fatalf("GC replaced/deleted the wrong Blip: %+v", got)
	}
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

func TestCollectTerminatedBlipsChatRetention(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, stateExists := range []bool{true, false} {
		t.Run(map[bool]string{true: "state exists", false: "state deleted"}[stateExists], func(t *testing.T) {
			old := gcBlip("chat-old", v1.BlipSucceeded, &t0)
			latest := gcBlip("chat-latest", v1.BlipFailed, ptrTime(t0.Add(time.Minute)))
			for _, b := range []*v1.Blip{old, latest} {
				b.Spec.State = "chat-state"
				b.Labels = map[string]string{v1.LabelChatSession: "session"}
			}
			old.Annotations = map[string]string{"chat.blip.dev/generation": "9"}
			latest.Annotations = map[string]string{"chat.blip.dev/generation": "10"}
			// Generation, not creation time or lexical name order, decides
			// which chat execution carries the retention clock.
			old.CreationTimestamp = metav1.NewTime(t0.Add(time.Hour))
			latest.CreationTimestamp = metav1.NewTime(t0)
			objects := []client.Object{old, latest,
				gcBlip("new", v1.BlipSucceeded, ptrTime(t0.Add(2*time.Minute)))}
			if stateExists {
				objects = append(objects, &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "chat-state"}})
			}
			c := gcClient(t, objects...)
			deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
			if err != nil {
				t.Fatal(err)
			}
			if stateExists {
				assertDeleted(t, c, deleted, 1, "chat-latest", "new")
			} else {
				assertDeleted(t, c, deleted, 2, "new")
			}
		})
	}
}

func TestCollectTerminatedBlipsProtectedChatDoesNotCountTowardThreshold(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	chat := gcBlip("chat", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute)))
	chat.Labels = map[string]string{v1.LabelChatSession: "session"}
	chat.Spec.State = "chat-state"
	c := gcClient(t, chat, gcBlip("old", v1.BlipSucceeded, &t0),
		&v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "chat-state"}})
	deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, c, deleted, 0, "chat", "old")
}

func TestCollectTerminatedBlipsChatWithRunningLatest(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old := gcBlip("chat-old", v1.BlipSucceeded, &t0)
	running := gcBlip("chat-running", v1.BlipRunning, nil)
	for _, b := range []*v1.Blip{old, running} {
		b.Spec.State = "chat-state"
		b.Labels = map[string]string{v1.LabelChatSession: "session"}
	}
	running.CreationTimestamp = metav1.NewTime(t0.Add(time.Minute))
	base := gcClient(t, old, running, gcBlip("new", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute))))
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1.BlipState); ok {
				t.Fatal("state lookup for an older chat generation")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, c, deleted, 1, "chat-running", "new")
}

func TestCollectTerminatedBlipsChatStateLookupError(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	chat := gcBlip("chat", v1.BlipSucceeded, &t0)
	chat.Labels = map[string]string{v1.LabelChatSession: "session"}
	chat.Spec.State = "chat-state"
	base := gcClient(t, chat, gcBlip("new", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute))))
	wantErr := errors.New("state lookup unavailable")
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1.BlipState); ok {
				return wantErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	deleted, err := CollectTerminatedBlips(context.Background(), c, 1)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	assertDeleted(t, c, deleted, 0, "chat", "new")
}

func TestNewerChatBlipFallback(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	a, b := gcBlip("a", v1.BlipSucceeded, nil), gcBlip("b", v1.BlipSucceeded, nil)
	a.CreationTimestamp = metav1.NewTime(t0.Add(time.Minute))
	b.CreationTimestamp = metav1.NewTime(t0)
	a.Annotations = map[string]string{"chat.blip.dev/generation": "invalid"}
	if !newerChatBlip(a, b) || newerChatBlip(b, a) {
		t.Fatal("missing or malformed generations should fall back to creation time")
	}
	b.CreationTimestamp = a.CreationTimestamp
	if newerChatBlip(a, b) || !newerChatBlip(b, a) {
		t.Fatal("equal creation times should fall back to name")
	}
}

func TestNewerChatBlipLegacyGeneration(t *testing.T) {
	a := gcBlip("chat-g9", v1.BlipSucceeded, nil)
	b := gcBlip("chat-g10", v1.BlipSucceeded, nil)
	if newerChatBlip(a, b) || !newerChatBlip(b, a) {
		t.Fatal("legacy generation suffixes must sort numerically")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
