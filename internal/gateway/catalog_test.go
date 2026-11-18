package gateway

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway/menu"
)

func catalogState(owner, name, parent string) *v1alpha1.BlipState {
	return &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: owner + "." + name, UID: types.UID(owner + "." + name + "-uid"), Labels: map[string]string{ownerLabel: owner}},
		Spec:       v1alpha1.BlipStateSpec{CopyFrom: parent},
	}
}

func catalogBlip(owner, name, state, phase string) *v1alpha1.Blip {
	return &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: owner + "." + name, UID: types.UID(owner + "." + name + "-uid"), Labels: map[string]string{ownerLabel: owner}},
		Spec:       v1alpha1.BlipSpec{State: state},
		Status:     v1alpha1.BlipStatus{Phase: phase, Pod: "pod-" + name},
	}
}

func catalogClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func startCatalog(t *testing.T, kube client.WithWatch) *Catalog {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := NewCatalog(kube, ns)
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Error("catalog did not stop")
		}
	})
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogOwnerTreeAndRunningReferences(t *testing.T) {
	root := catalogState("alice", "home", "")
	fork := catalogState("alice", "fork", root.Name)
	orphan := catalogState("alice", "orphan", "alice.deleted")
	foreignParent := catalogState("alice", "foreign-parent", "bob.home")
	legacy := catalogState("alice", "legacy", "")
	legacy.Name = "legacy"
	badLabel := catalogState("alice", "secret", "")
	badLabel.Labels[ownerLabel] = "bob"
	otherNamespace := catalogState("alice", "elsewhere", "")
	otherNamespace.Namespace = "elsewhere"
	worker := catalogBlip("alice", "worker", "", v1alpha1.BlipRunning)
	worker.Spec.Mounts = []v1alpha1.Mount{{State: fork.Name, Path: "/work", Writable: true}}
	worker.Status.Mounts = []v1alpha1.MountStatus{{State: fork.Name, StateUID: string(fork.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
	readOnly := catalogBlip("alice", "reader", "", v1alpha1.BlipRunning)
	readOnly.Spec.Mounts = []v1alpha1.Mount{{State: root.Name, Path: "/work"}}
	readOnly.Status.Mounts = []v1alpha1.MountStatus{{State: root.Name, StateUID: string(root.UID), Path: "/work", Phase: v1alpha1.MountMounted}}
	c := startCatalog(t, catalogClient(t, root, fork, orphan, foreignParent, legacy, badLabel, otherNamespace,
		catalogState("bob", "home", ""), worker, readOnly,
		catalogBlip("alice", "home", root.Name, v1alpha1.BlipPending),
		catalogBlip("bob", "thief", orphan.Name, v1alpha1.BlipRunning)))
	entries, err := c.List("alice")
	want := []menu.Entry{
		{ID: foreignParent.Name, UID: string(foreignParent.UID), Name: "foreign-parent"},
		{ID: fork.Name, UID: string(fork.UID), Name: "fork", Parent: root.Name, Running: true},
		{ID: root.Name, UID: string(root.UID), Name: "home"},
		{ID: orphan.Name, UID: string(orphan.UID), Name: "orphan"},
		{ID: legacy.Name, UID: string(legacy.UID), Name: "legacy"},
	}
	if err != nil || !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %#v, err %v; want %#v", entries, err, want)
	}
	// CopyFrom is lineage, not lifecycle ownership: deleting a parent leaves
	// the copy visible, now as a top-level entry.
	if err := c.states.GetIndexer().Delete(root); err != nil {
		t.Fatal(err)
	}
	entries, err = c.List("alice")
	if err != nil || len(entries) != 4 || entries[1].ID != fork.Name || entries[1].Parent != "" {
		t.Fatalf("orphaned fork disappeared: %#v, %v", entries, err)
	}
}

type catalogTrackedWatch struct {
	watch.Interface
	once    sync.Once
	stopped *atomic.Int32
}

func (w *catalogTrackedWatch) Stop() {
	w.once.Do(func() {
		w.Interface.Stop()
		w.stopped.Add(1)
	})
}

func TestCatalogSharesWatchesAndStops(t *testing.T) {
	var lists, watches, stopped atomic.Int32
	kube := interceptor.NewClient(catalogClient(t), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists.Add(1)
			return c.List(ctx, list, opts...)
		},
		Watch: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
			w, err := c.Watch(ctx, list, opts...)
			if err != nil {
				return nil, err
			}
			watches.Add(1)
			return &catalogTrackedWatch{Interface: w, stopped: &stopped}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewCatalog(kube, ns)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return watches.Load() == 2 })
	var cancels []func()
	var channels []<-chan struct{}
	for range 30 {
		ch, unsubscribe := c.Subscribe("alice")
		cancels = append(cancels, unsubscribe)
		channels = append(channels, ch)
		if _, err := c.List("alice"); err != nil {
			t.Fatal(err)
		}
	}
	if lists.Load() != 2 || watches.Load() != 2 {
		t.Fatalf("per-session API calls: lists %d watches %d", lists.Load(), watches.Load())
	}
	st := catalogState("alice", "created", "")
	if err := kube.Create(ctx, st); err != nil {
		t.Fatal(err)
	}
	for _, ch := range channels {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("subscriber did not see state creation")
		}
	}
	for i, unsubscribe := range cancels {
		if i%2 == 0 {
			unsubscribe()
			unsubscribe()
		}
	}
	cancel()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("catalog did not stop")
	}
	if stopped.Load() != 2 || len(c.subs) != 0 {
		t.Fatalf("leaked watches/subscriptions: stopped=%d subs=%d", stopped.Load(), len(c.subs))
	}
	for i, ch := range channels {
		if _, ok := <-ch; ok {
			t.Fatalf("subscription %d not closed", i)
		}
		cancels[i]()
	}
	ch, unsubscribe := c.Subscribe("alice")
	defer unsubscribe()
	if _, ok := <-ch; ok {
		t.Fatal("subscription after shutdown not closed")
	}
}

func TestCatalogEventsOwnersAndTombstones(t *testing.T) {
	kube := catalogClient(t)
	c := startCatalog(t, kube)
	alice, cancelAlice := c.Subscribe("alice")
	defer cancelAlice()
	bob, cancelBob := c.Subscribe("bob")
	defer cancelBob()
	st := catalogState("alice", "home", "")
	if err := kube.Create(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, alice)
	st.Labels[ownerLabel] = "bob"
	if err := kube.Update(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, alice)
	awaitCatalogEvent(t, bob)
	if err := kube.Delete(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, bob)
	// Missed watch deletions arrive as tombstones; duplicate bursts coalesce.
	for range 100 {
		c.changed(cache.DeletedFinalStateUnknown{Key: st.Name, Obj: st})
	}
	if len(bob) != 1 || len(alice) != 0 {
		t.Fatalf("notifications did not coalesce/isolate: alice=%d bob=%d", len(alice), len(bob))
	}
	awaitCatalogEvent(t, bob)
	worker := catalogBlip("alice", "worker", "alice.home", v1alpha1.BlipRunning)
	if err := kube.Create(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, alice)
	worker.Status.Phase = v1alpha1.BlipSaving
	if err := kube.Update(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, alice)
	if err := kube.Delete(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, alice)
	c.changed(&cache.DeletedFinalStateUnknown{Key: worker.Name, Obj: worker})
	awaitCatalogEvent(t, alice)
}

func awaitCatalogEvent(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("subscription closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("catalog event not received")
	}
}

func TestCatalogInitialSyncCancellation(t *testing.T) {
	kube := interceptor.NewClient(catalogClient(t), interceptor.Funcs{
		List: func(ctx context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewCatalog(kube, ns)
	if err := c.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v", err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("initial sync cancellation leaked informers")
	}
}

func TestCatalogRunningRequiresAttachedState(t *testing.T) {
	cases := []struct {
		name   string
		change func(*v1alpha1.BlipState, *v1alpha1.Blip)
		want   bool
	}{
		{name: "mounted", want: true},
		{name: "absent", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts = nil }},
		{name: "pending", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Phase = v1alpha1.MountPending }},
		{name: "failed", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Phase = v1alpha1.MountFailed }},
		{name: "unmounting", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Phase = v1alpha1.MountUnmounting }},
		{name: "saving", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Phase = v1alpha1.MountSaving }},
		{name: "old-uid", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].StateUID = "old-state" }},
		{name: "missing-uid", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].StateUID = "" }},
		{name: "old-path", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Path = "/old" }},
		{name: "read-only", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Mounts[0].Writable = false }},
		{name: "root-mounted", want: true, change: func(st *v1alpha1.BlipState, b *v1alpha1.Blip) {
			b.Spec.State, b.Status.RootAttachmentID = st.Name, "root-attachment"
			st.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: "root-attachment"}
		}},
		{name: "root-old-attachment", change: func(st *v1alpha1.BlipState, b *v1alpha1.Blip) {
			b.Spec.State, b.Status.RootAttachmentID = st.Name, "old-attachment"
			st.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: "new-attachment"}
		}},
		{name: "root-no-writer", change: func(st *v1alpha1.BlipState, b *v1alpha1.Blip) {
			b.Spec.State, b.Status.RootAttachmentID = st.Name, "root-attachment"
		}},
		{name: "root-old-worker", change: func(st *v1alpha1.BlipState, b *v1alpha1.Blip) {
			b.Spec.State, b.Status.RootAttachmentID = st.Name, "root-attachment"
			st.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: "old-worker", AttachmentID: "root-attachment"}
		}},
	}
	var objects []client.Object
	want := make(map[string]bool)
	for _, tt := range cases {
		st := catalogState("alice", tt.name, "")
		b := catalogBlip("alice", "worker-"+tt.name, "", v1alpha1.BlipRunning)
		b.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Path: "/work", Writable: true}}
		b.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
		if tt.change != nil {
			tt.change(st, b)
		}
		if b.Spec.State != "" {
			b.Spec.Mounts, b.Status.Mounts = nil, nil
		}
		objects = append(objects, st, b)
		want[st.Name] = tt.want
	}
	c := startCatalog(t, catalogClient(t, objects...))
	entries, err := c.List("alice")
	if err != nil || len(entries) != len(cases) {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	for _, entry := range entries {
		if entry.Running != want[entry.ID] {
			t.Errorf("%s Running=%t, want %t", entry.ID, entry.Running, want[entry.ID])
		}
	}
}

func TestCatalogRecoversClosedWatch(t *testing.T) {
	stateWatches := make(chan watch.Interface, 8)
	kube := interceptor.NewClient(catalogClient(t), interceptor.Funcs{
		Watch: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
			w, err := c.Watch(ctx, list, opts...)
			if _, ok := list.(*v1alpha1.BlipStateList); ok && err == nil {
				stateWatches <- w
			}
			return w, err
		},
	})
	c := startCatalog(t, kube)
	changes, unsubscribe := c.Subscribe("alice")
	defer unsubscribe()
	var first watch.Interface
	select {
	case first = <-stateWatches:
	case <-time.After(5 * time.Second):
		t.Fatal("initial state watch missing")
	}
	first.Stop()
	select {
	case <-stateWatches:
	case <-time.After(5 * time.Second):
		t.Fatal("state watch did not reconnect")
	}
	st := catalogState("alice", "after-reconnect", "")
	if err := kube.Create(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	awaitCatalogEvent(t, changes)
	entries, err := c.List("alice")
	if err != nil || len(entries) != 1 || entries[0].UID != string(st.UID) {
		t.Fatalf("reconnected watch did not refresh the catalog: %v, %v", entries, err)
	}
}
