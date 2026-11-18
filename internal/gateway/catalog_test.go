package gateway

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
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

func gatewayBase() *v1alpha1.BlipState {
	size := resource.MustParse("10Gi")
	return &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gateway-base", UID: "base-uid"},
		Spec:       v1alpha1.BlipStateSpec{Image: "reg/dev:1", Size: &size},
	}
}

func mountRoot(b *v1alpha1.Blip, mounts ...v1alpha1.Mount) *v1alpha1.BlipState {
	root := catalogState(b.Labels[ownerLabel], "root-"+b.Name, "")
	b.Spec.State = root.Name
	root.Spec.Mounts = mounts
	return root
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

func TestCatalogListsOwnedRoots(t *testing.T) {
	root := catalogState("alice", "home", "")
	stopped := catalogState("alice", "stopped", "")
	base := catalogState("alice", "base", "")
	base.Spec.Image = "reg/dev:1"
	ownerless := catalogState("alice", "ownerless", "")
	ownerless.Name, ownerless.Labels = "shared-data", nil
	other := catalogState("bob", "home", "")
	mismatched := catalogState("alice", "mismatched", "")
	mismatched.Labels[ownerLabel] = "bob"
	wrongPrefix := catalogState("bob", "wrong-prefix", "")
	wrongPrefix.Labels[ownerLabel] = "alice"
	deleting := catalogState("alice", "deleting", "")
	deleting.Finalizers = []string{"blip.dev/test"}
	running := catalogBlip("alice", "root-worker", root.Name, v1alpha1.BlipRunning)
	running.Status.RootAttachmentID = "root-attachment"
	root.Status.Writer = &v1alpha1.Writer{BlipName: running.Name, BlipUID: string(running.UID), AttachmentID: "root-attachment"}
	stoppedWorker := catalogBlip("alice", "stopped-worker", stopped.Name, v1alpha1.BlipRunning)
	stoppedWorker.Spec.Stop = true
	kube := catalogClient(t, root, stopped, base, ownerless, other, mismatched, wrongPrefix, deleting, running, stoppedWorker)
	if err := kube.Delete(context.Background(), deleting); err != nil {
		t.Fatal(err)
	}
	c := startCatalog(t, kube)
	entries, err := c.List("alice")
	want := []menu.Entry{
		{ID: root.Name, UID: string(root.UID), Name: "home", Running: true},
		{ID: stopped.Name, UID: string(stopped.UID), Name: "stopped"},
	}
	if err != nil || !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %#v, err %v; want %#v", entries, err, want)
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

func TestCatalogOwnerlessChangesDoNotNotify(t *testing.T) {
	base := gatewayBase()
	fork := catalogState("alice", "fork", base.Name)
	c := startCatalog(t, catalogClient(t, base, fork))
	entries, err := c.List("alice")
	want := []menu.Entry{{ID: fork.Name, UID: string(fork.UID), Name: "fork"}}
	if err != nil || !reflect.DeepEqual(entries, want) {
		t.Fatalf("alice entries = %#v, err %v; want %#v", entries, err, want)
	}
	if entries, err := c.List("bob"); err != nil || len(entries) != 0 {
		t.Fatalf("bob sees shared base: %v, %v", entries, err)
	}
	alice, cancelAlice := c.Subscribe("alice")
	defer cancelAlice()
	bob, cancelBob := c.Subscribe("bob")
	defer cancelBob()
	c.changed(base)
	select {
	case <-alice:
		t.Fatal("ownerless state notified alice")
	default:
	}
	select {
	case <-bob:
		t.Fatal("ownerless state notified bob")
	default:
	}
	// Matching owners still receive notifications after the ownerless event
	// was dropped.
	c.changed(fork)
	awaitCatalogEvent(t, alice)
	select {
	case <-bob:
		t.Fatal("alice's state notified bob")
	default:
	}
}

func TestCatalogHidesWritableMountTargets(t *testing.T) {
	root := catalogState("alice", "root", "")
	data := catalogState("alice", "data", "")
	cache := catalogState("alice", "cache", "")
	root.Spec.Mounts = []v1alpha1.Mount{
		{State: data.Name, Path: "/work", Writable: true},
		{State: cache.Name, Path: "/cache"},
	}
	// Deleting states still hide their writable mount targets.
	aux := catalogState("alice", "aux", "")
	oldRoot := catalogState("alice", "old-root", "")
	oldRoot.Finalizers = []string{"blip.dev/test"}
	oldRoot.Spec.Mounts = []v1alpha1.Mount{{State: aux.Name, Path: "/aux", Writable: true}}
	kube := catalogClient(t, root, data, cache, aux, oldRoot)
	if err := kube.Delete(context.Background(), oldRoot); err != nil {
		t.Fatal(err)
	}
	c := startCatalog(t, kube)
	entries, err := c.List("alice")
	want := []menu.Entry{
		{ID: cache.Name, UID: string(cache.UID), Name: "cache"},
		{ID: root.Name, UID: string(root.UID), Name: "root"},
	}
	if err != nil || !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %#v, err %v; want %#v", entries, err, want)
	}
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
		{name: "attached", want: true},
		{name: "no-writer", change: func(st *v1alpha1.BlipState, _ *v1alpha1.Blip) { st.Status.Writer = nil }},
		{name: "old-worker", change: func(st *v1alpha1.BlipState, _ *v1alpha1.Blip) { st.Status.Writer.BlipUID = "old-worker" }},
		{name: "old-attachment", change: func(st *v1alpha1.BlipState, _ *v1alpha1.Blip) { st.Status.Writer.AttachmentID = "old-attachment" }},
		{name: "missing-attachment", want: true, change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.RootAttachmentID = "" }},
		{name: "not-running", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Status.Phase = v1alpha1.BlipSaving }},
		{name: "stopping", change: func(_ *v1alpha1.BlipState, b *v1alpha1.Blip) { b.Spec.Stop = true }},
	}
	var objects []client.Object
	want := make(map[string]bool)
	for _, tt := range cases {
		st := catalogState("alice", tt.name, "")
		b := catalogBlip("alice", "worker-"+tt.name, st.Name, v1alpha1.BlipRunning)
		b.Status.RootAttachmentID = "root-attachment"
		st.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: "root-attachment"}
		if tt.change != nil {
			tt.change(st, b)
		}
		objects = append(objects, st, b)
		want[st.Name] = tt.want
	}
	c := startCatalog(t, catalogClient(t, objects...))
	entries, err := c.List("alice")
	if err != nil || len(entries) != len(want) {
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
