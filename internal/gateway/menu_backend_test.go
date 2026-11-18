package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

func backendServer(t *testing.T, kube client.WithWatch) *Server {
	t.Helper()
	var uid atomic.Int32
	kube = interceptor.NewClient(kube, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			// The fake API does not allocate UIDs, unlike an API server.
			if obj.GetUID() == "" {
				obj.SetUID(types.UID(fmt.Sprintf("created-%d", uid.Add(1))))
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	return &Server{
		Config: Config{Namespace: ns, Image: "registry/configured:1", Pool: "small", StateSize: resource.MustParse("20Gi")},
		Kube:   kube, Catalog: startCatalog(t, kube),
	}
}

func TestMenuBackendCreate(t *testing.T) {
	s := backendServer(t, catalogClient(t, catalogState("alice", "existing", ""), catalogBlip("alice", "worker", "", v1alpha1.BlipPending)))
	b := s.menuBackend("alice")
	ctx := context.Background()
	for _, name := range []string{"", "Upper", "../other", "a.b", strings.Repeat("a", 64), "existing", "worker"} {
		if _, err := b.Create(ctx, name); err == nil {
			t.Errorf("created invalid or colliding sandbox %q", name)
		}
	}
	e, err := b.Create(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "alice.new" || e.Name != "new" || e.UID == "" || e.Parent != "" || e.Running {
		t.Fatalf("created entry = %#v", e)
	}
	var st v1alpha1.BlipState
	if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: e.ID}, &st); err != nil {
		t.Fatal(err)
	}
	if st.Spec.Image != s.Image || st.Spec.CopyFrom != "" || st.Spec.Size == nil || !st.Spec.Size.Equal(s.StateSize) || st.Labels[ownerLabel] != "alice" {
		t.Fatalf("created state = %#v", st)
	}
	if err := s.Kube.Get(ctx, client.ObjectKeyFromObject(&st), &v1alpha1.Blip{}); !apierrors.IsNotFound(err) {
		t.Fatalf("create also created a Blip: %v", err)
	}
	eventually(t, func() bool {
		entries, _ := b.List(ctx)
		for _, got := range entries {
			if got.UID == e.UID {
				return true
			}
		}
		return false
	})
}

func TestMenuBackendDeleteAssociationsPreservesOthers(t *testing.T) {
	st := catalogState("alice", "home", "")
	st.Finalizers = []string{"blip.dev/test"}
	root := catalogBlip("alice", "root-worker", st.Name, v1alpha1.BlipRunning)
	writer := catalogBlip("alice", "mount-worker", "", v1alpha1.BlipRunning)
	writer.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Path: "/work", Writable: true}}
	writer.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
	reader := catalogBlip("alice", "reader", "", v1alpha1.BlipRunning)
	reader.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Path: "/work"}}
	reader.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Phase: v1alpha1.MountMounted}}
	saving := catalogBlip("alice", "saving", "", v1alpha1.BlipSaving)
	saving.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID)}}
	owner := catalogBlip("alice", "owner", "", v1alpha1.BlipSucceeded)
	st.OwnerReferences = []metav1.OwnerReference{{APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip", Name: owner.Name, UID: owner.UID}}
	foreign := catalogBlip("bob", "foreign", st.Name, v1alpha1.BlipRunning)
	unrelated := catalogBlip("alice", "home", "alice.other", v1alpha1.BlipRunning)
	child := catalogState("alice", "child", st.Name)
	objects := []client.Object{st, root, writer, reader, saving, owner, foreign, unrelated, child}
	for _, b := range []*v1alpha1.Blip{root, writer, reader, saving, owner} {
		b.Finalizers = []string{"blip.dev/test"}
	}
	var deletes int
	kube := interceptor.NewClient(catalogClient(t, objects...), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			o := (&client.DeleteOptions{}).ApplyOptions(opts)
			if o.Preconditions == nil || o.Preconditions.UID == nil || *o.Preconditions.UID != obj.GetUID() || o.Preconditions.ResourceVersion == nil ||
				o.PropagationPolicy == nil || *o.PropagationPolicy != metav1.DeletePropagationOrphan {
				t.Fatalf("unsafe delete of %s: %#v", obj.GetName(), o)
			}
			deletes++
			return c.Delete(ctx, obj, opts...)
		},
	})
	s := backendServer(t, kube)
	if err := s.menuBackend("alice").Delete(context.Background(), stateEntry(st, "alice")); err != nil {
		t.Fatal(err)
	}
	if deletes != 6 {
		t.Fatalf("deleted %d resources, want state plus five associated Blips", deletes)
	}
	for _, obj := range objects {
		live := obj.DeepCopyObject().(client.Object)
		if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(obj), live); err != nil {
			t.Fatalf("finalized resource prematurely removed: %s: %v", obj.GetName(), err)
		}
		shouldDelete := obj != foreign && obj != unrelated && obj != child
		if (live.GetDeletionTimestamp() != nil) != shouldDelete {
			t.Errorf("resource %s deletion = %v, want %v", obj.GetName(), live.GetDeletionTimestamp(), shouldDelete)
		}
	}
}

func TestMenuBackendRejectsStaleUIDAndChangedOwnership(t *testing.T) {
	for _, mutate := range []string{"uid", "owner", "missing-uid"} {
		t.Run(mutate, func(t *testing.T) {
			st := catalogState("alice", "home", "")
			entry := stateEntry(st, "alice")
			switch mutate {
			case "uid":
				st.UID = "replacement"
			case "owner":
				st.Labels[ownerLabel] = "bob"
			case "missing-uid":
				entry.UID = ""
			}
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
			s := backendServer(t, catalogClient(t, st, worker))
			if err := s.menuBackend("alice").Delete(context.Background(), entry); err == nil {
				t.Fatal("unsafe delete accepted")
			}
			if _, err := s.openState(context.Background(), "alice", entry, wire.Open{Mode: wire.OpenExec}); err == nil {
				t.Fatal("unsafe open accepted")
			}
			for _, obj := range []client.Object{st, worker} {
				if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil || obj.GetDeletionTimestamp() != nil {
					t.Fatalf("resource changed: %s: %v", obj.GetName(), err)
				}
			}
		})
	}
}

func TestMenuBackendDeleteRechecksWorkerOwner(t *testing.T) {
	st := catalogState("alice", "home", "")
	worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
	kube := interceptor.NewClient(catalogClient(t, st, worker), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1alpha1.Blip); ok && key.Name == worker.Name {
				var live v1alpha1.Blip
				if err := c.Get(ctx, key, &live); err != nil {
					return err
				}
				live.Labels[ownerLabel] = "bob"
				if err := c.Update(ctx, &live); err != nil {
					return err
				}
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	s := backendServer(t, kube)
	if err := s.menuBackend("alice").Delete(context.Background(), stateEntry(st, "alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(worker), worker); err != nil || worker.DeletionTimestamp != nil {
		t.Fatalf("relabelled worker was deleted: %v", err)
	}
}

func TestOpenStateTargetsRunningWorkersByReference(t *testing.T) {
	for _, mount := range []bool{false, true} {
		t.Run(fmt.Sprintf("mount=%t", mount), func(t *testing.T) {
			st := catalogState("alice", "fork", "alice.home")
			st.Name = "legacy-fork"
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
			worker.Name = "legacy-worker"
			if mount {
				worker.Spec.State = ""
				worker.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Path: "/work", Writable: true}}
				worker.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
			}
			st.OwnerReferences = []metav1.OwnerReference{{APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip", Name: worker.Name, UID: worker.UID}}
			st.Status.Writer = &v1alpha1.Writer{BlipName: worker.Name, BlipUID: string(worker.UID)}
			s := backendServer(t, catalogClient(t, st, worker))
			guest := &fakeguest.Guest{}
			var sessionCtx context.Context
			s.Sessions = &session.Client{Connect: func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
				sessionCtx = ctx
				return guest.Connect(ctx, namespace, pod)
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sess, err := s.openState(ctx, "alice", stateEntry(st, "alice"), wire.Open{Mode: wire.OpenExec})
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			if _, deadline := sessionCtx.Deadline(); deadline || sessionCtx != ctx || sessionCtx.Err() != nil {
				t.Fatal("guest session inherited startup timeout/cancellation")
			}
			if opens := guest.Opens(); len(opens) != 1 || opens[0].Pod != worker.Status.Pod {
				t.Fatalf("wrong worker target: %#v", opens)
			}
		})
	}
}

func TestOpenStateWaitsForMountReadiness(t *testing.T) {
	for _, tt := range []struct {
		name, initial, next string
		noUID               bool
	}{
		{name: "absent-to-mounted", next: v1alpha1.MountMounted},
		{name: "pending-to-mounted", initial: v1alpha1.MountPending, next: v1alpha1.MountMounted},
		{name: "unmounting-to-mounted", initial: v1alpha1.MountUnmounting, next: v1alpha1.MountMounted},
		{name: "pending-to-failed", initial: v1alpha1.MountPending, next: v1alpha1.MountFailed},
		{name: "acquisition-failed", next: v1alpha1.MountFailed, noUID: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := catalogState("alice", "fork", "alice.home")
			worker := catalogBlip("alice", "worker", "", v1alpha1.BlipRunning)
			worker.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Path: "/work", Writable: true}}
			mount := v1alpha1.MountStatus{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: tt.initial}
			if tt.initial != "" {
				worker.Status.Mounts = []v1alpha1.MountStatus{mount}
			}
			var started atomic.Bool
			listed := make(chan struct{}, 1)
			kube := interceptor.NewClient(catalogClient(t, st, worker), interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					err := c.List(ctx, list, opts...)
					if started.Load() {
						select {
						case listed <- struct{}{}:
						default:
						}
					}
					return err
				},
			})
			s := backendServer(t, kube)
			entries, err := s.Catalog.List("alice")
			if err != nil || len(entries) != 1 || entries[0].Running {
				t.Fatalf("unattached state has Running badge: %v, %v", entries, err)
			}
			changes, unsubscribe := s.Catalog.Subscribe("alice")
			defer unsubscribe()
			type result struct {
				pod string
				err error
			}
			done := make(chan result, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started.Store(true)
			go func() {
				pod, err := s.startSelectedState(ctx, "alice", stateEntry(st, "alice"))
				done <- result{pod, err}
			}()
			select {
			case <-listed:
			case <-ctx.Done():
				t.Fatal("startup did not read the worker")
			}
			select {
			case got := <-done:
				t.Fatalf("startup returned before mount attached: %+v", got)
			case <-time.After(30 * time.Millisecond):
			}
			mount.Phase = tt.next
			if tt.next == v1alpha1.MountFailed {
				mount.Message = "selected filesystem could not be mounted"
			}
			if tt.noUID {
				mount.StateUID = ""
			}
			worker.Status.Mounts = []v1alpha1.MountStatus{mount}
			if err := s.Kube.Update(ctx, worker); err != nil {
				t.Fatal(err)
			}
			awaitCatalogEvent(t, changes)
			select {
			case got := <-done:
				if tt.next == v1alpha1.MountMounted {
					if got.err != nil || got.pod != worker.Status.Pod {
						t.Fatalf("mounted worker not opened: %+v", got)
					}
				} else if got.err == nil || !strings.Contains(got.err.Error(), mount.Message) || got.pod != "" {
					t.Fatalf("failed mount did not return its message: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal("mount update did not wake startup")
			}
			entries, err = s.Catalog.List("alice")
			if err != nil || len(entries) != 1 || entries[0].Running != (tt.next == v1alpha1.MountMounted) {
				t.Fatalf("updated mount badge incorrect: %v, %v", entries, err)
			}
		})
	}
}

func TestOpenStateWaitsForCurrentRootAttachment(t *testing.T) {
	st := catalogState("alice", "home", "")
	worker := catalogBlip("alice", "home", st.Name, v1alpha1.BlipRunning)
	worker.Status.RootAttachmentID = "old-attachment"
	st.Status.Writer = &v1alpha1.Writer{BlipName: worker.Name, BlipUID: string(worker.UID), AttachmentID: "current-attachment"}
	s := backendServer(t, catalogClient(t, st, worker))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if pod, err := s.startSelectedState(ctx, "alice", stateEntry(st, "alice")); !errors.Is(err, context.DeadlineExceeded) || pod != "" {
		t.Fatalf("opened stale root attachment: pod=%q err=%v", pod, err)
	}
	worker.Status.RootAttachmentID = st.Status.Writer.AttachmentID
	if err := s.Kube.Update(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	pod, err := s.startSelectedState(context.Background(), "alice", stateEntry(st, "alice"))
	if err != nil || pod != worker.Status.Pod {
		t.Fatalf("current root attachment not opened: pod=%q err=%v", pod, err)
	}
}

func TestOpenStatePreservesFinishedWorkerForks(t *testing.T) {
	for _, mount := range []bool{false, true} {
		t.Run(fmt.Sprintf("mount=%t", mount), func(t *testing.T) {
			st := catalogState("alice", "worker", "alice.home")
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipSucceeded)
			if mount {
				worker.Spec.State = ""
				worker.Spec.Mounts = []v1alpha1.Mount{{State: st.Name, Writable: true}}
			}
			st.OwnerReferences = []metav1.OwnerReference{{APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip", Name: worker.Name, UID: worker.UID}}
			s := backendServer(t, catalogClient(t, st, worker))
			_, err := s.openState(context.Background(), "alice", stateEntry(st, "alice"), wire.Open{Mode: wire.OpenExec})
			if err == nil || !strings.Contains(err.Error(), "preserved") {
				t.Fatalf("expected preserved-worker error: %v", err)
			}
			for _, obj := range []client.Object{st, worker} {
				live := obj.DeepCopyObject().(client.Object)
				if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(obj), live); err != nil || live.GetUID() != obj.GetUID() || live.GetDeletionTimestamp() != nil {
					t.Fatalf("worker state was destroyed/replaced: %s: %v", obj.GetName(), err)
				}
			}
		})
	}
}

func TestOpenStateRestartsDurableRootWithoutRecreatingState(t *testing.T) {
	st := catalogState("alice", "home", "")
	worker := catalogBlip("alice", "home", st.Name, v1alpha1.BlipSucceeded)
	var creates int
	kube := interceptor.NewClient(catalogClient(t, st, worker), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			b, ok := obj.(*v1alpha1.Blip)
			if !ok {
				t.Fatal("selected state was recreated")
			}
			creates++
			b.Status = v1alpha1.BlipStatus{Phase: v1alpha1.BlipRunning, Pod: "new-pod"}
			return c.Create(ctx, obj, opts...)
		},
	})
	s := backendServer(t, kube)
	pod, err := s.startSelectedState(context.Background(), "alice", stateEntry(st, "alice"))
	if err != nil || pod != "new-pod" || creates != 1 {
		t.Fatalf("restart: pod=%q creates=%d err=%v", pod, creates, err)
	}
	var live v1alpha1.BlipState
	if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(st), &live); err != nil || live.UID != st.UID {
		t.Fatalf("state changed: %v", err)
	}
}

func TestOpenStateNeverRecreatesDeletedSelection(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace=%t", replace), func(t *testing.T) {
			st := catalogState("alice", "home", "")
			kube := interceptor.NewClient(catalogClient(t, st), interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*v1alpha1.Blip); !ok {
						t.Fatal("selected state was recreated")
					}
					if err := c.Delete(ctx, st); err != nil {
						return err
					}
					if replace {
						next := st.DeepCopy()
						next.UID, next.ResourceVersion = "replacement", ""
						if err := c.Create(ctx, next); err != nil {
							return err
						}
					}
					return c.Create(ctx, obj, opts...)
				},
			})
			s := backendServer(t, kube)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := s.startSelectedState(ctx, "alice", stateEntry(st, "alice")); err == nil {
				t.Fatal("opened deleted/replaced selection")
			}
			var live v1alpha1.BlipState
			err := s.Kube.Get(ctx, client.ObjectKeyFromObject(st), &live)
			if replace && (err != nil || live.UID != "replacement") || !replace && !apierrors.IsNotFound(err) {
				t.Fatalf("deleted selection recreated or replacement changed: %#v, %v", live, err)
			}
		})
	}
}
