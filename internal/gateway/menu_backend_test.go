package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway/menu"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

func backendServer(t *testing.T, kube client.WithWatch) *Server {
	t.Helper()
	kube = withUIDs(kube)
	return &Server{
		Config: Config{Namespace: ns, BaseState: "gateway-base", Pool: "small", StateSize: resource.MustParse("20Gi")},
		Kube:   kube, Catalog: startCatalog(t, kube),
	}
}

func TestMenuBackendCreate(t *testing.T) {
	s := backendServer(t, catalogClient(t, gatewayBase(), catalogState("alice", "existing", ""), catalogBlip("alice", "worker", "", v1alpha1.BlipPending)))
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
	if e.ID != "alice.new" || e.Name != "new" || e.UID == "" || e.Running {
		t.Fatalf("created entry = %#v", e)
	}
	var st v1alpha1.BlipState
	if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: e.ID}, &st); err != nil {
		t.Fatal(err)
	}
	if st.Spec.Image != "" || st.Spec.CopyFrom != s.BaseState || st.Spec.Size == nil || !st.Spec.Size.Equal(s.StateSize) || st.Labels[v1alpha1.LabelOwner] != "alice" || len(st.OwnerReferences) != 0 {
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

func TestForkStateCopiesWorkspace(t *testing.T) {
	for _, explicitIdle := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-idle=%t", explicitIdle), func(t *testing.T) {
			source := catalogState("alice", "source", "gateway-base")
			source.Spec.Runtime = &v1alpha1.RuntimeDefaults{
				Env:        []v1alpha1.EnvVar{{Name: "WORKSPACE", Value: "inherited"}},
				WorkingDir: "/work", User: "1000", Network: &v1alpha1.NetworkPolicy{},
			}
			if explicitIdle {
				source.Spec.Runtime.IdleTimeout = &metav1.Duration{} // explicit zero wins
			}
			data := catalogState("alice", "data", "gateway-base")
			tools := gatewayBase()
			tools.Name = "shared-tools"
			source.Spec.Mounts = []v1alpha1.Mount{
				{State: data.Name, Path: "/work", Writable: true},
				{State: "shared-tools", Path: "/tools"},
				{State: "temporary", Path: "/tmp/work", Writable: true, BlipUID: "old-worker"},
			}
			s := backendServer(t, catalogClient(t, source, data, tools))
			s.IdleTimeout = time.Minute
			ctx := context.Background()
			root, err := s.forkState(ctx, "alice", "alice.fork", source)
			if err != nil {
				t.Fatal(err)
			}
			wantRuntime := source.Spec.Runtime.DeepCopy()
			if !explicitIdle {
				wantRuntime.IdleTimeout = &metav1.Duration{Duration: time.Minute}
			}
			if root.Spec.Image != "" || root.Spec.CopyFrom != source.Name || root.Spec.Size != nil || len(root.OwnerReferences) != 0 || !reflect.DeepEqual(root.Spec.Runtime, wantRuntime) {
				t.Fatalf("fork configuration: %#v", root)
			}
			if len(root.Spec.Mounts) != 2 || root.Spec.Mounts[0].State == data.Name || root.Spec.Mounts[1] != source.Spec.Mounts[1] {
				t.Fatalf("fork mounts: %#v", root.Spec.Mounts)
			}
			var child v1alpha1.BlipState
			if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: root.Spec.Mounts[0].State}, &child); err != nil {
				t.Fatal(err)
			}
			if child.Spec.CopyFrom != data.Name || child.Labels[v1alpha1.LabelOwner] != "alice" || len(child.OwnerReferences) != 0 {
				t.Fatalf("writable mount was not copied independently: %#v", child)
			}
			var liveSource v1alpha1.BlipState
			if err := s.Kube.Get(ctx, client.ObjectKeyFromObject(source), &liveSource); err != nil || !reflect.DeepEqual(liveSource.Spec, source.Spec) {
				t.Fatalf("fork changed the shared source: %v", err)
			}
			if b := s.sandboxBlip("alice", root.Name); b.Spec.IdleTimeout != nil {
				t.Fatal("execution overrides the durable runtime default")
			}
		})
	}
}

func TestMenuBackendImportedAndSharedStatesCannotRun(t *testing.T) {
	for _, owner := range []string{"", "alice", "bob"} {
		t.Run("owner="+owner, func(t *testing.T) {
			st := gatewayBase()
			if owner != "" {
				st.Labels = map[string]string{v1alpha1.LabelOwner: owner}
				st.Name = owner + ".base"
			}
			s := backendServer(t, catalogClient(t, st))
			entry := stateEntry(st, "alice")
			// The menu only lists owned roots, but startup revalidates the
			// live state so an imported base cannot be run writable.
			_, err := s.startSelectedState(context.Background(), "alice", entry)
			if err == nil {
				t.Fatal("imported/shared state was run writable")
			}
			if owner == "alice" && !strings.Contains(err.Error(), "cannot be run directly") {
				t.Fatalf("unexpected start error: %v", err)
			}
			deleteErr := s.menuBackend("alice").Delete(context.Background(), entry)
			if (deleteErr != nil) != (owner != "alice") {
				t.Fatalf("delete owner %q: %v", owner, deleteErr)
			}
		})
	}
}

func TestMenuBackendRejectsReplacedSelection(t *testing.T) {
	st := catalogState("alice", "home", "")
	s := backendServer(t, catalogClient(t, st))
	entry := menu.Entry{ID: st.Name, UID: "previous-home"}
	if _, err := s.startSelectedState(context.Background(), "alice", entry); err == nil {
		t.Fatal("startup accepted a replaced selection")
	}
	var list v1alpha1.BlipStateList
	if err := s.Kube.List(context.Background(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("replaced selection created states: %v, %v", list.Items, err)
	}
}

func TestMenuBackendDeleteAssociationsPreservesOthers(t *testing.T) {
	st := catalogState("alice", "home", "")
	st.Finalizers = []string{"blip.dev/test"}
	root := catalogBlip("alice", "root-worker", st.Name, v1alpha1.BlipRunning)
	writer := catalogBlip("alice", "mount-worker", "", v1alpha1.BlipRunning)
	writerRoot := mountRoot(writer, v1alpha1.Mount{State: st.Name, Path: "/work", Writable: true})
	writer.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
	reader := catalogBlip("alice", "reader", "", v1alpha1.BlipRunning)
	readerRoot := mountRoot(reader, v1alpha1.Mount{State: st.Name, Path: "/work"})
	saving := catalogBlip("alice", "saving", "", v1alpha1.BlipSaving)
	saving.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID)}}
	foreign := catalogBlip("bob", "foreign", st.Name, v1alpha1.BlipRunning)
	unrelated := catalogBlip("alice", "home", "alice.other", v1alpha1.BlipRunning)
	child := catalogState("alice", "child", st.Name)
	objects := []client.Object{st, root, writer, reader, saving, foreign, unrelated, child, writerRoot, readerRoot}
	for _, b := range []*v1alpha1.Blip{root, writer, reader, saving} {
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
	if deletes != 5 {
		t.Fatalf("deleted %d resources, want state plus four associated Blips", deletes)
	}
	for _, obj := range objects {
		live := obj.DeepCopyObject().(client.Object)
		if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(obj), live); err != nil {
			t.Fatalf("finalized resource prematurely removed: %s: %v", obj.GetName(), err)
		}
		shouldDelete := obj == st || obj == root || obj == writer || obj == reader || obj == saving
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
				st.Labels[v1alpha1.LabelOwner] = "bob"
			case "missing-uid":
				entry.UID = ""
			}
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
			s := backendServer(t, catalogClient(t, st, worker))
			if err := s.menuBackend("alice").Delete(context.Background(), entry); err == nil {
				t.Fatal("unsafe delete accepted")
			}
			if _, err := s.openState(context.Background(), context.Background(), "alice", entry, wire.Open{Mode: wire.OpenExec}); err == nil {
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
				live.Labels[v1alpha1.LabelOwner] = "bob"
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
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
			objects := []client.Object{st, worker}
			if mount {
				objects = append(objects, mountRoot(worker, v1alpha1.Mount{State: st.Name, Path: "/work", Writable: true}))
				worker.Status.Mounts = []v1alpha1.MountStatus{{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: v1alpha1.MountMounted}}
			}
			st.Status.Writer = &v1alpha1.Writer{BlipName: worker.Name, BlipUID: string(worker.UID)}
			s := backendServer(t, catalogClient(t, objects...))
			guest := &fakeguest.Guest{}
			var sessionCtx context.Context
			s.Sessions = &session.Client{Connect: func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
				sessionCtx = ctx
				return guest.Connect(ctx, namespace, pod)
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sess, err := s.openState(ctx, ctx, "alice", stateEntry(st, "alice"), wire.Open{Mode: wire.OpenExec})
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

func TestOpenStateRetryReusesOpenID(t *testing.T) {
	st := catalogState("alice", "fork", "alice.home")
	worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipRunning)
	st.Status.Writer = &v1alpha1.Writer{BlipName: worker.Name, BlipUID: string(worker.UID)}
	s := backendServer(t, catalogClient(t, st, worker))
	guest := &fakeguest.Guest{}
	captured := make(chan wire.Open, 1)
	var first atomic.Bool
	s.Sessions = &session.Client{Connect: func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		if first.CompareAndSwap(false, true) {
			return captureEOFConn{opens: captured}, nil
		}
		return guest.Connect(ctx, namespace, pod)
	}}
	sess, err := s.openState(context.Background(), context.Background(), "alice", stateEntry(st, "alice"), wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	opens := guest.Opens()
	if len(opens) != 1 {
		t.Fatalf("guest opened %d sessions, want 1", len(opens))
	}
	var failed wire.Open
	select {
	case failed = <-captured:
	default:
		t.Fatal("the failed attempt did not send an open")
	}
	got := opens[0].Open
	if failed.OpenID == "" || got.OpenID != failed.OpenID {
		t.Fatalf("retry OpenID = %q, first attempt = %q; want the same non-empty ID", got.OpenID, failed.OpenID)
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
			root := mountRoot(worker, v1alpha1.Mount{State: st.Name, Path: "/work", Writable: true})
			mount := v1alpha1.MountStatus{State: st.Name, StateUID: string(st.UID), Path: "/work", Writable: true, Phase: tt.initial}
			if tt.initial != "" {
				worker.Status.Mounts = []v1alpha1.MountStatus{mount}
			}
			var started atomic.Bool
			listed := make(chan struct{}, 1)
			kube := interceptor.NewClient(catalogClient(t, st, worker, root), interceptor.Funcs{
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
			if err != nil || len(entries) != 1 || entries[0].ID != root.Name {
				t.Fatalf("mount target should be hidden: %v, %v", entries, err)
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
			if err != nil || len(entries) != 1 || entries[0].ID != root.Name {
				t.Fatalf("mount target appeared after update: %v, %v", entries, err)
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

func TestOpenStateRestartsFinishedWorkerForks(t *testing.T) {
	for _, mount := range []bool{false, true} {
		t.Run(fmt.Sprintf("mount=%t", mount), func(t *testing.T) {
			st := catalogState("alice", "worker", "alice.home")
			worker := catalogBlip("alice", "worker", st.Name, v1alpha1.BlipSucceeded)
			worker.Spec.Command = []string{"true"}
			objects := []client.Object{st, worker}
			if mount {
				objects = append(objects, mountRoot(worker, v1alpha1.Mount{State: st.Name, Path: "/work", Writable: true}))
			}
			kube := interceptor.NewClient(catalogClient(t, objects...), interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					b, ok := obj.(*v1alpha1.Blip)
					if !ok || b.Spec.State != st.Name || len(b.Spec.Command) != 0 {
						t.Fatalf("unexpected restart: %#v", obj)
					}
					b.Status = v1alpha1.BlipStatus{Phase: v1alpha1.BlipRunning, Pod: "restarted"}
					return c.Create(ctx, obj, opts...)
				},
			})
			s := backendServer(t, kube)
			pod, err := s.startSelectedState(context.Background(), "alice", stateEntry(st, "alice"))
			if err != nil || pod != "restarted" {
				t.Fatalf("restart: pod=%q err=%v", pod, err)
			}
			var live v1alpha1.BlipState
			if err := s.Kube.Get(context.Background(), client.ObjectKeyFromObject(st), &live); err != nil || live.UID != st.UID || live.DeletionTimestamp != nil {
				t.Fatalf("state was destroyed/replaced: %v", err)
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
