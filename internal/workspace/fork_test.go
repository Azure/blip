// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func testState(name string) *v1alpha1.BlipState {
	return &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}}
}

func testClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestForkWorkspaceSnapshot(t *testing.T) {
	ctx := context.Background()
	src := testState("shared")
	src.Spec.Image = "registry/base:v1"
	src.Spec.Runtime = &v1alpha1.RuntimeDefaults{
		Env: []v1alpha1.EnvVar{{Name: "A", Value: "original"}}, WorkingDir: "/work", User: "dev",
		Network: &v1alpha1.NetworkPolicy{},
	}
	src.Spec.Mounts = []v1alpha1.Mount{
		{State: "repo", Path: "/work", Writable: true},
		{State: "cache", Path: "/cache", Writable: true},
		{State: "tools", Path: "/tools"},
		{State: "transient", Path: "/temporary", Writable: true, BlipUID: "old-execution"},
	}
	repo := testState("repo")
	// A mounted state's configuration is not part of this workspace.
	repo.Spec.Runtime = &v1alpha1.RuntimeDefaults{User: "other"}
	repo.Spec.Mounts = []v1alpha1.Mount{{State: "missing-nested", Path: "/nested", Writable: true}}
	c := testClient(t, src, repo, testState("cache"), testState("tools"))
	dest := testState("alice.worker")
	dest.Labels = map[string]string{v1alpha1.LabelOwner: "alice"}
	size := resource.MustParse("20Gi")
	dest.Spec.Size, dest.Spec.Replicas = &size, 2
	dest.Spec.NodeSelector = map[string]string{"disk": "ssd"}
	if _, err := Fork(ctx, c, src, dest, nil); err != nil {
		t.Fatal(err)
	}
	if dest.Spec.CopyFrom != src.Name || dest.Spec.Image != "" || len(dest.Spec.Mounts) != 3 || !reflect.DeepEqual(dest.Spec.Runtime, src.Spec.Runtime) {
		t.Fatalf("root spec: %+v", dest.Spec)
	}
	if dest.Spec.Size.String() != "20Gi" || dest.Spec.Replicas != 2 || len(dest.OwnerReferences) != 0 {
		t.Fatalf("root: %+v", dest)
	}
	for i := 0; i < 2; i++ {
		m := dest.Spec.Mounts[i]
		if m.State == src.Spec.Mounts[i].State || !strings.HasPrefix(m.State, "alice.worker-") || len(validation.IsDNS1123Subdomain(m.State)) != 0 {
			t.Fatalf("child mount: %+v", m)
		}
		var child v1alpha1.BlipState
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: m.State}, &child); err != nil {
			t.Fatal(err)
		}
		if child.Spec.CopyFrom != src.Spec.Mounts[i].State || child.Spec.Runtime != nil || len(child.Spec.Mounts) != 0 ||
			len(child.OwnerReferences) != 1 || child.OwnerReferences[0].Kind != "BlipState" || child.OwnerReferences[0].Name != dest.Name ||
			child.Labels[v1alpha1.LabelOwner] != "alice" || child.Spec.Replicas != 2 || child.Spec.Size != nil {
			t.Fatalf("child: %+v", child)
		}
	}
	if dest.Spec.Mounts[2] != src.Spec.Mounts[2] {
		t.Fatal("read-only reference changed")
	}
	src.Spec.Runtime.Env[0].Value = "changed"
	src.Spec.Mounts[0].Path = "/changed"
	if dest.Spec.Runtime.Env[0].Value != "original" || dest.Spec.Mounts[0].Path != "/work" {
		t.Fatal("fork aliases source configuration")
	}
	if err := c.Delete(ctx, src); err != nil {
		t.Fatal(err)
	}
	var saved v1alpha1.BlipState
	if err := c.Get(ctx, client.ObjectKeyFromObject(dest), &saved); err != nil || saved.Spec.Runtime.Env[0].Value != "original" {
		t.Fatalf("snapshot after source deletion: %+v %v", saved, err)
	}
}

func TestForkRollbackPreservesExistingStates(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			ctx := context.Background()
			src, dest := testState("source"), testState("worker")
			src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}, {State: "b", Path: "/b", Writable: true}}
			base := testClient(t, src, testState("a"), testState("b"))
			count := 0
			var raced string
			c := interceptor.NewClient(base, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				count++
				if count == failAt {
					// Another creator wins the race after destination preflight.
					existing := testState(obj.GetName())
					existing.Labels = map[string]string{"existing": "keep"}
					if err := c.Create(ctx, existing); err != nil {
						t.Fatal(err)
					}
					raced = existing.Name
					return apierrors.NewAlreadyExists(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), obj.GetName())
				}
				return c.Create(ctx, obj, opts...)
			}})
			if _, err := Fork(ctx, c, src, dest, nil); !apierrors.IsAlreadyExists(err) {
				t.Fatalf("error: %v", err)
			}
			var states v1alpha1.BlipStateList
			if err := base.List(ctx, &states); err != nil {
				t.Fatal(err)
			}
			if len(states.Items) != 4 {
				t.Fatalf("rollback left %d states: %+v", len(states.Items), states.Items)
			}
			var existing v1alpha1.BlipState
			if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: raced}, &existing); err != nil || existing.Labels["existing"] != "keep" {
				t.Fatalf("existing state changed: %+v %v", existing, err)
			}
		})
	}
}

func TestCheckSourceAllowsFailedPending(t *testing.T) {
	src := testState("src")
	src.Status.Phase = v1alpha1.StateFailed
	src.Status.Message = "initial version failed: fetch: device busy"
	src.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n1"}
	if err := CheckSource(src); err != nil {
		t.Fatalf("failed-but-pending source rejected: %v", err)
	}
	src.Status.Pending = nil
	if err := CheckSource(src); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("terminally failed source accepted: %v", err)
	}
}

func TestForkPreflightAndReplacementSafety(t *testing.T) {
	ctx := context.Background()
	src, dest := testState("source"), testState("worker")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}}
	c := testClient(t, src, testState("a"), dest)
	if _, err := Fork(ctx, c, src, dest, nil); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("existing root: %v", err)
	}
	var states v1alpha1.BlipStateList
	_ = c.List(ctx, &states)
	if len(states.Items) != 3 {
		t.Fatal("created child despite existing root")
	}
	_ = c.Delete(ctx, dest)
	var child *v1alpha1.BlipState
	failure := apierrors.NewForbidden(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), dest.Name, errors.New("root create denied"))
	cleanupAttempted := false
	c = interceptor.NewClient(c, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			cleanupAttempted = true
			// The fake client does not enforce UID delete preconditions.
			options := &client.DeleteOptions{}
			options.ApplyOptions(opts)
			if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != "original" {
				t.Fatal("rollback did not pin the created state's UID")
			}
			return apierrors.NewConflict(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), obj.GetName(), errors.New("UID changed"))
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetName() == dest.Name {
				_ = c.Delete(ctx, child)
				replacement := testState(child.Name)
				replacement.UID = types.UID("replacement")
				if err := c.Create(ctx, replacement); err != nil {
					t.Fatal(err)
				}
				return failure
			}
			obj.SetUID(types.UID("original"))
			child = obj.(*v1alpha1.BlipState)
			return c.Create(ctx, obj, opts...)
		},
	})
	if _, err := Fork(ctx, c, src, dest, nil); !errors.Is(err, failure) {
		t.Fatalf("fork failure: %v", err)
	}
	if !cleanupAttempted {
		t.Fatal("definitive rejection did not trigger cleanup")
	}
	var replacement v1alpha1.BlipState
	if err := c.Get(ctx, client.ObjectKeyFromObject(child), &replacement); err != nil || replacement.UID != "replacement" {
		t.Fatalf("deleted replacement: %+v %v", replacement, err)
	}
}

func TestForkPreservesStatesAfterAmbiguousCreate(t *testing.T) {
	for _, stage := range []string{"root", "child"} {
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"canceled", context.Canceled},
			{"deadline", context.DeadlineExceeded},
			{"response lost", io.ErrUnexpectedEOF},
			{"API timeout", apierrors.NewTimeoutError("response lost", 1)},
			{"server failure", apierrors.NewInternalError(errors.New("response lost"))},
		} {
			t.Run(stage+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				src, dest := testState("source"), testState("worker")
				src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}, {State: "b", Path: "/b", Writable: true}}
				base := testClient(t, src, testState("a"), testState("b"))
				var persisted []client.ObjectKey
				uids := 0
				c := interceptor.NewClient(base, interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						uids++
						obj.SetUID(types.UID(fmt.Sprintf("uid-%d", uids)))
						// The server commits the object, but the client never gets
						// the response (or its assigned resourceVersion and UID).
						if err := c.Create(ctx, obj.DeepCopyObject().(client.Object), opts...); err != nil {
							t.Fatal(err)
						}
						persisted = append(persisted, client.ObjectKeyFromObject(obj))
						if stage == "root" && obj.GetName() == dest.Name || stage == "child" && len(persisted) == 2 {
							if errors.Is(tc.err, context.Canceled) {
								cancel()
							}
							return tc.err
						}
						return nil
					},
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if stage == "root" {
							t.Fatalf("ambiguous root create caused deletion of %q", obj.GetName())
						}
						options := &client.DeleteOptions{}
						options.ApplyOptions(opts)
						if options.Preconditions == nil || options.Preconditions.UID == nil {
							t.Fatalf("child rollback did not pin %q's UID", obj.GetName())
						}
						return c.Delete(ctx, obj, opts...)
					},
				})
				if _, err := Fork(ctx, c, src, dest, nil); !errors.Is(err, tc.err) {
					t.Fatalf("error: %v, want %v", err, tc.err)
				}
				var root v1alpha1.BlipState
				err := base.Get(context.Background(), client.ObjectKeyFromObject(dest), &root)
				if stage == "child" {
					if !apierrors.IsNotFound(err) || len(persisted) != 2 {
						t.Fatalf("continued after ambiguous child create: root error %v, created %v", err, persisted)
					}
					// Children known by UID are rolled back. The create whose
					// response was lost may have persisted an ownerless state
					// with no UID to pin, so it is left for explicit cleanup.
					if err := base.Get(context.Background(), persisted[0], &v1alpha1.BlipState{}); !apierrors.IsNotFound(err) {
						t.Fatalf("child before the ambiguous create was not rolled back: %v", err)
					}
					if err := base.Get(context.Background(), persisted[1], &v1alpha1.BlipState{}); err != nil {
						t.Fatalf("ambiguous child state lost: %v", err)
					}
					return
				}
				for _, key := range persisted {
					if err := base.Get(context.Background(), key, &v1alpha1.BlipState{}); err != nil {
						t.Fatalf("persisted state %q lost: %v", key.Name, err)
					}
				}
				if err != nil || len(root.Spec.Mounts) != 2 {
					t.Fatalf("persisted root: %+v, %v", root, err)
				}
				for _, mount := range root.Spec.Mounts {
					if err := base.Get(context.Background(), client.ObjectKey{Namespace: root.Namespace, Name: mount.State}, &v1alpha1.BlipState{}); err != nil {
						t.Fatalf("durable root references missing child %q: %v", mount.State, err)
					}
				}
			})
		}
	}
}

func TestForkRollsBackValidationRejection(t *testing.T) {
	for _, stage := range []string{"root", "child"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			src, dest := testState("source"), testState("worker")
			src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}, {State: "b", Path: "/b", Writable: true}}
			base := testClient(t, src, testState("a"), testState("b"))
			creates := 0
			c := interceptor.NewClient(base, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				creates++
				if stage == "root" && obj.GetName() == dest.Name || stage == "child" && creates == 2 {
					return apierrors.NewInvalid(v1alpha1.GroupVersion.WithKind("BlipState").GroupKind(), obj.GetName(), field.ErrorList{field.Invalid(field.NewPath("spec", "replicas"), 4, "must be at most 3")})
				}
				return c.Create(ctx, obj, opts...)
			}})
			if _, err := Fork(ctx, c, src, dest, nil); !apierrors.IsInvalid(err) {
				t.Fatalf("error: %v", err)
			}
			var states v1alpha1.BlipStateList
			if err := base.List(ctx, &states); err != nil {
				t.Fatal(err)
			}
			if len(states.Items) != 3 {
				t.Fatalf("validation rejection left copies: %+v", states.Items)
			}
			for _, original := range []string{"source", "a", "b"} {
				if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: original}, &v1alpha1.BlipState{}); err != nil {
					t.Fatalf("source %q lost: %v", original, err)
				}
			}
		})
	}
}

// TestForkRollsBackChildrenAfterTransportError covers a transport error or
// cancellation while creating the second writable-mount copy. No root exists
// yet, so the child already created by this call is an orphan and must be
// rolled back even though the error does not prove the failed create was
// rejected.
func TestForkRollsBackChildrenAfterTransportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"canceled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
		{"response lost", io.ErrUnexpectedEOF},
		{"server failure", apierrors.NewInternalError(errors.New("response lost"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			src, dest := testState("source"), testState("worker")
			src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}, {State: "b", Path: "/b", Writable: true}}
			base := testClient(t, src, testState("a"), testState("b"))
			creates, uids := 0, 0
			c := interceptor.NewClient(base, interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					creates++
					if creates == 2 {
						return tc.err
					}
					uids++
					obj.SetUID(types.UID(fmt.Sprintf("uid-%d", uids)))
					return c.Create(ctx, obj, opts...)
				},
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					options := &client.DeleteOptions{}
					options.ApplyOptions(opts)
					if options.Preconditions == nil || options.Preconditions.UID == nil {
						t.Fatalf("rollback did not pin %q's UID", obj.GetName())
					}
					return c.Delete(ctx, obj, opts...)
				},
			})
			if _, err := Fork(ctx, c, src, dest, nil); !errors.Is(err, tc.err) {
				t.Fatalf("error: %v, want %v", err, tc.err)
			}
			var states v1alpha1.BlipStateList
			if err := base.List(ctx, &states); err != nil {
				t.Fatal(err)
			}
			if len(states.Items) != 3 {
				t.Fatalf("rollback left %d states: %+v", len(states.Items), states.Items)
			}
			for _, name := range []string{"source", "a", "b"} {
				if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &v1alpha1.BlipState{}); err != nil {
					t.Fatalf("source %q lost: %v", name, err)
				}
			}
		})
	}
}

func TestChildNamesBoundedAndDistinct(t *testing.T) {
	root := testState("alice." + strings.Repeat("long-name.", 20) + "end")
	root.Labels = map[string]string{v1alpha1.LabelOwner: "alice"}
	mount := v1alpha1.Mount{State: "repo", Path: "/work"}
	name := childName(root, mount)
	if len(name) > 70 || len(validation.IsDNS1123Subdomain(name)) != 0 || !strings.HasPrefix(name, "alice.") || name != childName(root, mount) {
		t.Fatalf("name %q", name)
	}
	root.Name += "x"
	if name == childName(root, mount) {
		t.Fatal("truncated names collide")
	}
}

// TestDurableForkCopiesOwnedByRoot reproduces a --keep fork: the root has no
// owner (it must outlive its Blip), but every hidden writable-mount copy is
// owned by the root so deleting the workspace root removes the copies too.
func TestDurableForkCopiesOwnedByRoot(t *testing.T) {
	ctx := context.Background()
	src := testState("src")
	src.Spec.Mounts = []v1alpha1.Mount{
		{State: "repo", Path: "/work", Writable: true},
		{State: "cache", Path: "/cache", Writable: true},
		{State: "tools", Path: "/tools"},
	}
	base := testClient(t, src, testState("repo"), testState("cache"), testState("tools"))
	created := 0
	c := interceptor.NewClient(base, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		created++
		// The API server assigns UIDs; the fake client does not.
		obj.SetUID(types.UID(fmt.Sprintf("uid-%d", created)))
		return c.Create(ctx, obj, opts...)
	}})
	dest := testState("keep")
	states, err := Fork(ctx, c, src, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 {
		t.Fatalf("created %d states", len(states))
	}
	root := states[len(states)-1]
	if root.Name != dest.Name || root.UID != "uid-3" {
		t.Fatalf("root %q uid %q", root.Name, root.UID)
	}
	if len(root.OwnerReferences) != 0 {
		t.Fatalf("durable root has an owner: %+v", root.OwnerReferences)
	}
	for _, st := range states[:len(states)-1] {
		var live v1alpha1.BlipState
		if err := base.Get(ctx, client.ObjectKeyFromObject(st), &live); err != nil {
			t.Fatal(err)
		}
		for _, ref := range [][]metav1.OwnerReference{st.OwnerReferences, live.OwnerReferences} {
			if len(ref) != 1 || ref[0].Kind != "BlipState" || ref[0].Name != root.Name ||
				ref[0].UID != root.UID || ref[0].APIVersion != v1alpha1.GroupVersion.String() {
				t.Fatalf("copy %q owner references: %+v", st.Name, ref)
			}
		}
	}
}

// TestForkRejectsDanglingReadOnlyMount verifies that --from validates every
// mount reference it copies, not only the writable ones it snapshots. A
// read-only reference to a state that is gone or going away would otherwise
// produce a fork that reports success but cannot start.
func TestForkRejectsDanglingReadOnlyMount(t *testing.T) {
	now := metav1.Now()
	for _, tc := range []struct {
		name  string
		state *v1alpha1.BlipState
		want  string
	}{
		{"missing", nil, "not found"},
		{"deleting", &v1alpha1.BlipState{
			ObjectMeta: metav1.ObjectMeta{Name: "ro", Namespace: "ns", DeletionTimestamp: &now, Finalizers: []string{"hold"}},
		}, "being deleted"},
		{"failed", &v1alpha1.BlipState{
			ObjectMeta: metav1.ObjectMeta{Name: "ro", Namespace: "ns"},
			Status:     v1alpha1.BlipStateStatus{Phase: v1alpha1.StateFailed, Message: "import failed"},
		}, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			src := testState("src")
			src.Spec.Mounts = []v1alpha1.Mount{{State: "ro", Path: "/ro"}}
			objects := []client.Object{src}
			if tc.state != nil {
				objects = append(objects, tc.state)
			}
			c := testClient(t, objects...)
			dest := testState("fork")
			states, err := Fork(ctx, c, src, dest, nil)
			if err == nil || !strings.Contains(err.Error(), `"ro"`) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error: %v", err)
			}
			if states != nil {
				t.Fatalf("returned %d states on rejection", len(states))
			}
			var list v1alpha1.BlipStateList
			if err := c.List(ctx, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != len(objects) {
				t.Fatalf("rejection created states: %+v", list.Items)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(dest), &v1alpha1.BlipState{}); !apierrors.IsNotFound(err) {
				t.Fatalf("destination created: %v", err)
			}
		})
	}
}

func TestForkOwnerReference(t *testing.T) {
	ctx := context.Background()
	src := testState("base")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "repo", Path: "/work", Writable: true}, {State: "tools", Path: "/tools"}}
	c := testClient(t, src, testState("repo"), testState("tools"))
	dest := testState("w1")
	owner := metav1.OwnerReference{APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip", Name: "w1", UID: types.UID("uid-w1")}
	if _, err := Fork(ctx, c, src, dest, &ForkOptions{Owner: &owner}); err != nil {
		t.Fatal(err)
	}
	refs := dest.OwnerReferences
	if len(refs) != 1 || refs[0] != owner {
		t.Fatalf("root owner references: %+v", refs)
	}
	var child v1alpha1.BlipState
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: dest.Spec.Mounts[0].State}, &child); err != nil {
		t.Fatal(err)
	}
	if len(child.OwnerReferences) != 1 || child.OwnerReferences[0] != owner {
		t.Fatalf("child owner references: %+v", child.OwnerReferences)
	}

	// The caller passes ownership through options, never through dest.
	dest = testState("w2")
	dest.OwnerReferences = refs
	if _, err := Fork(ctx, c, src, dest, nil); err == nil || !strings.Contains(err.Error(), "owner references") {
		t.Fatalf("dest owner references accepted: %v", err)
	}
}

// TestForkReturnsEveryCreatedState lets a caller roll back a fork it cannot
// keep. Every state Fork created must be named in the result, root last;
// read-only references and a Blip's transient mounts are not created.
func TestForkReturnsEveryCreatedState(t *testing.T) {
	ctx := context.Background()
	src := testState("src")
	src.Spec.Mounts = []v1alpha1.Mount{
		{State: "repo", Path: "/work", Writable: true},
		{State: "cache", Path: "/cache", Writable: true},
		{State: "tools", Path: "/tools"},
		{State: "transient", Path: "/temporary", Writable: true, BlipUID: "blip-uid"},
	}
	c := testClient(t, src, testState("repo"), testState("cache"), testState("tools"))
	dest := testState("dev")
	created, err := Fork(ctx, c, src, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 3 {
		t.Fatalf("created %d states, want root plus two writable copies", len(created))
	}
	for _, st := range created {
		var live v1alpha1.BlipState
		if err := c.Get(ctx, client.ObjectKeyFromObject(st), &live); err != nil {
			t.Fatalf("created state %q is not readable: %v", st.Name, err)
		}
	}
	if created[len(created)-1].Name != dest.Name {
		t.Fatalf("root is not last: %q", created[len(created)-1].Name)
	}
	want := map[string]bool{
		dest.Name:                 true,
		dest.Spec.Mounts[0].State: true,
		dest.Spec.Mounts[1].State: true,
	}
	for _, st := range created {
		if !want[st.Name] {
			t.Fatalf("unexpected created state %q", st.Name)
		}
	}
	for _, st := range created {
		if st.Name == "transient" || st.Name == "tools" {
			t.Fatalf("Fork claims to have created pre-existing state %q", st.Name)
		}
	}
}

func TestForkCarriesGitRepoIdentity(t *testing.T) {
	ctx := context.Background()
	src := testState("chat-abc")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "chat-abc-r-demo", Path: "/src/demo", Writable: true}}
	claim := testState("chat-abc-r-demo")
	claim.Labels = map[string]string{v1alpha1.LabelOwner: "chat-abc", v1alpha1.LabelGitRepo: "demo"}
	claim.Annotations = map[string]string{v1alpha1.AnnotationGitSource: "gitcache-demo-1"}
	c := testClient(t, src, claim)
	dest := testState("chat-def")
	dest.Labels = map[string]string{v1alpha1.LabelOwner: "chat-abc"}
	if _, err := Fork(ctx, c, src, dest, nil); err != nil {
		t.Fatal(err)
	}
	var child v1alpha1.BlipState
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: dest.Spec.Mounts[0].State}, &child); err != nil {
		t.Fatal(err)
	}
	if child.Labels[v1alpha1.LabelGitRepo] != "demo" || child.Labels[v1alpha1.LabelOwner] != "chat-abc" {
		t.Fatalf("child labels = %v, want the owner and git repo labels", child.Labels)
	}
	if child.Annotations[v1alpha1.AnnotationGitSource] != "gitcache-demo-1" {
		t.Fatalf("child annotations = %v, want the cache source", child.Annotations)
	}
}
