package workspace

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

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
		IdleTimeout: &metav1.Duration{Duration: time.Minute}, Network: &v1alpha1.NetworkPolicy{},
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
	dest.Labels = map[string]string{"blip.dev/owner": "alice"}
	size := resource.MustParse("20Gi")
	dest.Spec.Size, dest.Spec.Replicas = &size, 2
	dest.Spec.NodeSelector = map[string]string{"disk": "ssd"}
	if err := Fork(ctx, c, src, dest); err != nil {
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
		if child.Spec.CopyFrom != src.Spec.Mounts[i].State || child.Spec.Runtime != nil || len(child.Spec.Mounts) != 0 || len(child.OwnerReferences) != 0 || child.Labels["blip.dev/owner"] != "alice" || child.Spec.Replicas != 2 || child.Spec.Size != nil {
			t.Fatalf("child: %+v", child)
		}
	}
	if dest.Spec.Mounts[2] != src.Spec.Mounts[2] {
		t.Fatal("read-only reference changed")
	}
	src.Spec.Runtime.Env[0].Value = "changed"
	src.Spec.Runtime.IdleTimeout.Duration = time.Hour
	src.Spec.Mounts[0].Path = "/changed"
	if dest.Spec.Runtime.Env[0].Value != "original" || dest.Spec.Runtime.IdleTimeout.Duration != time.Minute || dest.Spec.Mounts[0].Path != "/work" {
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
			if err := Fork(ctx, c, src, dest); !apierrors.IsAlreadyExists(err) {
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

func TestForkPreflightAndReplacementSafety(t *testing.T) {
	ctx := context.Background()
	src, dest := testState("source"), testState("worker")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "a", Path: "/a", Writable: true}}
	c := testClient(t, src, testState("a"), dest)
	if err := Fork(ctx, c, src, dest); !apierrors.IsAlreadyExists(err) {
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
	if err := Fork(ctx, c, src, dest); !errors.Is(err, failure) {
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
				c := interceptor.NewClient(base, interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
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
						t.Fatalf("ambiguous create caused deletion of %q", obj.GetName())
						return nil
					},
				})
				if err := Fork(ctx, c, src, dest); !errors.Is(err, tc.err) {
					t.Fatalf("error: %v, want %v", err, tc.err)
				}
				for _, key := range persisted {
					if err := base.Get(context.Background(), key, &v1alpha1.BlipState{}); err != nil {
						t.Fatalf("persisted state %q lost: %v", key.Name, err)
					}
				}
				var root v1alpha1.BlipState
				err := base.Get(context.Background(), client.ObjectKeyFromObject(dest), &root)
				if stage == "child" {
					if !apierrors.IsNotFound(err) || len(persisted) != 2 {
						t.Fatalf("continued after ambiguous child create: root error %v, created %v", err, persisted)
					}
					return
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
			if err := Fork(ctx, c, src, dest); !apierrors.IsInvalid(err) {
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

func TestChildNamesBoundedAndDistinct(t *testing.T) {
	root := testState("alice." + strings.Repeat("long-name.", 20) + "end")
	root.Labels = map[string]string{"blip.dev/owner": "alice"}
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
