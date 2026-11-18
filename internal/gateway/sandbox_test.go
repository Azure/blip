package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestForkInheritsWorkspaceSizeAndNeverShrinksBase(t *testing.T) {
	for _, tt := range []struct {
		name, sourceSize, actualSize, gatewaySize, want string
	}{
		{name: "base-40Gi", sourceSize: "40Gi", actualSize: "40Gi", gatewaySize: "20Gi", want: "40Gi"},
		{name: "base-observed-size", sourceSize: "10Gi", actualSize: "40Gi", gatewaySize: "20Gi", want: "40Gi"},
		{name: "base-extra-space", sourceSize: "40Gi", actualSize: "40Gi", gatewaySize: "80Gi", want: "80Gi"},
		{name: "pending-base-known-size", sourceSize: "40Gi", gatewaySize: "20Gi", want: "40Gi"},
		{name: "pending-base-unresolved-size", gatewaySize: "20Gi"},
		{name: "base-sizing-disabled", sourceSize: "40Gi", actualSize: "40Gi", gatewaySize: "0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := gatewayBase()
			source.Spec.Size = nil
			if tt.sourceSize != "" {
				size := resource.MustParse(tt.sourceSize)
				source.Spec.Size = &size
			}
			if tt.actualSize != "" {
				size := resource.MustParse(tt.actualSize)
				source.Status.SizeBytes = size.Value()
			}
			s := backendServer(t, catalogClient(t, source))
			s.StateSize = resource.MustParse(tt.gatewaySize)
			ctx := context.Background()
			if _, err := s.menuBackend("alice").Create(ctx, "copy"); err != nil {
				t.Fatal(err)
			}
			var copy v1alpha1.BlipState
			if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: "alice.copy"}, &copy); err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if copy.Spec.Size != nil {
					t.Fatalf("size = %s, want source-size inheritance", copy.Spec.Size)
				}
			} else if copy.Spec.Size == nil || !copy.Spec.Size.Equal(resource.MustParse(tt.want)) {
				t.Fatalf("size = %v, want %s", copy.Spec.Size, tt.want)
			}
		})
	}
}

func TestEnsureStateReturnsChildConflictWithoutRoot(t *testing.T) {
	base, data := gatewayBase(), gatewayBase()
	data.Name = "shared-data"
	base.Spec.Mounts = []v1alpha1.Mount{{State: data.Name, Path: "/work", Writable: true}}
	s := backendServer(t, catalogClient(t, base, data))
	ctx := context.Background()
	entry, err := s.menuBackend("alice").Create(ctx, "collision")
	if err != nil {
		t.Fatal(err)
	}
	var root v1alpha1.BlipState
	key := client.ObjectKey{Namespace: ns, Name: entry.ID}
	if err := s.Kube.Get(ctx, key, &root); err != nil {
		t.Fatal(err)
	}
	childName := root.Spec.Mounts[0].State
	if err := s.Kube.Delete(ctx, &root); err != nil {
		t.Fatal(err)
	}
	var rootGets int
	s.Kube = interceptor.NewClient(s.Kube, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if key.Name == entry.ID {
				rootGets++
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = s.ensureState(ctx, "alice", entry.ID)
	if !apierrors.IsAlreadyExists(err) || !strings.Contains(err.Error(), childName) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("child conflict = %v", err)
	}
	if rootGets != 2 {
		t.Fatalf("root gets = %d, want initial lookup and one race check", rootGets)
	}
	var child v1alpha1.BlipState
	if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: childName}, &child); err != nil {
		t.Fatalf("existing child was changed: %v", err)
	}
}

func TestEnsureStateAcceptsOnlyOwnedConcurrentRoot(t *testing.T) {
	for _, owner := range []string{"alice", "bob"} {
		t.Run(owner, func(t *testing.T) {
			s := backendServer(t, catalogClient(t, gatewayBase()))
			var creates int
			s.Kube = interceptor.NewClient(s.Kube, interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					creates++
					other := obj.DeepCopyObject().(client.Object)
					other.SetLabels(map[string]string{v1alpha1.LabelOwner: owner})
					if err := c.Create(ctx, other, opts...); err != nil {
						return err
					}
					return apierrors.NewAlreadyExists(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), obj.GetName())
				},
			})
			err := s.ensureState(context.Background(), "alice", "alice.race")
			if (err != nil) != (owner != "alice") || creates != 1 {
				t.Fatalf("race owner=%s: err=%v creates=%d", owner, err, creates)
			}
		})
	}
}
