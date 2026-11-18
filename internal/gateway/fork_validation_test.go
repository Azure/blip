package gateway

import (
	"context"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestForkValidatesSourceBeforeCreatingStates(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*v1alpha1.BlipState)
		valid  bool
	}{
		{name: "owned-prefix", valid: true},
		{name: "pending-owned-prefix", valid: true, change: func(st *v1alpha1.BlipState) { st.Status.Phase = v1alpha1.StatePending }},
		{name: "shared-image", valid: true, change: func(st *v1alpha1.BlipState) {
			st.Name, st.Labels, st.Spec.Image = "shared-image", nil, "reg/dev:1"
		}},
		{name: "same-owner-legacy", change: func(st *v1alpha1.BlipState) { st.Name = "legacy" }},
		{name: "ownerless-filesystem", change: func(st *v1alpha1.BlipState) { st.Name, st.Labels = "shared-data", nil }},
		{name: "ownerless-copy", change: func(st *v1alpha1.BlipState) {
			st.Name, st.Labels, st.Spec.CopyFrom = "shared-copy", nil, "shared-image"
		}},
		{name: "wrong-owner-label", change: func(st *v1alpha1.BlipState) { st.Labels[v1alpha1.LabelOwner] = "bob" }},
		{name: "failed", change: func(st *v1alpha1.BlipState) { st.Status.Phase = v1alpha1.StateFailed }},
		{name: "deleting", change: deletingForkFixture},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := catalogState("alice", "source", "")
			if tt.change != nil {
				tt.change(source)
			}
			s := backendServer(t, catalogClient(t, source))
			var creates int
			s.Kube = countForkCreates(s.Kube, &creates)
			_, err := s.forkState(context.Background(), "alice", "alice.copy", source)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%t: %v", tt.valid, err)
			}
			if !tt.valid && creates != 0 {
				t.Fatalf("invalid source created %d states", creates)
			}
		})
	}
}

func TestForkValidatesEveryInheritedMountBeforeCreatingStates(t *testing.T) {
	for _, writable := range []bool{false, true} {
		mode := "read-only/"
		if writable {
			mode = "writable/"
		}
		for _, tt := range []struct {
			name      string
			change    func(*v1alpha1.BlipState)
			valid     bool
			missing   bool
			temporary bool
		}{
			{name: "owned-prefix", valid: true},
			{name: "shared-image", valid: true, change: func(st *v1alpha1.BlipState) {
				st.Name, st.Labels, st.Spec.Image = "shared-image", nil, "reg/tools:1"
			}},
			{name: "pending-image", valid: true, change: func(st *v1alpha1.BlipState) {
				st.Name, st.Labels, st.Spec.Image, st.Status.Phase = "pending-image", nil, "reg/tools:1", v1alpha1.StatePending
			}},
			{name: "same-owner-legacy", change: func(st *v1alpha1.BlipState) { st.Name = "legacy" }},
			{name: "ownerless-filesystem", change: func(st *v1alpha1.BlipState) { st.Name, st.Labels = "shared-data", nil }},
			{name: "foreign-owner", change: func(st *v1alpha1.BlipState) {
				st.Name, st.Labels[v1alpha1.LabelOwner] = "bob.data", "bob"
			}},
			{name: "owner-prefix-wrong-label", change: func(st *v1alpha1.BlipState) { st.Labels[v1alpha1.LabelOwner] = "bob" }},
			{name: "failed", change: func(st *v1alpha1.BlipState) { st.Status.Phase = v1alpha1.StateFailed }},
			{name: "deleting", change: deletingForkFixture},
			{name: "missing", missing: true},
			{name: "temporary-missing-is-not-inherited", missing: true, temporary: true, valid: true},
		} {
			t.Run(mode+tt.name, func(t *testing.T) {
				source := catalogState("alice", "source", "")
				first := catalogState("alice", "first", "")
				mounted := catalogState("alice", "mounted", "")
				if tt.change != nil {
					tt.change(mounted)
				}
				mount := v1alpha1.Mount{State: mounted.Name, Path: "/other", Writable: writable}
				if tt.temporary {
					mount.BlipUID = "old-worker"
				}
				// A valid RW mount first makes sure preflight covers all refs
				// before the helper starts creating any of the child copies.
				source.Spec.Mounts = []v1alpha1.Mount{{State: first.Name, Path: "/first", Writable: true}, mount}
				objects := []client.Object{source, first}
				if !tt.missing {
					objects = append(objects, mounted)
				}
				s := backendServer(t, catalogClient(t, objects...))
				var creates int
				s.Kube = countForkCreates(s.Kube, &creates)
				_, err := s.forkState(context.Background(), "alice", "alice.copy", source)
				if (err == nil) != tt.valid {
					t.Fatalf("valid=%t: %v", tt.valid, err)
				}
				if !tt.valid && creates != 0 {
					t.Fatalf("invalid inherited mount created %d states", creates)
				}
			})
		}
	}
}

func deletingForkFixture(st *v1alpha1.BlipState) {
	now := metav1.Now()
	st.DeletionTimestamp = &now
	st.Finalizers = []string{"test"}
}

func countForkCreates(kube client.WithWatch, count *int) client.WithWatch {
	return interceptor.NewClient(kube, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			*count++
			return c.Create(ctx, obj, opts...)
		},
	})
}
