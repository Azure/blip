package node

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/peer"
)

func fakeReader(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// A source created moments ago can be absent from the node's informer cache
// while an unlabelled destination already copies it. A missing source must not
// authorize the export: the agent fills copy sources in from an uncached read
// so copyAllowed still runs.
func TestAuthorizeCopySourceMissingFromCache(t *testing.T) {
	src := state("src")
	src.Labels = map[string]string{ownerLabel: "alice"}
	src.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	dst := func() *v1alpha1.BlipState {
		s := state("dst")
		s.Spec.CopyFrom = "src"
		s.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-src", CommitID: "c1"}
		s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 1, Replicas: []string{"n2"}}
		return s
	}
	req := peer.ExportRequest{StateUID: "uid-src", CommitID: "c1", Purpose: "copy"}

	t.Run("stale cache denies unlabelled cross-owner copy", func(t *testing.T) {
		// The destination is cached; the labelled source is not yet.
		a := newAgent(Config{}, fakeReader(t, dst()), fakeReader(t, src, dst()), nil)
		if err := a.authorize("n2", req); err == nil {
			t.Fatal("cross-owner copy allowed while the source was missing from the cache")
		}
	})

	t.Run("stale cache allows same-owner copy", func(t *testing.T) {
		same := dst()
		same.Labels = map[string]string{ownerLabel: "alice"}
		a := newAgent(Config{}, fakeReader(t, same), fakeReader(t, src, same), nil)
		if err := a.authorize("n2", req); err != nil {
			t.Fatalf("same-owner copy denied: %v", err)
		}
	})

	t.Run("deleted source keeps the allowance", func(t *testing.T) {
		a := newAgent(Config{}, fakeReader(t, dst()), fakeReader(t, dst()), nil)
		if err := a.authorize("n2", req); err != nil {
			t.Fatalf("copy of a deleted source denied: %v", err)
		}
	})

	t.Run("failed live read fails closed", func(t *testing.T) {
		scheme, err := Scheme()
		if err != nil {
			t.Fatal(err)
		}
		live := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "blipstates"}, key.Name, errors.New("denied"))
				},
			}).Build()
		a := newAgent(Config{}, fakeReader(t, dst()), live, nil)
		if err := a.authorize("n2", req); err == nil {
			t.Fatal("forbidden live read did not fail closed")
		}
	})
}
