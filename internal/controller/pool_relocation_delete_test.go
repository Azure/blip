package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestW521RelocationLostDeleteKeepsMaxCount covers a relocation delete that
// loses its optimistic-lock race, for example because a Blip claimed the spare
// after the pool listed it. The delete did not free a slot, so creating the
// replacement would exceed maxCount.
func TestW521RelocationLostDeleteKeepsMaxCount(t *testing.T) {
	e := newEnv(t)
	e.c = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.DeleteOption) error {
		if o.GetName() == "default-spare" {
			return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, o.GetName(), errors.New("simulated concurrent claim"))
		}
		return c.Delete(ctx, o, opts...)
	}})
	e.pool.Client = e.c
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 2)
	pool := e.getPool("default")

	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Spec.NodeName = "n1"
	claimed.Status.Phase = corev1.PodRunning
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	spare := e.pool.podFor(pool, "default-spare")
	spare.Spec.NodeName = "n2"
	spare.Status.Phase = corev1.PodRunning
	spare.Labels[v1.LabelWarm] = "true"
	spare.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	e.create(claimed, spare)

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) > 2 {
		t.Fatalf("%d pods after a lost relocation delete, maxCount is 2: %+v", len(pods), pods)
	}
	if e.podGone(spare.Name) {
		t.Fatal("spare is gone despite the conflicting delete")
	}
	for _, p := range pods {
		if p.Annotations[v1.AnnotationPinnedNode] == "n1" && p.Name != "default-claimed" {
			t.Fatalf("created replacement on the hot node despite the lost delete: %+v", p)
		}
	}
}
