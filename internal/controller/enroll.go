package controller

import (
	"context"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// enrollmentRetry is how often an unenrolling node is rechecked while it
// drains.
const enrollmentRetry = 10 * time.Second

// EnrollReconciler labels nodes selected by a BlipPool so the node agent runs
// there. It removes the labels again, after a graceful drain, when no pool
// selects the node.
type EnrollReconciler struct {
	client.Client
}

func (r *EnrollReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(predicate.LabelChangedPredicate{})).
		Watches(&v1.BlipPool{}, handler.EnqueueRequestsFromMapFunc(r.allNodes),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1.BlipNode{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			return []reconcile.Request{req("", o.GetName())}
		}), builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				old, ok := e.ObjectOld.(*v1.BlipNode)
				if !ok {
					return true
				}
				now, ok := e.ObjectNew.(*v1.BlipNode)
				if !ok {
					return true
				}
				return !slices.Equal(old.Status.Hypervisors, now.Status.Hypervisors) ||
					old.Status.SafeToRemove != now.Status.SafeToRemove ||
					old.Spec.Drain != now.Spec.Drain
			},
		})).
		Named("blipenrollment").
		Complete(r)
}

func (r *EnrollReconciler) allNodes(ctx context.Context, _ client.Object) []reconcile.Request {
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(nodes.Items))
	for i := range nodes.Items {
		out = append(out, req("", nodes.Items[i].Name))
	}
	return out
}

func (r *EnrollReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	node := &corev1.Node{}
	if err := r.Get(ctx, rq.NamespacedName, node); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if node.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	matched, migrating, err := r.matchesPool(ctx, node)
	if err != nil {
		return reconcile.Result{}, err
	}
	if migrating && !matched {
		// Old pools without a selector cannot express membership. Leave
		// nodes alone until every pool has been updated; unenrolling here
		// would drain a working cluster during an upgrade.
		return reconcile.Result{}, nil
	}
	bn := &v1.BlipNode{}
	if err := r.Get(ctx, client.ObjectKey{Name: node.Name}, bn); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		bn = nil
	}
	if matched {
		return reconcile.Result{}, r.enroll(ctx, node, bn)
	}
	return r.unenroll(ctx, node, bn)
}

// matchesPool reports whether any pool selects node and whether any live pool
// still has an empty selector (a pre-required-field pool). An empty selector
// cannot express membership, so while one exists the cluster is migrating and
// unselected nodes must not be drained.
func (r *EnrollReconciler) matchesPool(ctx context.Context, node *corev1.Node) (matched, migrating bool, err error) {
	var pools v1.BlipPoolList
	if err := r.List(ctx, &pools); err != nil {
		return false, false, err
	}
	nodeLabels := labels.Set(node.Labels)
	for i := range pools.Items {
		pool := &pools.Items[i]
		if pool.DeletionTimestamp != nil {
			continue
		}
		if len(pool.Spec.NodeSelector) == 0 {
			migrating = true
			continue
		}
		if labels.SelectorFromSet(pool.Spec.NodeSelector).Matches(nodeLabels) {
			matched = true
		}
	}
	return matched, migrating, nil
}

// enroll labels a matching node and clears an enrollment drain left by a
// previous unenroll. A drain without the annotation is an operator drain and
// is preserved.
func (r *EnrollReconciler) enroll(ctx context.Context, node *corev1.Node, bn *v1.BlipNode) error {
	if bn != nil && bn.Spec.Drain && bn.Annotations[AnnotationEnrollmentDrain] == "true" {
		base := bn.DeepCopy()
		bn.Spec.Drain = false
		delete(bn.Annotations, AnnotationEnrollmentDrain)
		if err := patchObject(ctx, r.Client, bn, base); err != nil {
			return client.IgnoreNotFound(err)
		}
	}
	want := map[string]bool{LabelEnrolled: true}
	switch {
	case bn == nil:
		// The agent registers its BlipNode at startup. If it disappears while
		// the node is still selected, keep advertising capabilities until it
		// comes back instead of making existing warm capacity unschedulable.
		for k := range node.Labels {
			if strings.HasPrefix(k, LabelHypervisorPrefix) {
				want[k] = true
			}
		}
	case !bn.Spec.Drain:
		for _, h := range bn.Status.Hypervisors {
			want[LabelHypervisorPrefix+h] = true
		}
	}
	return r.patchLabels(ctx, node, want)
}

// unenroll drains a node that no pool selects, then removes the enrollment
// labels and the BlipNode. The node agent keeps running until the drain is
// safe, so it can stop VMs and move state replicas.
func (r *EnrollReconciler) unenroll(ctx context.Context, node *corev1.Node, bn *v1.BlipNode) (reconcile.Result, error) {
	if bn == nil {
		return reconcile.Result{}, r.patchLabels(ctx, node, nil)
	}
	if !bn.Spec.Drain {
		log.FromContext(ctx).Info("draining node: no BlipPool selects it", "node", node.Name)
		base := bn.DeepCopy()
		bn.Spec.Drain = true
		if bn.Annotations == nil {
			bn.Annotations = map[string]string{}
		}
		bn.Annotations[AnnotationEnrollmentDrain] = "true"
		if err := patchObject(ctx, r.Client, bn, base); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	// Keep the agent scheduled while draining, but stop new VM pods from
	// selecting this node by dropping the hypervisor labels now. A node that
	// was never enrolled has no agent label to keep.
	if err := r.patchLabels(ctx, node, keepEnrolled(node)); err != nil {
		return reconcile.Result{}, err
	}
	if !bn.Status.SafeToRemove {
		return reconcile.Result{RequeueAfter: enrollmentRetry}, nil
	}
	if err := r.patchLabels(ctx, node, nil); err != nil {
		return reconcile.Result{}, err
	}
	log.FromContext(ctx).Info("unenrolled node", "node", node.Name)
	if err := r.Delete(ctx, bn); err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// keepEnrolled returns the labels that keep an already-enrolled agent
// scheduled without advertising a hypervisor for new VM pods.
func keepEnrolled(node *corev1.Node) map[string]bool {
	if node.Labels[LabelEnrolled] == "true" {
		return map[string]bool{LabelEnrolled: true}
	}
	return map[string]bool{}
}

// patchLabels makes the controller-owned labels on node equal want. All other
// labels are left alone.
func (r *EnrollReconciler) patchLabels(ctx context.Context, node *corev1.Node, want map[string]bool) error {
	base := node.DeepCopy()
	if node.Labels == nil && len(want) > 0 {
		node.Labels = map[string]string{}
	}
	for k := range node.Labels {
		if (k == LabelEnrolled || strings.HasPrefix(k, LabelHypervisorPrefix)) && !want[k] {
			delete(node.Labels, k)
		}
	}
	for k := range want {
		node.Labels[k] = "true"
	}
	if semanticEqual(base.Labels, node.Labels) {
		return nil
	}
	// Node status changes constantly; a merge patch without a resourceVersion
	// precondition only touches the labels we changed.
	return r.Patch(ctx, node, client.MergeFrom(base))
}
