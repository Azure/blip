package controller

import (
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// NodeReconciler stops Blips on draining nodes and decides when they are safe
// to remove.
type NodeReconciler struct {
	client.Client
}

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.BlipNode{}).
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.drainingNodes)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			if n := o.(*corev1.Pod).Spec.NodeName; n != "" && !isVacant(o.(*corev1.Pod)) {
				return []reconcile.Request{req("", n)}
			}
			return nil
		})).
		Named("blipnode").
		Complete(r)
}

func (r *NodeReconciler) drainingNodes(ctx context.Context, _ client.Object) []reconcile.Request {
	var bns v1.BlipNodeList
	if err := r.List(ctx, &bns); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, bn := range bns.Items {
		if bn.Spec.Drain || bn.Status.SafeToRemove {
			out = append(out, req("", bn.Name))
		}
	}
	return out
}

func (r *NodeReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	bn := &v1.BlipNode{}
	if err := r.Get(ctx, rq.NamespacedName, bn); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	safe := false
	if bn.Spec.Drain {
		if err := r.stopBlips(ctx, bn.Name); err != nil {
			return reconcile.Result{}, err
		}
		var err error
		if safe, err = r.safeToRemove(ctx, bn.Name); err != nil {
			return reconcile.Result{}, err
		}
	}
	if bn.Status.SafeToRemove != safe {
		base := bn.DeepCopy()
		bn.Status.SafeToRemove = safe
		if err := r.Status().Patch(ctx, bn, client.MergeFrom(base)); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	return reconcile.Result{}, nil
}

// stopBlips asks every unfinished Blip running on node to stop. Durable
// states save through the normal Blip shutdown path and the pod is deleted;
// new claims are already kept off draining nodes.
func (r *NodeReconciler) stopBlips(ctx context.Context, node string) error {
	var blips v1.BlipList
	if err := r.List(ctx, &blips); err != nil {
		return err
	}
	for i := range blips.Items {
		b := &blips.Items[i]
		if finished(b) || b.Spec.Stop || b.Status.Node != node {
			continue
		}
		base := b.DeepCopy()
		b.Spec.Stop = true
		if err := patchObject(ctx, r.Client, b, base); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// safeToRemove reports whether a draining node holds nothing that still
// needs it: no writer, pending version, or placement (repair moves those off
// draining nodes once replacements hold the commit), no unfinished claimed
// Blip, and no claimed VM pod that is not terminated.
func (r *NodeReconciler) safeToRemove(ctx context.Context, node string) (bool, error) {
	var states v1.BlipStateList
	if err := r.List(ctx, &states); err != nil {
		return false, err
	}
	for _, st := range states.Items {
		s := st.Status
		if s.Writer != nil && s.Writer.Node == node || slices.Contains(s.Placements, node) {
			return false, nil
		}
		if s.Pending != nil && (s.Pending.SourceNode == node || slices.Contains(s.Pending.Replicas, node)) {
			return false, nil
		}
	}
	var blips v1.BlipList
	if err := r.List(ctx, &blips); err != nil {
		return false, err
	}
	for _, b := range blips.Items {
		if !finished(&b) && b.Status.Node == node {
			return false, nil
		}
	}
	claimed, _ := labels.NewRequirement(LabelBlipUID, selection.Exists, nil)
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*claimed)}); err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == node && !podTerminated(&p) {
			return false, nil
		}
	}
	return true, nil
}
