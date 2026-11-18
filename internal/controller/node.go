package controller

import (
	"context"
	"slices"
	"time"

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

// drainRetry rechecks a draining node that is not safe yet. Watches normally
// wake it sooner (a finished Blip, a released writer, a deleted pod); the
// retry covers a missed or coalesced event.
const drainRetry = 10 * time.Second

// NodeReconciler stops Blips on draining nodes and decides when they are safe
// to remove.
type NodeReconciler struct {
	client.Client
}

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.BlipNode{}).
		Watches(&v1.Blip{}, handler.EnqueueRequestsFromMapFunc(r.blipNodes)).
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

// blipNodes maps a Blip to the draining nodes it occupies. A Blip finishing
// is the last thing that can hold a drain open, but the pod delete event may
// have been handled while the Blip was still running, so without this watch
// SafeToRemove can stay false forever.
func (r *NodeReconciler) blipNodes(ctx context.Context, o client.Object) []reconcile.Request {
	b, ok := o.(*v1.Blip)
	if !ok {
		return nil
	}
	candidates := []string{b.Status.Node}
	if b.Status.Pod != "" {
		pod := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: b.Status.Pod}, pod); err == nil {
			candidates = append(candidates, pod.Spec.NodeName)
		}
	}
	seen := map[string]bool{}
	var out []reconcile.Request
	for _, name := range candidates {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		bn := &v1.BlipNode{}
		if err := r.Get(ctx, client.ObjectKey{Name: name}, bn); err != nil {
			continue
		}
		if bn.Spec.Drain || bn.Status.SafeToRemove {
			out = append(out, req("", name))
		}
	}
	return out
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
	if bn.Spec.Drain {
		if err := r.stopBlips(ctx, bn.Name); err != nil {
			return reconcile.Result{}, err
		}
	}
	safe, err := syncSafeToRemove(ctx, r.Client, bn)
	if err != nil {
		return reconcile.Result{}, err
	}
	if bn.Spec.Drain && !safe {
		// Keep recomputing while the drain is not safe. The event that frees
		// the last Blip can arrive before that Blip has finished, in which
		// case nothing else wakes this node.
		return reconcile.Result{RequeueAfter: drainRetry}, nil
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
		if v1.Finished(b) || b.Spec.Stop || b.Status.Node != node {
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

// syncSafeToRemove recomputes the node's safe-to-remove verdict and persists
// it. A node that is not draining is never safe by this definition; its drain
// verdict belongs to an earlier drain.
func syncSafeToRemove(ctx context.Context, c client.Client, bn *v1.BlipNode) (bool, error) {
	safe := false
	if bn.Spec.Drain {
		var err error
		if safe, err = nodeSafeToRemove(ctx, c, bn.Name); err != nil {
			return false, err
		}
	}
	if bn.Status.SafeToRemove != safe {
		base := bn.DeepCopy()
		bn.Status.SafeToRemove = safe
		if err := patchStatus(ctx, c, bn, base); err != nil {
			return safe, client.IgnoreNotFound(err)
		}
	}
	return safe, nil
}

// nodeSafeToRemove reports whether a draining node holds nothing that still
// needs it: no writer, pending version, or placement (repair moves those off
// draining nodes once replacements hold the commit), no unfinished claimed
// Blip, and no claimed VM pod that is not terminated.
func nodeSafeToRemove(ctx context.Context, c client.Client, node string) (bool, error) {
	var states v1.BlipStateList
	if err := c.List(ctx, &states); err != nil {
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
	if err := c.List(ctx, &blips); err != nil {
		return false, err
	}
	for _, b := range blips.Items {
		if !v1.Finished(&b) && b.Status.Node == node {
			return false, nil
		}
	}
	claimed, _ := labels.NewRequirement(v1.LabelBlipUID, selection.Exists, nil)
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*claimed)}); err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == node && !podTerminated(&p) {
			return false, nil
		}
	}
	return true, nil
}
