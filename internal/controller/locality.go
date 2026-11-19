package controller

import (
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// localWait bounds how long a Blip whose states are ready waits for a VM on
// the node that holds its data before it claims any warm VM. A VM elsewhere
// starts on a remote clone, which is slower to use and must fully hydrate
// before a save, so a short wait for a local VM usually pays off.
const localWait = 30 * time.Second

// podNode is the node a VM pod runs on or, while unscheduled, is pinned to.
func podNode(p *corev1.Pod) string {
	if p.Spec.NodeName != "" {
		return p.Spec.NodeName
	}
	return p.Annotations[v1.AnnotationPinnedNode]
}

// unschedulable reports whether the scheduler found no node for p.
func unschedulable(p *corev1.Pod) bool {
	if p.Spec.NodeName != "" {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return true
		}
	}
	return false
}

// poolSelector is the node selector of the pool's VM pods.
func poolSelector(pool *v1.BlipPool) map[string]string {
	_, _, hypervisor := poolShape(pool)
	selector := map[string]string{}
	for k, v := range pool.Spec.NodeSelector {
		selector[k] = v
	}
	selector[v1.LabelEnrolled] = "true"
	selector[v1.LabelHypervisorPrefix+hypervisor] = "true"
	return selector
}

// statePlacements are the nodes that hold (or are being given) the version a
// Blip would use: the committed one, or the one a copy is still producing.
func statePlacements(st *v1.BlipState) []string {
	if st.Status.Committed == nil && st.Status.Pending != nil {
		return st.Status.Pending.Replicas
	}
	return st.Status.Placements
}

// placementScores ranks nodes by how much of the Blip's durable data they
// hold: the root state outweighs all writable mounts together.
func placementScores(b *v1.Blip, states map[string]*v1.BlipState) map[string]int {
	score := map[string]int{}
	var mounts []v1.Mount
	if root := states[b.Spec.State]; root != nil && b.Spec.State != "" {
		mounts = v1.DesiredMounts(root, b)
		for _, n := range statePlacements(root) {
			score[n] += len(mounts) + 1
		}
	}
	for _, m := range mounts {
		if st := states[m.State]; m.Writable && st != nil {
			for _, n := range statePlacements(st) {
				score[n]++
			}
		}
	}
	return score
}

// homeNodes are the usable nodes of the pool with the highest positive
// score, sorted by name.
func homeNodes(score map[string]int, cl *cluster, selector map[string]string) []string {
	best := 0
	var out []string
	for n, s := range score {
		if s <= 0 || !cl.usable(n, selector) {
			continue
		}
		if s > best {
			best, out = s, nil
		}
		if s == best {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// updateLocality records the node the Blip's data lives on. A fallback is
// re-evaluated while the Blip is still waiting: if the data has moved to a
// different usable home, the Blip follows it instead of keeping the node it
// fell back on. A fallback on the current home node is kept until a local VM
// is actually claimable (see pending), because the pool still boots a pinned
// VM for a waiting fallback.
//
// settled means every state the Blip references is ready. A durable Blip
// whose states are ready but which has no usable home node must fall back,
// or it would wait forever. While the states are still being built, a Blip
// created before its state (a fork) has no home yet; leave locality unset so
// the pool does not boot a VM away from data that is about to appear.
func updateLocality(b *v1.Blip, home []string, settled bool) {
	loc := b.Status.Locality
	switch {
	case loc != nil && loc.Fallback:
		if len(home) == 0 || slices.Contains(home, loc.Node) {
			return
		}
		// The data moved to another usable node. Start a fresh local wait
		// rather than pinning the replacement to a node that no longer
		// holds it.
		loc.Fallback = false
		loc.Node = home[0]
		loc.Since = nil
	case len(home) == 0:
		if loc != nil || (settled && b.Spec.State != "") {
			if loc == nil {
				loc = &v1.Locality{}
				b.Status.Locality = loc
			}
			loc.Fallback = true
		}
	case loc == nil:
		b.Status.Locality = &v1.Locality{Node: home[0]}
	case !slices.Contains(home, loc.Node):
		loc.Node = home[0]
	}
}

// waitLocally decides whether a Blip with usable states and no warm VM on a
// home node keeps waiting for one. It returns why the wait is over, or how
// long it may still last.
func (r *BlipReconciler) waitLocally(b *v1.Blip, pool *v1.BlipPool, pods []corev1.Pod, home []string) (string, time.Duration) {
	loc := b.Status.Locality
	now := r.now()
	if loc.Since == nil {
		since := metav1.NewTime(now)
		loc.Since = &since
	}
	left := loc.Since.Add(localWait).Sub(now)
	if left <= 0 {
		return fmt.Sprintf("no VM on node %q within %s", loc.Node, localWait), 0
	}
	local, total := false, 0
	for i := range pods {
		p := &pods[i]
		if podTerminated(p) {
			continue
		}
		total++
		if !isVacant(p) || p.DeletionTimestamp != nil || !slices.Contains(home, podNode(p)) {
			continue
		}
		if unschedulable(p) {
			return fmt.Sprintf("node %q has no room for a VM", podNode(p)), 0
		}
		local = true
	}
	if max := int(pool.Spec.MaxCount); !local && max > 0 && total >= max {
		return fmt.Sprintf("pool %q is at maxCount", pool.Name), 0
	}
	return "", left
}
