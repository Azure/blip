package controller

import (
	"context"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	// heartbeatTimeout marks a node unhealthy.
	heartbeatTimeout = 60 * time.Second
	// repairAfter is how long a node may be unhealthy before its replicas
	// are replaced.
	repairAfter = 2 * time.Minute
)

// cluster is a snapshot of the nodes that can hold states.
type cluster struct {
	now   time.Time
	nodes map[string]*v1.BlipNode
	k8s   map[string]*corev1.Node
	names []string
}

func loadCluster(ctx context.Context, c client.Reader, now time.Time) (*cluster, error) {
	var bns v1.BlipNodeList
	if err := c.List(ctx, &bns); err != nil {
		return nil, err
	}
	var ns corev1.NodeList
	if err := c.List(ctx, &ns); err != nil {
		return nil, err
	}
	cl := &cluster{now: now, nodes: map[string]*v1.BlipNode{}, k8s: map[string]*corev1.Node{}}
	for i := range bns.Items {
		cl.nodes[bns.Items[i].Name] = &bns.Items[i]
		cl.names = append(cl.names, bns.Items[i].Name)
	}
	for i := range ns.Items {
		cl.k8s[ns.Items[i].Name] = &ns.Items[i]
	}
	sort.Strings(cl.names)
	return cl, nil
}

func heartbeatAge(bn *v1.BlipNode, now time.Time) time.Duration {
	if bn.Status.Heartbeat == nil {
		return time.Duration(1<<63 - 1)
	}
	return now.Sub(bn.Status.Heartbeat.Time)
}

func healthy(bn *v1.BlipNode, now time.Time) bool {
	return heartbeatAge(bn, now) < heartbeatTimeout
}

// usable reports whether new replicas may be placed on the node.
func (c *cluster) usable(name string, selector map[string]string) bool {
	bn, k := c.nodes[name], c.k8s[name]
	if bn == nil || k == nil || bn.Spec.Drain || !healthy(bn, c.now) ||
		bn.Status.Incarnation == "" || len(bn.Status.Hypervisors) == 0 ||
		k.Labels[v1.LabelEnrolled] != "true" {
		return false
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(k.Labels))
}

// schedulable reports whether the scheduler could place a pod with selector and
// tolerations on the node. usable checks enrollment and health, but not the
// pod's selector, cordon, or taints, so a node can be usable while every pod
// this pool builds is rejected there.
func (c *cluster) schedulable(name string, selector map[string]string, tolerations []corev1.Toleration) bool {
	if !c.usable(name, selector) {
		return false
	}
	k := c.k8s[name]
	if k.Spec.Unschedulable {
		return false
	}
	for i := range k.Spec.Taints {
		taint := k.Spec.Taints[i]
		if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		tolerated := false
		for j := range tolerations {
			if tolerations[j].ToleratesTaint(&taint) {
				tolerated = true
				break
			}
		}
		if !tolerated {
			return false
		}
	}
	return true
}

// bad reports whether replicas on the node must be replaced.
func (c *cluster) bad(name string) bool {
	bn, k := c.nodes[name], c.k8s[name]
	return bn == nil || k == nil || bn.Spec.Drain || heartbeatAge(bn, c.now) > repairAfter
}

// holds reports whether the node's current incarnation reports commitID.
func (c *cluster) holds(st *v1.BlipState, name, commitID string) bool {
	bn := c.nodes[name]
	if bn == nil {
		return false
	}
	for _, o := range st.Status.Nodes {
		if o.Node == name && o.Incarnation == bn.Status.Incarnation {
			return slices.Contains(o.Commits, commitID)
		}
	}
	return false
}

// currentObservation reports whether o was written by the node's current
// incarnation. An entry from another incarnation is stale: the node lost the
// storage it described, so its commits and errors no longer apply.
func (c *cluster) currentObservation(o v1.NodeObservation) bool {
	bn := c.nodes[o.Node]
	return bn != nil && o.Incarnation == bn.Status.Incarnation
}

// choose returns up to n usable nodes, excluding exclude: nodes in prefer
// first (in order), then by free space, then by name.
func (c *cluster) choose(n int, selector map[string]string, prefer, exclude []string) []string {
	rank := func(name string) int {
		if i := slices.Index(prefer, name); i >= 0 {
			return i
		}
		return len(prefer)
	}
	var cands []string
	for _, name := range c.names {
		if c.usable(name, selector) && !slices.Contains(exclude, name) {
			cands = append(cands, name)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return c.nodes[a].Status.FreeBytes > c.nodes[b].Status.FreeBytes
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	return cands
}

// nextCrossing is when one of names next crosses threshold. skipDraining
// ignores nodes that are already draining.
func (c *cluster) nextCrossing(names []string, threshold time.Duration, skipDraining bool) time.Duration {
	var next time.Duration
	for _, name := range names {
		bn := c.nodes[name]
		if bn == nil || (skipDraining && bn.Spec.Drain) || bn.Status.Heartbeat == nil {
			continue
		}
		if d := threshold - heartbeatAge(bn, c.now) + time.Second; d > 0 && (next == 0 || d < next) {
			next = d
		}
	}
	return next
}

// healthyNode reports whether the node has both objects and is heartbeating.
func (c *cluster) healthyNode(name string) bool {
	bn := c.nodes[name]
	return bn != nil && c.k8s[name] != nil && healthy(bn, c.now)
}

// avoidNodes is the set of known nodes no new VM may use.
func (c *cluster) avoidNodes() map[string]bool {
	avoid := map[string]bool{}
	for name := range c.nodes {
		if !c.usable(name, nil) {
			avoid[name] = true
		}
	}
	for name, k := range c.k8s {
		if k.Labels[v1.LabelEnrolled] == "true" && !c.usable(name, nil) {
			avoid[name] = true
		}
	}
	return avoid
}
