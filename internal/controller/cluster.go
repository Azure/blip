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

// drainingNodes returns the names of nodes that new VMs must avoid.
func drainingNodes(ctx context.Context, c client.Reader) (map[string]bool, error) {
	var bns v1.BlipNodeList
	if err := c.List(ctx, &bns); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, bn := range bns.Items {
		if bn.Spec.Drain {
			out[bn.Name] = true
		}
	}
	return out, nil
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
		k.Labels[LabelEnrolled] != "true" {
		return false
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(k.Labels))
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

// nextCheck is when one of names next crosses the repair threshold.
func (c *cluster) nextCheck(names []string) time.Duration {
	var next time.Duration
	for _, name := range names {
		bn := c.nodes[name]
		if bn == nil || bn.Status.Heartbeat == nil {
			continue
		}
		if d := repairAfter - heartbeatAge(bn, c.now) + time.Second; d > 0 && (next == 0 || d < next) {
			next = d
		}
	}
	return next
}
