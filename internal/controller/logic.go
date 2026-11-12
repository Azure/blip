package controller

import (
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/proto/nodepb"
)

// candidate is a free slot pod and the score of its node (design 6.3).
type candidate struct {
	Pod     *corev1.Pod
	Node    string
	Current bool    // built from the pool's current template (shape)
	Score   int     // storage locality: 100 if the root volume's group has a member on the node, +1 per data volume group
	Free    int     // free capacity: free ready slots on the node
	Load    float64 // lower is better
}

// sortCandidates orders candidates best first.
func sortCandidates(cs []candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Current != b.Current {
			return a.Current
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Free != b.Free {
			return a.Free > b.Free
		}
		if a.Load != b.Load {
			return a.Load < b.Load
		}
		return a.Pod.Name < b.Pod.Name
	})
}

// podReady reports whether the pod has Ready=True.
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// freeSlot reports whether the pod is a claimable slot of the SKU.
func freeSlot(p *corev1.Pod, sku string) bool {
	return p.Labels[api.LabelSlot] == api.SlotFree && p.Labels[api.LabelSKU] == sku &&
		p.DeletionTimestamp == nil && p.Spec.NodeName != "" && p.Status.Phase == corev1.PodRunning && podReady(p)
}

// nodeLoad is the load of a compute node: assigned share of slots, plus
// local pool usage as a tie breaker.
func nodeLoad(c *nodepb.ComputeCapacity) float64 {
	if c == nil || c.Slots == 0 {
		return 1
	}
	return float64(c.AssignedSlots)/float64(c.Slots) + c.DataPercent/1000
}

// quotaLimit reads the running-blip limit for a SKU from namespace annotations.
func quotaLimit(annotations map[string]string, sku string, def int) int {
	if v, ok := annotations[api.QuotaAnnotation(sku)]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// storageFullness is the highest of data, metadata and LV count usage, in percent (design 7.9).
func storageFullness(c *nodepb.StorageCapacity) float64 {
	if c == nil {
		return 0
	}
	f := c.DataPercent
	if c.MetadataPercent > f {
		f = c.MetadataPercent
	}
	if c.MaxLvs > 0 {
		if l := float64(c.LvCount) * 100 / float64(c.MaxLvs); l > f {
			f = l
		}
	}
	return f
}

// poolSizing is the input of a pool's scaling decision.
type poolSizing struct {
	MinFree, MaxFree int
	MaxSlots         *int
	Demand           int // Blips of the SKU scheduled within the demand window
	Waiting          int // Blips of the SKU waiting with NoCapacity
	Assigned         int // claimed pods of the pool
	Headroom         int // quota limit minus running Blips of the SKU
}

// poolTarget returns the free buffer target and the number of unclaimed
// current-shape slot pods (free and booting) the pool should have.
// desiredFree is minFree plus recent demand, at most maxFree, and the part
// above minFree is capped by the quota headroom. Waiting Blips are added on
// top. maxSlots bounds the target to maxSlots minus assigned pods.
func poolTarget(s poolSizing) (desiredFree, target int) {
	extra := min(s.Demand, s.MaxFree-s.MinFree, max(s.Headroom, 0))
	desiredFree = s.MinFree + max(extra, 0)
	target = desiredFree + s.Waiting
	if s.MaxSlots != nil {
		target = min(target, *s.MaxSlots-s.Assigned)
	}
	return desiredFree, max(target, 0)
}

// scaleStep decides how many pods to create (> 0) or delete (< 0). Scale up
// is immediate; scale down happens only once have exceeded target for
// delay. lowSince is when have first exceeded target (zero if it does not);
// wait is how long until a pending scale down is due.
func scaleStep(have, target int, lowSince, now time.Time, delay time.Duration) (delta int, since time.Time, wait time.Duration) {
	switch {
	case have < target:
		return target - have, time.Time{}, 0
	case have == target:
		return 0, time.Time{}, 0
	}
	if lowSince.IsZero() {
		lowSince = now
	}
	if el := now.Sub(lowSince); el < delay {
		return 0, lowSince, delay - el
	}
	return target - have, lowSince, 0
}

// sortForDeletion orders unclaimed slot pods so the cheapest to lose come
// first: unscheduled, then not Ready, then on nodes with the most free
// slots of the pool.
func sortForDeletion(pods []*corev1.Pod, freeOnNode map[string]int) {
	rank := func(p *corev1.Pod) int {
		switch {
		case p.Spec.NodeName == "":
			return 0
		case !podReady(p):
			return 1
		}
		return 2
	}
	sort.SliceStable(pods, func(i, j int) bool {
		a, b := pods[i], pods[j]
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if fa, fb := freeOnNode[a.Spec.NodeName], freeOnNode[b.Spec.NodeName]; fa != fb {
			return fa > fb
		}
		return a.Name < b.Name
	})
}
