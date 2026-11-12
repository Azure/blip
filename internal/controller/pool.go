package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// expectationTimeout bounds how long a create or delete the cache does not
// show yet is still counted.
const expectationTimeout = time.Minute

// poolState is the in-memory pacing state of a pool. Losing it (controller
// restart) only delays a scale down or risks one extra create.
type poolState struct {
	lowSince time.Time            // since when unclaimed pods exceed the target
	creates  map[string]time.Time // created pod names the cache does not show yet
	deletes  map[types.UID]time.Time
	retry    bool // a delete was skipped (assumed claim) or failed
}

func (c *Controller) poolStateFor(key types.NamespacedName) *poolState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.pools[key]
	if st == nil {
		st = &poolState{creates: map[string]time.Time{}, deletes: map[types.UID]time.Time{}}
		c.pools[key] = st
	}
	return st
}

func poolSKU(p *v1.BlipPool) string {
	if p.Spec.SKU == "" {
		return api.DefaultSKU
	}
	return p.Spec.SKU
}

func blipSKU(b *v1.Blip) string {
	if b.Spec.SKU == "" {
		return api.DefaultSKU
	}
	return b.Spec.SKU
}

// olderPool reports whether a wins a duplicate SKU against b.
func olderPool(a, b *v1.BlipPool) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// poolForSKU returns the pool that serves sku in ns (the oldest one), or nil.
func (c *Controller) poolForSKU(ctx context.Context, ns, sku string) (*v1.BlipPool, error) {
	var l v1.BlipPoolList
	if err := c.List(ctx, &l, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	var best *v1.BlipPool
	for i := range l.Items {
		p := &l.Items[i]
		if poolSKU(p) == sku && p.DeletionTimestamp == nil && (best == nil || olderPool(p, best)) {
			best = p
		}
	}
	return best, nil
}

// reconcilePool keeps the pool's free buffer: it creates current-shape slot
// pods up to the target, deletes surplus free pods after scaleDownDelay and
// replaces free pods of an old shape.
func (c *Controller) reconcilePool(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var pool v1.BlipPool
	if err := c.Get(ctx, req.NamespacedName, &pool); err != nil {
		if apierrors.IsNotFound(err) {
			c.mu.Lock()
			delete(c.pools, req.NamespacedName)
			c.mu.Unlock()
			for _, s := range []string{"free", "booting", "assigned"} {
				metricPoolSlots.DeleteLabelValues(req.Namespace, req.Name, s)
			}
			metricPoolDesiredFree.DeleteLabelValues(req.Namespace, req.Name)
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if pool.DeletionTimestamp != nil {
		// The garbage collector deletes the owned (unclaimed) pods.
		return reconcile.Result{}, nil
	}
	now := timeNow()
	sku := poolSKU(&pool)
	st := c.poolStateFor(req.NamespacedName)
	tmpl, hash := slotPod(&pool, &c.opts)

	winner, err := c.poolForSKU(ctx, pool.Namespace, sku)
	if err != nil {
		return reconcile.Result{}, err
	}
	duplicate := winner != nil && winner.UID != pool.UID

	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(pool.Namespace), client.MatchingLabels{api.LabelPool: pool.Name}); err != nil {
		return reconcile.Result{}, err
	}
	// Settle expectations against the cache.
	seen := map[string]bool{}
	live := map[types.UID]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		seen[p.Name] = true
		if p.DeletionTimestamp == nil {
			live[p.UID] = true
		}
	}
	c.mu.Lock()
	for n, t := range st.creates {
		if seen[n] || now.Sub(t) > expectationTimeout {
			delete(st.creates, n)
		}
	}
	for u, t := range st.deletes {
		if !live[u] || now.Sub(t) > expectationTimeout {
			delete(st.deletes, u)
		}
	}
	pendingCreates := len(st.creates)
	c.mu.Unlock()

	var cur, old []*corev1.Pod // unclaimed, owned, not deleting
	var dead []*corev1.Pod     // unclaimed, owned, Failed or Succeeded
	assigned, curReady, free, booting := 0, 0, 0, 0
	freeOnNode := map[string]int{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil {
			continue
		}
		if p.Labels[api.LabelSlot] == api.SlotAssigned {
			assigned++
			continue
		}
		c.mu.Lock()
		_, deleting := st.deletes[p.UID]
		c.mu.Unlock()
		if p.Labels[api.LabelSlot] != api.SlotFree || !poolOwned(p, &pool) || deleting {
			continue
		}
		// A free pod the kubelet rejected (e.g. UnexpectedAdmissionError
		// while the device plugin re-registers) or evicted never restarts:
		// replace it.
		if p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodSucceeded {
			dead = append(dead, p)
			continue
		}
		ready := p.Spec.NodeName != "" && podReady(p)
		if ready {
			free++
			freeOnNode[p.Spec.NodeName]++
		} else {
			booting++
		}
		if p.Labels[api.LabelTemplateHash] == hash {
			cur = append(cur, p)
			if ready {
				curReady++
			}
		} else {
			old = append(old, p)
		}
	}
	booting += pendingCreates

	c.mu.Lock()
	st.retry = false
	c.mu.Unlock()
	status := pool.Status.DeepCopy()
	status.ObservedGeneration = pool.Generation
	status.TemplateHash = hash
	scaled := false
	createErr := ""
	var wait time.Duration
	if n := c.deleteFreePods(ctx, st, dead); n > 0 {
		scaled = true
	}

	if duplicate {
		all := append(append([]*corev1.Pod{}, cur...), old...)
		if n := c.deleteFreePods(ctx, st, all); n > 0 {
			scaled = true
		}
		status.DesiredFree = 0
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: api.CondReady, Status: metav1.ConditionFalse,
			ObservedGeneration: pool.Generation, Reason: api.ReasonDuplicateSKU,
			Message: fmt.Sprintf("blippool %s already serves SKU %q in this namespace", winner.Name, sku)})
	} else {
		var blips v1.BlipList
		if err := c.List(ctx, &blips, client.InNamespace(pool.Namespace)); err != nil {
			return reconcile.Result{}, err
		}
		window := 5 * time.Minute
		if pool.Spec.DemandWindow != nil {
			window = pool.Spec.DemandWindow.Duration
		}
		demand, waiting := 0, 0
		var waiters []types.NamespacedName
		for i := range blips.Items {
			b := &blips.Items[i]
			if blipSKU(b) != sku {
				continue
			}
			cond := meta.FindStatusCondition(b.Status.Conditions, api.CondScheduled)
			if cond == nil {
				continue
			}
			if cond.Status == metav1.ConditionTrue && now.Sub(cond.LastTransitionTime.Time) < window {
				demand++
				// Wake the pool when the Blip leaves the window.
				if d := window - now.Sub(cond.LastTransitionTime.Time) + time.Second; wait == 0 || d < wait {
					wait = d
				}
			}
			if cond.Status == metav1.ConditionFalse && cond.Reason == api.ReasonNoCapacity && b.Status.Allocation == nil && !isFinished(b) {
				waiting++
				waiters = append(waiters, types.NamespacedName{Namespace: b.Namespace, Name: b.Name})
			}
		}
		var ns corev1.Namespace
		if err := c.Get(ctx, types.NamespacedName{Name: pool.Namespace}, &ns); err != nil {
			return reconcile.Result{}, err
		}
		c.schedMu.Lock()
		running, err := c.countRunning(ctx, pool.Namespace, sku)
		c.schedMu.Unlock()
		if err != nil {
			return reconcile.Result{}, err
		}
		in := poolSizing{MinFree: int(pool.Spec.MinFree), MaxFree: int(pool.Spec.MaxFree), Demand: demand, Waiting: waiting,
			Assigned: assigned, Headroom: quotaLimit(ns.Annotations, sku, c.opts.DefaultQuota) - running}
		if pool.Spec.MaxSlots != nil {
			m := int(*pool.Spec.MaxSlots)
			in.MaxSlots = &m
		}
		desiredFree, target := poolTarget(in)
		status.DesiredFree = int32(desiredFree)

		delay := 10 * time.Minute
		if pool.Spec.ScaleDownDelay != nil {
			delay = pool.Spec.ScaleDownDelay.Duration
		}
		have := len(cur) + pendingCreates
		delta, since, w := scaleStep(have, target, st.lowSince, now, delay)
		c.mu.Lock()
		st.lowSince = since
		c.mu.Unlock()
		if w > 0 && (wait == 0 || w < wait) {
			wait = w
		}
		// Old-shape pods still count against maxSlots.
		blocked := 0
		if delta > 0 && in.MaxSlots != nil {
			room := max(*in.MaxSlots-assigned-have-len(old), 0)
			if delta > room {
				blocked = delta - room
				delta = room
			}
		}
		for i := 0; i < delta; i++ {
			p := tmpl.DeepCopy()
			if err := c.Create(ctx, p); err != nil {
				createErr = err.Error()
				c.log.Error(err, "create slot pod", "namespace", pool.Namespace, "pool", pool.Name)
				break
			}
			c.mu.Lock()
			st.creates[p.Name] = now
			c.mu.Unlock()
			booting++
			scaled = true
		}
		if delta < 0 {
			sortForDeletion(cur, freeOnNode)
			if n := c.deleteFreePods(ctx, st, cur[:-delta]); n > 0 {
				scaled = true
			}
		}
		// Rollout: old-shape pods that are not Ready go at once; Ready ones
		// as current-shape pods become Ready (or to make room under maxSlots).
		if len(old) > 0 {
			sortForDeletion(old, freeOnNode)
			var oldReady, victims []*corev1.Pod
			for _, p := range old {
				if p.Spec.NodeName != "" && podReady(p) {
					oldReady = append(oldReady, p)
				} else {
					victims = append(victims, p)
				}
			}
			n := min(max(curReady+len(oldReady)-target, blocked-len(victims), 0), len(oldReady))
			victims = append(victims, oldReady[:n]...)
			if c.deleteFreePods(ctx, st, victims) > 0 {
				scaled = true
			}
		}
		switch {
		case createErr != "":
			meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: api.CondReady, Status: metav1.ConditionFalse,
				ObservedGeneration: pool.Generation, Reason: api.ReasonCreateFailed, Message: createErr})
		case curReady >= int(pool.Spec.MinFree):
			meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: api.CondReady, Status: metav1.ConditionTrue,
				ObservedGeneration: pool.Generation, Reason: api.ReasonPoolReady, Message: fmt.Sprintf("%d free slots", curReady)})
		default:
			meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: api.CondReady, Status: metav1.ConditionFalse,
				ObservedGeneration: pool.Generation, Reason: api.ReasonScaling, Message: fmt.Sprintf("%d of %d free slots ready", curReady, pool.Spec.MinFree)})
		}
		// Blips waiting for capacity retry once there is a free slot.
		if free > 0 {
			for _, k := range waiters {
				c.enqueueBlip(k)
			}
		}
	}

	// Pods deleted above stop counting at once.
	c.mu.Lock()
	for _, p := range append(append([]*corev1.Pod{}, cur...), old...) {
		if _, gone := st.deletes[p.UID]; gone {
			if p.Spec.NodeName != "" && podReady(p) {
				free--
			} else {
				booting--
			}
		}
	}
	pending := len(st.creates) + len(st.deletes)
	if st.retry {
		pending++
	}
	c.mu.Unlock()
	status.Free, status.Booting, status.Assigned = int32(free), int32(booting), int32(assigned)
	if scaled {
		t := metav1.NewTime(now)
		status.LastScaleTime = &t
	}
	metricPoolSlots.WithLabelValues(pool.Namespace, pool.Name, "free").Set(float64(free))
	metricPoolSlots.WithLabelValues(pool.Namespace, pool.Name, "booting").Set(float64(booting))
	metricPoolSlots.WithLabelValues(pool.Namespace, pool.Name, "assigned").Set(float64(assigned))
	metricPoolDesiredFree.WithLabelValues(pool.Namespace, pool.Name).Set(float64(status.DesiredFree))
	if !equality.Semantic.DeepEqual(status, &pool.Status) {
		pool.Status = *status
		if err := c.Status().Update(ctx, &pool); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	switch {
	case createErr != "":
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	case pending > 0 && (wait == 0 || wait > 2*time.Second):
		wait = 2 * time.Second
	}
	if wait == 0 || wait > time.Minute {
		wait = time.Minute
	}
	return reconcile.Result{RequeueAfter: wait}, nil
}

// deleteFreePods deletes unclaimed slot pods. It holds the scheduling lock
// so no claim is in flight, skips pods with an assumed claim, and deletes
// with UID and resourceVersion preconditions so a pod claimed after the
// cache read is never deleted. It returns how many it deleted; pods it
// skipped or could not delete set st.retry.
func (c *Controller) deleteFreePods(ctx context.Context, st *poolState, pods []*corev1.Pod) int {
	if len(pods) == 0 {
		return 0
	}
	c.schedMu.Lock()
	defer c.schedMu.Unlock()
	n := 0
	for _, p := range pods {
		if _, taken := c.assumed[podKey(p.Namespace, p.Name)]; taken {
			st.retry = true
			continue
		}
		uid, rv := p.UID, p.ResourceVersion
		err := c.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name}},
			client.Preconditions{UID: &uid, ResourceVersion: &rv})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				st.retry = true
			}
			if !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
				c.log.Error(err, "delete free slot pod", "namespace", p.Namespace, "pod", p.Name)
			}
			continue
		}
		c.mu.Lock()
		st.deletes[p.UID] = timeNow()
		c.mu.Unlock()
		n++
	}
	return n
}

// poolsForBlip maps a Blip to the pools of its namespace and SKU.
func (c *Controller) poolsForBlip(ctx context.Context, o client.Object) []reconcile.Request {
	b, ok := o.(*v1.Blip)
	if !ok {
		return nil
	}
	var l v1.BlipPoolList
	if err := c.List(ctx, &l, client.InNamespace(b.Namespace)); err != nil {
		return nil
	}
	sku := blipSKU(b)
	var r []reconcile.Request
	for _, p := range l.Items {
		if poolSKU(&p) == sku {
			r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name}})
		}
	}
	return r
}

// poolsForPool maps a pool to every pool of its namespace with the same
// SKU, so a deleted winner hands over to the next one.
func (c *Controller) poolsForPool(ctx context.Context, o client.Object) []reconcile.Request {
	p, ok := o.(*v1.BlipPool)
	if !ok {
		return nil
	}
	var l v1.BlipPoolList
	if err := c.List(ctx, &l, client.InNamespace(p.Namespace)); err != nil {
		return nil
	}
	var r []reconcile.Request
	for _, q := range l.Items {
		if q.Name != p.Name && poolSKU(&q) == poolSKU(p) {
			r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: q.Namespace, Name: q.Name}})
		}
	}
	sort.Slice(r, func(i, j int) bool { return r[i].Name < r[j].Name })
	return r
}

// pendingBlipsForPool maps a pool to the unscheduled Blips of its namespace
// and SKU, so Blips waiting with UnknownSKU retry when a pool appears.
func (c *Controller) pendingBlipsForPool(ctx context.Context, o client.Object) []reconcile.Request {
	p, ok := o.(*v1.BlipPool)
	if !ok {
		return nil
	}
	return c.pendingBlips(ctx, p.Namespace, poolSKU(p))
}

// pendingBlips returns the Blips in ns that wait for a slot of sku.
func (c *Controller) pendingBlips(ctx context.Context, ns, sku string) []reconcile.Request {
	var l v1.BlipList
	if err := c.List(ctx, &l, client.InNamespace(ns)); err != nil {
		return nil
	}
	var r []reconcile.Request
	for _, b := range l.Items {
		if blipSKU(&b) == sku && b.Status.Allocation == nil && !isFinished(&b) {
			r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: b.Namespace, Name: b.Name}})
		}
	}
	return r
}
