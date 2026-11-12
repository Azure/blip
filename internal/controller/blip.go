package controller

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// blipRun is the state of one Blip reconcile.
type blipRun struct {
	b       *v1.Blip
	key     types.NamespacedName
	now     time.Time
	written bool // status already written
	next    time.Duration
}

func (r *blipRun) owner() Owner { return Owner{Kind: "Blip", Namespace: r.b.Namespace, Name: r.b.Name} }

func (r *blipRun) deleted() bool { return r.b.DeletionTimestamp != nil }

// after asks for a requeue no later than d.
func (r *blipRun) after(d time.Duration) {
	if d <= 0 {
		d = 100 * time.Millisecond
	}
	if r.next == 0 || d < r.next {
		r.next = d
	}
}

func (c *Controller) reconcileBlip(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var b v1.Blip
	if err := c.Get(ctx, req.NamespacedName, &b); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if b.DeletionTimestamp == nil && !controllerutil.ContainsFinalizer(&b, api.FinalizerCleanup) {
		patch := client.MergeFrom(b.DeepCopy())
		controllerutil.AddFinalizer(&b, api.FinalizerCleanup)
		return reconcile.Result{}, c.Patch(ctx, &b, patch)
	}
	if b.DeletionTimestamp != nil && !controllerutil.ContainsFinalizer(&b, api.FinalizerCleanup) {
		return reconcile.Result{}, nil
	}
	if stale, err := c.staleCopy(ctx, &b); err != nil || stale {
		return reconcile.Result{RequeueAfter: 100 * time.Millisecond}, client.IgnoreNotFound(err)
	}
	orig := b.DeepCopy()
	r := &blipRun{b: &b, key: req.NamespacedName, now: timeNow()}
	if a := b.Status.Allocation; a != nil && !isFinished(&b) {
		c.mu.Lock()
		c.allocKey[a.ID] = req.NamespacedName
		c.mu.Unlock()
	}
	initConditions(&b)
	res, err := c.stepBlip(ctx, r)
	if r.next > 0 && (res.RequeueAfter == 0 || r.next < res.RequeueAfter) && !res.Requeue {
		res.RequeueAfter = r.next
	}
	if !r.written && !equality.Semantic.DeepEqual(orig.Status, b.Status) {
		if uerr := c.Status().Update(ctx, &b); uerr != nil {
			if apierrors.IsConflict(uerr) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, uerr
		}
		c.wrote(&b)
	}
	if err != nil {
		if _, ok := err.(*refusal); ok {
			return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return res, err
	}
	if b.DeletionTimestamp != nil && isFinished(&b) {
		c.forgetBlip(ctx, &b)
		patch := client.MergeFrom(b.DeepCopy())
		controllerutil.RemoveFinalizer(&b, api.FinalizerCleanup)
		return reconcile.Result{}, client.IgnoreNotFound(c.Patch(ctx, &b, patch))
	}
	return res, nil
}

func (c *Controller) stepBlip(ctx context.Context, r *blipRun) (reconcile.Result, error) {
	b := r.b
	if isFinished(b) {
		return c.finishedStep(ctx, r)
	}
	if b.Status.Allocation == nil {
		if isFailed(b) || r.deleted() {
			if !isFailed(b) {
				setFailed(b, api.ReasonCancelled, "")
			}
			// Claims taken before a slot was found.
			if done, err := c.releaseUnattached(ctx, r); err != nil || !done {
				return reconcile.Result{RequeueAfter: time.Second}, err
			}
			setFinished(b, r.now)
			return reconcile.Result{}, nil
		}
		return c.schedule(ctx, r)
	}
	if !isFailed(b) && !isTrue(b.Status.Conditions, api.CondComplete) && !rescheduling(b) {
		res, err, cont := c.run(ctx, r)
		if !cont {
			return res, err
		}
	}
	done, err := c.release(ctx, r)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !done {
		r.after(5 * time.Second)
		return reconcile.Result{}, nil
	}
	if rescheduling(b) && !isFailed(b) {
		return c.finishReschedule(ctx, r)
	}
	setFinished(b, r.now)
	if !isFailed(b) {
		b.Status.Phase = v1.BlipSucceeded
	} else {
		b.Status.Phase = v1.BlipFailed
	}
	b.Status.Message = strings.TrimSpace(b.Status.Message)
	return reconcile.Result{Requeue: true}, nil
}

// wrote records the resourceVersion of a status this controller wrote.
func (c *Controller) wrote(b *v1.Blip) {
	c.mu.Lock()
	c.written[types.NamespacedName{Namespace: b.Namespace, Name: b.Name}] = b.ResourceVersion
	c.mu.Unlock()
}

// staleCopy reports whether the cached Blip is older than a status this
// controller wrote. Acting on such a copy could repeat or undo steps (for
// example release an attachment that is attached), so the reconcile waits
// for the cache. Only after an own write is the live object read.
func (c *Controller) staleCopy(ctx context.Context, b *v1.Blip) (bool, error) {
	key := types.NamespacedName{Namespace: b.Namespace, Name: b.Name}
	c.mu.Lock()
	w, ok := c.written[key]
	c.mu.Unlock()
	if !ok {
		return false, nil
	}
	if w != b.ResourceVersion {
		var cur v1.Blip
		if err := c.live.Get(ctx, key, &cur); err != nil {
			return false, err
		}
		if cur.ResourceVersion != b.ResourceVersion {
			return true, nil
		}
	}
	c.mu.Lock()
	if c.written[key] == w {
		delete(c.written, key)
	}
	c.mu.Unlock()
	return false, nil
}

func ttlAfterFinished(b *v1.Blip) time.Duration {
	if b.Spec.TTLSecondsAfterFinished != nil {
		return time.Duration(*b.Spec.TTLSecondsAfterFinished) * time.Second
	}
	return 300 * time.Second
}

func (c *Controller) finishedStep(ctx context.Context, r *blipRun) (reconcile.Result, error) {
	b := r.b
	// Revoke the guest's service account tokens at once.
	if a := b.Status.Allocation; a != nil {
		if err := c.deleteBinding(ctx, b.Namespace, a.ID); err != nil {
			return reconcile.Result{}, err
		}
	}
	// Keep operation results for a while: a stale cache may still show the
	// Blip unfinished and repeat the cleanup.
	if b.Status.CompletionTime == nil || r.now.Sub(b.Status.CompletionTime.Time) > time.Minute {
		c.forgetBlip(ctx, b)
	}
	if r.deleted() {
		return reconcile.Result{}, nil
	}
	end := r.now
	if b.Status.CompletionTime != nil {
		end = b.Status.CompletionTime.Time
	}
	exp := end.Add(ttlAfterFinished(b))
	if r.now.Before(exp) {
		return reconcile.Result{RequeueAfter: exp.Sub(r.now)}, nil
	}
	uid := b.UID
	err := c.Delete(ctx, b, client.Preconditions{UID: &uid})
	return reconcile.Result{}, client.IgnoreNotFound(err)
}

// forgetBlip drops in-memory state of a finished Blip.
// It also deletes the allocation's token binding Secret, revoking its
// service account tokens.
func (c *Controller) forgetBlip(ctx context.Context, b *v1.Blip) {
	if b.DeletionTimestamp != nil {
		c.mu.Lock()
		delete(c.written, types.NamespacedName{Namespace: b.Namespace, Name: b.Name})
		c.mu.Unlock()
	}
	a := b.Status.Allocation
	if a == nil {
		return
	}
	c.nodes.Forget(a.ID + ".")
	c.nodes.ForgetAlloc(a.ID)
	c.mu.Lock()
	delete(c.allocKey, a.ID)
	c.mu.Unlock()
	c.forgetCreds(a.ID)
	if err := c.deleteBinding(ctx, b.Namespace, a.ID); err != nil {
		c.log.Error(err, "delete token binding secret", "blip", b.Namespace+"/"+b.Name)
	}
	for _, vs := range b.Status.Volumes {
		c.retryClear(vs.AttachmentID)
	}
}

// wait sets Scheduled=False with a reason and requeues.
func (c *Controller) wait(r *blipRun, reason, msg string) (reconcile.Result, error) {
	setCond(&r.b.Status.Conditions, r.b.Generation, api.CondScheduled, false, reason, msg)
	r.b.Status.Phase = v1.BlipPending
	after := 5 * time.Second
	switch reason {
	case api.ReasonWaitingForBlipVol:
		after = 10 * time.Second
	case api.ReasonVolumeInUse:
		after = 3 * time.Second
	}
	return reconcile.Result{RequeueAfter: after}, nil
}

// waitReleasing waits like wait, but first gives back claims taken by an
// earlier pass, so a waiting Blip does not keep volumes from others.
func (c *Controller) waitReleasing(ctx context.Context, r *blipRun, reason, msg string) (reconcile.Result, error) {
	if _, err := c.releaseUnattached(ctx, r); err != nil {
		return reconcile.Result{}, err
	}
	return c.wait(r, reason, msg)
}

// releaseUnattached releases the claims of volumes that were claimed but
// never sent to a node (no allocation yet) and resets their entries.
func (c *Controller) releaseUnattached(ctx context.Context, r *blipRun) (bool, error) {
	b := r.b
	var keep []v1.BlipVolumeStatus
	for _, vs := range b.Status.Volumes {
		if vs.Generation > 0 && vs.State == v1.VolumeReserving {
			if err := c.releaseClaim(ctx, b, &vs); err != nil {
				return false, err
			}
		}
		if vs.State != v1.VolumeReserving {
			keep = append(keep, vs)
		} else if vs.ResumedFrom != nil {
			// Keep the record of where this attempt resumes from.
			keep = append(keep, v1.BlipVolumeStatus{Name: vs.Name, BlipVolRef: vs.BlipVolRef, Message: vs.Message, ResumedFrom: vs.ResumedFrom})
		}
	}
	b.Status.Volumes = keep
	return true, nil
}

// resolved is a spec volume and its BlipVol.
type resolved struct {
	spec v1.BlipVolume
	vol  *v1.BlipVol
}

// resolveVolumes gets every spec volume. It returns a wait reason if one
// is missing or not ready, or a failure reason if one failed.
func (c *Controller) resolveVolumes(ctx context.Context, b *v1.Blip) ([]resolved, string, string, bool, error) {
	var out []resolved
	for _, sv := range b.Spec.Volumes {
		var bv v1.BlipVol
		err := c.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: sv.BlipVolRef.Name}, &bv)
		if apierrors.IsNotFound(err) || (err == nil && bv.DeletionTimestamp != nil) {
			return nil, api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %q not found", sv.BlipVolRef.Name), false, nil
		}
		if err != nil {
			return nil, "", "", false, err
		}
		switch bv.Status.Phase {
		case v1.BlipVolFailed:
			return nil, api.ReasonInputBlipVolFailed, fmt.Sprintf("blipvol %q failed", bv.Name), true, nil
		case v1.BlipVolReady:
			if currentSnap(&bv) == nil {
				return nil, api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %q has no Ready snapshot", bv.Name), false, nil
			}
		default:
			return nil, api.ReasonWaitingForBlipVol, fmt.Sprintf("blipvol %q is not ready", bv.Name), false, nil
		}
		out = append(out, resolved{spec: sv, vol: &bv})
	}
	return out, "", "", false, nil
}

// schedule resolves the volumes, checks quota and capacity,
// claims every volume and then a slot (design 4.1 and 6.3).
func (c *Controller) schedule(ctx context.Context, r *blipRun) (reconcile.Result, error) {
	b := r.b
	if res, stop := c.rescheduleWait(r); stop {
		return res, nil
	}
	vols, reason, msg, failed, err := c.resolveVolumes(ctx, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	if failed {
		setFailed(b, reason, msg)
		return reconcile.Result{Requeue: true}, nil
	}
	if reason != "" {
		return c.waitReleasing(ctx, r, reason, msg)
	}
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("storage config: %w", err)
	}
	var root *resolved
	for i := range vols {
		if vols[i].spec.Name == b.Spec.RootVolume {
			root = &vols[i]
		}
		v := vols[i].vol
		cur := currentSnap(v)
		g := cfg.Group(cur.StorageGroup)
		if g == nil {
			return c.waitReleasing(ctx, r, api.ReasonNoCapacity, fmt.Sprintf("storage group %q is not configured", cur.StorageGroup))
		}
		if n := len(c.snapReplicas(cur)); n < 2 {
			return c.waitReleasing(ctx, r, api.ReasonNoCapacity, fmt.Sprintf("%d replicas of blipvol %s are reachable, need 2", n, v.Name))
		}
	}
	if root == nil {
		// CRD validation requires rootVolume to name an entry in volumes.
		return reconcile.Result{}, fmt.Errorf("rootVolume %q names no volume", b.Spec.RootVolume)
	}
	rootGroup := cfg.Group(currentSnap(root.vol).StorageGroup)
	if f := c.groupFullness(rootGroup); f >= c.opts.StorageFullThreshold {
		return c.waitReleasing(ctx, r, api.ReasonStorageFull, fmt.Sprintf("storage group %s is %.0f%% full", rootGroup.Name, f))
	}
	sku := b.Spec.SKU
	if sku == "" {
		sku = api.DefaultSKU
	}
	// Each namespace has its own pools: a SKU exists in a namespace when a
	// BlipPool serves it there, and only its slot pods are candidates.
	skuPool, err := c.poolForSKU(ctx, b.Namespace, sku)
	if err != nil {
		return reconcile.Result{}, err
	}
	if skuPool == nil {
		return c.waitReleasing(ctx, r, api.ReasonUnknownSKU, fmt.Sprintf("no BlipPool for SKU %q in namespace %s", sku, b.Namespace))
	}
	sa := serviceAccountName(b)
	var sao corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: sa}, &sao); apierrors.IsNotFound(err) {
		return c.waitReleasing(ctx, r, api.ReasonServiceAccountNotFound, fmt.Sprintf("service account %q not found", sa))
	} else if err != nil {
		return reconcile.Result{}, err
	}

	c.schedMu.Lock()
	defer c.schedMu.Unlock()
	c.pruneAssumed(ctx)
	for _, a := range c.assumed {
		if a.blip == r.key && a.uid == b.UID {
			// Claimed already; the cache does not show it yet.
			return reconcile.Result{RequeueAfter: 200 * time.Millisecond}, nil
		}
	}
	var ns corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: b.Namespace}, &ns); err != nil {
		return reconcile.Result{}, err
	}
	limit := quotaLimit(ns.Annotations, sku, c.opts.DefaultQuota)
	used, err := c.countRunning(ctx, b.Namespace, sku)
	if err != nil {
		return reconcile.Result{}, err
	}
	metricQuotaUsed.WithLabelValues(b.Namespace, sku).Set(float64(used))
	if used >= limit {
		return c.waitReleasing(ctx, r, api.ReasonQuotaExceeded, fmt.Sprintf("%d of %d running blips for SKU %q", used, limit, sku))
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(b.Namespace), client.MatchingLabels{api.LabelSKU: sku, api.LabelSlot: api.SlotFree}); err != nil {
		return reconcile.Result{}, err
	}
	var cands []candidate
	perNode := map[string]int{}
	tooFewDisks := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		if !freeSlot(p, sku) {
			continue
		}
		if _, taken := c.assumed[podKey(p.Namespace, p.Name)]; taken {
			continue
		}
		info := c.nodes.Info(p.Spec.NodeName)
		if !info.Connected {
			continue
		}
		cc := info.Capacity.GetCompute()
		if cc != nil && cc.MemoryPressure {
			continue
		}
		if info.DisksPerSlot() < len(b.Spec.Volumes) {
			tooFewDisks++
			continue
		}
		score := 0
		for _, v := range vols {
			if g := cfg.Group(currentSnap(v.vol).StorageGroup); g != nil && slices.Contains(g.Nodes, p.Spec.NodeName) {
				if v.spec.Name == b.Spec.RootVolume {
					score += 100
				} else {
					score++
				}
			}
		}
		perNode[p.Spec.NodeName]++
		cur := skuPool.Status.TemplateHash != "" && p.Labels[api.LabelTemplateHash] == skuPool.Status.TemplateHash
		cands = append(cands, candidate{Pod: p, Node: p.Spec.NodeName, Current: cur, Score: score, Load: nodeLoad(cc)})
	}
	if len(cands) == 0 {
		if tooFewDisks > 0 {
			return c.waitReleasing(ctx, r, api.ReasonTooManyVolumes, fmt.Sprintf("%d volumes, but free slots of SKU %q have fewer disks", len(b.Spec.Volumes), sku))
		}
		return c.waitReleasing(ctx, r, api.ReasonNoCapacity, fmt.Sprintf("no free slot for SKU %q", sku))
	}
	for i := range cands {
		cands[i].Free = perNode[cands[i].Node]
	}
	sortCandidates(cands)

	// Act only on a current copy of the Blip: claims follow the attachment
	// IDs recorded in its status, and the status update after the slot
	// claim must not conflict and waste the claimed pod.
	var cur v1.Blip
	if err := c.live.Get(ctx, r.key, &cur); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if cur.ResourceVersion != b.ResourceVersion {
		return reconcile.Result{RequeueAfter: 100 * time.Millisecond}, nil
	}
	// Record the attachments before claiming, so a claim is always found
	// again from the Blip status after a lost write.
	if changed, err := c.planVolumes(ctx, b, vols); err != nil || changed {
		r.after(100 * time.Millisecond)
		return reconcile.Result{}, err
	}
	// Wait without touching anything while the cache shows a volume
	// claimed by someone else; claiming and rolling back would only wake
	// every waiter again.
	for _, v := range vols {
		if cl := v.vol.Status.Claim; cl != nil && cl.BlipUID != string(b.UID) {
			return c.waitReleasing(ctx, r, api.ReasonVolumeInUse, fmt.Sprintf("blipvol %s is attached to blip %s", v.vol.Name, cl.BlipName))
		}
	}
	// Claim every volume in UID order; on a refusal give all back.
	order := make([]int, len(b.Status.Volumes))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		return b.Status.Volumes[order[i]].BlipVolRef.UID < b.Status.Volumes[order[j]].BlipVolRef.UID
	})
	for _, i := range order {
		vs := &b.Status.Volumes[i]
		gen, snap, err := c.claimVol(ctx, b, vs)
		if err != nil {
			if rf, ok := err.(*refusal); ok {
				for _, j := range order {
					if err := c.releaseClaim(ctx, b, &b.Status.Volumes[j]); err != nil {
						return reconcile.Result{}, err
					}
					b.Status.Volumes[j].Generation = 0
				}
				return c.wait(r, rf.reason, rf.msg)
			}
			return reconcile.Result{}, err
		}
		vs.Generation, vs.Snapshot = gen, snap
		c.noteResumed(ctx, b, vs)
	}

	allocID := newID()
	var pod *corev1.Pod
	for _, cand := range cands {
		p, err := c.claim(ctx, cand.Pod, b, allocID)
		if err == nil {
			pod = p
			break
		}
		if !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
	}
	if pod == nil {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	c.assumed[podKey(pod.Namespace, pod.Name)] = assumedClaim{blip: r.key, uid: b.UID, namespace: b.Namespace, sku: sku, allocID: allocID, at: r.now}
	start := metav1.NewTime(r.now)
	deadline := metav1.NewTime(r.now.Add(time.Duration(b.Spec.MaxTTLSeconds) * time.Second))
	if b.Spec.MaxTTLSeconds == 0 {
		deadline = metav1.NewTime(r.now.Add(time.Hour))
	}
	b.Status.Allocation = &v1.Allocation{ID: allocID, Node: pod.Spec.NodeName, PodName: pod.Name, PodUID: string(pod.UID)}
	// A rescheduled Blip keeps the start and deadline of its first attempt.
	if b.Status.StartTime == nil || b.Status.Deadline == nil {
		b.Status.StartTime, b.Status.Deadline = &start, &deadline
	}
	b.Status.NextScheduleTime = nil
	if rescheduling(b) {
		reason, msg := "Rescheduled", fmt.Sprintf("attempt %d", b.Status.RescheduleCount+1)
		if lost := resumedLost(b); lost != "" {
			// Keep the loss of writes visible while the attempt runs.
			reason, msg = api.ReasonResumedFromOlderSnapshot, msg+": "+lost
		}
		setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, false, reason, msg)
	}
	b.Status.PodIP = pod.Status.PodIP
	b.Status.Phase = v1.BlipRunning
	setCond(&b.Status.Conditions, b.Generation, api.CondScheduled, true, api.ReasonClaimed, fmt.Sprintf("slot %s on node %s", pod.Name, pod.Spec.NodeName))
	err = c.Status().Update(ctx, b)
	if err == nil {
		c.wrote(b)
	}
	if err != nil {
		// Claimed pods never return to free (design 6.3).
		delete(c.assumed, podKey(pod.Namespace, pod.Name))
		c.deletePod(ctx, pod.Namespace, pod.Name, pod.UID)
		return reconcile.Result{}, err
	}
	r.written = true
	c.mu.Lock()
	c.allocKey[allocID] = r.key
	c.mu.Unlock()
	return reconcile.Result{Requeue: true}, nil
}

// planVolumes makes sure every spec volume has a Reserving entry with an
// attachment ID and slot disk. It reports whether it changed any.
func (c *Controller) planVolumes(ctx context.Context, b *v1.Blip, vols []resolved) (bool, error) {
	added := false
	for i, v := range vols {
		vs := volStatus(b, v.spec.Name)
		if vs != nil && vs.BlipVolRef != nil && vs.BlipVolRef.UID == string(v.vol.UID) && vs.State == v1.VolumeReserving {
			continue
		}
		if vs != nil && vs.Generation > 0 {
			// The BlipVol was replaced: give back the claim on the old one.
			if err := c.releaseClaim(ctx, b, vs); err != nil {
				return false, err
			}
		}
		disk := int32(i)
		nvs := v1.BlipVolumeStatus{Name: v.spec.Name, BlipVolRef: &v1.ObjectRef{Name: v.vol.Name, UID: string(v.vol.UID)},
			AttachmentID: newID(), SlotDisk: &disk, State: v1.VolumeReserving,
			DevicePath: api.GuestVolumePath(v.spec.Name)}
		if vs != nil {
			nvs.ResumedFrom = vs.ResumedFrom
			nvs.Message = vs.Message
			*vs = nvs
		} else {
			b.Status.Volumes = append(b.Status.Volumes, nvs)
		}
		added = true
	}
	// Drop entries of volumes no longer in spec.
	for i := range b.Status.Volumes {
		vs := &b.Status.Volumes[i]
		if specVol(b, vs.Name) == nil && vs.Generation > 0 {
			if err := c.releaseClaim(ctx, b, vs); err != nil {
				return false, err
			}
		}
	}
	n := len(b.Status.Volumes)
	b.Status.Volumes = slices.DeleteFunc(b.Status.Volumes, func(vs v1.BlipVolumeStatus) bool {
		return specVol(b, vs.Name) == nil
	})
	return added || len(b.Status.Volumes) != n, nil
}

// claim patches a free pod to assigned with a resourceVersion precondition.
func (c *Controller) claim(ctx context.Context, pod *corev1.Pod, b *v1.Blip, allocID string) (*corev1.Pod, error) {
	p := pod.DeepCopy()
	p.Labels[api.LabelSlot] = api.SlotAssigned
	p.Labels[api.LabelNamespace] = b.Namespace
	p.Labels[api.LabelName] = b.Name
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[api.AnnotationBlipUID] = string(b.UID)
	p.Annotations[api.AnnotationAllocationID] = allocID
	// The pod leaves its pool: without the BlipPool owner reference,
	// deleting the pool never deletes a live Blip's pod. The pool label
	// stays, so the pool still counts it as assigned.
	var refs []metav1.OwnerReference
	for _, o := range p.OwnerReferences {
		if o.Kind != "BlipPool" {
			refs = append(refs, o)
		}
	}
	p.OwnerReferences = refs
	if refs == nil {
		// A merge patch needs an explicit empty list to remove all owners.
		p.OwnerReferences = []metav1.OwnerReference{}
	}
	err := c.Patch(ctx, p, client.MergeFromWithOptions(pod, client.MergeFromWithOptimisticLock{}))
	return p, err
}

// podKey keys slot pods (assumed claims) by namespace and name.
func podKey(ns, name string) string { return ns + "/" + name }

func serviceAccountName(b *v1.Blip) string {
	if b.Spec.ServiceAccountName != "" {
		return b.Spec.ServiceAccountName
	}
	return "default"
}

func (c *Controller) deletePod(ctx context.Context, ns, name string, uid types.UID) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	var pre client.Preconditions
	if uid != "" {
		pre.UID = &uid
	}
	if err := c.Delete(ctx, p, pre); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		c.log.Error(err, "delete slot pod", "namespace", ns, "pod", name)
	}
}

// pruneAssumed drops assumed claims the cache now shows, of Blips that are
// gone (also when a new Blip has the same name), or that are old.
func (c *Controller) pruneAssumed(ctx context.Context) {
	for pod, a := range c.assumed {
		var b v1.Blip
		err := c.Get(ctx, a.blip, &b)
		if apierrors.IsNotFound(err) || (err == nil && (b.UID != a.uid || b.Status.Allocation != nil)) || timeNow().Sub(a.at) > 2*time.Minute {
			delete(c.assumed, pod)
		}
	}
}

// countRunning counts Blips with an allocation that are not Finished, plus
// assumed claims the cache does not show yet.
func (c *Controller) countRunning(ctx context.Context, ns, sku string) (int, error) {
	var l v1.BlipList
	if err := c.List(ctx, &l, client.InNamespace(ns)); err != nil {
		return 0, err
	}
	n := 0
	seen := map[string]bool{}
	for _, b := range l.Items {
		s := b.Spec.SKU
		if s == "" {
			s = api.DefaultSKU
		}
		if s == sku && isRunningForQuota(&b) {
			n++
			seen[b.Status.Allocation.ID] = true
		}
	}
	for _, a := range c.assumed {
		if a.namespace == ns && a.sku == sku && !seen[a.allocID] {
			n++
		}
	}
	return n, nil
}

// run drives an allocated Blip. cont is true when the run ended (Failed or
// Complete set) and the release should follow.
func (c *Controller) run(ctx context.Context, r *blipRun) (res reconcile.Result, err error, cont bool) {
	b := r.b
	a := b.Status.Allocation
	rt := c.nodes.Alloc(a.ID)
	recordRuntime(b, rt)
	fail := func(reason, msg string) (reconcile.Result, error, bool) {
		c.endAttempt(r, reason, msg)
		return reconcile.Result{}, nil, true
	}
	// A guest that booted and exited started, even if no reconcile saw
	// it running: a short run can end between two reconciles.
	if rt.Started && rt.Exit != nil && !isTrue(b.Status.Conditions, api.CondStarted) {
		setCond(&b.Status.Conditions, b.Generation, api.CondStarted, true, api.ReasonStarted, "")
	}
	if r.deleted() {
		return fail(api.ReasonCancelled, "")
	}
	if c.nodes.Lost(a.Node) || (!c.nodes.Connected(a.Node) && c.fenced(ctx, a.Node)) {
		return fail(api.ReasonNodeLost, fmt.Sprintf("node %s unreachable", a.Node))
	}
	if rt.Exit != nil {
		complete, reason, msg := exitOutcome(rt.Exit)
		if complete {
			b.Status.Message = ""
			setCond(&b.Status.Conditions, b.Generation, api.CondComplete, true, api.ReasonSucceeded, msg)
			setCond(&b.Status.Conditions, b.Generation, api.CondFailed, false, api.ReasonSucceeded, "")
			return reconcile.Result{}, nil, true
		}
		return fail(reason, msg)
	}
	if b.Status.Deadline != nil && !r.now.Before(b.Status.Deadline.Time) {
		return fail(api.ReasonTTLExceeded, "the deadline passed")
	}
	// Only the node detects slot loss (pod gone, slot given away, Cloud
	// Hypervisor unreachable); an unreachable node is NodeLost above.
	if rt.SlotLost != "" {
		return fail(api.ReasonSlotLost, rt.SlotLost)
	}
	if isTrue(b.Status.Conditions, api.CondStarted) && c.nodes.AllocMissing(a.Node, a.ID) {
		return fail(api.ReasonSlotLost, "allocation missing on node "+a.Node)
	}
	if !isTrue(b.Status.Conditions, api.CondStarted) {
		if rt.Started {
			setCond(&b.Status.Conditions, b.Generation, api.CondStarted, true, api.ReasonStarted, "")
			b.Status.Phase = v1.BlipRunning
			if st := attemptStart(b); st != nil {
				metricBootLatency.Observe(r.now.Sub(st.Time).Seconds())
			}
			metricStartLatency.Observe(r.now.Sub(b.CreationTimestamp.Time).Seconds())
		} else {
			if reason, msg := c.acquire(ctx, r); reason != "" {
				return fail(reason, msg)
			}
		}
	}
	if isTrue(b.Status.Conditions, api.CondStarted) {
		r.after(c.rotateCreds(ctx, r))
		c.reconcileAttachments(ctx, r, false)
		if err := c.captureLoop(ctx, r); err != nil {
			return reconcile.Result{}, err, false
		}
	}
	next := 30 * time.Second
	if !c.nodes.Connected(a.Node) {
		next = c.opts.NodeLostTimeout / 4
	}
	if b.Status.Deadline != nil {
		next = min(next, b.Status.Deadline.Sub(r.now)+time.Second)
	}
	r.after(next)
	return reconcile.Result{}, nil, false
}

// recordRuntime copies the restart count and the guest exit code the node
// reported into the status.
func recordRuntime(b *v1.Blip, rt AllocRuntime) {
	if rt.Started || rt.Exit != nil {
		b.Status.RestartCount = rt.RestartCount()
	}
	if rt.Exit != nil && rt.Exit.ExitCode != nil {
		code := rt.Exit.GetExitCode()
		b.Status.LastExitCode = &code
	}
}

// exitOutcome is the Blip result of the node's exit report: complete,
// or the Failed reason and message. blipd slot classified the exit; the
// reason is used as is; an exit without one counts as HypervisorExited.
func exitOutcome(e *nodepb.Exited) (complete bool, reason, msg string) {
	reason = e.Reason
	if reason == "" {
		reason = api.ReasonHypervisorExited
	}
	return reason == api.ReasonSucceeded, reason, e.Message
}

func blipRef(b *v1.Blip) *nodepb.ObjectRef {
	return &nodepb.ObjectRef{Namespace: b.Namespace, Name: b.Name, Uid: string(b.UID)}
}

// slotKillMargin is how long after the graceful stop at the deadline
// blipd slot waits before it kills the VM itself.
const slotKillMargin = 10 * time.Second

// acquire binds the slot, attaches every initial volume and starts the
// workload (design 4.1 step 4 and 5). It returns a failure reason, or ""
// while in progress.
func (c *Controller) acquire(ctx context.Context, r *blipRun) (string, string) {
	b := r.b
	a := b.Status.Allocation
	own := r.owner()
	to := c.opts.CommandTimeout
	var deadline *timestamppb.Timestamp
	if b.Status.Deadline != nil {
		deadline = timestamppb.New(b.Status.Deadline.Time)
	}
	res := c.nodes.Do(a.Node, a.ID+".assign", own, to, &nodepb.Command{Op: &nodepb.Command_AssignSlot{AssignSlot: &nodepb.AssignSlot{
		AllocationId: a.ID, Blip: blipRef(b),
		Pod:      &nodepb.ObjectRef{Namespace: b.Namespace, Name: a.PodName, Uid: a.PodUID},
		Deadline: deadline,
		// blipd slot kills only after the graceful stop the controller
		// starts at the deadline has run out.
		KillGrace: durationpb.New(c.opts.GracefulTimeout + slotKillMargin),
		Ports:     blipPorts(b),
	}}})
	if res == nil {
		return "", ""
	}
	if !ok(res) {
		return api.ReasonStartFailed, "assign: " + resultErr(res)
	}
	// Attach every initial volume.
	if reason, msg := c.reconcileAttachments(ctx, r, true); reason != "" {
		return reason, msg
	}
	var refs []*nodepb.VolumeRef
	rootAtt := ""
	for _, vs := range b.Status.Volumes {
		if vs.State != v1.VolumeAttached {
			setCond(&b.Status.Conditions, b.Generation, api.CondVolumesReady, false, api.ReasonAttaching, "attaching "+vs.Name)
			return "", ""
		}
		refs = append(refs, &nodepb.VolumeRef{AttachmentId: vs.AttachmentID, Uid: vs.BlipVolRef.UID, Name: vs.Name})
		if vs.Name == b.Spec.RootVolume {
			rootAtt = vs.AttachmentID
		}
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondVolumesReady, true, "Attached", fmt.Sprintf("%d volumes attached", len(refs)))
	init := b.Spec.Init
	if len(init) == 0 {
		init = api.DefaultInit
	}
	creds, err := c.startCreds(ctx, b, r.now)
	if apierrors.IsNotFound(err) {
		return api.ReasonStartFailed, fmt.Sprintf("service account token: %v", err)
	}
	if err != nil {
		c.log.Error(err, "mint token", "blip", r.key)
		r.after(2 * time.Second)
		return "", ""
	}
	res = c.nodes.Do(a.Node, a.ID+".start", own, to, &nodepb.Command{Op: &nodepb.Command_StartWorkload{StartWorkload: &nodepb.StartWorkload{
		AllocationId: a.ID, Blip: blipRef(b), RootAttachmentId: rootAtt, Volumes: refs,
		Params:      &nodepb.RunParams{Init: init, RootMountOptions: b.Spec.RootMountOptions, Hostname: b.Name},
		Credentials: creds,
	}}})
	if res != nil && !ok(res) {
		return api.ReasonStartFailed, "start: " + resultErr(res)
	}
	return "", ""
}

func volStatus(b *v1.Blip, name string) *v1.BlipVolumeStatus {
	for i := range b.Status.Volumes {
		if b.Status.Volumes[i].Name == name {
			return &b.Status.Volumes[i]
		}
	}
	return nil
}

func specVol(b *v1.Blip, name string) *v1.BlipVolume {
	for i := range b.Spec.Volumes {
		if b.Spec.Volumes[i].Name == name {
			return &b.Spec.Volumes[i]
		}
	}
	return nil
}
