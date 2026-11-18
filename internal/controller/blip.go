package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// Blip status reasons.
const (
	ReasonInvalidSpec   = "InvalidSpec"
	ReasonPoolNotFound  = "PoolNotFound"
	ReasonImageResolve  = "ImageResolveFailed"
	ReasonImageNotFound = "ImageNotFound"
	ReasonStateNotFound = "StateNotFound"
	ReasonStateNotReady = "StateNotReady"
	ReasonStateFailed   = "StateFailed"
	ReasonStateBusy     = "StateBusy"
	ReasonWaitingForVM  = "WaitingForVM"
	ReasonStarting      = "Starting"
	ReasonPrepareFailed = "PrepareFailed"
	ReasonStartTimeout  = "StartTimeout"
	ReasonStopped       = "Stopped"
	ReasonCompleted     = "Completed"
	ReasonError         = "Error"
	ReasonPodLost       = "PodLost"
	ReasonRuntimeFailed = "RuntimeFailed"
	ReasonSaveFailed    = "SaveFailed"
	exitAnnotationGrace = 30 * time.Second
)

const (
	// AnnotationPrepareError is set by the node agent when it cannot
	// prepare a claimed pod's disks. Some errors are transient, so it is
	// surfaced immediately but only fails the Blip after startTimeout.
	AnnotationPrepareError = "blip.dev/prepare-error"
	// startTimeout bounds how long a claimed Blip may stay Starting.
	startTimeout = 10 * time.Minute
	// pendingTimeout bounds how long a Blip may wait for a VM before it is
	// claimed. Image builds and state copies happen in this window.
	pendingTimeout = 30 * time.Minute
)

// BlipReconciler runs the Blip lifecycle.
type BlipReconciler struct {
	client.Client
	// Live is an uncached reader: before claiming, it confirms that the
	// Blip has not claimed a pod the cache does not show yet and that the
	// candidate still matches the current pool template.
	Live client.Reader
	Config
}

func (r *BlipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Live == nil {
		r.Live = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Blip{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.podBlips)).
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			return r.blipsBy(ctx, o.GetNamespace(), indexStates, o.GetName(), false)
		})).
		Watches(&v1.BlipPool{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			return r.blipsBy(ctx, o.GetNamespace(), indexPool, o.GetName(), true)
		})).
		Named("blip").
		// A fork storm creates many independent Blips; one reconcile does
		// several sequential gets/patches, so serializing them made command
		// start latency grow with the number of concurrent forks.
		WithOptions(controller.Options{MaxConcurrentReconciles: 8}).
		Complete(r)
}

func (r *BlipReconciler) podBlips(ctx context.Context, o client.Object) []reconcile.Request {
	p := o.(*corev1.Pod)
	if !isVacant(p) {
		if name := p.Annotations[AnnotationBlip]; name != "" {
			return []reconcile.Request{req(p.Namespace, name)}
		}
		return nil
	}
	// A pinned pod the scheduler cannot place ends the local wait of the
	// Blips it was booted for.
	if !ready(p) && !(p.Annotations[AnnotationPinnedNode] != "" && unschedulable(p)) {
		return nil
	}
	return r.blipsBy(ctx, p.Namespace, indexPool, p.Labels[LabelPool], true)
}

func (r *BlipReconciler) blipsBy(ctx context.Context, ns, field, value string, waiting bool) []reconcile.Request {
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(ns), client.MatchingFields{field: value}); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, b := range blips.Items {
		if !waiting || b.Status.Pod == "" && !finished(&b) {
			out = append(out, req(b.Namespace, b.Name))
		}
	}
	return out
}

func (r *BlipReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	b := &v1.Blip{}
	if err := r.Get(ctx, rq.NamespacedName, b); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if finished(b) {
		return reconcile.Result{}, r.cleanup(ctx, b)
	}
	if b.DeletionTimestamp == nil && !controllerutil.ContainsFinalizer(b, Finalizer) {
		base := b.DeepCopy()
		controllerutil.AddFinalizer(b, Finalizer)
		if err := patchObject(ctx, r.Client, b, base); err != nil {
			return reconcile.Result{}, err
		}
	}

	base := b.DeepCopy()
	var result reconcile.Result
	var err error
	switch b.Status.Phase {
	case "", v1.BlipPending:
		result, err = r.pending(ctx, b, base)
	case v1.BlipRunning:
		result, err = r.running(ctx, b)
	}
	if err == nil && b.Status.Phase == v1.BlipSaving {
		err = r.saving(ctx, b)
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if deadline, ok := r.startDeadline(b); ok {
		if left := deadline.Sub(r.now()); left > 0 && (result.RequeueAfter == 0 || left < result.RequeueAfter) {
			result.RequeueAfter = left
		}
	}
	if err := r.flush(ctx, b, base); err != nil {
		return reconcile.Result{}, err
	}
	if finished(b) {
		return reconcile.Result{}, r.cleanup(ctx, b)
	}
	return result, nil
}

// flush writes b.Status if it changed since base and makes base current.
func (r *BlipReconciler) flush(ctx context.Context, b, base *v1.Blip) error {
	if semanticEqual(base.Status, b.Status) {
		return nil
	}
	if err := patchStatus(ctx, r.Client, b, base); err != nil {
		return err
	}
	*base = *b.DeepCopy()
	return nil
}

// cleanup deletes the pod of a finished Blip and removes the finalizer
// once it is being deleted.
func (r *BlipReconciler) cleanup(ctx context.Context, b *v1.Blip) error {
	var err error
	if b.Status.Pod != "" {
		pod := &corev1.Pod{}
		err = r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.Pod}, pod)
		if err == nil && string(pod.UID) == b.Status.PodUID && pod.DeletionTimestamp == nil {
			err = r.Delete(ctx, pod, client.Preconditions{UID: &pod.UID})
		}
	}
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return err
	}
	if b.DeletionTimestamp != nil && controllerutil.ContainsFinalizer(b, Finalizer) {
		base := b.DeepCopy()
		controllerutil.RemoveFinalizer(b, Finalizer)
		return client.IgnoreNotFound(patchObject(ctx, r.Client, b, base))
	}
	return nil
}

func interactive(b *v1.Blip) bool { return len(b.Spec.Command) == 0 }

func stopping(b *v1.Blip) bool { return b.Spec.Stop || b.DeletionTimestamp != nil }

func wait(b *v1.Blip, reason, msg string) {
	b.Status.Phase = v1.BlipPending
	b.Status.Reason = reason
	b.Status.Message = msg
}

func (r *BlipReconciler) finish(b *v1.Blip, phase, reason, msg string) {
	b.Status.Phase = phase
	b.Status.Reason = reason
	b.Status.Message = msg
	now := metav1.NewTime(r.now())
	b.Status.FinishTime = &now
}

// startDeadline is when the bounded startup of b expires. Pending Blips
// without a pod get pendingTimeout to build images or copies; claimed ones
// get startTimeout to prepare disks. Running Blips get one check at the same
// deadline in case their pod never reports an observation.
func (r *BlipReconciler) startDeadline(b *v1.Blip) (time.Time, bool) {
	switch {
	case b.Status.Phase == v1.BlipRunning && b.Status.StartTime != nil:
		return b.Status.StartTime.Add(startTimeout), true
	case b.Status.Phase == v1.BlipPending && b.Status.Pod != "" && b.Status.StartTime != nil:
		return b.Status.StartTime.Add(startTimeout), true
	case b.Status.Phase == v1.BlipPending && b.Status.Pod == "" && !b.CreationTimestamp.IsZero():
		return b.CreationTimestamp.Add(pendingTimeout), true
	}
	return time.Time{}, false
}

// pending acquires the Blip's states and claims a warm pod.
func (r *BlipReconciler) pending(ctx context.Context, b, base *v1.Blip) (reconcile.Result, error) {
	claimed, err := r.claimedPod(ctx, r.Client, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	if claimed != nil {
		return reconcile.Result{}, r.startRunning(ctx, b, claimed)
	}
	if stopping(b) {
		if err := r.unclaim(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
		phase := v1.BlipFailed
		if interactive(b) {
			phase = v1.BlipSucceeded
		}
		r.finish(b, phase, ReasonStopped, "stopped before start")
		return reconcile.Result{}, nil
	}
	if msg := validateSpec(b); msg != "" {
		if err := r.unclaim(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
		r.finish(b, v1.BlipFailed, ReasonInvalidSpec, msg)
		return reconcile.Result{}, nil
	}
	if since := b.CreationTimestamp.Time; !since.IsZero() && r.now().Sub(since) > pendingTimeout {
		r.finish(b, v1.BlipFailed, ReasonStartTimeout, "timed out waiting for a VM")
		return reconcile.Result{}, nil
	}
	pool := &v1.BlipPool{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: poolName(b)}, pool); err != nil {
		if apierrors.IsNotFound(err) {
			wait(b, ReasonPoolNotFound, fmt.Sprintf("pool %q not found", poolName(b)))
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if b.Spec.Image != "" && b.Status.ImageDigest == "" {
		secrets := slices.Clone(b.Spec.ImagePullSecrets)
		secrets = append(secrets, pool.Spec.ImagePullSecrets...)
		d, err := digestImage(ctx, r.Registry, b.Spec.Image, b.Namespace, secrets)
		if errors.Is(err, ErrImageNotFound) {
			r.finish(b, v1.BlipFailed, ReasonImageNotFound, err.Error())
			return reconcile.Result{}, nil
		}
		if err != nil {
			wait(b, ReasonImageResolve, fmt.Sprintf("resolve image %s: %v", b.Spec.Image, err))
			return reconcile.Result{RequeueAfter: retryAfter}, nil
		}
		b.Status.ImageDigest = d
	}

	states := map[string]*v1.BlipState{}
	all := map[string]*v1.BlipState{}
	names := []string{b.Spec.State}
	for _, m := range b.Spec.Mounts {
		names = append(names, m.State)
	}
	var waitReason, waitMsg string
	for _, n := range names {
		if n == "" {
			continue
		}
		st, reason, msg, err := r.usableState(ctx, b.Namespace, n)
		if err != nil {
			return reconcile.Result{}, err
		}
		if reason == ReasonStateFailed {
			r.finish(b, v1.BlipFailed, reason, msg)
			return reconcile.Result{}, r.unclaim(ctx, b)
		}
		if st != nil {
			all[n] = st
		}
		if reason != "" {
			if waitReason == "" {
				waitReason, waitMsg = reason, msg
			}
			continue
		}
		states[n] = st
	}

	// Record where the data lives even while a copy is still in progress,
	// so the pool can boot a VM there before the Blip is ready to claim it.
	cl, err := loadCluster(ctx, r.Client, r.now())
	if err != nil {
		return reconcile.Result{}, err
	}
	home := homeNodes(placementScores(b, all), cl, poolSelector(pool))
	updateLocality(b, home, waitReason == "")
	if waitReason != "" {
		wait(b, waitReason, waitMsg)
		return reconcile.Result{}, r.unclaim(ctx, b)
	}

	pods, err := r.poolPods(ctx, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	candidates := r.warmPods(b, pool, states, pods, cl)
	if loc := b.Status.Locality; loc != nil && !loc.Fallback {
		local := slices.DeleteFunc(slices.Clone(candidates), func(p corev1.Pod) bool {
			return !slices.Contains(home, p.Spec.NodeName)
		})
		if len(local) > 0 {
			candidates = local
		} else if why, left := r.waitLocally(b, pool, pods, home); why == "" {
			wait(b, ReasonWaitingForVM, fmt.Sprintf("waiting for a VM on node %q, which holds the Blip's data", loc.Node))
			return reconcile.Result{RequeueAfter: left}, r.unclaim(ctx, b)
		} else {
			log.FromContext(ctx).Info("starting away from the Blip's data", "node", loc.Node, "reason", why)
			loc.Fallback = true
		}
	}
	if len(candidates) == 0 {
		wait(b, ReasonWaitingForVM, fmt.Sprintf("waiting for a warm VM in pool %q", poolName(b)))
		return reconcile.Result{}, r.unclaim(ctx, b)
	}

	var writable []string
	if b.Spec.State != "" {
		writable = append(writable, b.Spec.State)
	}
	for _, m := range b.Spec.Mounts {
		if m.Writable {
			writable = append(writable, m.State)
		}
	}
	if err := r.releaseHeld(ctx, b, writable...); err != nil {
		return reconcile.Result{}, err
	}
	ids, blocked, err := r.acquire(ctx, b, states, writable, nil)
	if err != nil {
		return reconcile.Result{}, err
	}
	if blocked != "" {
		wait(b, ReasonStateBusy, blocked)
		return reconcile.Result{}, r.unclaim(ctx, b)
	}

	if b.Spec.State != "" {
		b.Status.RootAttachmentID = ids[b.Spec.State]
	} else if b.Status.RootAttachmentID == "" {
		b.Status.RootAttachmentID = newID()
	}
	var mounts []v1.MountStatus
	for _, m := range b.Spec.Mounts {
		mounts = append(mounts, r.newMount(b, m, states[m.State], ids[m.State]))
	}
	b.Status.Mounts = mounts
	wait(b, ReasonWaitingForVM, "claiming a VM")
	// The node reads the attachments from status once it sees the claim.
	if err := r.flush(ctx, b, base); err != nil {
		return reconcile.Result{}, err
	}

	// A stale cache may not show a claim this Blip already made.
	pod, err := r.claimedPod(ctx, r.Live, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	if pod == nil {
		if pod, err = r.claim(ctx, b, candidates); err != nil {
			return reconcile.Result{}, err
		}
	}
	if pod == nil {
		wait(b, ReasonWaitingForVM, fmt.Sprintf("waiting for a warm VM in pool %q", poolName(b)))
		return reconcile.Result{}, nil
	}
	return reconcile.Result{}, r.startRunning(ctx, b, pod)
}

// unclaim gives up everything a Blip acquired before claiming a pod.
func (r *BlipReconciler) unclaim(ctx context.Context, b *v1.Blip) error {
	if err := r.releaseHeld(ctx, b); err != nil {
		return err
	}
	b.Status.Mounts = nil
	if b.Spec.State != "" {
		b.Status.RootAttachmentID = ""
	}
	return nil
}

// newMount builds the status entry of an acquired mount. Read-only mounts
// pin the committed version; writable ones record their base version.
func (r *BlipReconciler) newMount(b *v1.Blip, m v1.Mount, st *v1.BlipState, writerID string) v1.MountStatus {
	ms := v1.MountStatus{
		State:    m.State,
		Path:     m.Path,
		Writable: m.Writable,
		StateUID: string(st.UID),
		CommitID: st.Status.Committed.ID,
		Phase:    v1.MountPending,
	}
	if m.Writable {
		ms.AttachmentID = writerID
		ms.CommitID = st.Status.Writer.BaseCommit
	} else {
		ms.AttachmentID = newID()
		for _, old := range b.Status.Mounts {
			if old.State == m.State && !old.Writable && old.Phase == v1.MountPending {
				ms.AttachmentID = old.AttachmentID
			}
		}
	}
	return ms
}

// usableState returns the state if a Blip can use it now, or a waiting
// reason.
func (r *BlipReconciler) usableState(ctx context.Context, ns, name string) (*v1.BlipState, string, string, error) {
	st := &v1.BlipState{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, st)
	switch {
	case apierrors.IsNotFound(err):
		return nil, ReasonStateNotFound, fmt.Sprintf("state %q not found", name), nil
	case err != nil:
		return nil, "", "", err
	case st.DeletionTimestamp != nil:
		return nil, ReasonStateNotFound, fmt.Sprintf("state %q is being deleted", name), nil
	case st.Status.Committed == nil && st.Status.Phase == v1.StateFailed:
		return nil, ReasonStateFailed, fmt.Sprintf("state %q failed: %s", name, st.Status.Message), nil
	case st.Status.Committed == nil:
		return st, ReasonStateNotReady, fmt.Sprintf("state %q has no committed version yet", name), nil
	case st.Status.Pending != nil:
		return st, ReasonStateNotReady, fmt.Sprintf("state %q is saving a new version", name), nil
	}
	return st, "", "", nil
}

// preparePromote checks that a read-only mount can become writable and
// acquires the writer before the old mount is torn down.
func (r *BlipReconciler) preparePromote(ctx context.Context, b *v1.Blip, sm v1.Mount, m v1.MountStatus) (string, error) {
	st, reason, msg, err := r.usableState(ctx, b.Namespace, sm.State)
	if err != nil {
		return "", err
	}
	if reason != "" {
		return msg, nil
	}
	if m.CommitID != st.Status.Committed.ID {
		return fmt.Sprintf("state %q has a newer version; unmount and mount it again", sm.State), nil
	}
	if w := st.Status.Writer; w != nil && (w.BlipUID != string(b.UID) || w.BaseCommit != m.CommitID) {
		return fmt.Sprintf("state %q is in use by blip %s", sm.State, w.BlipName), nil
	}
	_, blocked, err := r.acquire(ctx, b, map[string]*v1.BlipState{sm.State: st}, []string{sm.State}, nil)
	if err != nil {
		return "", err
	}
	return blocked, nil
}

// sealResult returns the node's seal report for an attachment.
func (r *BlipReconciler) sealResult(ctx context.Context, ns, state, id string) (v1.SealResult, bool, error) {
	st := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: state}, st); err != nil {
		if apierrors.IsNotFound(err) {
			return v1.SealResult{AttachmentID: id, Error: "state was deleted"}, true, nil
		}
		return v1.SealResult{}, false, err
	}
	for _, sr := range st.Status.Seals {
		if sr.AttachmentID == id {
			return sr, true, nil
		}
	}
	return v1.SealResult{}, false, nil
}

func sealError(sr v1.SealResult) string {
	if sr.Error != "" {
		return sr.Error
	}
	return "save failed without an error"
}

// claimedPod finds a pod this Blip already claimed.
func (r *BlipReconciler) claimedPod(ctx context.Context, c client.Reader, b *v1.Blip) (*corev1.Pod, error) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(b.Namespace), client.MatchingLabels{LabelBlipUID: string(b.UID)}); err != nil {
		return nil, err
	}
	for i := range pods.Items {
		return &pods.Items[i], nil
	}
	return nil, nil
}

// poolPods lists the pods of the Blip's pool.
func (r *BlipReconciler) poolPods(ctx context.Context, b *v1.Blip) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(b.Namespace), client.MatchingLabels{LabelPool: poolName(b)}); err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// warmPods returns the claimable pods among pods, preferring nodes that hold
// the root state, then nodes that hold more writable mount states. Pods the
// pool pinned to another node for other Blips come last.
func (r *BlipReconciler) warmPods(b *v1.Blip, pool *v1.BlipPool, states map[string]*v1.BlipState, pods []corev1.Pod, cl *cluster) []corev1.Pod {
	var out []corev1.Pod
	for _, p := range pods {
		// Never claim a VM on a node that is not a usable BlipNode: missing
		// Kubernetes Node, draining, stale heartbeat, or no incarnation.
		if claimableForPool(&p, pool) && cl.usable(p.Spec.NodeName, nil) {
			out = append(out, p)
		}
	}
	score := placementScores(b, states)
	pinnedAway := func(p *corev1.Pod) bool {
		return p.Annotations[AnnotationPinnedNode] != "" && score[p.Spec.NodeName] == 0
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := score[out[i].Spec.NodeName], score[out[j].Spec.NodeName]
		if si != sj {
			return si > sj
		}
		if ai, aj := pinnedAway(&out[i]), pinnedAway(&out[j]); ai != aj {
			return aj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// claimableForPool excludes stale warm VMs before the pool reconciler has
// deleted them. Claiming one would let it keep its old topology indefinitely.
func claimableForPool(p *corev1.Pod, pool *v1.BlipPool) bool {
	return pool.DeletionTimestamp == nil && p.Namespace == pool.Namespace &&
		p.Labels[LabelPool] == pool.Name && p.Annotations[annotationTemplateHash] == templateHash(pool) &&
		isVacant(p) && ready(p)
}

// claim takes the first candidate that nobody changed since the cache saw
// it and that still matches the live pool template: the resourceVersion
// check makes concurrent claims or pod changes fail.
func (r *BlipReconciler) claim(ctx context.Context, b *v1.Blip, candidates []corev1.Pod) (*corev1.Pod, error) {
	for i := range candidates {
		base := &candidates[i]
		// Selection may have used a stale pool, or the pool may have changed
		// while we acquired states. Recheck on every attempt, including after
		// losing a claim race on an earlier candidate.
		pool := &v1.BlipPool{}
		if err := r.Live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: poolName(b)}, pool); err != nil {
			return nil, client.IgnoreNotFound(err)
		}
		if !claimableForPool(base, pool) {
			continue
		}
		p := base.DeepCopy()
		p.Labels[LabelBlipUID] = string(b.UID)
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[AnnotationBlip] = b.Name
		p.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(b, v1.GroupVersion.WithKind("Blip"))}
		if err := setVMOwner(ctx, r.Client, p, b); err != nil {
			return nil, err
		}
		err := patchObject(ctx, r.Client, p, base)
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			if err := restoreVMOwner(ctx, r.Client, r.Live, p.Namespace, p.Name); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		log.FromContext(ctx).Info("claimed VM pod", "pod", p.Name, "node", p.Spec.NodeName)
		return p, nil
	}
	return nil, nil
}

func (r *BlipReconciler) startRunning(ctx context.Context, b *v1.Blip, pod *corev1.Pod) error {
	b.Status.Pod = pod.Name
	b.Status.PodUID = string(pod.UID)
	b.Status.Node = pod.Spec.NodeName
	if b.Status.StartTime == nil {
		now := metav1.NewTime(r.now())
		b.Status.StartTime = &now
	}
	// Re-read the claimed pod: the node annotates preparation errors after
	// the claim was written, so the cached claim may be stale.
	fresh := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: pod.Name}, fresh); err == nil && string(fresh.UID) == b.Status.PodUID {
		pod = fresh
	}
	if err := r.ensureWriterPods(ctx, b); err != nil {
		return err
	}
	// Running means the guest accepted the claim; until then the node is
	// still preparing disks.
	var obs podapi.Observed
	if raw := pod.Annotations[AnnotationObserved]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &obs)
	}
	started := obs.ClaimID != "" || obs.Exit != nil || obs.Phase == podapi.PhaseExited ||
		pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded ||
		pod.DeletionTimestamp != nil || stopping(b)
	if !started {
		prepareErr := pod.Annotations[AnnotationPrepareError]
		msg := "preparing the root disk on " + pod.Spec.NodeName
		reason := ReasonStarting
		switch {
		case prepareErr != "":
			reason = ReasonPrepareFailed
			msg += ": " + prepareErr
		case obs.Error != "":
			msg += ": " + obs.Error
		}
		if r.now().Sub(b.Status.StartTime.Time) > startTimeout {
			reason = ReasonStartTimeout
			msg = "timed out starting sandbox"
			if prepareErr != "" {
				reason = ReasonPrepareFailed
				msg += ": " + prepareErr
			}
			r.finish(b, v1.BlipFailed, reason, msg)
			return nil
		}
		wait(b, reason, msg)
		return nil
	}
	b.Status.Phase = v1.BlipRunning
	b.Status.Reason = ""
	b.Status.Message = ""
	now := metav1.NewTime(r.now())
	b.Status.StartTime = &now
	return nil
}

// running mirrors the pod's observed state and applies mount changes.
func (r *BlipReconciler) running(ctx context.Context, b *v1.Blip) (reconcile.Result, error) {
	pod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.Pod}, pod)
	if apierrors.IsNotFound(err) || err == nil && string(pod.UID) != b.Status.PodUID {
		pod = nil
	} else if err != nil {
		return reconcile.Result{}, err
	}
	var obs podapi.Observed
	if pod != nil {
		if raw := pod.Annotations[AnnotationObserved]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &obs)
		}
	}
	if pod != nil && pod.Annotations[AnnotationObserved] == "" && b.Status.StartTime != nil &&
		!stopping(b) && r.now().Sub(b.Status.StartTime.Time) > startTimeout {
		r.finish(b, v1.BlipFailed, ReasonStartTimeout, "timed out starting sandbox: the VM never reported its state")
		return reconcile.Result{}, nil
	}
	if err := r.ensureWriterPods(ctx, b); err != nil {
		return reconcile.Result{}, err
	}
	b.Status.Sessions = int32(obs.Sessions)
	b.Status.Message = obs.Error
	if obs.Exit != nil {
		if obs.Exit.Reason != ReasonStopped {
			code := int32(obs.Exit.Code)
			b.Status.ExitCode = &code
		}
		b.Status.Reason = obs.Exit.Reason
		if b.Status.Reason == "" || b.Status.Reason == ReasonCompleted {
			b.Status.Reason = ReasonCompleted
			if obs.Exit.Code != 0 || obs.Exit.Signal != "" {
				b.Status.Reason = ReasonError
			}
		}
		if out := strings.TrimSpace(obs.Exit.Output); out != "" && b.Status.Message == "" {
			b.Status.Message = out
		}
	}

	fenced, after := r.fenced(b, pod, &obs)
	if !fenced {
		if err := r.syncMounts(ctx, b, pod, &obs); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{RequeueAfter: after}, nil
	}
	// Every disk is closed: active mounts are detached.
	var mounts []v1.MountStatus
	for _, m := range b.Status.Mounts {
		switch {
		case m.Writable && m.Phase != v1.MountFailed:
			m.Phase = v1.MountSaving
			mounts = append(mounts, m)
		case m.Writable || m.Phase == v1.MountFailed:
			mounts = append(mounts, m)
		}
	}
	b.Status.Mounts = mounts
	b.Status.Sessions = 0
	b.Status.Phase = v1.BlipSaving
	return reconcile.Result{}, nil
}

// fenced reports whether the VM can no longer write its disks, setting the
// exit reason when the runtime did not report one.
func (r *BlipReconciler) fenced(b *v1.Blip, pod *corev1.Pod, obs *podapi.Observed) (bool, time.Duration) {
	setReason := func(reason, msg string) {
		if b.Status.ExitCode == nil && b.Status.Reason != ReasonStopped {
			b.Status.Reason = reason
			if msg != "" {
				b.Status.Message = msg
			}
		}
	}
	switch {
	case pod == nil:
		setReason(ReasonPodLost, "the VM pod disappeared")
		return true, 0
	case obs.Phase == podapi.PhaseExited:
		if stopping(b) {
			setReason(ReasonStopped, "")
		} else {
			setReason(ReasonRuntimeFailed, "the VM exited without an exit status")
		}
		return true, 0
	case pod.Status.Phase == corev1.PodFailed:
		setReason(ReasonRuntimeFailed, "the VM runtime failed: "+terminationMessage(pod))
		return true, 0
	case pod.Status.Phase == corev1.PodSucceeded:
		// The runtime reports Exited before it exits; give the node time
		// to mirror it.
		if left := exitAnnotationGrace - r.now().Sub(finishedAt(pod)); left > 0 {
			return false, left
		}
		setReason(ReasonPodLost, "the VM exited without an exit status")
		return true, 0
	}
	return false, 0
}

func terminationMessage(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if t := cs.State.Terminated; t != nil {
			return fmt.Sprintf("exit code %d %s %s", t.ExitCode, t.Reason, t.Message)
		}
	}
	return p.Status.Message
}

func finishedAt(p *corev1.Pod) time.Time {
	for _, cs := range p.Status.ContainerStatuses {
		if t := cs.State.Terminated; t != nil {
			return t.FinishedAt.Time
		}
	}
	return time.Time{}
}

// saving waits until the root state and every writable mount resolved
// their attachments, then finishes the Blip.
func (r *BlipReconciler) saving(ctx context.Context, b *v1.Blip) error {
	outstanding := false
	var saveErr string
	if b.Spec.State != "" && b.Status.RootAttachmentID != "" {
		done, msg, err := r.attachment(ctx, b.Namespace, b.Spec.State, b.Status.RootAttachmentID)
		if err != nil {
			return err
		}
		outstanding = !done
		if msg != "" {
			saveErr = fmt.Sprintf("save of state %s failed: %s", b.Spec.State, msg)
		}
	}
	var mounts []v1.MountStatus
	for _, m := range b.Status.Mounts {
		if m.Writable {
			done, msg, err := r.attachment(ctx, b.Namespace, m.State, m.AttachmentID)
			if err != nil {
				return err
			}
			switch {
			case !done:
				outstanding = true
			case msg != "":
				m.Phase, m.Message = v1.MountFailed, "save failed: "+msg
				if saveErr == "" {
					saveErr = fmt.Sprintf("save of state %s failed: %s", m.State, msg)
				}
			case m.Phase == v1.MountSaving:
				continue
			}
		}
		mounts = append(mounts, m)
	}
	b.Status.Mounts = mounts
	if saveErr != "" {
		if b.Status.Message != "" {
			saveErr += "\n" + b.Status.Message
		}
		r.finish(b, v1.BlipFailed, ReasonSaveFailed, saveErr)
		return nil
	}
	if outstanding {
		return nil
	}
	code := b.Status.ExitCode
	if code != nil && *code == 0 || b.Status.Reason == ReasonStopped {
		r.finish(b, v1.BlipSucceeded, b.Status.Reason, b.Status.Message)
		return nil
	}
	msg := b.Status.Message
	if code != nil && msg == "" {
		msg = fmt.Sprintf("exit code %d", *code)
	}
	r.finish(b, v1.BlipFailed, b.Status.Reason, msg)
	return nil
}

// attachment reports whether a writable attachment of state is resolved,
// and its seal error if saving failed.
func (r *BlipReconciler) attachment(ctx context.Context, ns, state, id string) (bool, string, error) {
	st := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: state}, st); err != nil {
		if apierrors.IsNotFound(err) {
			return true, "state was deleted", nil
		}
		return false, "", err
	}
	s := st.Status
	if s.Writer != nil && s.Writer.AttachmentID == id || s.Pending != nil && s.Pending.AttachmentID == id {
		return false, "", nil
	}
	for _, sr := range s.Seals {
		if sr.AttachmentID != id {
			continue
		}
		if sr.CommitID == "" {
			if sr.Error == "" {
				return true, "save failed without an error", nil
			}
			return true, sr.Error, nil
		}
		return true, "", nil
	}
	// The attachment is no longer in progress and no seal result exists.
	// Never report success: the save outcome is unknown.
	return true, fmt.Sprintf("no seal result for attachment %s", id), nil
}
