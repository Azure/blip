package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
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
	ReasonNetworkFailed = "NetworkFailed"
	ReasonSaveFailed    = "SaveFailed"
)

// exitAnnotationGrace lets a pod that reported Succeeded still publish its
// final observation before the controller treats the exit as pod loss.
const exitAnnotationGrace = 30 * time.Second

// reasonStateDeleting is an internal state condition: usableState returns it
// when a referenced state is terminating. Unlike a plain missing state (which
// may be created again), a deleting state can never become usable. A Blip must
// finish instead of waiting for it, or the state finalizer would wait for that
// Blip forever.
const reasonStateDeleting = "StateDeleting"

const (
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
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.stateBlips)).
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
		if name := p.Annotations[v1.AnnotationBlip]; name != "" {
			return []reconcile.Request{req(p.Namespace, name)}
		}
		return nil
	}
	// A pinned pod the scheduler cannot place ends the local wait of the
	// Blips it was booted for.
	if !ready(p) && !(p.Annotations[v1.AnnotationPinnedNode] != "" && unschedulable(p)) {
		return nil
	}
	return r.blipsBy(ctx, p.Namespace, indexPool, p.Labels[v1.LabelPool], true)
}

func (r *BlipReconciler) blipsBy(ctx context.Context, ns, field, value string, waiting bool) []reconcile.Request {
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(ns), client.MatchingFields{field: value}); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, b := range blips.Items {
		if !waiting || b.Status.Pod == "" && !v1.Finished(&b) {
			out = append(out, req(b.Namespace, b.Name))
		}
	}
	return out
}

// A child can become usable before its root's Blip publishes any attachment.
// Follow exactly one profile edge: auxiliary states do not expand recursively.
func (r *BlipReconciler) stateBlips(ctx context.Context, o client.Object) []reconcile.Request {
	out := r.blipsBy(ctx, o.GetNamespace(), indexStates, o.GetName(), false)
	var roots v1.BlipStateList
	if err := r.List(ctx, &roots, client.InNamespace(o.GetNamespace()), client.MatchingFields{indexMounts: o.GetName()}); err != nil {
		return out
	}
	for _, root := range roots.Items {
		for _, rq := range r.blipsBy(ctx, root.Namespace, indexStates, root.Name, false) {
			// indexStates also includes status mounts. Only root users inherit
			// this profile's desired mounts.
			b := &v1.Blip{}
			if r.Get(ctx, rq.NamespacedName, b) == nil && b.Spec.State == root.Name && !slices.Contains(out, rq) {
				out = append(out, rq)
			}
		}
	}
	return out
}

func (r *BlipReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	b := &v1.Blip{}
	if err := r.Get(ctx, rq.NamespacedName, b); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if err := r.releaseUnpublished(ctx, b); err != nil {
		return reconcile.Result{}, err
	}
	if v1.Finished(b) {
		return r.finished(ctx, b)
	}
	if b.DeletionTimestamp == nil && !controllerutil.ContainsFinalizer(b, v1.Finalizer) {
		base := b.DeepCopy()
		controllerutil.AddFinalizer(b, v1.Finalizer)
		if err := patchObject(ctx, r.Client, b, base); err != nil {
			return reconcile.Result{}, err
		}
	}
	if r.deadlineExceeded(b) {
		if err := r.stopForDeadline(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
		// Re-enter so the normal stop path stops the VM and finishes.
		return r.Reconcile(ctx, rq)
	}

	base := b.DeepCopy()
	var result reconcile.Result
	var err error
	switch b.Status.Phase {
	case "", v1.BlipPending:
		result, err = r.pending(ctx, b, base)
	case v1.BlipRunning:
		result, err = r.running(ctx, b, base)
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
	if v1.Finished(b) {
		// This reconcile finished the Blip. TTL deletion starts on the next
		// reconcile, which the status update triggers, so a TTL of 0 still
		// leaves the result readable once.
		return reconcile.Result{}, r.cleanup(ctx, b)
	}
	return result, nil
}

// finished cleans up a finished Blip and deletes it once its TTL elapses.
func (r *BlipReconciler) finished(ctx context.Context, b *v1.Blip) (reconcile.Result, error) {
	if err := r.cleanup(ctx, b); err != nil {
		return reconcile.Result{}, err
	}
	// cleanup removed the finalizer of a Blip that is already being deleted.
	if b.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	deadline, ok := r.ttlDeadline(b)
	if !ok {
		return reconcile.Result{}, nil
	}
	if left := deadline.Sub(r.now()); left > 0 {
		return reconcile.Result{RequeueAfter: left}, nil
	}
	if err := r.Delete(ctx, b); err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// ttlDeadline is when spec.ttlSecondsAfterFinished deletes a finished Blip.
// A TTL of 0 is already due.
func (r *BlipReconciler) ttlDeadline(b *v1.Blip) (time.Time, bool) {
	if b.Spec.TTLSecondsAfterFinished == nil || b.Status.FinishTime == nil {
		return time.Time{}, false
	}
	return b.Status.FinishTime.Add(time.Duration(*b.Spec.TTLSecondsAfterFinished) * time.Second), true
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

// podOutput reads the serial console of a VM pod and returns the tail of the
// lines the guest mirrored from the command, without boot noise. It is best
// effort: a missing log or a read error simply leaves the output empty.
func (r *BlipReconciler) podOutput(ctx context.Context, namespace, pod string) (string, bool) {
	if r.Config.PodLogs == nil {
		return "", false
	}
	rc, err := r.Config.PodLogs(ctx, namespace, pod)
	if err != nil {
		return "", false
	}
	defer rc.Close()
	var lines []string
	total := 0
	truncated := false
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "blip: ")
		if !ok {
			continue
		}
		lines = append(lines, line)
		total += len(line) + 1
		for total > maxRetainedOutput && len(lines) > 1 {
			total -= len(lines[0]) + 1
			lines = lines[1:]
			truncated = true
		}
	}
	if len(lines) == 0 {
		return "", false
	}
	return retainTail(lines, truncated), true
}

// retainTail joins the newest whole lines that fit in maxRetainedOutput. When
// earlier lines were removed it reserves room for outputTruncated and prefixes
// it, so a consumer can tell the head is missing. Only a line longer than the
// bound is split.
func retainTail(lines []string, truncated bool) string {
	limit := maxRetainedOutput
	if truncated {
		limit -= len(outputTruncated)
	}
	total := 0
	for _, line := range lines {
		total += len(line) + 1
	}
	start := 0
	// Always keep the newest line, even when it alone exceeds the bound; the
	// byte-level cut below preserves its tail rather than losing all output.
	for total > limit && len(lines)-start > 1 {
		total -= len(lines[start]) + 1
		start++
	}
	out := strings.Join(lines[start:], "\n")
	if len(out) > 0 {
		out += "\n"
	}
	if truncated {
		out = outputTruncated + out
	}
	if len(out) > maxRetainedOutput {
		// A single line exceeded the bound; keep its most recent bytes and
		// start at a line boundary when one is left.
		cut := len(out) - (maxRetainedOutput - len(outputTruncated))
		// Start at the next line boundary when that leaves output behind;
		// an overlong line's final newline must not discard its whole tail.
		if i := strings.IndexByte(out[cut:], '\n'); i >= 0 && i+1 < len(out)-cut {
			cut += i + 1
		}
		out = outputTruncated + out[cut:]
	}
	return out
}

// maxRetainedOutput bounds the command output copied from the serial console
// into Blip status. The full output is in the pod log until it is deleted;
// this tail is what survives.
const maxRetainedOutput = 64 << 10

const outputTruncated = "[earlier output was truncated]\n"

// cleanup preserves the tail of a finished command, deletes its pod, and
// removes the finalizer once the Blip is being deleted.
func (r *BlipReconciler) cleanup(ctx context.Context, b *v1.Blip) error {
	var err error
	if b.Status.Pod != "" {
		pod := &corev1.Pod{}
		err = r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.Pod}, pod)
		if err == nil && string(pod.UID) == b.Status.PodUID && pod.DeletionTimestamp == nil {
			if out, ok := r.podOutput(ctx, b.Namespace, pod.Name); ok && b.Status.Output == "" {
				base := b.DeepCopy()
				b.Status.Output = out
				if err = patchStatus(ctx, r.Client, b, base); err != nil {
					return err
				}
			}
			err = r.Delete(ctx, pod, client.Preconditions{UID: &pod.UID})
		}
	}
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return err
	}
	if b.DeletionTimestamp != nil && controllerutil.ContainsFinalizer(b, v1.Finalizer) {
		base := b.DeepCopy()
		controllerutil.RemoveFinalizer(b, v1.Finalizer)
		return client.IgnoreNotFound(patchObject(ctx, r.Client, b, base))
	}
	return nil
}

func stopping(b *v1.Blip) bool { return b.Spec.Stop || b.DeletionTimestamp != nil }

// deletedByOwner reports whether st is being deleted while an owner other
// than b is responsible. Owner references created by the CLI do not set the
// controller flag, so every owner UID matters rather than only the controller
// reference. Deleting a workspace through its owner removes the data, so a
// borrowed writer cannot preserve a save into it.
func deletedByOwner(st *v1.BlipState, b *v1.Blip) bool {
	if len(st.OwnerReferences) == 0 {
		return false
	}
	for _, owner := range st.OwnerReferences {
		if owner.UID == b.UID {
			return false
		}
	}
	return true
}

// deletingState returns the state while it is being deleted and b is not.
// Any deletion of a workspace removes the data its writer would save, whether
// it comes from an owner (a Blip or its TTL) or from a direct delete of a
// durable, borrowed, or writable-mount state. When b itself is being deleted
// its save is handled by the normal deletion path, not reported as discarded.
func (r *BlipReconciler) deletingState(ctx context.Context, b *v1.Blip, name string) (*v1.BlipState, error) {
	if b.DeletionTimestamp != nil {
		return nil, nil
	}
	st := &v1.BlipState{}
	switch err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: name}, st); {
	case apierrors.IsNotFound(err):
		// A missing state is already reported as a failed save by attachment.
		return nil, nil
	case err != nil:
		return nil, err
	case st.DeletionTimestamp != nil:
		return st, nil
	}
	return nil, nil
}

// discardedSave explains a save that a state deletion throws away.
func discardedSave(st *v1.BlipState, b *v1.Blip) string {
	if deletedByOwner(st, b) {
		return fmt.Sprintf("state %q was deleted by its owner while in use; the save was discarded", st.Name)
	}
	return fmt.Sprintf("state %q was deleted while in use; the save was discarded", st.Name)
}

// deletingMount returns the first desired writable mount whose state is being
// deleted while b is not. Its disk is about to be removed while this Blip
// writes to it.
func (r *BlipReconciler) deletingMount(ctx context.Context, b *v1.Blip, mounts []v1.Mount) (*v1.BlipState, error) {
	seen := map[string]bool{}
	for _, m := range mounts {
		if !m.Writable || seen[m.State] {
			continue
		}
		seen[m.State] = true
		st, err := r.deletingState(ctx, b, m.State)
		if err != nil || st != nil {
			return st, err
		}
	}
	return nil, nil
}

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

// deadlineTime returns start plus seconds, saturating seconds at the largest
// value whose nanosecond duration fits in an int64. The CRD rejects larger
// values, but an object stored before that bound existed must not wrap the
// duration negative and stop the Blip immediately.
func deadlineTime(start time.Time, seconds int64) time.Time {
	const maxSeconds = int64(math.MaxInt64 / int64(time.Second))
	if seconds > maxSeconds {
		seconds = maxSeconds
	}
	return start.Add(time.Duration(seconds) * time.Second)
}

// deadlineExceeded reports whether a started, unfinished Blip has outlived
// spec.activeDeadlineSeconds. A Blip that is already stopping is left to that
// stop so the deadline cannot restart it, and Saving means the command already
// stopped.
func (r *BlipReconciler) deadlineExceeded(b *v1.Blip) bool {
	if v1.Finished(b) || stopping(b) || b.Status.Phase == v1.BlipSaving ||
		b.Spec.ActiveDeadlineSeconds == nil || b.Status.StartTime == nil {
		return false
	}
	return !r.now().Before(deadlineTime(b.Status.StartTime.Time, *b.Spec.ActiveDeadlineSeconds))
}

// stopForDeadline sets spec.stop as an expired deadline would. A conflict is
// retried against the latest object, so a concurrent spec edit is not lost.
func (r *BlipReconciler) stopForDeadline(ctx context.Context, b *v1.Blip) error {
	return r.stop(ctx, b, "DeadlineExceeded")
}

// stop sets spec.stop and records why, retrying against a concurrent edit.
// The stop reason is only recorded once, so a later cause does not overwrite
// the first.
func (r *BlipReconciler) stop(ctx context.Context, b *v1.Blip, reason string) error {
	key := client.ObjectKeyFromObject(b)
	for attempt := 0; ; attempt++ {
		base := b.DeepCopy()
		b.Spec.Stop = true
		if b.Annotations[v1.AnnotationStopReason] == "" {
			if b.Annotations == nil {
				b.Annotations = map[string]string{}
			}
			b.Annotations[v1.AnnotationStopReason] = reason
		}
		err := patchObject(ctx, r.Client, b, base)
		if err == nil || !apierrors.IsConflict(err) || attempt >= 4 {
			return err
		}
		if err := r.Get(ctx, key, b); err != nil {
			return client.IgnoreNotFound(err)
		}
	}
}

// startDeadline is the earliest bound on a Blip's current phase. Pending Blips
// without a pod get pendingTimeout to build images or copies; claimed ones get
// startTimeout to prepare disks. Running Blips get one check at the same
// deadline in case their pod never reports an observation. An active deadline
// is a second bound on the start time and is also requeued here so it fires
// without another event.
func (r *BlipReconciler) startDeadline(b *v1.Blip) (time.Time, bool) {
	var deadline time.Time
	add := func(t time.Time) {
		if deadline.IsZero() || t.Before(deadline) {
			deadline = t
		}
	}
	switch {
	case b.Status.Phase == v1.BlipRunning && b.Status.StartTime != nil:
		add(b.Status.StartTime.Add(startTimeout))
	case b.Status.Phase == v1.BlipPending && b.Status.Pod != "" && b.Status.StartTime != nil:
		add(b.Status.StartTime.Add(startTimeout))
	case b.Status.Phase == v1.BlipPending && b.Status.Pod == "" && !b.CreationTimestamp.IsZero():
		add(b.CreationTimestamp.Add(pendingTimeout))
	}
	if !v1.Finished(b) && b.Spec.ActiveDeadlineSeconds != nil && b.Status.StartTime != nil {
		add(deadlineTime(b.Status.StartTime.Time, *b.Spec.ActiveDeadlineSeconds))
	}
	return deadline, !deadline.IsZero()
}

// pending acquires the Blip's states and claims a warm pod.
func (r *BlipReconciler) pending(ctx context.Context, b, base *v1.Blip) (reconcile.Result, error) {
	claimed, err := claimedPod(ctx, r.Client, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	if claimed != nil && lostClaim(claimed) {
		// A graceful pod deletion leaves the object Terminating for its
		// grace period. The guest never accepted the claim, so this is the
		// same lost claim as a pod that vanished: forget it and use the rest
		// of this pass to claim a replacement.
		claimed = nil
	}
	if claimed == nil {
		if err := r.forgetLostClaim(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
	}
	if claimed != nil {
		return reconcile.Result{}, r.startRunning(ctx, b, claimed)
	}
	finish := func(phase, reason, msg string) (reconcile.Result, error) {
		if err := r.unclaim(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
		r.finish(b, phase, reason, msg)
		return reconcile.Result{}, nil
	}
	fail := func(reason, msg string) (reconcile.Result, error) {
		if reason == reasonStateDeleting {
			reason = ReasonStateNotFound
		}
		return finish(v1.BlipFailed, reason, msg)
	}
	if stopping(b) {
		return finish(v1.BlipFailed, ReasonStopped, "stopped before start")
	}
	if b.Spec.State == "" {
		return fail(ReasonInvalidSpec, "state is required")
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
	root, mounts, reason, msg, err := r.rootIntent(ctx, b)
	if err != nil {
		return reconcile.Result{}, err
	}
	if rootReplaced(b, root) {
		// The workspace this Blip saw was deleted and a different state now
		// exists under the same name. It is not the Blip's data, so fail
		// instead of claiming a VM and committing into a substituted volume.
		res, err := fail(ReasonStateNotFound, rootReplacedMessage(b.Spec.State, b.Status.RootStateUID, string(root.UID)))
		res.RequeueAfter = retryAfter
		return res, err
	}
	if root != nil && b.Status.RootStateUID == "" {
		// Remember that the workspace existed. A later NotFound is then a
		// deletion, not the launch window before the CLI creates it.
		b.Status.RootStateUID = string(root.UID)
	}
	if reason != "" {
		gone := reason == ReasonStateNotFound && b.Status.RootStateUID != ""
		if gone {
			// The root was seen and is now gone. Nothing recreates a
			// Blip's workspace, so the pending timeout would only delay
			// a failure that is already certain.
			msg = fmt.Sprintf("state %q was deleted while the Blip was pending", b.Spec.State)
		}
		if reason == ReasonInvalidSpec || reason == reasonStateDeleting || gone {
			res, err := fail(reason, msg)
			res.RequeueAfter = retryAfter
			return res, err
		}
		if err := r.unclaim(ctx, b); err != nil {
			return reconcile.Result{}, err
		}
		wait(b, reason, msg)
		return reconcile.Result{RequeueAfter: retryAfter}, nil
	}

	states := map[string]*v1.BlipState{}
	all := map[string]*v1.BlipState{}
	names := []string{b.Spec.State}
	for _, m := range mounts {
		names = append(names, m.State)
	}
	var waitReason, waitMsg string
	for i, n := range names {
		if n == "" {
			continue
		}
		st, reason, msg, err := r.usableState(ctx, b.Namespace, n)
		if err != nil {
			return reconcile.Result{}, err
		}
		if i == 0 && rootReplaced(b, st) {
			// The root was deleted and recreated between the two reads.
			return fail(ReasonStateNotFound, rootReplacedMessage(b.Spec.State, b.Status.RootStateUID, string(st.UID)))
		}
		if reason == ReasonStateFailed {
			return fail(reason, msg)
		}
		if reason == reasonStateDeleting {
			// A terminating state can never become usable. Finish so the
			// state finalizer does not wait for a Blip that can never
			// release it. unclaim releases any writer this Blip took
			// before it was queued (there is no pod yet: claimedPod was
			// checked above).
			return fail(reason, msg)
		}
		if i > 0 && reason == ReasonStateNotFound {
			// The root exists, so this is not the launch window: the CLI
			// creates a Blip before workspace.Fork creates its workspace,
			// but Fork creates mount copies before the root and mount --new
			// commits the state before adding it to the root. A mount state
			// named by an existing root that is fully gone was deleted and
			// cannot be recreated for this Blip. Waiting would only delay
			// the certain failure until the pending timeout.
			return fail(reason, fmt.Sprintf("mount state %q was deleted while the Blip was pending", n))
		}
		if st != nil {
			all[n] = st
			writable := i == 0 || mounts[i-1].Writable
			if msg := mountStateError(b, st, writable); msg != "" {
				return fail(ReasonInvalidSpec, msg)
			}
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
	if loc := b.Status.Locality; loc != nil {
		local := slices.DeleteFunc(slices.Clone(candidates), func(p corev1.Pod) bool {
			return !slices.Contains(home, p.Spec.NodeName)
		})
		switch {
		case len(local) > 0:
			if loc.Fallback {
				// Capacity is available at the data node again. Return to
				// the pinned placement instead of keeping a fallback that a
				// transient maxCount caused for the rest of the Blip's life.
				loc.Fallback = false
				loc.Node = podNode(&local[0])
				loc.Since = nil
			}
			candidates = local
		case loc.Fallback:
			// No local VM is claimable yet. Keep the fallback eligible for
			// any VM while the pool still treats the data node as demand.
		default:
			if why, left := r.waitLocally(b, pool, pods, home); why == "" {
				wait(b, ReasonWaitingForVM, fmt.Sprintf("waiting for a VM on node %q, which holds the Blip's data", loc.Node))
				return reconcile.Result{RequeueAfter: left}, r.unclaim(ctx, b)
			} else {
				log.FromContext(ctx).Info("starting away from the Blip's data", "node", loc.Node, "reason", why)
				loc.Fallback = true
			}
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
	for _, m := range mounts {
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

	b.Status.RootAttachmentID = ids[b.Spec.State]
	var attached []v1.MountStatus
	for _, m := range mounts {
		attached = append(attached, r.newMount(b, m, states[m.State], ids[m.State]))
	}
	b.Status.Mounts = attached
	wait(b, ReasonWaitingForVM, "claiming a VM")
	// The node reads the attachments from status once it sees the claim.
	if err := r.flush(ctx, b, base); err != nil {
		return reconcile.Result{}, err
	}

	// A stale cache may not show a claim this Blip already made.
	pod, err := claimedPod(ctx, r.Live, b)
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

// rootReplaced reports whether the live root state is a different object than
// the one this Blip saw when it became Pending. A state created under the same
// name after the original was deleted is a different workspace.
func rootReplaced(b *v1.Blip, root *v1.BlipState) bool {
	return root != nil && b.Status.RootStateUID != "" && b.Status.RootStateUID != string(root.UID)
}

func rootReplacedMessage(name, want, got string) string {
	return fmt.Sprintf("state %q was replaced while the Blip was pending (was %s, now %s); refusing to use the substituted workspace", name, want, got)
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
		ms.AttachmentID = r.newID()
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
		return nil, reasonStateDeleting, fmt.Sprintf("state %q is being deleted", name), nil
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
	if msg := mountStateError(b, st, true); msg != "" {
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
func claimedPod(ctx context.Context, c client.Reader, b *v1.Blip) (*corev1.Pod, error) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(b.Namespace), client.MatchingLabels{v1.LabelBlipUID: string(b.UID)}); err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, nil
	}
	return &pods.Items[0], nil
}

// forgetLostClaim clears the status of a claimed pod that disappeared before
// its guest started. A forced pod deletion can leave no claim and no pod that
// the Blip can talk to, so without this the Blip keeps reporting a dead pod
// and charges the waiting time against a replacement VM's start deadline. The
// cache may be stale around a claim, so the live reader decides whether the pod
// is really gone.
func (r *BlipReconciler) forgetLostClaim(ctx context.Context, b *v1.Blip) error {
	if b.Status.Pod == "" {
		return nil
	}
	pod := &corev1.Pod{}
	err := r.Live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.Pod}, pod)
	switch {
	case err == nil && string(pod.UID) == b.Status.PodUID && !lostClaim(pod):
		// Still a live claim; keep its pod and start time.
		return nil
	case err != nil && !apierrors.IsNotFound(err):
		return err
	}
	b.Status.Pod = ""
	b.Status.PodUID = ""
	b.Status.Node = ""
	b.Status.StartTime = nil
	return nil
}

// claimAccepted reports whether the guest accepted the claim or already
// produced an exit. Merely being scheduled, prepared, or deleted is not a
// start: only the node's observation proves that the guest has the disks.
func claimAccepted(pod *corev1.Pod) bool {
	obs := observed(pod)
	return obs.ClaimID != "" || obs.Exit != nil || obs.Phase == podapi.PhaseExited ||
		pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded
}

// lostClaim reports whether a claimed pod is terminating before its guest
// accepted the claim. A graceful delete keeps the pod listed with a
// DeletionTimestamp for the termination grace period, but that claim can never
// start this Blip and must not be mistaken for a running guest.
func lostClaim(pod *corev1.Pod) bool {
	return pod.DeletionTimestamp != nil && !claimAccepted(pod)
}

// observed decodes the node's observation annotation, if present.
func observed(pod *corev1.Pod) podapi.Observed {
	var obs podapi.Observed
	if raw := pod.Annotations[v1.AnnotationObserved]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &obs)
	}
	return obs
}

// poolPods lists the pods of the Blip's pool.
func (r *BlipReconciler) poolPods(ctx context.Context, b *v1.Blip) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(b.Namespace), client.MatchingLabels{v1.LabelPool: poolName(b)}); err != nil {
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
		if claimableForPool(&p, pool, r.RuntimeImage) && cl.usable(p.Spec.NodeName, nil) {
			out = append(out, p)
		}
	}
	score := placementScores(b, states)
	pinnedAway := func(p *corev1.Pod) bool {
		return p.Annotations[v1.AnnotationPinnedNode] != "" && score[p.Spec.NodeName] == 0
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
// deleted them. Claiming one would let it keep its old topology or guest
// image indefinitely.
func claimableForPool(p *corev1.Pod, pool *v1.BlipPool, runtimeImage string) bool {
	return pool.DeletionTimestamp == nil && p.Namespace == pool.Namespace &&
		p.Labels[v1.LabelPool] == pool.Name && p.Annotations[v1.AnnotationTemplateHash] == templateHash(pool, runtimeImage) &&
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
		if !claimableForPool(base, pool, r.RuntimeImage) {
			continue
		}
		p := base.DeepCopy()
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		p.Labels[v1.LabelBlipUID] = string(b.UID)
		if owner := blipOwner(b); owner != "" {
			p.Labels[v1.LabelOwner] = owner
		} else {
			delete(p.Labels, v1.LabelOwner)
		}
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[v1.AnnotationBlip] = b.Name
		p.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(b, v1.GroupVersion.WithKind("Blip"))}
		if err := setVMOwner(ctx, r.Client, p, b); err != nil {
			return nil, err
		}
		// The claim patch is atomic: a lost race leaves the live pod, including
		// its owner label, unchanged. Only the admission table needs restoring.
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

// syncPodOwner keeps a claimed pod's owner label equal to its Blip's. The
// label is written at claim time, but an owner added or changed afterwards
// must propagate: the api-proxy authorizes pod reads by the pod label, so a
// stale label hides the guest's own pod (or leaves it visible to the previous
// owner).
func (r *BlipReconciler) syncPodOwner(ctx context.Context, b *v1.Blip, pod *corev1.Pod) error {
	owner := blipOwner(b)
	if pod.Labels[v1.LabelOwner] == owner {
		return nil
	}
	base := pod.DeepCopy()
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	if owner == "" {
		delete(pod.Labels, v1.LabelOwner)
	} else {
		pod.Labels[v1.LabelOwner] = owner
	}
	return client.IgnoreNotFound(patchObject(ctx, r.Client, pod, base))
}

func (r *BlipReconciler) startRunning(ctx context.Context, b *v1.Blip, pod *corev1.Pod) error {
	// A different pod is a fresh claim: it gets its own start window instead of
	// inheriting the time already spent on a pod that is gone.
	reclaimed := b.Status.Pod != pod.Name || b.Status.PodUID != string(pod.UID)
	b.Status.Pod = pod.Name
	b.Status.PodUID = string(pod.UID)
	b.Status.Node = pod.Spec.NodeName
	if reclaimed || b.Status.StartTime == nil {
		now := metav1.NewTime(r.now())
		b.Status.StartTime = &now
	}
	// Re-read the claimed pod: the node annotates preparation errors after
	// the claim was written, so the cached claim may be stale.
	fresh := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: pod.Name}, fresh); err == nil && string(fresh.UID) == b.Status.PodUID {
		pod = fresh
	}
	if err := r.syncPodOwner(ctx, b, pod); err != nil {
		return err
	}
	if err := r.ensureWriterPods(ctx, b); err != nil {
		return err
	}
	// Running means the guest accepted the claim; until then the node is
	// still preparing disks. A pod that is only Terminating was filtered out
	// by pending unless the guest already accepted it.
	obs := observed(pod)
	started := claimAccepted(pod) || stopping(b)
	if !started {
		prepareErr := pod.Annotations[v1.AnnotationPrepareError]
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
			msg = "timed out starting the VM"
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
	// A mount in status when the guest accepts the claim had to be attached
	// first, so its disk holds data even if the last observation did not
	// include it. Mounts added later to the running Blip are not in the claim
	// and may never attach.
	if obs.ClaimID != "" {
		for i := range b.Status.Mounts {
			if b.Status.Mounts[i].Writable {
				b.Status.Mounts[i].InClaim = true
			}
		}
	}
	b.Status.Phase = v1.BlipRunning
	b.Status.Reason = ""
	b.Status.Message = ""
	now := metav1.NewTime(r.now())
	b.Status.StartTime = &now
	return nil
}

// running mirrors the pod's observed state and applies mount changes.
func (r *BlipReconciler) running(ctx context.Context, b *v1.Blip, base *v1.Blip) (reconcile.Result, error) {
	pod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.Pod}, pod)
	if apierrors.IsNotFound(err) || err == nil && string(pod.UID) != b.Status.PodUID {
		pod = nil
	} else if err != nil {
		return reconcile.Result{}, err
	}
	if pod != nil {
		if err := r.syncPodOwner(ctx, b, pod); err != nil {
			return reconcile.Result{}, err
		}
	}
	var obs podapi.Observed
	if pod != nil {
		obs = observed(pod)
	}
	if pod != nil && pod.Annotations[v1.AnnotationObserved] == "" && b.Status.StartTime != nil &&
		r.now().Sub(b.Status.StartTime.Time) > startTimeout {
		// A VM that never reported an observation has no state to save, so
		// stopping or deleting it must not wait for one either.
		r.finish(b, v1.BlipFailed, ReasonStartTimeout, "timed out starting the VM: the VM never reported its state")
		return reconcile.Result{}, nil
	}
	if err := r.ensureWriterPods(ctx, b); err != nil {
		return reconcile.Result{}, err
	}
	b.Status.Sessions = int32(obs.Sessions)
	b.Status.Message = obs.Error
	if obs.Report != nil && (b.Status.Report == nil || int64(obs.Report.Seq) > b.Status.Report.Seq) {
		t := metav1.NewTime(obs.Report.Time)
		b.Status.Report = &v1.BlipReport{Seq: int64(obs.Report.Seq), Text: obs.Report.Text, Time: &t}
	}
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
		if !stopping(b) {
			root, mounts, reason, msg, err := r.rootIntent(ctx, b)
			if err != nil {
				return reconcile.Result{}, err
			}
			if reason != "" {
				if reason == reasonStateDeleting && b.DeletionTimestamp == nil && root != nil {
					// The workspace is being removed, whether by its
					// owner or directly. Its deletion also removes the
					// data this Blip would save, so stop now and fail
					// the save instead of reporting success for a
					// discarded result.
					if err := r.stop(ctx, b, reasonStateDeleting); err != nil {
						return reconcile.Result{}, err
					}
					*base = *b.DeepCopy()
					by := ""
					if deletedByOwner(root, b) {
						by = " by its owner"
					}
					b.Status.Reason, b.Status.Message = ReasonStateNotFound,
						fmt.Sprintf("state %q is being deleted%s; stopping before the workspace is removed", root.Name, by)
					return reconcile.Result{}, nil
				}
				b.Status.Reason, b.Status.Message = reason, msg
				return reconcile.Result{RequeueAfter: retryAfter}, nil
			}
			if st, err := r.deletingMount(ctx, b, mounts); err != nil {
				return reconcile.Result{}, err
			} else if st != nil {
				// A writable mount is being removed, whether by its
				// owner or directly. Its deletion also removes the
				// data this Blip is writing, so stop now and fail the
				// save instead of reporting success for a discarded
				// result.
				if err := r.stop(ctx, b, reasonStateDeleting); err != nil {
					return reconcile.Result{}, err
				}
				*base = *b.DeepCopy()
				by := ""
				if deletedByOwner(st, b) {
					by = " by its owner"
				}
				b.Status.Reason, b.Status.Message = ReasonStateNotFound,
					fmt.Sprintf("mount state %q is being deleted%s; stopping before the workspace is removed", st.Name, by)
				return reconcile.Result{}, nil
			}
			b.Status.Reason = ""
			// A live policy that fails to compile is replaced with default
			// deny. The node records the cause on the pod; surface it so a
			// Running Blip does not look healthy while all egress is blocked.
			if perr := pod.Annotations[v1.AnnotationPrepareError]; strings.HasPrefix(perr, "network policy:") {
				b.Status.Reason = ReasonNetworkFailed
				b.Status.Message = perr
			}
			if err := r.syncMounts(ctx, b, mounts, pod, &obs); err != nil {
				return reconcile.Result{}, err
			}
			if mountsReconciled(b, mounts) {
				b.Status.StateGeneration = root.Generation
			} else if after == 0 || after > retryAfter {
				after = retryAfter
			}
		}
		return reconcile.Result{RequeueAfter: after}, nil
	}
	// Every disk is closed: active mounts are detached.
	var mounts []v1.MountStatus
	for _, m := range b.Status.Mounts {
		switch {
		case m.Writable && m.Phase == v1.MountPending && !m.InClaim && !m.Switching && diskNeverAttached(&obs, m.AttachmentID):
			// The node never observed an attached disk, so the guest could
			// not have written this mount. Release its writer and drop it
			// instead of sealing a filesystem that was never mounted. A
			// mount that was part of the accepted claim is excluded: the
			// guest only accepted the claim after attaching it.
			if m.AttachmentID != "" {
				if err := r.releaseUnattachedWriter(ctx, b, m.State, m.AttachmentID); err != nil {
					return reconcile.Result{}, err
				}
			}
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

// desiredMounts returns the root state's current mount set. ok is false when
// the root is gone or deleting, so its topology cannot be used to decide what
// a finishing Blip should still report.
func (r *BlipReconciler) desiredMounts(ctx context.Context, b *v1.Blip) (map[string]bool, bool, error) {
	if b.Spec.State == "" {
		return nil, false, nil
	}
	root := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Spec.State}, root); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if root.DeletionTimestamp != nil {
		return nil, false, nil
	}
	desired := map[string]bool{}
	for _, m := range v1.DesiredMounts(root, b) {
		desired[m.State] = true
	}
	return desired, true, nil
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
			default:
				// attachment resolves a deleting state without a seal so
				// the finalizers cannot deadlock. Report the discarded
				// save rather than marking the doomed mount mounted.
				st, err := r.deletingState(ctx, b, m.State)
				if err != nil {
					return err
				}
				if st != nil {
					msg := discardedSave(st, b)
					m.Phase, m.Message = v1.MountFailed, "save failed: "+msg
					if saveErr == "" {
						saveErr = msg
					}
				}
			}
		}
		mounts = append(mounts, m)
	}
	b.Status.Mounts = mounts
	if outstanding {
		if saveErr != "" {
			b.Status.Reason, b.Status.Message = ReasonSaveFailed, saveErr
		}
		return nil
	}
	// A workspace being removed cannot keep this save, whether its deletion
	// comes from its owner (a Blip or its TTL) or directly. attachment
	// deliberately treats a deleting state as resolved so the finalizer
	// cannot deadlock with the Blip; without this check the writer would
	// report Succeeded for data that is about to disappear.
	if b.Spec.State != "" && saveErr == "" {
		st, err := r.deletingState(ctx, b, b.Spec.State)
		if err != nil {
			return err
		}
		if st != nil {
			saveErr = discardedSave(st, b)
		}
	}
	// Every attachment is resolved. A writable mount still marked Saving was
	// saved successfully, so show its final ready phase instead of leaving
	// the finished Blip looking like it is still saving.
	for i := range b.Status.Mounts {
		if m := &b.Status.Mounts[i]; m.Writable && m.Phase == v1.MountSaving {
			m.Phase, m.Message, m.Switching = v1.MountMounted, "", false
		}
	}
	// A mount removed from desired intent while the Blip was stopping has
	// been saved above, but it is no longer part of the root's topology: a
	// finished Blip must not keep reporting it as mounted.
	if desired, ok, err := r.desiredMounts(ctx, b); err != nil {
		return err
	} else if ok {
		b.Status.Mounts = slices.DeleteFunc(b.Status.Mounts, func(m v1.MountStatus) bool {
			return m.Phase != v1.MountFailed && !desired[m.State]
		})
	}
	if saveErr != "" {
		if b.Status.Message != "" && b.Status.Reason != ReasonSaveFailed {
			saveErr += "\n" + b.Status.Message
		}
		r.finish(b, v1.BlipFailed, ReasonSaveFailed, saveErr)
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
	if st.DeletionTimestamp != nil {
		// The state finalizer resolves a deleting state's writer, and its
		// seal may never be recorded here. Waiting for one would keep both
		// the Blip and the state's finalizer stuck forever.
		return true, "", nil
	}
	s := st.Status
	if s.Writer != nil && s.Writer.AttachmentID == id || s.Pending != nil && s.Pending.AttachmentID == id {
		return false, "", nil
	}
	sr, found, err := r.sealResult(ctx, ns, state, id)
	if err != nil {
		return false, "", err
	}
	if !found {
		// The attachment is no longer in progress and no seal result exists.
		// Never report success: the save outcome is unknown.
		return true, fmt.Sprintf("no seal result for attachment %s", id), nil
	}
	if sr.CommitID == "" {
		return true, sealError(sr), nil
	}
	return true, "", nil
}
