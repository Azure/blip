package controller

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	defaultStateSize = 10 << 30
	// retryAfter paces retries of failures that no watch event resolves
	// (registry errors).
	retryAfter = 30 * time.Second
	// drainSaveFallback bounds how long a save waits for replicas when its
	// source node is draining but still healthy and holds the sealed commit.
	// Draining nodes may refuse new placements, so a replica fetch can be
	// impossible; after this bound the state commits on the source alone and
	// repair replicates it once a usable node can read it. This keeps a drain
	// from wedging the Blip and both finalizers forever.
	drainSaveFallback = 5 * time.Minute
	// replicaErrorFallback bounds how long a save waits for a replica that
	// keeps reporting an error and does not hold the sealed commit. A
	// node-local storage failure can make every fetch retry fail (for
	// example an orphan device that answers create with "Device or resource
	// busy"), and a healthy node is never replaced as a failed replica.
	// After this bound the state commits with the nodes that hold the
	// version; repair replicates it once the node can fetch again. This
	// keeps a stuck save, its Blip, and both finalizers from waiting forever.
	replicaErrorFallback = 5 * time.Minute
	// maxSeals is the API limit for BlipState.status.seals.
	maxSeals = 32
	// recentSeals is how many seal results are kept even when no Blip
	// references them.
	recentSeals = 8
	// maxCopyChain bounds the copyFrom walk used to detect cycles. A real
	// chain is far shorter; an unbounded one cannot make progress anyway.
	maxCopyChain = 32
)

// StateReconciler drives BlipState versions: initial version, commits,
// seals, repair, and deletion. It never writes status.nodes.
type StateReconciler struct {
	client.Client
	// Live is an uncached reader used to confirm destructive decisions.
	Live client.Reader
	Config
}

func (r *StateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Live == nil {
		r.Live = mgr.GetAPIReader()
	}
	allStates := handler.EnqueueRequestsFromMapFunc(r.allStates)
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.BlipState{}).
		Watches(&v1.BlipNode{}, allStates, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				a, b := e.ObjectOld.(*v1.BlipNode), e.ObjectNew.(*v1.BlipNode)
				now := r.now()
				return a.Spec != b.Spec || a.Status.Incarnation != b.Status.Incarnation ||
					healthy(a, now) != healthy(b, now)
			},
		})).
		Watches(&corev1.Node{}, allStates, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(event.UpdateEvent) bool { return false },
		})).
		Watches(&v1.Blip{}, handler.EnqueueRequestsFromMapFunc(r.blipStates)).
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.copies)).
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.profileStates)).
		// A copy that commits or stops blocking can release its source's
		// finalizer; wake the source instead of waiting for a resync.
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.copySource), builder.WithPredicates(copySourcePredicate())).
		Named("blipstate").
		// Live copies and seals of independent states do not share locks
		// in the controller; a single worker made parallel forks queue
		// behind each other while waiting for node status.
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

func (r *StateReconciler) allStates(ctx context.Context, _ client.Object) []reconcile.Request {
	var states v1.BlipStateList
	if err := r.List(ctx, &states); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(states.Items))
	for i, st := range states.Items {
		out[i] = req(st.Namespace, st.Name)
	}
	return out
}

func (r *StateReconciler) blipStates(ctx context.Context, o client.Object) []reconcile.Request {
	b := o.(*v1.Blip)
	refs := stateRefs(b)
	root := &v1.BlipState{}
	if b.Spec.State != "" && r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Spec.State}, root) == nil {
		for _, m := range v1.DesiredMounts(root, b) {
			if !slices.Contains(refs, m.State) {
				refs = append(refs, m.State)
			}
		}
	}
	var out []reconcile.Request
	for _, s := range refs {
		out = append(out, req(b.Namespace, s))
		out = append(out, r.copiesOf(ctx, b.Namespace, s)...)
	}
	// Wake profiles carrying this execution's temporary collect references.
	var roots v1.BlipStateList
	if r.List(ctx, &roots, client.InNamespace(b.Namespace), client.MatchingFields{indexMountUID: string(b.UID)}) == nil {
		for _, st := range roots.Items {
			out = append(out, req(st.Namespace, st.Name))
		}
	}
	return out
}

// Root edits wake reservations on their children (including removed children
// through the watch's old-object mapping). Child saves wake roots whose stale
// temporary references were retained until the save completed.
func (r *StateReconciler) profileStates(ctx context.Context, o client.Object) []reconcile.Request {
	st := o.(*v1.BlipState)
	var out []reconcile.Request
	for _, m := range st.Spec.Mounts {
		out = append(out, req(st.Namespace, m.State))
	}
	var roots v1.BlipStateList
	if r.List(ctx, &roots, client.InNamespace(st.Namespace), client.MatchingFields{indexMounts: st.Name}) == nil {
		for _, root := range roots.Items {
			out = append(out, req(root.Namespace, root.Name))
		}
	}
	return out
}

// copies maps a state to states copying from it.
func (r *StateReconciler) copies(ctx context.Context, o client.Object) []reconcile.Request {
	return r.copiesOf(ctx, o.GetNamespace(), o.GetName())
}

func (r *StateReconciler) copiesOf(ctx context.Context, namespace, name string) []reconcile.Request {
	var states v1.BlipStateList
	if err := r.List(ctx, &states, client.InNamespace(namespace), client.MatchingFields{indexCopyFrom: name}); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, st := range states.Items {
		out = append(out, req(st.Namespace, st.Name))
	}
	return out
}

// copySource maps a state copying another to the source state. It wakes the
// source when the copy stops or starts blocking the source's deletion, so the
// finalizer is retried without waiting for the periodic resync.
func (r *StateReconciler) copySource(_ context.Context, o client.Object) []reconcile.Request {
	st, ok := o.(*v1.BlipState)
	if !ok || st.Spec.CopyFrom == "" || st.Spec.CopyFrom == st.Name {
		return nil
	}
	return []reconcile.Request{req(st.Namespace, st.Spec.CopyFrom)}
}

// copySourcePredicate keeps copySource from mapping unrelated status churn
// (messages, node observations) that cannot change whether the copy blocks
// its source.
func copySourcePredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			old, ok := e.ObjectOld.(*v1.BlipState)
			if !ok {
				return false
			}
			cur, ok := e.ObjectNew.(*v1.BlipState)
			if !ok {
				return false
			}
			// deletionBlockers considers a copy blocking while it has no
			// committed version, names a source it copied from, and can
			// still use that source. A failed or deleting copy stops
			// blocking, so wake the source on those transitions too.
			return old.Spec.CopyFrom != cur.Spec.CopyFrom ||
				(old.Status.Committed == nil) != (cur.Status.Committed == nil) ||
				old.Status.Phase != cur.Status.Phase ||
				(old.DeletionTimestamp == nil) != (cur.DeletionTimestamp == nil) ||
				!equality.Semantic.DeepEqual(old.Status.CopiedFrom, cur.Status.CopiedFrom)
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

func (r *StateReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	st := &v1.BlipState{}
	if err := r.Get(ctx, rq.NamespacedName, st); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	deleting := st.DeletionTimestamp != nil
	if !deleting {
		if err := pruneTemporaryMounts(ctx, r.Client, r.Live, st); err != nil {
			return reconcile.Result{}, err
		}
	}
	if !deleting && !controllerutil.ContainsFinalizer(st, v1.Finalizer) {
		base := st.DeepCopy()
		controllerutil.AddFinalizer(st, v1.Finalizer)
		if err := patchObject(ctx, r.Client, st, base); err != nil {
			return reconcile.Result{}, err
		}
	}
	cl, err := loadCluster(ctx, r.Client, r.now())
	if err != nil {
		return reconcile.Result{}, err
	}

	base := st.DeepCopy()
	var msgs []string
	var result reconcile.Result
	var forceRecovered bool
	if st.Status.Writer != nil {
		orphan, err := r.unpublishedWriter(ctx, st)
		if err != nil {
			return reconcile.Result{}, err
		}
		if orphan {
			w := st.Status.Writer
			st.Status.Writer = nil
			err := r.recordSeal(ctx, st, v1.SealResult{
				AttachmentID: w.AttachmentID,
				Error:        "writer released before any blip published the attachment",
			})
			if err != nil {
				return reconcile.Result{}, err
			}
			msgs = append(msgs, fmt.Sprintf("released unpublished writer of %s", w.BlipName))
		} else {
			msg, recovered, err := r.writer(ctx, st, cl)
			if err != nil {
				return reconcile.Result{}, err
			}
			forceRecovered = recovered
			msgs = append(msgs, msg)
		}
	}
	if cf := st.Status.CopiedFrom; cf != nil && cf.AttachmentID != "" && st.Status.Committed == nil && !deleting {
		stale, err := r.liveCopyStale(ctx, st, cl)
		if err != nil {
			return reconcile.Result{}, err
		}
		if stale {
			st.Status.CopiedFrom = nil
			st.Status.Pending = nil
			// A failed live copy can still fall back to the source's
			// committed version, so it is a retry, not a dead end.
			st.Status.Phase = v1.StatePending
			st.Status.LastError = ""
			if st.Spec.Size == nil {
				st.Status.SizeBytes = 0
			}
			msgs = append(msgs, "copy source writer changed; replanning")
		}
	}
	switch {
	case st.Status.Pending != nil:
		msg, err := r.pending(ctx, st, cl)
		if err != nil {
			return reconcile.Result{}, err
		}
		msgs = append(msgs, msg)
	case st.Status.Committed == nil && st.Status.Phase == v1.StateFailed:
		msgs = append(msgs, st.Status.Message)
	case st.Status.Committed == nil && !deleting:
		msg, retry, err := r.initialize(ctx, st, cl)
		if err != nil {
			return reconcile.Result{}, err
		}
		msgs = append(msgs, msg)
		if retry {
			result.RequeueAfter = retryAfter
		}
		if st.Status.Pending != nil {
			msg, err := r.pending(ctx, st, cl)
			if err != nil {
				return reconcile.Result{}, err
			}
			msgs = append(msgs, msg)
		}
	case st.Status.Committed != nil:
		msgs = append(msgs, r.repair(st, cl))
	}

	var blockers []string
	if deleting {
		if blockers, err = r.deletionBlockers(ctx, st); err != nil {
			return reconcile.Result{}, err
		}
		if len(blockers) > 0 {
			msgs = append(msgs, "deleting: waiting for "+strings.Join(blockers, ", "))
		}
	}
	if st.Status.Phase != v1.StateFailed || st.Status.Committed != nil {
		st.Status.Phase = statePhase(st)
	}
	st.Status.Message = joinMessages(msgs)
	if !semanticEqual(base.Status, st.Status) {
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	if deleting && len(blockers) == 0 && controllerutil.ContainsFinalizer(st, v1.Finalizer) {
		base := st.DeepCopy()
		controllerutil.RemoveFinalizer(st, v1.Finalizer)
		return reconcile.Result{}, client.IgnoreNotFound(patchObject(ctx, r.Client, st, base))
	}
	if forceRecovered || (st.Status.Writer == nil && st.Annotations[v1.AnnotationForceRecover] != "") {
		// Remove the one-shot annotation after its writer change is
		// persisted. A later writer must not be recovered silently. The
		// no-writer case also clears it after a conflicted status patch
		// already removed the writer.
		if err := r.clearForceRecover(ctx, st); err != nil {
			return reconcile.Result{}, err
		}
	}

	nodes := slices.Clone(st.Status.Placements)
	if p := st.Status.Pending; p != nil {
		nodes = append(nodes, p.SourceNode)
		nodes = append(nodes, p.Replicas...)
	}
	if next := cl.nextCrossing(nodes, repairAfter, false); next > 0 && (result.RequeueAfter == 0 || next < result.RequeueAfter) {
		result.RequeueAfter = next
	}
	return result, nil
}

func statePhase(st *v1.BlipState) string {
	switch s := st.Status; {
	case s.Committed == nil:
		return v1.StatePending
	case s.Pending != nil:
		return v1.StateSaving
	case s.Writer != nil:
		return v1.StateInUse
	default:
		return v1.StateReady
	}
}

func joinMessages(msgs []string) string {
	var out []string
	for _, m := range msgs {
		if m != "" {
			out = append(out, m)
		}
	}
	return strings.Join(out, "; ")
}

// copyChainCycle reports a self or cyclic copyFrom chain, or "" when the
// chain is acyclic. A source with a committed version can serve a copy even
// if its own provisioning history is cyclic, so the walk stops there.
func (r *StateReconciler) copyChainCycle(ctx context.Context, st *v1.BlipState) (string, error) {
	seen := map[string]bool{st.Name: true}
	path := []string{st.Name}
	name := st.Spec.CopyFrom
	for depth := 0; name != ""; depth++ {
		if depth >= maxCopyChain {
			return fmt.Sprintf("copy source chain from %q is deeper than %d states", st.Name, maxCopyChain), nil
		}
		if seen[name] {
			path = append(path, name)
			return "copy source cycle: " + strings.Join(path, " -> "), nil
		}
		src := &v1.BlipState{}
		err := r.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: name}, src)
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		seen[name] = true
		path = append(path, name)
		if src.Status.Committed != nil {
			return "", nil
		}
		name = src.Spec.CopyFrom
	}
	return "", nil
}

// copySourceFailure reports why a copy source that has not committed cannot
// serve, or "" while the copy should keep waiting for it.
func copySourceFailure(src *v1.BlipState) string {
	if src.Status.Phase != v1.StateFailed {
		return ""
	}
	if src.Status.Message != "" {
		return src.Status.Message
	}
	if src.Status.LastError != "" {
		return src.Status.LastError
	}
	return "initialization failed"
}

// initialize resolves the source and plans the initial version.
func (r *StateReconciler) initialize(ctx context.Context, st *v1.BlipState, cl *cluster) (msg string, retry bool, err error) {
	s := &st.Status
	// Admission rejects this, but a client that bypasses the CRD schema (or
	// an object created before the rule) must not reach the node with a
	// zero or negative filesystem size.
	if st.Spec.Size != nil && st.Spec.Size.Sign() <= 0 {
		s.Phase = v1.StateFailed
		return fmt.Sprintf("size %s must be greater than 0", st.Spec.Size.String()), false, nil
	}
	if st.Spec.Size != nil && st.Spec.Size.CmpInt64(v1.MaxStateSizeBytes) > 0 {
		s.Phase = v1.StateFailed
		max := resource.NewQuantity(v1.MaxStateSizeBytes, resource.BinarySI)
		return fmt.Sprintf("size %s is too large (maximum %s)", st.Spec.Size.String(), max.String()), false, nil
	}
	if st.Spec.CopyFrom == st.Name {
		s.Phase = v1.StateFailed
		s.CopiedFrom = nil
		s.Pending = nil
		return fmt.Sprintf("copy source %q is the state itself", st.Name), false, nil
	}
	if cycle, err := r.copyChainCycle(ctx, st); err != nil {
		return "", false, err
	} else if cycle != "" {
		s.Phase = v1.StateFailed
		s.CopiedFrom = nil
		s.Pending = nil
		return cycle, false, nil
	}
	var minSize int64
	var prefer []string
	switch {
	case st.Spec.Image != "":
		if s.ImageDigest == "" {
			d, err := r.Registry.Digest(ctx, st.Spec.Image, st.Namespace, st.Spec.ImagePullSecrets)
			if terminalImageError(err) {
				s.Phase = v1.StateFailed
				return err.Error(), false, nil
			}
			if err != nil {
				return fmt.Sprintf("resolve image %s: %v", st.Spec.Image, err), true, nil
			}
			s.ImageDigest = d
		}
		if s.ImageConfig == nil {
			cfg, err := r.Registry.ImageConfig(ctx, s.ImageDigest, st.Namespace, st.Spec.ImagePullSecrets)
			if terminalImageError(err) {
				s.Phase = v1.StateFailed
				return err.Error(), false, nil
			}
			if err != nil {
				return fmt.Sprintf("resolve image config %s: %v", st.Spec.Image, err), true, nil
			}
			s.ImageConfig = cfg
		}
	case st.Spec.CopyFrom != "":
		// A live copy is replanned from scratch: its source node must be
		// the writer's node.
		if s.CopiedFrom == nil || s.CopiedFrom.AttachmentID != "" {
			s.CopiedFrom = nil
			src := &v1.BlipState{}
			err := r.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: st.Spec.CopyFrom}, src)
			if apierrors.IsNotFound(err) {
				s.Phase = v1.StateFailed
				return fmt.Sprintf("copy source %q not found", st.Spec.CopyFrom), false, nil
			}
			if err != nil {
				return "", false, err
			}
			if owner := st.Labels[v1.LabelOwner]; !readableBy(owner, src) {
				s.Phase = v1.StateFailed
				return fmt.Sprintf("copy source %q is not owned by %s or a shared image template", src.Name, owner), false, nil
			}
			switch {
			case src.DeletionTimestamp != nil && src.Status.Committed == nil:
				// A source with no committed version can never serve the
				// copy once it is gone. Fail cleanly without pinning the
				// source's finalizer on a build that cannot succeed.
				s.Phase = v1.StateFailed
				return fmt.Sprintf("copy source %q is being deleted", src.Name), false, nil
			case src.Status.Committed == nil && src.Status.Phase == v1.StateFailed && src.Status.Pending == nil:
				// A failed import can still commit a pending version, and
				// workspace.CheckSource accepts exactly that source. Only a
				// source with no pending commit is terminally failed.
				s.Phase = v1.StateFailed
				return fmt.Sprintf("copy source %q failed: %s", src.Name, copySourceFailure(src)), false, nil
			case src.Status.Committed == nil:
				return fmt.Sprintf("waiting for copy source %q to commit", src.Name), false, nil
			case src.Status.Pending != nil:
				return fmt.Sprintf("copy source %q is saving", src.Name), false, nil
			}
			if w := src.Status.Writer; w != nil {
				if msg, err := r.liveWriter(ctx, st, src, cl); err != nil || msg != "" {
					return msg, false, err
				}
				s.CopiedFrom = &v1.CopySource{StateUID: string(src.UID), AttachmentID: w.AttachmentID, Nodes: []string{w.Node}}
			} else {
				var holders []string
				for _, n := range src.Status.Placements {
					// A healthy draining holder still serves the commit it
					// sealed; only unhealthy or stale-incarnation holders
					// cannot. Accepting them blindly would place a copy that
					// can never fetch and pin the source finalizer forever.
					if cl.healthyNode(n) && cl.holds(src, n, src.Status.Committed.ID) {
						holders = append(holders, n)
					}
				}
				if len(holders) == 0 {
					// No node can serve the source right now. A node may
					// recover, so retry for the same bounded window as an
					// unplaceable copy, then fail terminally and release the
					// source finalizer.
					msg := fmt.Sprintf("no healthy holder of copy source %q; retrying", src.Name)
					if s.UnplaceableSince == nil {
						now := metav1.NewTime(cl.now)
						s.UnplaceableSince = &now
						return msg, true, nil
					}
					if cl.now.Sub(s.UnplaceableSince.Time) < pendingTimeout {
						return msg, true, nil
					}
					s.Phase = v1.StateFailed
					s.UnplaceableSince = nil
					return fmt.Sprintf("copy source %q has no healthy holder after %s", src.Name, pendingTimeout), false, nil
				}
				s.CopiedFrom = &v1.CopySource{StateUID: string(src.UID), CommitID: src.Status.Committed.ID, Nodes: holders}
			}
			s.UnplaceableSince = nil
			if s.ImageConfig == nil && src.Status.ImageConfig != nil {
				s.ImageConfig = src.Status.ImageConfig.DeepCopy()
			}
			minSize = src.Status.SizeBytes
		}
		prefer = s.CopiedFrom.Nodes
	}
	if minSize > 0 && st.Spec.Size != nil && st.Spec.Size.Value() < minSize {
		s.Phase = v1.StateFailed
		return fmt.Sprintf("size %s is smaller than copy source %q (%s)",
			st.Spec.Size.String(), st.Spec.CopyFrom, resource.NewQuantity(minSize, resource.BinarySI).String()), false, nil
	}
	if s.SizeBytes == 0 {
		s.SizeBytes = defaultStateSize
		if st.Spec.Size != nil {
			s.SizeBytes = st.Spec.Size.Value()
		} else if minSize > 0 {
			s.SizeBytes = minSize
		}
		s.SizeBytes = max(s.SizeBytes, minSize)
	}

	nodes := cl.choose(replicas(st), st.Spec.NodeSelector, prefer, nil)
	size := resource.NewQuantity(s.SizeBytes, resource.BinarySI)
	if s.CopiedFrom != nil && s.CopiedFrom.AttachmentID == "" && s.SizeBytes > 0 {
		// A committed copy source is only a preferred read source; the copy
		// itself can live on any node with room. Skip nodes that cannot hold
		// it instead of failing while another target still fits.
		var full []string
		for _, n := range cl.names {
			if cl.usable(n, st.Spec.NodeSelector) && cl.nodes[n].Status.FreeBytes < s.SizeBytes {
				full = append(full, n)
			}
		}
		if len(full) > 0 {
			nodes = cl.choose(replicas(st), st.Spec.NodeSelector, prefer, full)
			if len(nodes) == 0 {
				s.Phase = v1.StateFailed
				return fmt.Sprintf("state needs %s per replica but no eligible node has enough free space", size.String()), false, nil
			}
		}
	}
	if len(nodes) == 0 {
		if st.Spec.CopyFrom == "" {
			return "no healthy node can hold the state", false, nil
		}
		// A copy pins its source until it commits. When no node matches its
		// immutable selector it can never make progress, so bound the wait
		// and fail terminally; otherwise the source finalizer waits forever.
		if s.UnplaceableSince == nil {
			now := metav1.NewTime(cl.now)
			s.UnplaceableSince = &now
			return fmt.Sprintf("no eligible node can hold copy source %q; retrying", st.Spec.CopyFrom), true, nil
		}
		if cl.now.Sub(s.UnplaceableSince.Time) < pendingTimeout {
			return fmt.Sprintf("no eligible node can hold copy source %q; retrying", st.Spec.CopyFrom), true, nil
		}
		s.Phase = v1.StateFailed
		s.UnplaceableSince = nil
		return fmt.Sprintf("no eligible node can hold copy source %q: its nodeSelector matches no node after %s", st.Spec.CopyFrom, pendingTimeout), false, nil
	}
	s.UnplaceableSince = nil
	if s.SizeBytes > 0 {
		for _, n := range nodes {
			if free := cl.nodes[n].Status.FreeBytes; free < s.SizeBytes {
				s.Phase = v1.StateFailed
				return fmt.Sprintf("state needs %s per replica but node %s has only %s free",
					size.String(), n, resource.NewQuantity(free, resource.BinarySI).String()), false, nil
			}
		}
	}
	s.Pending = &v1.PendingCommit{CommitID: r.newID(), Generation: 1, SourceNode: nodes[0], Replicas: nodes}
	return "", false, nil
}

// liveWriter returns why the copy cannot snapshot the source's writer
// attachment now, or "" when it is attached to a running VM on a node that
// can hold the copy (the copy's source node).
func (r *StateReconciler) liveWriter(ctx context.Context, st, src *v1.BlipState, cl *cluster) (string, error) {
	w := src.Status.Writer
	busy := fmt.Sprintf("copy source %q has a writer (%s) that is not running", src.Name, w.BlipName)
	if w.PodUID == "" || w.Node == "" {
		return busy, nil
	}
	b := &v1.Blip{}
	err := r.Get(ctx, types.NamespacedName{Namespace: src.Namespace, Name: w.BlipName}, b)
	if apierrors.IsNotFound(err) {
		return busy, nil
	}
	if err != nil {
		return "", err
	}
	if string(b.UID) != w.BlipUID || v1.Finished(b) || stopping(b) || b.Status.Phase == v1.BlipSaving {
		return busy, nil
	}
	if b.Status.RootAttachmentID != w.AttachmentID {
		attached := false
		for _, m := range b.Status.Mounts {
			if m.AttachmentID == w.AttachmentID && (m.Phase == v1.MountPending || m.Phase == v1.MountMounted) {
				attached = true
			}
		}
		if !attached {
			return fmt.Sprintf("copy source %q has a writer (%s) that is unmounting it", src.Name, w.BlipName), nil
		}
	}
	if !cl.usable(w.Node, st.Spec.NodeSelector) {
		return fmt.Sprintf("copy source %q has a writer (%s) on %s, which cannot hold the copy", src.Name, w.BlipName, w.Node), nil
	}
	return "", nil
}

// liveCopyStale reports whether a live copy lost its source attachment
// before the source node built the copy's commit.
func (r *StateReconciler) liveCopyStale(ctx context.Context, st *v1.BlipState, cl *cluster) (bool, error) {
	cf := st.Status.CopiedFrom
	if p := st.Status.Pending; p != nil && cl.holds(st, p.SourceNode, p.CommitID) {
		return false, nil
	}
	src := &v1.BlipState{}
	err := r.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: st.Spec.CopyFrom}, src)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	w := src.Status.Writer
	if string(src.UID) != cf.StateUID || w == nil || w.AttachmentID != cf.AttachmentID {
		return true, nil
	}
	if w.BlipName == "" {
		return true, nil
	}
	// A live copy needs the writer's pod to freeze. If its Blip finished,
	// started saving, or is being deleted, the pod is gone or going; replan
	// from the version the source saves instead of waiting for a freeze that
	// cannot happen.
	srcBlip := &v1.Blip{}
	err = r.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: w.BlipName}, srcBlip)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if v1.Finished(srcBlip) || stopping(srcBlip) || srcBlip.Status.Phase == v1.BlipSaving ||
		(w.BlipUID != "" && string(srcBlip.UID) != w.BlipUID) {
		return true, nil
	}
	return false, nil
}

// replicas is how many nodes should hold the state. Every eligible node
// holds an image state, and each builds generation 1 from the image itself.
func replicas(st *v1.BlipState) int {
	switch {
	case st.Spec.Image != "":
		return math.MaxInt
	case st.Spec.Replicas <= 0:
		return 3
	}
	return int(st.Spec.Replicas)
}

// pending replaces failed replicas of the pending version and commits it
// once every replica holds it.
func (r *StateReconciler) pending(ctx context.Context, st *v1.BlipState, cl *cluster) (string, error) {
	s := &st.Status
	p := s.Pending
	if p.Since == nil {
		now := metav1.NewTime(cl.now)
		p.Since = &now
	}
	if stop, msg, err := r.pendingSource(ctx, st, cl); err != nil {
		return "", err
	} else if stop {
		return msg, nil
	}
	if drainSaveExpired(st, cl, p) {
		// The source sealed the commit and is only draining, but no replica
		// could fetch it. Commit with the source and any replica that did
		// fetch: the data is durable on the source and repair can replicate
		// it once a usable node can read it.
		kept := slices.DeleteFunc(slices.Clone(p.Replicas), func(n string) bool {
			return n != p.SourceNode && !cl.holds(st, n, p.CommitID)
		})
		if !slices.Contains(kept, p.SourceNode) {
			kept = append([]string{p.SourceNode}, kept...)
		}
		p.Replicas = kept
	}
	for i, n := range p.Replicas {
		if n == p.SourceNode || !cl.bad(n) || cl.holds(st, n, p.CommitID) {
			continue
		}
		if repl := cl.choose(1, st.Spec.NodeSelector, nil, p.Replicas); len(repl) == 1 {
			p.Replicas[i] = repl[0]
		}
	}
	switch {
	case st.Spec.Image != "":
		// Every eligible node is already a replica of an image state, so a
		// failed one has no stand-in: drop it. Generation 1 is built from
		// the image on each node, so its source is not special.
		p.Replicas = slices.DeleteFunc(p.Replicas, func(n string) bool {
			return (n != p.SourceNode || p.Generation == 1) && cl.bad(n) && !cl.holds(st, n, p.CommitID)
		})
		if p.Generation == 1 && !slices.Contains(p.Replicas, p.SourceNode) {
			if len(p.Replicas) == 0 {
				s.Pending = nil
				return "no eligible node can build generation 1; replanning", nil
			}
			p.SourceNode = p.Replicas[0]
		}
	case p.Generation == 1:
		// Generation 1 is built from empty (or the copy source) by the
		// surviving source node, so a failed replica with no replacement
		// only delays the build. Drop it and commit with the survivors;
		// repair adds replicas back when a node is available again.
		p.Replicas = slices.DeleteFunc(p.Replicas, func(n string) bool {
			return n != p.SourceNode && cl.bad(n) && !cl.holds(st, n, p.CommitID)
		})
	default:
		// A later generation exists only as the commit its source sealed,
		// so it can commit with fewer replicas while a surviving node
		// still holds it. Without a holder, pendingSource reports the
		// lost save instead of committing data no node can provide.
		if servingSource(st, cl, p) || usableHolder(st, cl, p, p.Replicas) != "" {
			p.Replicas = slices.DeleteFunc(p.Replicas, func(n string) bool {
				return n != p.SourceNode && cl.bad(n) && !cl.holds(st, n, p.CommitID)
			})
		}
	}
	var fallback string
	if p.Generation > 1 {
		dropped, lost := resolveFailedReplicas(st, cl, p)
		switch {
		case lost:
			// No node at all still holds the sealed version, so waiting can
			// never make the save succeed. Fail the attachment's seal so the
			// Blip reports a failed save instead of hanging forever.
			if p.AttachmentID != "" {
				sr := v1.SealResult{AttachmentID: p.AttachmentID,
					Error: fmt.Sprintf("pending generation %d lost: no node holds commit %s", p.Generation, p.CommitID)}
				if err := r.recordSeal(ctx, st, sr); err != nil {
					return "", err
				}
			}
			s.Pending = nil
			s.LastError = ""
			return fmt.Sprintf("pending generation %d lost: no node holds %s", p.Generation, p.CommitID), nil
		case len(dropped) > 0:
			fallback = fmt.Sprintf("saved generation %d with fewer replicas: %s", p.Generation, strings.Join(dropped, "; "))
		}
	}
	var waiting, errs []string
	for _, n := range p.Replicas {
		if !cl.holds(st, n, p.CommitID) {
			waiting = append(waiting, n)
		}
		for _, o := range st.Status.Nodes {
			if o.Node == n && o.Error != "" && cl.currentObservation(o) {
				errs = append(errs, fmt.Sprintf("%s: %s", n, o.Error))
			}
		}
	}
	switch {
	case len(errs) > 0:
		s.LastError = strings.Join(errs, "; ")
	default:
		s.LastError = ""
	}
	if len(waiting) > 0 {
		msg := fmt.Sprintf("saving generation %d: waiting for %s", p.Generation, strings.Join(waiting, ", "))
		if p.Generation == 1 && len(errs) > 0 && initialSourceSettled(st, cl, p) {
			// Keep pending so a retry or a recovered node can still
			// complete it, but surface a failing initial build (for
			// example an image larger than the requested size). Until
			// the source reports the commit or an error, replicas that
			// cannot see it are only waiting for it to publish.
			s.Phase = v1.StateFailed
			return "initial version failed: " + s.LastError, nil
		}
		return joinMessages(append([]string{msg}, errs...)), nil
	}
	s.Committed = &v1.Commit{
		ID:           p.CommitID,
		Generation:   p.Generation,
		SizeBytes:    s.SizeBytes,
		Time:         metav1.NewTime(cl.now),
		AttachmentID: p.AttachmentID,
	}
	s.Placements = p.Replicas
	s.Pending = nil
	s.LastError = ""
	return fallback, nil
}

// resolveFailedReplicas drops replicas that have reported an error past
// replicaErrorFallback without holding the sealed commit, as long as a usable
// node still holds it. It returns one "node: error" string per dropped replica.
// Such a replica may never fetch (for example a permanent node-local device
// failure); waiting for it would wedge the save, the Blip, and the state
// finalizer. Repair re-adds the placement and retries the fetch once the node
// can serve it.
//
// lost reports that a replica error outlived the bound while no node at all
// (including a draining or unhealthy one) holds the commit: the save can never
// complete and must fail instead of waiting forever.
func resolveFailedReplicas(st *v1.BlipState, cl *cluster, p *v1.PendingCommit) (dropped []string, lost bool) {
	if p.Since == nil || cl.now.Sub(p.Since.Time) < replicaErrorFallback {
		return nil, false
	}
	errs := map[string]string{}
	for _, o := range st.Status.Nodes {
		if o.Error != "" && (o.Node == p.SourceNode || slices.Contains(p.Replicas, o.Node)) &&
			cl.currentObservation(o) {
			errs[o.Node] = o.Error
		}
	}
	if len(errs) == 0 {
		return nil, false
	}
	if !servingSource(st, cl, p) && usableHolder(st, cl, p, p.Replicas) == "" {
		return nil, !saveHeld(st, cl, p)
	}
	for _, n := range p.Replicas {
		if !cl.holds(st, n, p.CommitID) && errs[n] != "" {
			dropped = append(dropped, fmt.Sprintf("%s: %s", n, errs[n]))
		}
	}
	p.Replicas = slices.DeleteFunc(p.Replicas, func(n string) bool {
		return !cl.holds(st, n, p.CommitID) && errs[n] != ""
	})
	return dropped, false
}

// saveHeld reports whether any replica or the source still holds the pending
// commit, whether or not that node is currently usable.
func saveHeld(st *v1.BlipState, cl *cluster, p *v1.PendingCommit) bool {
	if cl.holds(st, p.SourceNode, p.CommitID) {
		return true
	}
	for _, n := range p.Replicas {
		if cl.holds(st, n, p.CommitID) {
			return true
		}
	}
	return false
}

// initialSourceSettled reports whether the source of an initial version has
// had its chance to build it: it reports holding the commit or reports an
// error. Before that, replica errors only mean the commit is not visible yet,
// so they do not prove that initialization failed.
func initialSourceSettled(st *v1.BlipState, cl *cluster, p *v1.PendingCommit) bool {
	if p.Generation != 1 {
		return true
	}
	if cl.holds(st, p.SourceNode, p.CommitID) {
		return true
	}
	for _, o := range st.Status.Nodes {
		if o.Node == p.SourceNode && o.Error != "" && cl.currentObservation(o) {
			return true
		}
	}
	return false
}

// pendingSource keeps Pending.SourceNode on a node that can serve the
// pending commit. Generation 1 may be replanned when its source is unusable;
// later generations switch to any healthy replica that holds the commit.
func (r *StateReconciler) pendingSource(ctx context.Context, st *v1.BlipState, cl *cluster) (stop bool, msg string, err error) {
	s := &st.Status
	p := s.Pending
	selector := st.Spec.NodeSelector
	if p.Generation == 1 {
		if cl.usable(p.SourceNode, selector) {
			return false, "", nil
		}
		if n := usableHolder(st, cl, p, p.Replicas); n != "" {
			p.SourceNode = n
			return false, "", nil
		}
		if st.Spec.Image == "" {
			s.Pending = nil
			return true, fmt.Sprintf("initial source node %s failed; replanning", p.SourceNode), nil
		}
		if n := firstUsable(st, cl, p.Replicas); n != "" {
			p.SourceNode = n
		}
		// Without an eligible replica the image branch below drops the
		// failed ones and replans when none remains.
		return false, "", nil
	}
	// A draining writer still serves its sealed disk to replacement replicas.
	// Draining forbids new placements, not completing an existing save.
	if servingSource(st, cl, p) {
		return false, "", nil
	}
	if n := usableHolder(st, cl, p, p.Replicas); n != "" {
		p.SourceNode = n
		return false, "", nil
	}
	if n := healthyHolder(st, cl, p, p.Replicas); n != "" {
		// The only holder is healthy but draining. It can still serve (or
		// keep) the commit it sealed, and drainSaveExpired commits on it
		// once replicas cannot fetch. Draining only forbids new placements.
		p.SourceNode = n
		return false, "", nil
	}
	if !cl.bad(p.SourceNode) {
		// The source may simply not have reported the commit yet.
		return false, "", nil
	}
	// A briefly stale or draining holder still has the only durable copy.
	// Never declare the save lost while any node reports it: a heartbeat
	// lag is not data loss, and a draining or unreachable node can recover.
	if saveHeld(st, cl, p) {
		return false, "", nil
	}
	// The node that sealed the pending version is gone and no replica
	// holds it. The committed version stays current; report the lost save
	// instead of waiting forever.
	if p.AttachmentID != "" {
		sr := v1.SealResult{
			AttachmentID: p.AttachmentID,
			Error:        fmt.Sprintf("pending generation %d lost: no replica holds commit %s", p.Generation, p.CommitID),
		}
		if err := r.recordSeal(ctx, st, sr); err != nil {
			return false, "", err
		}
	}
	s.Pending = nil
	return true, fmt.Sprintf("pending generation %d lost: no node holds %s", p.Generation, p.CommitID), nil
}

// A healthy draining source can still serve its sealed commit even though it
// cannot take new placements. Replica loss must not strand that existing save.
func servingSource(st *v1.BlipState, cl *cluster, p *v1.PendingCommit) bool {
	return cl.healthyNode(p.SourceNode) && cl.holds(st, p.SourceNode, p.CommitID)
}

// drainSaveExpired reports whether a save has waited past drainSaveFallback
// for replicas of a commit that a healthy draining source already holds. Such
// replicas may be unable to fetch at all (draining nodes are not sources for
// new placements), so waiting longer only wedges the save.
func drainSaveExpired(st *v1.BlipState, cl *cluster, p *v1.PendingCommit) bool {
	if p.Generation <= 1 || p.Since == nil || cl.now.Sub(p.Since.Time) < drainSaveFallback {
		return false
	}
	bn := cl.nodes[p.SourceNode]
	return bn != nil && bn.Spec.Drain && servingSource(st, cl, p)
}

// usableHolder returns a usable replica that holds the pending commit.
func usableHolder(st *v1.BlipState, cl *cluster, p *v1.PendingCommit, replicas []string) string {
	for _, n := range replicas {
		if cl.usable(n, st.Spec.NodeSelector) && cl.holds(st, n, p.CommitID) {
			return n
		}
	}
	return ""
}

// healthyHolder returns a healthy replica that holds the pending commit even
// if it is draining. Draining forbids new placements, not serving or keeping a
// commit the node already sealed, so such a holder can complete the save.
func healthyHolder(st *v1.BlipState, cl *cluster, p *v1.PendingCommit, replicas []string) string {
	for _, n := range replicas {
		if cl.healthyNode(n) && cl.holds(st, n, p.CommitID) {
			return n
		}
	}
	return ""
}

// firstUsable returns the first usable node in names.
func firstUsable(st *v1.BlipState, cl *cluster, names []string) string {
	for _, n := range names {
		if cl.usable(n, st.Spec.NodeSelector) {
			return n
		}
	}
	return ""
}

// writer turns a seal report into a pending version, or keeps a writer
// reserved when it cannot be confirmed stopped.
func (r *StateReconciler) writer(ctx context.Context, st *v1.BlipState, cl *cluster) (string, bool, error) {
	s := &st.Status
	w := s.Writer
	if w.PodUID == "" {
		// Not claimed yet: release if the Blip is gone.
		b := &v1.Blip{}
		err := r.Live.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: w.BlipName}, b)
		if err != nil && !apierrors.IsNotFound(err) {
			return "", false, err
		}
		if apierrors.IsNotFound(err) || string(b.UID) != w.BlipUID || v1.Finished(b) {
			s.Writer = nil
		}
		return "", false, nil
	}
	for _, o := range s.Nodes {
		if o.Node != w.Node {
			continue
		}
		for _, sr := range o.Sealed {
			if sr.AttachmentID != w.AttachmentID {
				continue
			}
			s.Writer = nil
			if err := r.recordSeal(ctx, st, sr); err != nil {
				return "", false, err
			}
			if sr.CommitID == "" {
				return fmt.Sprintf("save of %s by %s failed: %s", w.AttachmentID, w.BlipName, sr.Error), false, nil
			}
			if s.Committed == nil {
				return "", false, errors.New("seal without committed version")
			}
			prefer := append([]string{w.Node}, s.Placements...)
			nodes := cl.choose(replicas(st), st.Spec.NodeSelector, prefer, nil)
			if len(nodes) == 0 {
				nodes = []string{w.Node}
			}
			if sr.SizeBytes > 0 {
				s.SizeBytes = sr.SizeBytes
			}
			s.Pending = &v1.PendingCommit{
				CommitID:     sr.CommitID,
				Generation:   s.Committed.Generation + 1,
				SourceNode:   w.Node,
				AttachmentID: w.AttachmentID,
				Replicas:     nodes,
			}
			return "", false, nil
		}
	}
	if v, ok := st.Annotations[v1.AnnotationForceRecover]; ok && v != "" {
		// The operator confirmed that the VM can no longer write. Report a
		// failed seal so the Blip fails instead of reporting success.
		s.Writer = nil
		sr := v1.SealResult{
			AttachmentID: w.AttachmentID,
			Error:        "writer cleared by force-recover annotation",
		}
		if err := r.recordSeal(ctx, st, sr); err != nil {
			return "", false, err
		}
		return fmt.Sprintf("writer of %s on %s cleared by force-recover annotation; unsaved changes are lost", w.BlipName, w.Node), true, nil
	}
	// A deleted Kubernetes Node does not prove that the VM stopped writing.
	// Keep the writer reserved (so nobody else can take it) until the node
	// reports a seal or an operator forces recovery.
	if cl.k8s[w.Node] == nil {
		err := r.Live.Get(ctx, types.NamespacedName{Name: w.Node}, &corev1.Node{})
		if err != nil && !apierrors.IsNotFound(err) {
			return "", false, err
		}
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("writer %s on deleted node %s cannot be confirmed stopped; annotate the state %s=%q after checking the node to recover", w.BlipName, w.Node, v1.AnnotationForceRecover, "true"), false, nil
		}
	}
	return "", false, nil
}

// unpublishedWriter reports whether a writer reservation was persisted before
// its Blip published the attachment, for example when the controller
// crashed between setting writer.podUID and writing Blip.status. The node
// only prepares attachments named by the Blip, so such a writer guards no
// disk and can be released once its owner is gone or terminal. A live Blip may
// be between acquire and status publication, even if its root intent changed
// meanwhile. Only that Blip's serialized reconcile can release unused slots.
func (r *StateReconciler) unpublishedWriter(ctx context.Context, st *v1.BlipState) (bool, error) {
	w := st.Status.Writer
	if w == nil {
		return false, nil
	}
	var blips v1.BlipList
	if err := r.Live.List(ctx, &blips, client.InNamespace(st.Namespace)); err != nil {
		return false, err
	}
	for _, b := range blips.Items {
		if b.Status.RootAttachmentID == w.AttachmentID {
			return false, nil
		}
		for _, m := range b.Status.Mounts {
			if m.AttachmentID == w.AttachmentID {
				return false, nil
			}
		}
		if string(b.UID) == w.BlipUID && !v1.Finished(&b) {
			return false, nil
		}
	}
	return true, nil
}

// recordSeal appends sr to status.seals, replacing any entry for the same
// attachment, and prunes old entries.
func (r *StateReconciler) recordSeal(ctx context.Context, st *v1.BlipState, sr v1.SealResult) error {
	seals := slices.DeleteFunc(st.Status.Seals, func(old v1.SealResult) bool {
		return old.AttachmentID == sr.AttachmentID
	})
	seals = append(seals, sr)
	refs, err := r.sealRefs(ctx, st.Namespace)
	if err != nil {
		return err
	}
	st.Status.Seals = pruneSeals(seals, refs)
	return nil
}

// sealRefs returns the attachment IDs that Blips in namespace still name in
// status. Those seal results must survive pruning so a Blip can report the
// outcome after the node stops reporting it.
func (r *StateReconciler) sealRefs(ctx context.Context, namespace string) (map[string]bool, error) {
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	refs := map[string]bool{}
	for _, b := range blips.Items {
		if b.Status.RootAttachmentID != "" {
			refs[b.Status.RootAttachmentID] = true
		}
		for _, m := range b.Status.Mounts {
			if m.AttachmentID != "" {
				refs[m.AttachmentID] = true
			}
		}
	}
	return refs, nil
}

// pruneSeals keeps every seal a Blip still references plus the most recent
// recentSeals, capped at maxSeals. seals is oldest first.
func pruneSeals(seals []v1.SealResult, refs map[string]bool) []v1.SealResult {
	seen := map[string]bool{}
	keep := make([]v1.SealResult, 0, min(len(seals), maxSeals))
	add := func(sr v1.SealResult) {
		if len(keep) >= maxSeals || seen[sr.AttachmentID] {
			return
		}
		seen[sr.AttachmentID] = true
		keep = append(keep, sr)
	}
	for i := len(seals) - 1; i >= 0; i-- {
		if refs[seals[i].AttachmentID] {
			add(seals[i])
		}
	}
	recent := 0
	for i := len(seals) - 1; i >= 0 && recent < recentSeals; i-- {
		if !seen[seals[i].AttachmentID] {
			add(seals[i])
			recent++
		}
	}
	slices.Reverse(keep)
	return keep
}

// clearForceRecover removes the force-recover annotation after it was used.
func (r *StateReconciler) clearForceRecover(ctx context.Context, st *v1.BlipState) error {
	fresh := &v1.BlipState{}
	if err := r.Live.Get(ctx, client.ObjectKeyFromObject(st), fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	if _, ok := fresh.Annotations[v1.AnnotationForceRecover]; !ok {
		return nil
	}
	base := fresh.DeepCopy()
	delete(fresh.Annotations, v1.AnnotationForceRecover)
	return client.IgnoreNotFound(patchObject(ctx, r.Client, fresh, base))
}

// repair replaces placements on draining, unhealthy, or deleted nodes and
// tops up missing replicas. Old placements are dropped once every remaining
// placement holds the committed version.
func (r *StateReconciler) repair(st *v1.BlipState, cl *cluster) string {
	s := &st.Status
	id := s.Committed.ID
	var good, bad []string
	for _, n := range s.Placements {
		if cl.bad(n) {
			bad = append(bad, n)
		} else {
			good = append(good, n)
		}
	}
	if missing := replicas(st) - len(good); missing > 0 {
		var holders []string
		for _, n := range cl.names {
			if cl.holds(st, n, id) {
				holders = append(holders, n)
			}
		}
		add := cl.choose(missing, st.Spec.NodeSelector, holders, s.Placements)
		s.Placements = append(s.Placements, add...)
		good = append(good, add...)
	}
	var waiting, errs []string
	for _, n := range good {
		if !cl.holds(st, n, id) {
			waiting = append(waiting, n)
			for _, o := range st.Status.Nodes {
				if o.Node == n && o.Error != "" && cl.currentObservation(o) {
					errs = append(errs, fmt.Sprintf("%s: %s", n, o.Error))
				}
			}
		}
	}
	s.LastError = strings.Join(errs, "; ")
	if len(bad) > 0 && len(good) > 0 && len(waiting) == 0 {
		s.Placements = good
		return ""
	}
	if len(waiting) > 0 {
		return "replicating to " + strings.Join(waiting, ", ")
	}
	if len(good) < replicas(st) && st.Spec.Image == "" {
		msg := fmt.Sprintf("%d of %d replicas; no other node can take one", len(good), replicas(st))
		if len(bad) > 0 {
			msg += " (" + strings.Join(bad, ", ") + " is draining or unhealthy)"
		}
		return msg
	}
	return ""
}

// blipBlocksDeletion reports whether b still uses st in a way that must
// outlive the state. Merely naming st in spec is not a use: a queued Blip
// that has not acquired a writer, a mount, or a pod cannot make progress
// against a terminating state. Treating it as a blocker would deadlock the
// state finalizer against that Pending Blip. The Blip controller fails such
// a Blip as soon as it observes the deletion.
func blipBlocksDeletion(b *v1.Blip, st *v1.BlipState) bool {
	if v1.Finished(b) {
		return false
	}
	// Only actual root use counts; offline profile references never block
	// deletion, even when some other filesystem is running or saving.
	if b.Spec.State == st.Name && (b.Status.RootAttachmentID != "" || b.Status.Pod != "") {
		return true
	}
	if w := st.Status.Writer; w != nil && w.BlipUID == string(b.UID) {
		return true
	}
	// An attachment was already assigned to the Blip. For a read-only
	// mount there is no writer slot on the state, so this is the only
	// record that the disk is about to be used.
	for _, m := range b.Status.Mounts {
		if m.State == st.Name && m.StateUID == string(st.UID) && m.AttachmentID != "" {
			return true
		}
	}
	return false
}

// deletionBlockers lists what keeps a deleted state alive.
func (r *StateReconciler) deletionBlockers(ctx context.Context, st *v1.BlipState) ([]string, error) {
	var out []string
	if w := st.Status.Writer; w != nil {
		out = append(out, "writer "+w.BlipName)
	}
	if st.Status.Pending != nil {
		if st.Status.Writer == nil {
			// Nothing is using the in-flight build or fetch yet. Nodes
			// finish it harmlessly; waiting for it would keep a failed
			// initial version alive forever.
			st.Status.Pending = nil
		} else {
			out = append(out, "pending version")
		}
	}
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(st.Namespace), client.MatchingFields{indexStates: st.Name}); err != nil {
		return nil, err
	}
	for _, b := range blips.Items {
		if !blipBlocksDeletion(&b, st) {
			continue
		}
		if w := st.Status.Writer; w != nil && w.BlipUID == string(b.UID) {
			// Already reported above; naming the holder twice only
			// makes the message noisier.
			continue
		}
		out = append(out, "blip "+b.Name)
	}
	var states v1.BlipStateList
	if err := r.deletionCopiesReader().List(ctx, &states, client.InNamespace(st.Namespace)); err != nil {
		return nil, err
	}
	for _, c := range states.Items {
		if c.Name == st.Name || c.Spec.CopyFrom != st.Name {
			continue
		}
		if copyBlocksDeletion(&c, st) {
			out = append(out, "copy "+c.Name)
		}
	}
	for _, root := range states.Items {
		if root.Name == st.Name || root.DeletionTimestamp != nil {
			continue
		}
		for _, m := range root.Spec.Mounts {
			if m.State == st.Name && m.BlipUID == "" {
				// A persistent mount reference outlives every execution. A
				// dangling name makes the root unable to fork or start, so
				// block deletion like a live writer or an unfinished copy.
				out = append(out, fmt.Sprintf("mount in root state %q (unmount it first)", root.Name))
				break
			}
		}
	}
	return out, nil
}

// deletionCopiesReader is the uncached reader used to confirm that no copy
// still needs a deleting source. A just-created copy may not be in the cache
// when the deletion is confirmed.
func (r *StateReconciler) deletionCopiesReader() client.Reader {
	if r.Live != nil {
		return r.Live
	}
	return r.Client
}

// copyBlocksDeletion reports whether a copy still needs the source state's
// data. A copy can only use the source while it is making progress: one that
// failed terminally (for example a size smaller than the source) will never
// commit, and one that is being deleted is no longer built by the controller.
// Neither may pin the source's finalizer forever.
//
// A copy pins its source from creation: status.copiedFrom is only written when
// the copy is first reconciled, so a copy that has not planned yet must still
// block deletion. Otherwise deleting the source in that window loses the only
// snapshot the copy could have taken.
func copyBlocksDeletion(c, src *v1.BlipState) bool {
	if c.DeletionTimestamp != nil || c.Status.Phase == v1.StateFailed || c.Status.Committed != nil {
		return false
	}
	if cf := c.Status.CopiedFrom; cf != nil {
		return cf.StateUID == string(src.UID)
	}
	return c.Spec.CopyFrom == src.Name
}
