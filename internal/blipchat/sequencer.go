package blipchat

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// seqRetries bounds how often a turn write or counter write is retried after a
// concurrent update. Conflicts are transient (a producer patching labels, or
// the leader committing a step), so retrying against a fresh object is enough.
const seqRetries = 8

// orphanGrace is how long a turn may race its thread before blipchat stops
// retrying it. A turn whose spec.thread is not a valid thread name can never
// be claimed and is terminal immediately.
const orphanGrace = 10 * time.Minute

// Sequencer stamps every new turn with the next sequence number of its thread.
// It is the only writer of status.seq and the only writer of
// BlipThread.status.lastSeq. Only the elected leader runs it; the deployment
// passes --leader-elect.
//
// The per-thread mutex serializes reconciles inside one process. Sequence
// allocation additionally uses a compare-and-swap on thread.status.lastSeq,
// so even a second process with its own mutex cannot hand out the same number.
type Sequencer struct {
	client.Client
	// Live is an uncached reader used to resolve an ambiguous turn write:
	// the cache may not show a status update that the API server committed
	// just before returning an error. It defaults to the manager's
	// APIReader; tests fall back to Client.
	Live client.Reader
	mu   sync.Map // namespace/name -> *sync.Mutex
}

func (s *Sequencer) liveReader() client.Reader {
	if s.Live != nil {
		return s.Live
	}
	return s.Client
}

func (s *Sequencer) lock(namespace, name string) func() {
	value, _ := s.mu.LoadOrStore(namespace+"/"+name, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Sequencer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var turn v1.BlipTurn
	if err := s.Get(ctx, req.NamespacedName, &turn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if turn.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	if turn.Status.Seq != 0 {
		// The turn was sequenced, but the process may have stopped before the
		// counter was persisted. Repair a lagging counter so it still names the
		// highest reserved sequence.
		return ctrl.Result{}, s.repairLastSeq(ctx, &turn)
	}
	key := client.ObjectKey{Namespace: turn.Namespace, Name: turn.Spec.Thread}
	unlock := s.lock(key.Namespace, key.Name)
	defer unlock()

	var thread v1.BlipThread
	if err := s.Get(ctx, key, &thread); err != nil {
		if apierrors.IsNotFound(err) {
			return s.orphan(ctx, &turn)
		}
		return ctrl.Result{}, err
	}
	if !turnBelongsToThread(&turn, &thread) {
		// A previous incarnation of a same-named thread already sequenced
		// (or owned) this turn. Leave it for pruning; never adopt it.
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, s.sequenceThread(ctx, &thread)
}

// sequenceThread numbers every waiting turn of a thread in creation order.
// Turns may be created before their thread exists, and the order in which
// their requeues fire is arbitrary; sorting by creation time (then
// resourceVersion, name, and UID) makes the assigned order deterministic.
// creationTimestamp has only second resolution, so several turns created in
// one second share it; resourceVersion preserves their write order.
func (s *Sequencer) sequenceThread(ctx context.Context, thread *v1.BlipThread) error {
	var turns v1.BlipTurnList
	if err := s.List(ctx, &turns, client.InNamespace(thread.Namespace), client.MatchingFields{turnField: thread.Name}); err != nil {
		return err
	}
	pending := make([]v1.BlipTurn, 0, len(turns.Items))
	for i := range turns.Items {
		t := &turns.Items[i]
		if t.Status.Seq != 0 || t.DeletionTimestamp != nil || !turnBelongsToThread(t, thread) {
			continue
		}
		pending = append(pending, *t)
	}
	sort.SliceStable(pending, func(i, j int) bool {
		a, b := &pending[i], &pending[j]
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			return a.CreationTimestamp.Before(&b.CreationTimestamp)
		}
		if c := compareResourceVersions(a.ResourceVersion, b.ResourceVersion); c != 0 {
			return c < 0
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.UID < b.UID
	})
	for i := range pending {
		if err := s.sequence(ctx, thread, &pending[i]); err != nil {
			return err
		}
	}
	return nil
}

// compareResourceVersions orders two resourceVersion strings. Kubernetes
// treats resourceVersion as opaque, but the API server assigns decimal values
// that increase with every write, so compare numerically when both parse.
// Otherwise (an empty string, or a value from another storage backend) fall
// back to lexical order to keep the tie-break deterministic.
func compareResourceVersions(a, b string) int {
	au, aerr := strconv.ParseUint(a, 10, 64)
	bu, berr := strconv.ParseUint(b, 10, 64)
	if aerr == nil && berr == nil {
		switch {
		case au < bu:
			return -1
		case au > bu:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

// sequence assigns a reserved sequence number to turn. The number is claimed
// first with reserveSeq: a number can only be handed out once, even when two
// sequencer processes race on the same thread. If the turn cannot be updated,
// releaseSeq gives the number back so a producer conflict does not leave a
// permanent hole.
func (s *Sequencer) sequence(ctx context.Context, thread *v1.BlipThread, turn *v1.BlipTurn) error {
	if turn.Status.Seq != 0 {
		return nil
	}
	if err := s.ensureTurnLabels(ctx, thread, turn); err != nil {
		return err
	}
	// The label patch decodes the API server response into turn, so it also
	// refreshes a status.seq a peer wrote while the patch was in flight. That
	// fresh resourceVersion would let our status write succeed and resequence
	// an already sealed turn. Re-read after labeling and never overwrite an
	// assigned sequence: it is immutable, and the peer's write is success.
	var refreshed v1.BlipTurn
	if err := s.liveReader().Get(ctx, client.ObjectKeyFromObject(turn), &refreshed); err != nil {
		return client.IgnoreNotFound(err)
	}
	if refreshed.Status.Seq != 0 {
		return nil
	}
	if !turnBelongsToThread(&refreshed, thread) {
		return nil
	}
	*turn = refreshed
	seq, err := s.reserveSeq(ctx, thread)
	if err != nil {
		return err
	}
	current := turn
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipTurn{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(turn), current); err != nil {
				s.releaseSeq(ctx, thread, seq)
				return client.IgnoreNotFound(err)
			}
			if current.Status.Seq != 0 {
				// Another sequencer won the turn. Give our number back unless
				// the winner used it (for example a peer that read the counter
				// before our CAS landed), in which case the counter must stay.
				if current.Status.Seq != seq {
					s.releaseSeq(ctx, thread, seq)
				}
				return nil
			}
			if !turnBelongsToThread(current, thread) {
				s.releaseSeq(ctx, thread, seq)
				return nil
			}
		}
		current.Status.Seq = seq
		current.Status.ThreadUID = string(thread.UID)
		current.Status.OrphanedAt = nil
		current.Status.AcceptedTime = &metav1.Time{Time: timeNow()}
		err := s.Status().Update(ctx, current)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) || attempt+1 >= seqRetries {
			return s.abandonSeq(ctx, thread, turn, seq, err)
		}
	}
}

// abandonSeq handles a failed turn-status write. The write is ambiguous: the
// API server may have committed it and only the response was lost, so the
// number may already be recorded on the turn. Re-read before giving the
// reservation back. A number is released only when the turn provably does not
// carry it; a failed re-read keeps it reserved, because a hole is recoverable
// but a duplicate sequence is not.
func (s *Sequencer) abandonSeq(ctx context.Context, thread *v1.BlipThread, turn *v1.BlipTurn, seq int64, cause error) error {
	var current v1.BlipTurn
	err := s.liveReader().Get(ctx, client.ObjectKeyFromObject(turn), &current)
	switch {
	case err == nil && current.Status.Seq == seq:
		// Our write landed; only the reply was lost. Keep the counter.
		return nil
	case err == nil:
		// The turn does not carry our number (still unsequenced, or a peer
		// numbered it differently), so this reservation is unused.
		s.releaseSeq(ctx, thread, seq)
		return cause
	case apierrors.IsNotFound(err):
		// The turn is gone, so no live turn can carry the number.
		s.releaseSeq(ctx, thread, seq)
		return cause
	default:
		return cause
	}
}

// reserveSeq claims the next sequence number for thread by advancing
// status.lastSeq with a compare-and-swap. A conflict means another writer (a
// second sequencer, or the coordinator updating another status field) got
// there first, so it re-reads the thread and recomputes the number instead of
// reusing the stale in-memory lastSeq. Exhausting the retries is an error;
// an already-used number is never returned as success.
func (s *Sequencer) reserveSeq(ctx context.Context, thread *v1.BlipThread) (int64, error) {
	current := thread
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipThread{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
				return 0, err
			}
		}
		seq := current.Status.LastSeq + 1
		current.Status.LastSeq = seq
		err := s.Status().Update(ctx, current)
		if err == nil {
			// The name may have been deleted and recreated during a
			// conflicting CAS. Copy the whole refreshed object, including
			// its UID, so the turn is pinned to the live incarnation rather
			// than stamping a dead thread UID.
			*thread = *current
			return seq, nil
		}
		if !apierrors.IsConflict(err) || attempt+1 >= seqRetries {
			return 0, err
		}
	}
}

// releaseSeq returns a reserved but unused number. It rewinds the counter only
// while it still names our reservation, so it can never move lastSeq below a
// number another writer has already claimed.
func (s *Sequencer) releaseSeq(ctx context.Context, thread *v1.BlipThread, seq int64) {
	current := thread
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipThread{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
				return
			}
		}
		if current.Status.LastSeq != seq {
			*thread = *current
			return
		}
		current.Status.LastSeq = seq - 1
		err := s.Status().Update(ctx, current)
		if err == nil {
			*thread = *current
			return
		}
		if !apierrors.IsConflict(err) || attempt+1 >= seqRetries {
			return
		}
	}
}

// raiseLastSeq repairs a lagging counter after a turn was numbered by an
// earlier process. It never assigns a number to a turn; reserveSeq is the only
// path that hands out new numbers. A counter that already covers seq needs no
// repair, so this can be retried safely.
func (s *Sequencer) raiseLastSeq(ctx context.Context, thread *v1.BlipThread, seq int64) error {
	current := thread
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipThread{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
				return err
			}
		}
		if current.Status.LastSeq >= seq {
			*thread = *current
			return nil
		}
		current.Status.LastSeq = seq
		err := s.Status().Update(ctx, current)
		if err == nil {
			*thread = *current
			return nil
		}
		if !apierrors.IsConflict(err) || attempt+1 >= seqRetries {
			return err
		}
	}
}

// repairLastSeq advances a lagging counter after a turn was sequenced but its
// counter write failed. It never touches a turn from another incarnation.
func (s *Sequencer) repairLastSeq(ctx context.Context, turn *v1.BlipTurn) error {
	key := client.ObjectKey{Namespace: turn.Namespace, Name: turn.Spec.Thread}
	var thread v1.BlipThread
	if err := s.Get(ctx, key, &thread); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !turnBelongsToThread(turn, &thread) {
		return nil
	}
	// Backfill the incarnation label on turns created before it existed, and
	// migrate a long thread's old name-derived label. Only turns of the
	// current incarnation get here; stale turns keep their old labels.
	if err := s.ensureTurnLabels(ctx, &thread, turn); err != nil {
		return err
	}
	if thread.Status.LastSeq >= turn.Status.Seq {
		return nil
	}
	unlock := s.lock(key.Namespace, key.Name)
	defer unlock()
	if err := s.Get(ctx, key, &thread); err != nil {
		return client.IgnoreNotFound(err)
	}
	if thread.Status.LastSeq >= turn.Status.Seq {
		return nil
	}
	return s.raiseLastSeq(ctx, &thread, turn.Status.Seq)
}

// ensureTurnLabels stamps a turn with the current thread label, incarnation,
// and owner. New turns already carry them; this backfills turns created before
// the incarnation label existed, rewrites a long thread's old name-derived
// hash to the reserved thread_ form, and owns turns created directly through
// the API so deleting the thread deletes them. Only a turn already known to
// belong to the current incarnation is passed here.
func (s *Sequencer) ensureTurnLabels(ctx context.Context, thread *v1.BlipThread, turn *v1.BlipTurn) error {
	wantThread, wantUID := v1.ThreadLabel(thread.Name), string(thread.UID)
	labelsOK := turn.Labels[v1.LabelThread] == wantThread && (wantUID == "" || turn.Labels[v1.LabelThreadUID] == wantUID)
	owned := wantUID == "" || hasThreadOwnerRef(turn, thread)
	if labelsOK && owned {
		return nil
	}
	patch := client.MergeFrom(turn.DeepCopy())
	if !labelsOK {
		if turn.Labels == nil {
			turn.Labels = map[string]string{}
		}
		turn.Labels[v1.LabelThread] = wantThread
		if wantUID != "" {
			turn.Labels[v1.LabelThreadUID] = wantUID
		}
	}
	if !owned {
		// No controller or blockOwnerDeletion flag: the sequencer binds the
		// turn to the thread incarnation for garbage collection without
		// taking ownership of any other field. Existing references (such as
		// the controller reference createTurnIn writes) are preserved.
		turn.OwnerReferences = append(turn.OwnerReferences, metav1.OwnerReference{
			APIVersion: v1.GroupVersion.String(),
			Kind:       "BlipThread",
			Name:       thread.Name,
			UID:        thread.UID,
		})
	}
	return s.Patch(ctx, turn, patch)
}

// hasThreadOwnerRef reports whether turn already references this thread as an
// owner. A reference to any incarnation of the thread is enough: adding a
// second BlipThread reference would give the turn two owners, and a turn of a
// previous incarnation must not be adopted or rewritten.
func hasThreadOwnerRef(turn *v1.BlipTurn, thread *v1.BlipThread) bool {
	for _, ref := range turn.OwnerReferences {
		if ref.APIVersion == v1.GroupVersion.String() && ref.Kind == "BlipThread" && ref.Name == thread.Name {
			return true
		}
	}
	return false
}

// orphan decides what to do with a turn whose thread does not exist. A turn
// may race its thread, but only for a bounded grace period: after that (or
// immediately when spec.thread cannot name a thread) blipchat records a
// terminal state and stops requeueing it. Retention then garbage-collects it.
func (s *Sequencer) orphan(ctx context.Context, turn *v1.BlipTurn) (ctrl.Result, error) {
	if turn.Status.OrphanedAt != nil {
		return ctrl.Result{}, nil
	}
	if len(validation.IsDNS1123Subdomain(turn.Spec.Thread)) == 0 {
		if timeNow().Sub(turn.CreationTimestamp.Time) < orphanGrace {
			// The thread may still be arriving.
			return ctrl.Result{RequeueAfter: requeueDelay}, nil
		}
	}
	current := &v1.BlipTurn{}
	if err := s.Get(ctx, client.ObjectKeyFromObject(turn), current); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if current.Status.Seq != 0 || current.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	if current.Status.OrphanedAt == nil {
		current.Status.OrphanedAt = &metav1.Time{Time: timeNow()}
		if err := s.Status().Update(ctx, current); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// turnsForThread maps a newly created thread to the turns already waiting for
// it, so turns that arrived first are sequenced without polling forever.
func (s *Sequencer) turnsForThread(ctx context.Context, obj client.Object) []reconcile.Request {
	thread, ok := obj.(*v1.BlipThread)
	if !ok {
		return nil
	}
	var turns v1.BlipTurnList
	if err := s.List(ctx, &turns, client.InNamespace(thread.Namespace), client.MatchingFields{turnField: thread.Name}); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for i := range turns.Items {
		t := &turns.Items[i]
		if t.Status.Seq != 0 || t.DeletionTimestamp != nil {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(t)})
	}
	return requests
}

// SetupWithManager registers the sequencer. Thread creates are watched so
// turns that were waiting for a thread are sequenced as soon as it appears,
// even after they were marked orphaned.
//
// The sequencer requires leader election: two replicas assigning numbers from
// their own per-thread mutex produced duplicate status.seq values, and a
// duplicate that is stamped after the coordinator consumed that number is
// silently skipped forever.
func (s *Sequencer) SetupWithManager(mgr ctrl.Manager) error {
	if s.Live == nil {
		s.Live = mgr.GetAPIReader()
	}
	needLeaderElection := true
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{NeedLeaderElection: &needLeaderElection}).
		For(&v1.BlipTurn{}).
		Watches(&v1.BlipThread{}, handler.EnqueueRequestsFromMapFunc(s.turnsForThread),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return true },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		Complete(s)
}
