package blipchat

import (
	"context"
	"sort"
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
	mu sync.Map // namespace/name -> *sync.Mutex
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
// their requeues fire is arbitrary; sorting by creation time (then name and
// UID) makes the assigned order deterministic.
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

// sequence assigns a reserved sequence number to turn. The number is claimed
// first with reserveSeq: a number can only be handed out once, even when two
// sequencer processes race on the same thread. If the turn cannot be updated,
// releaseSeq gives the number back so a producer conflict does not leave a
// permanent hole.
func (s *Sequencer) sequence(ctx context.Context, thread *v1.BlipThread, turn *v1.BlipTurn) error {
	if turn.Status.Seq != 0 {
		return nil
	}
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
			s.releaseSeq(ctx, thread, seq)
			return err
		}
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
	if thread.Status.LastSeq >= turn.Status.Seq || !turnBelongsToThread(turn, &thread) {
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
