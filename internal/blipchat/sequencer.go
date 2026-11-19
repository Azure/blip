package blipchat

import (
	"context"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// seqRetries bounds how often a turn write or counter write is retried after a
// concurrent update. Conflicts are transient (a producer patching labels, or
// the leader committing a step), so retrying against a fresh object is enough.
const seqRetries = 8

// Sequencer stamps every new turn with the next sequence number of its thread.
// It is the only writer of status.seq and the only writer of
// BlipThread.status.lastSeq, and it is serialized per thread.
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
			// A turn may race its thread. Keep it until the thread exists.
			return ctrl.Result{RequeueAfter: requeueDelay}, nil
		}
		return ctrl.Result{}, err
	}
	if !turnBelongsToThread(&turn, &thread) {
		// A previous incarnation of a same-named thread already sequenced
		// (or owned) this turn. Leave it for pruning; never adopt it.
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, s.sequence(ctx, &thread, &turn)
}

// sequence assigns the next sequence number to turn. The turn write happens
// first: a conflict on the turn is retried without consuming a number, so
// producers updating a turn cannot burn sequence numbers. Only after the turn
// holds its number does the sequencer advance status.lastSeq.
func (s *Sequencer) sequence(ctx context.Context, thread *v1.BlipThread, turn *v1.BlipTurn) error {
	seq := thread.Status.LastSeq + 1
	current := turn
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipTurn{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(turn), current); err != nil {
				return client.IgnoreNotFound(err)
			}
			if current.Status.Seq != 0 {
				// Another sequencer won; do not consume this number.
				return nil
			}
			if !turnBelongsToThread(current, thread) {
				return nil
			}
		}
		current.Status.Seq = seq
		current.Status.ThreadUID = string(thread.UID)
		current.Status.AcceptedTime = &metav1.Time{Time: timeNow()}
		err := s.Status().Update(ctx, current)
		if err == nil {
			return s.advanceLastSeq(ctx, thread, seq)
		}
		if !apierrors.IsConflict(err) || attempt+1 >= seqRetries {
			return err
		}
	}
}

// advanceLastSeq persists a reserved sequence number. It retries conflicts
// against a fresh thread so a concurrent coordinator commit cannot leave the
// counter behind.
func (s *Sequencer) advanceLastSeq(ctx context.Context, thread *v1.BlipThread, seq int64) error {
	current := thread
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			current = &v1.BlipThread{}
			if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
				return err
			}
		}
		if current.Status.LastSeq >= seq {
			thread.Status.LastSeq = current.Status.LastSeq
			return nil
		}
		current.Status.LastSeq = seq
		err := s.Status().Update(ctx, current)
		if err == nil {
			thread.Status.LastSeq = seq
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
	return s.advanceLastSeq(ctx, &thread, turn.Status.Seq)
}

// SetupWithManager registers the sequencer.
func (s *Sequencer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&v1.BlipTurn{}).Complete(s)
}
