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
	if turn.Status.Seq != 0 || turn.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
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
	seq := thread.Status.LastSeq + 1
	thread.Status.LastSeq = seq
	if err := s.Status().Update(ctx, &thread); err != nil {
		return ctrl.Result{}, err
	}
	turn.Status.Seq = seq
	turn.Status.AcceptedTime = &metav1.Time{Time: timeNow()}
	if err := s.Status().Update(ctx, &turn); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the sequencer.
func (s *Sequencer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&v1.BlipTurn{}).Complete(s)
}
