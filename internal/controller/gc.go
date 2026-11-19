package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// DefaultTerminatedBlipGCThreshold is how many finished Blips may remain
// before the oldest are deleted.
const DefaultTerminatedBlipGCThreshold = 1000

// blipGCInterval is how often the garbage collector looks for excess finished
// Blips.
const blipGCInterval = time.Minute

// CollectTerminatedBlips deletes the oldest finished Blips when more than
// threshold of them remain in a namespace. A finished Blip is Succeeded or
// Failed, is not already being deleted, and is ordered by status.finishTime
// (missing finish times are oldest). Each namespace is collected against its
// own threshold, so one namespace cannot evict another's finished Blips. It
// returns how many Blips it deleted. A non-positive threshold disables
// collection.
func CollectTerminatedBlips(ctx context.Context, c client.Client, threshold int) (int, error) {
	if threshold <= 0 {
		return 0, nil
	}
	var list v1.BlipList
	if err := c.List(ctx, &list); err != nil {
		return 0, err
	}
	byNamespace := map[string][]v1.Blip{}
	for _, b := range list.Items {
		if b.DeletionTimestamp == nil && v1.Finished(&b) {
			byNamespace[b.Namespace] = append(byNamespace[b.Namespace], b)
		}
	}
	var errs []error
	deleted := 0
	for namespace, finished := range byNamespace {
		if len(finished) <= threshold {
			continue
		}
		sort.Slice(finished, func(i, j int) bool {
			a, b := &finished[i], &finished[j]
			// A missing finish time sorts as the oldest.
			if (a.Status.FinishTime == nil) != (b.Status.FinishTime == nil) {
				return a.Status.FinishTime == nil
			}
			if a.Status.FinishTime != nil && !a.Status.FinishTime.Time.Equal(b.Status.FinishTime.Time) {
				return a.Status.FinishTime.Before(b.Status.FinishTime)
			}
			if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
				return a.CreationTimestamp.Before(&b.CreationTimestamp)
			}
			return a.Name < b.Name
		})
		for i := 0; i < len(finished)-threshold; i++ {
			b := &finished[i]
			if err := c.Delete(ctx, b); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				errs = append(errs, fmt.Errorf("delete blip %s/%s: %w", namespace, b.Name, err))
				continue
			}
			deleted++
		}
	}
	return deleted, errors.Join(errs...)
}

// terminatedBlipGC periodically collects excess finished Blips in each
// namespace. Only the leader runs it.
type terminatedBlipGC struct {
	client    client.Client
	threshold int
}

// NewTerminatedBlipGC returns a manager.Runnable that garbage-collects
// finished Blips. A threshold of zero or less disables it.
func NewTerminatedBlipGC(c client.Client, threshold int) manager.Runnable {
	return &terminatedBlipGC{client: c, threshold: threshold}
}

// NeedLeaderElection makes the manager run the collector only on the leader.
func (g *terminatedBlipGC) NeedLeaderElection() bool { return true }

// Start runs an initial collection pass and then one per interval until ctx is
// canceled.
func (g *terminatedBlipGC) Start(ctx context.Context) error {
	if g.threshold <= 0 {
		return nil
	}
	log := ctrl.Log.WithName("terminated-blip-gc")
	g.collect(ctx, log)
	ticker := time.NewTicker(blipGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			g.collect(ctx, log)
		}
	}
}

func (g *terminatedBlipGC) collect(ctx context.Context, log logr.Logger) {
	deleted, err := CollectTerminatedBlips(ctx, g.client, g.threshold)
	if err != nil {
		log.Error(err, "collecting terminated blips")
	}
	if deleted > 0 {
		log.Info("deleted terminated blips", "count", deleted)
	}
}
