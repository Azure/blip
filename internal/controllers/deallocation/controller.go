package deallocation

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func Add(mgr ctrl.Manager, ns, pool string) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("deallocation").
		For(&kubevirtv1.VirtualMachine{}).
		WithEventFilter(predicate.Or(
			predicate.AnnotationChangedPredicate{},
			predicate.GenerationChangedPredicate{},
		)).
		Complete(&controller{
			Client:    mgr.GetClient(),
			Namespace: ns,
			PoolName:  pool,
		})
}

type controller struct {
	Client    client.Client
	Namespace string
	PoolName  string
}

func (r *controller) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req.Namespace != r.Namespace {
		return reconcile.Result{}, nil
	}

	var vm kubevirtv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get VM: %w", err)
	}

	ann := vm.GetAnnotations()
	if vm.Labels["blip.io/pool"] != r.PoolName {
		return reconcile.Result{}, nil
	}
	if _, claimed := ann["blip.io/session-id"]; !claimed {
		return reconcile.Result{}, nil
	}

	var reason string
	if ann["blip.io/release"] == "true" {
		reason = "released"
	} else if isExpired(&vm) {
		reason = "expired"
	} else {
		if remaining := timeUntilExpiry(&vm); remaining > 0 {
			return reconcile.Result{RequeueAfter: remaining}, nil
		}
		return reconcile.Result{}, nil
	}

	slog.Info("deleting VM",
		"name", vm.Name,
		"reason", reason,
		"session_id", ann["blip.io/session-id"],
		"claimed_at", ann["blip.io/claimed-at"],
		"max_duration", ann["blip.io/max-duration"],
		"claimed_by", ann["blip.io/claimed-by"],
	)

	if err := r.Client.Delete(ctx, &vm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("delete VM %s: %w", vm.Name, err)
	}

	slog.Info("deleted VM", "name", vm.Name, "reason", reason)
	return reconcile.Result{}, nil
}

// parseClaimTTL extracts the claimed-at timestamp and max-duration from a VM's annotations.
func parseClaimTTL(a metav1.Object) (claimedAt time.Time, maxDuration time.Duration, ok bool) {
	ann := a.GetAnnotations()
	claimedAtStr, found := ann["blip.io/claimed-at"]
	if !found {
		return time.Time{}, 0, false
	}
	maxDurStr, found := ann["blip.io/max-duration"]
	if !found {
		return time.Time{}, 0, false
	}
	claimedAt, err := time.Parse(time.RFC3339, claimedAtStr)
	if err != nil {
		return time.Time{}, 0, false
	}
	maxDurSec, err := strconv.Atoi(maxDurStr)
	if err != nil || maxDurSec <= 0 {
		return time.Time{}, 0, false
	}
	return claimedAt, time.Duration(maxDurSec) * time.Second, true
}

func isExpired(a metav1.Object) bool {
	claimedAt, maxDuration, ok := parseClaimTTL(a)
	if !ok {
		return false
	}
	return time.Since(claimedAt) > maxDuration
}

func timeUntilExpiry(a metav1.Object) time.Duration {
	claimedAt, maxDuration, ok := parseClaimTTL(a)
	if !ok {
		return 0
	}
	remaining := time.Until(claimedAt.Add(maxDuration))
	if remaining < 0 {
		return 0
	}
	return remaining
}
