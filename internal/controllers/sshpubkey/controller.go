package sshpubkey

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TODO: Rename to "session" configmaps
//
// TODO: Always use generateName for these configmaps, dedup in this controller as needed
//
// TODO: Add unit tests

const (
	// LabelUser identifies ConfigMaps that hold a user's SSH public key.
	LabelUser = "blip.azure.com/user"

	// AnnotationExpiration holds an RFC 3339 expiration timestamp.
	AnnotationExpiration = "blip.azure.com/expiration"
)

// Add registers the sshpubkey controller with the manager.
func Add(mgr ctrl.Manager, ns string) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("sshpubkey").
		For(&corev1.ConfigMap{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			_, ok := obj.GetLabels()[LabelUser]
			return ok
		})).
		Complete(&controller{
			Client:    mgr.GetClient(),
			Namespace: ns,
		})
}

type controller struct {
	Client    client.Client
	Namespace string
}

func (c *controller) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req.Namespace != c.Namespace {
		return reconcile.Result{}, nil
	}

	var cm corev1.ConfigMap
	if err := c.Client.Get(ctx, req.NamespacedName, &cm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get ConfigMap: %w", err)
	}

	// Only process ConfigMaps with the user label.
	user := cm.Labels[LabelUser]
	if user == "" {
		return reconcile.Result{}, nil
	}

	// If no expiration is set, nothing to do.
	expirationStr, ok := cm.Annotations[AnnotationExpiration]
	if !ok || expirationStr == "" {
		return reconcile.Result{}, nil
	}

	expiration, err := time.Parse(time.RFC3339, expirationStr)
	if err != nil {
		slog.Error("invalid expiration timestamp, ignoring ConfigMap",
			"name", cm.Name,
			"namespace", cm.Namespace,
			"expiration", expirationStr,
			"error", err,
		)
		return reconcile.Result{}, nil
	}

	remaining := time.Until(expiration)
	if remaining > 0 {
		// Cap requeue duration to handle clock skew and annotation updates.
		const maxRequeue = 1 * time.Hour
		requeue := min(remaining, maxRequeue)
		slog.Info("SSH public key not yet expired, requeueing",
			"name", cm.Name,
			"user", user,
			"expires_in", remaining.Round(time.Second),
		)
		return reconcile.Result{RequeueAfter: requeue}, nil
	}

	// Expired — delete the ConfigMap.
	slog.Info("deleting expired SSH public key ConfigMap",
		"name", cm.Name,
		"namespace", cm.Namespace,
		"user", user,
		"expiration", expirationStr,
	)

	if err := c.Client.Delete(ctx, &cm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("delete ConfigMap %s: %w", cm.Name, err)
	}

	slog.Info("deleted expired SSH public key ConfigMap", "name", cm.Name, "user", user)
	return reconcile.Result{}, nil
}
