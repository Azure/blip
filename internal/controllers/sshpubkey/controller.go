package sshpubkey

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// LabelUser identifies session ConfigMaps that hold a user's SSH public key.
	LabelUser = "blip.azure.com/user"

	// AnnotationExpiration holds an RFC 3339 expiration timestamp.
	AnnotationExpiration = "blip.azure.com/expiration"

	// AnnotationSubject holds the OIDC subject for audit purposes.
	AnnotationSubject = "blip.azure.com/subject"
)

// Add registers the session controller with the manager.
func Add(mgr ctrl.Manager, ns string) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("session").
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

	// Only process session ConfigMaps with the user label.
	user := cm.Labels[LabelUser]
	if user == "" {
		return reconcile.Result{}, nil
	}

	// Deduplicate: if multiple session ConfigMaps exist for the same user,
	// keep only the one with the latest expiration and delete the rest.
	// This handles races where generateName creates multiple ConfigMaps
	// for the same user (e.g. concurrent auth requests).
	if err := c.deduplicateUserSessions(ctx, &cm, user); err != nil {
		return reconcile.Result{}, fmt.Errorf("deduplicate sessions for user %s: %w", user, err)
	}

	// Re-fetch the ConfigMap — it may have been deleted by deduplication.
	if err := c.Client.Get(ctx, req.NamespacedName, &cm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("re-get ConfigMap: %w", err)
	}

	// If no expiration is set, nothing to do.
	expirationStr, ok := cm.Annotations[AnnotationExpiration]
	if !ok || expirationStr == "" {
		return reconcile.Result{}, nil
	}

	expiration, err := time.Parse(time.RFC3339, expirationStr)
	if err != nil {
		slog.Error("invalid expiration timestamp, ignoring session ConfigMap",
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
		slog.Info("session not yet expired, requeueing",
			"name", cm.Name,
			"user", user,
			"expires_in", remaining.Round(time.Second),
		)
		return reconcile.Result{RequeueAfter: requeue}, nil
	}

	// Expired — delete the ConfigMap.
	slog.Info("deleting expired session ConfigMap",
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

	slog.Info("deleted expired session ConfigMap", "name", cm.Name, "user", user)
	return reconcile.Result{}, nil
}

// deduplicateUserSessions ensures only one session ConfigMap exists per user.
// When multiple ConfigMaps share the same blip.azure.com/user label, the one
// with the latest expiration is kept and all others are deleted. ConfigMaps
// without an expiration annotation are considered to have the lowest priority
// (deleted first). Among ConfigMaps with equal expiration, the one with the
// latest creation timestamp wins (most recently created).
func (c *controller) deduplicateUserSessions(ctx context.Context, triggered *corev1.ConfigMap, user string) error {
	var cms corev1.ConfigMapList
	if err := c.Client.List(ctx, &cms,
		client.InNamespace(c.Namespace),
		client.MatchingLabels{LabelUser: user},
	); err != nil {
		return fmt.Errorf("list session ConfigMaps for user %s: %w", user, err)
	}

	if len(cms.Items) <= 1 {
		return nil
	}

	// Sort: latest expiration first, then latest creation timestamp, then
	// lexicographically greatest name as a deterministic tiebreaker to
	// prevent oscillation when two ConfigMaps have identical timestamps.
	sort.Slice(cms.Items, func(i, j int) bool {
		ei := parseExpiration(cms.Items[i].Annotations[AnnotationExpiration])
		ej := parseExpiration(cms.Items[j].Annotations[AnnotationExpiration])
		if !ei.Equal(ej) {
			return ei.After(ej)
		}
		if !cms.Items[i].CreationTimestamp.Equal(&cms.Items[j].CreationTimestamp) {
			return cms.Items[i].CreationTimestamp.After(cms.Items[j].CreationTimestamp.Time)
		}
		return cms.Items[i].Name > cms.Items[j].Name
	})

	// Keep the first (winner), delete the rest.
	winner := cms.Items[0].Name
	slog.Info("deduplicating session ConfigMaps for user",
		"user", user,
		"total", len(cms.Items),
		"keeping", winner,
	)

	for i := 1; i < len(cms.Items); i++ {
		cm := &cms.Items[i]
		slog.Info("deleting duplicate session ConfigMap",
			"name", cm.Name,
			"user", user,
			"winner", winner,
		)
		if err := c.Client.Delete(ctx, cm); err != nil {
			if k8serrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("delete duplicate ConfigMap %s: %w", cm.Name, err)
		}
	}

	return nil
}

// parseExpiration parses an RFC 3339 timestamp, returning zero time on failure.
func parseExpiration(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
