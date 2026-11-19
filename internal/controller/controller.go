// Package controller implements blip-controller: the enrollment, node, pool,
// state, and blip reconcilers. See the README's implementation outline.
package controller

import (
	"context"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Field indexes.
const (
	indexPool     = "spec.pool"
	indexStates   = "blip.stateRefs"
	indexCopyFrom = "spec.copyFrom"
	indexMounts   = "state.mountRefs"
	indexMountUID = "state.mountBlipUIDs"
)

// Config configures the controllers.
type Config struct {
	RuntimeImage string
	Registry     Registry
	// Now defaults to time.Now.
	Now func() time.Time
	// NewID generates attachment and commit IDs: 16 lowercase hex characters.
	// It defaults to cryptographic randomness. Hooks are per instance and must
	// be safe for concurrent reconciles when used with a manager.
	NewID func() string
	// NewPodName defaults to the pool name plus a random five-character suffix.
	NewPodName func(pool string) string
	// PodLogs opens the serial console of a VM pod. It is used once when a
	// Blip finishes to preserve the tail of its command output.
	PodLogs func(ctx context.Context, namespace, pod string) (io.ReadCloser, error)
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) newID() string {
	if c.NewID != nil {
		return c.NewID()
	}
	return newID()
}

func (c *Config) newPodName(pool string) string {
	if c.NewPodName != nil {
		return c.NewPodName(pool)
	}
	return pool + "-" + utilrand.String(5)
}

// Indexes lists the field indexes the reconcilers rely on.
var Indexes = []struct {
	Obj     client.Object
	Field   string
	Extract client.IndexerFunc
}{
	{&v1.Blip{}, indexPool, func(o client.Object) []string { return []string{poolName(o.(*v1.Blip))} }},
	{&v1.Blip{}, indexStates, func(o client.Object) []string { return stateRefs(o.(*v1.Blip)) }},
	{&v1.BlipState{}, indexCopyFrom, func(o client.Object) []string {
		if s := o.(*v1.BlipState).Spec.CopyFrom; s != "" {
			return []string{s}
		}
		return nil
	}},
	{&v1.BlipState{}, indexMounts, func(o client.Object) []string {
		var refs []string
		for _, m := range o.(*v1.BlipState).Spec.Mounts {
			refs = append(refs, m.State)
		}
		return refs
	}},
	{&v1.BlipState{}, indexMountUID, func(o client.Object) []string {
		var refs []string
		for _, m := range o.(*v1.BlipState).Spec.Mounts {
			if m.BlipUID != "" {
				refs = append(refs, m.BlipUID)
			}
		}
		return refs
	}},
}

// Setup registers indexes and all reconcilers with mgr.
func Setup(ctx context.Context, mgr ctrl.Manager, cfg Config) error {
	for _, ix := range Indexes {
		if err := mgr.GetFieldIndexer().IndexField(ctx, ix.Obj, ix.Field, ix.Extract); err != nil {
			return err
		}
	}
	c := mgr.GetClient()
	if err := (&EnrollReconciler{Client: c}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&NodeReconciler{Client: c}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&PoolReconciler{Client: c, Config: cfg}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&StateReconciler{Client: c, Live: mgr.GetAPIReader(), Config: cfg}).SetupWithManager(mgr); err != nil {
		return err
	}
	return (&BlipReconciler{Client: c, Config: cfg}).SetupWithManager(mgr)
}

func poolName(b *v1.Blip) string {
	if b.Spec.Pool == "" {
		return "default"
	}
	return b.Spec.Pool
}

// stateRefs are the states a Blip references from its spec or status.
func stateRefs(b *v1.Blip) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(b.Spec.State)
	for _, m := range b.Status.Mounts {
		add(m.State)
	}
	return out
}

func isVacant(p *corev1.Pod) bool { return p.Labels[v1.LabelBlipUID] == "" }

func podTerminated(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

func req(namespace, name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}
}
