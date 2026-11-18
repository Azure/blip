// Package controller implements blip-controller: the node, pool, state, and
// blip reconcilers. See docs/ARCHITECTURE.md.
package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Labels, annotations, and the finalizer (the complete list is in
// docs/ARCHITECTURE.md).
const (
	LabelPool             = "blip.dev/pool"
	LabelBlipUID          = "blip.dev/blip-uid"
	LabelWarm             = "blip.dev/warm"
	LabelEnrolled         = "blip.dev/enrolled"
	LabelHypervisorPrefix = "blip.dev/hypervisor-"
	LabelOwner            = "blip.dev/owner"
	AnnotationBlip        = "blip.dev/blip"
	AnnotationObserved    = "blip.dev/observed"
	// AnnotationEnrollmentDrain marks a drain the controller started because
	// the node stopped matching every pool. It is cleared if the node matches
	// a pool again; a drain without it is an operator drain and is left alone.
	AnnotationEnrollmentDrain = "blip.dev/enrollment-drain"
	// AnnotationPinnedNode marks a VM pod the pool booted for Blips whose
	// data lives on that node; the pod's node affinity allows only it.
	AnnotationPinnedNode = "blip.dev/pinned-node"
	Finalizer            = "blip.dev/finalizer"
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
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
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

func finished(b *v1.Blip) bool {
	return b.Status.Phase == v1.BlipSucceeded || b.Status.Phase == v1.BlipFailed
}

func isVacant(p *corev1.Pod) bool { return p.Labels[LabelBlipUID] == "" }

func podTerminated(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

func req(namespace, name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}
}
