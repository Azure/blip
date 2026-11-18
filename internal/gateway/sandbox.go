package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/workspace"
)

// fullSandboxName joins the owner and sandbox name. The owner is a DNS label,
// which cannot contain ".", so "." separates the two parts unambiguously:
// alice/"dev-default" and alice-dev/"default" produce different names.
func fullSandboxName(owner, name string) (string, error) {
	full := v1alpha1.OwnerPrefix(owner) + name
	if len(full) > 63 {
		return "", fmt.Errorf("sandbox name %q is too long", full)
	}
	return full, nil
}

// SandboxName maps an SSH user name to a sandbox name.
func SandboxName(user string) (string, error) {
	if user == "" {
		return "default", nil
	}
	if !dnsLabel.MatchString(user) {
		return "", fmt.Errorf("invalid sandbox name %q: use lowercase letters, digits and '-'", user)
	}
	return user, nil
}

// ensureSandbox makes sure the sandbox's state exists and its interactive
// blip runs, and returns the blip's pod. It is idempotent and safe to run
// from several gateway replicas at once. Existing resources are only served
// when they belong to owner.
func (s *Server) ensureSandbox(ctx context.Context, owner, name string) (string, error) {
	if err := s.ensureState(ctx, owner, name); err != nil {
		return "", err
	}
	// The shared catalog already watches every state and Blip for this owner,
	// so one session must not add a watch or poll loop of its own.
	changes, unsubscribe := s.Catalog.Subscribe(owner)
	defer unsubscribe()
	key := client.ObjectKey{Namespace: s.Namespace, Name: name}
	recreated := false
	for {
		var b v1alpha1.Blip
		err := s.Kube.Get(ctx, key, &b)
		switch {
		case apierrors.IsNotFound(err):
			if err := s.Kube.Create(ctx, s.sandboxBlip(owner, name)); err != nil && !apierrors.IsAlreadyExists(err) {
				return "", err
			}
			continue
		case err != nil:
			return "", err
		case !ownedResource(&b, owner):
			return "", fmt.Errorf("sandbox %s is not owned by the authenticated owner", name)
		case b.DeletionTimestamp == nil && v1alpha1.Finished(&b):
			if recreated {
				return "", fmt.Errorf("sandbox %s stopped while starting: %s %s", name, b.Status.Reason, b.Status.Message)
			}
			recreated = true
			if err := s.recreateFinished(ctx, &b); err != nil {
				return "", err
			}
			s.Log.Info("recreating finished sandbox", "sandbox", name, "phase", b.Status.Phase)
			continue
		case b.DeletionTimestamp == nil && b.Status.Reason == "StateNotFound":
			// The state can disappear between ensureState and the Blip
			// starting, for example when an admin deletes it. Recreate it so
			// the pending Blip can proceed instead of hanging the SSH client.
			if err := s.ensureState(ctx, owner, name); err != nil {
				return "", err
			}
			continue
		case b.DeletionTimestamp == nil && !b.Spec.Stop && b.Status.Phase == v1alpha1.BlipRunning && b.Status.Pod != "":
			return b.Status.Pod, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for sandbox %s: %w", name, ctx.Err())
		case _, ok := <-changes:
			if !ok {
				return "", fmt.Errorf("waiting for sandbox %s: %w", name, errors.New("sandbox catalog is stopped"))
			}
		}
	}
}

// recreateFinished deletes a finished Blip so a fresh worker can start in its
// place. The preconditions keep the delete from touching a replacement, and
// orphan propagation preserves the state and anything that names the old
// worker as an owner. Both callers re-read and revalidate after the delete, so
// a lost race (NotFound) or a changed object (Conflict) is not an error.
func (s *Server) recreateFinished(ctx context.Context, b *v1alpha1.Blip) error {
	err := s.Kube.Delete(ctx, b,
		client.Preconditions{UID: &b.UID, ResourceVersion: &b.ResourceVersion},
		client.PropagationPolicy(metav1.DeletePropagationOrphan))
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return err
	}
	return nil
}

func (s *Server) ensureState(ctx context.Context, owner, name string) error {
	key := client.ObjectKey{Namespace: s.Namespace, Name: name}
	for {
		var st v1alpha1.BlipState
		if err := s.Kube.Get(ctx, key, &st); err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
			source, err := s.baseState(ctx)
			if err != nil {
				return err
			}
			if _, err := s.forkState(ctx, owner, name, source); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					return err
				}
				// A child-name conflict is not a root creation race. Only
				// accept a concurrent fork when its root actually exists.
				if getErr := s.Kube.Get(ctx, key, &st); getErr != nil {
					if apierrors.IsNotFound(getErr) {
						return err
					}
					return getErr
				}
			} else {
				s.Log.Info("created sandbox state", "state", name, "base-state", s.BaseState)
				return nil
			}
		}
		if !ownedResource(&st, owner) {
			return fmt.Errorf("sandbox state %s is not owned by the authenticated owner", name)
		}
		if st.DeletionTimestamp != nil {
			// Wait for the old state to disappear so the Blip can start on
			// the replacement instead of seeing a state that is going away.
			if err := s.waitStateGone(ctx, key); err != nil {
				return err
			}
			continue
		}
		if st.Status.Phase == v1alpha1.StateFailed {
			return fmt.Errorf("sandbox state %s failed: %s", name, st.Status.Message)
		}
		if st.Spec.Image != "" {
			return fmt.Errorf("sandbox state %s is an imported image and cannot be run directly", name)
		}
		return nil
	}
}

func (s *Server) baseState(ctx context.Context) (*v1alpha1.BlipState, error) {
	if s.BaseState == "" {
		return nil, fmt.Errorf("sandbox base state is not configured")
	}
	var st v1alpha1.BlipState
	if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: s.BaseState}, &st); err != nil {
		return nil, err
	}
	if !sharedImage(&st) {
		return nil, fmt.Errorf("sandbox base state %s is not a shared image import", st.Name)
	}
	return &st, nil
}

func (s *Server) forkState(ctx context.Context, owner, name string, source *v1alpha1.BlipState) (*v1alpha1.BlipState, error) {
	if err := validateForkState(source, owner); err != nil {
		return nil, err
	}
	// Check every inherited reference before Fork creates any states. The
	// controller permits owner-prefixed states and shared image imports only.
	for _, m := range source.Spec.Mounts {
		if m.BlipUID != "" {
			continue
		}
		var mounted v1alpha1.BlipState
		if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: m.State}, &mounted); err != nil {
			return nil, fmt.Errorf("read inherited mount %s: %w", m.State, err)
		}
		if err := validateForkState(&mounted, owner); err != nil {
			return nil, fmt.Errorf("inherited mount %s: %w", m.State, err)
		}
	}
	// Apply the gateway default to the copied runtime, leaving explicit source
	// defaults (including a zero timeout) authoritative for future executions.
	source = source.DeepCopy()
	if s.IdleTimeout > 0 {
		if source.Spec.Runtime == nil {
			source.Spec.Runtime = &v1alpha1.RuntimeDefaults{}
		}
		if source.Spec.Runtime.IdleTimeout == nil {
			source.Spec.Runtime.IdleTimeout = &metav1.Duration{Duration: s.IdleTimeout}
		}
	}
	dest := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: map[string]string{v1alpha1.LabelOwner: owner}},
		Spec:       v1alpha1.BlipStateSpec{Size: s.baseForkSize(source)},
	}
	if err := workspace.Fork(ctx, s.Kube, source, dest); err != nil {
		return nil, err
	}
	return dest, nil
}

func validateForkState(st *v1alpha1.BlipState, owner string) error {
	if !accessibleState(st, owner) {
		return fmt.Errorf("state %s is not owned by %s with its name prefix or a shared image import", st.Name, owner)
	}
	return workspace.CheckSource(st)
}

func (s *Server) baseForkSize(source *v1alpha1.BlipState) *resource.Quantity {
	// A new sandbox inherits its base size. The gateway may request extra
	// space, but never shrink the base. If the base has not resolved its size
	// yet, let the controller inherit it once available.
	if s.StateSize.Sign() <= 0 || source.Spec.Size == nil && source.Status.SizeBytes <= 0 {
		return nil
	}
	size := s.StateSize.DeepCopy()
	if source.Spec.Size != nil && source.Spec.Size.Cmp(size) > 0 {
		size = source.Spec.Size.DeepCopy()
	}
	if source.Status.SizeBytes > size.Value() {
		size = *resource.NewQuantity(source.Status.SizeBytes, resource.BinarySI)
	}
	return &size
}

// waitStateGone waits until the state is deleted. A state that stops being
// deleted is an error: deletion cannot be canceled.
func (s *Server) waitStateGone(ctx context.Context, key client.ObjectKey) error {
	return wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		var st v1alpha1.BlipState
		err := s.Kube.Get(ctx, key, &st)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if st.DeletionTimestamp == nil {
			return false, fmt.Errorf("sandbox state %s is not being deleted", key.Name)
		}
		return false, nil
	})
}

func (s *Server) sandboxBlip(owner, name string) *v1alpha1.Blip {
	return &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: map[string]string{v1alpha1.LabelOwner: owner}},
		Spec:       v1alpha1.BlipSpec{Pool: s.Pool, State: name},
	}
}
