package gateway

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// ownerLabel records the owner a sandbox resource belongs to. The gateway only
// serves resources whose label matches the authenticated owner.
const ownerLabel = "blip.dev/owner"

// fullSandboxName joins the owner and sandbox name. The owner is a DNS label,
// which cannot contain ".", so "." separates the two parts unambiguously:
// alice/"dev-default" and alice-dev/"default" produce different names.
func fullSandboxName(owner, name string) (string, error) {
	full := owner + "." + name
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

func finished(b *v1alpha1.Blip) bool {
	return b.Status.Phase == v1alpha1.BlipSucceeded || b.Status.Phase == v1alpha1.BlipFailed
}

// ensureSandbox makes sure the sandbox's state exists and its interactive
// blip runs, and returns the blip's pod. It is idempotent and safe to run
// from several gateway replicas at once. Existing resources are only served
// when they belong to owner.
func (s *Server) ensureSandbox(ctx context.Context, owner, name string) (string, error) {
	if err := s.ensureState(ctx, owner, name); err != nil {
		return "", err
	}
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
		case b.Labels[ownerLabel] != owner:
			return "", fmt.Errorf("sandbox %s is not owned by the authenticated owner", name)
		case b.DeletionTimestamp == nil && finished(&b):
			if recreated {
				return "", fmt.Errorf("sandbox %s stopped while starting: %s %s", name, b.Status.Reason, b.Status.Message)
			}
			recreated = true
			err := s.Kube.Delete(ctx, &b, client.Preconditions{UID: &b.UID})
			if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
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
		if err := s.waitChange(ctx, key, b.ResourceVersion); err != nil {
			return "", fmt.Errorf("waiting for sandbox %s: %w", name, err)
		}
	}
}

func (s *Server) ensureState(ctx context.Context, owner, name string) error {
	size := s.StateSize
	key := client.ObjectKey{Namespace: s.Namespace, Name: name}
	for {
		st := &v1alpha1.BlipState{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: map[string]string{ownerLabel: owner}},
			Spec:       v1alpha1.BlipStateSpec{Image: s.Image, Size: &size},
		}
		err := s.Kube.Create(ctx, st)
		if err == nil {
			s.Log.Info("created sandbox state", "state", name, "image", s.Image)
			return nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		if err := s.Kube.Get(ctx, key, st); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
		if st.Labels[ownerLabel] != owner {
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
		return nil
	}
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
	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: map[string]string{ownerLabel: owner}},
		Spec:       v1alpha1.BlipSpec{Pool: s.Pool, State: name},
	}
	if s.IdleTimeout > 0 {
		b.Spec.IdleTimeout = &metav1.Duration{Duration: s.IdleTimeout}
	}
	return b
}

// waitChange returns when the blip's resource version differs from rv or the
// blip is gone.
func (s *Server) waitChange(ctx context.Context, key client.ObjectKey, rv string) error {
	w, err := s.Kube.Watch(ctx, &v1alpha1.BlipList{}, client.InNamespace(key.Namespace), client.MatchingFields{"metadata.name": key.Name})
	if err != nil {
		return err
	}
	defer w.Stop()
	var b v1alpha1.Blip
	if err := s.Kube.Get(ctx, key, &b); err != nil || b.ResourceVersion != rv {
		return client.IgnoreNotFound(err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				return nil
			}
			o, isBlip := ev.Object.(*v1alpha1.Blip)
			if ev.Type == watch.Error {
				return nil
			}
			if isBlip && o.Name == key.Name && (ev.Type == watch.Deleted || o.ResourceVersion != rv) {
				return nil
			}
		}
	}
}
