package gateway

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway/menu"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// openState never calls ensureState: a selection pins an existing state, and
// cannot silently recreate it after deletion. Startup waits use the shared
// catalog's events rather than adding a watch or polling loop per SSH session.
//
// guestCtx owns the guest transport and may outlive ctx: the gateway's hangup
// path uses it to deliver HUP and KILL after the SSH connection is gone.
func (s *Server) openState(ctx, guestCtx context.Context, owner string, entry menu.Entry, o wire.Open) (*session.Session, error) {
	if o.OpenID == "" {
		o.OpenID = newOpenID()
	}
	return retryUnreachable(ctx, nil,
		func(startCtx context.Context) (string, error) {
			return s.startSelectedState(startCtx, owner, entry)
		},
		func(pod string) (*session.Session, error) {
			// Confirm that the selected state was not replaced or relabeled
			// while it was starting, before reaching its guest.
			if _, err := s.selectedState(ctx, owner, entry, false); err != nil {
				return nil, err
			}
			return s.Sessions.Open(guestCtx, s.Namespace, pod, o)
		})
}

func (s *Server) startSelectedState(ctx context.Context, owner string, entry menu.Entry) (string, error) {
	changes, unsubscribe := s.Catalog.Subscribe(owner)
	defer unsubscribe()
	recreated := false
	for {
		st, err := s.selectedState(ctx, owner, entry, false)
		if err != nil {
			return "", err
		}
		if st.Status.Phase == v1alpha1.StateFailed {
			return "", fmt.Errorf("sandbox state %s failed: %s", st.Name, st.Status.Message)
		}
		var list v1alpha1.BlipList
		if err := s.Kube.List(ctx, &list, client.InNamespace(s.Namespace)); err != nil {
			return "", err
		}
		var sameName, pending *v1alpha1.Blip
		var mountErr error
		for i := range list.Items {
			b := &list.Items[i]
			if b.Name == st.Name {
				sameName = b
			}
			if !ownedResource(b, owner) {
				continue
			}
			root, err := s.workerRoot(ctx, b)
			if err != nil {
				return "", err
			}
			if !v1alpha1.Finished(b) {
				if err := selectedMountError(b, root, st); err != nil {
					mountErr = err
				}
			}
			if runningBlip(b) && b.Status.Pod != "" && stateAttached(b, root, st) {
				// Confirm that the target itself was not replaced or relabeled
				// since the list, before reaching its guest.
				var live v1alpha1.Blip
				if err := s.Kube.Get(ctx, client.ObjectKeyFromObject(b), &live); err != nil {
					return "", err
				}
				if live.UID != b.UID || !ownedResource(&live, owner) || !runningBlip(&live) || live.Status.Pod == "" {
					return "", fmt.Errorf("sandbox worker %s changed; select the state again", b.Name)
				}
				root, err = s.workerRoot(ctx, &live)
				if err != nil {
					return "", err
				}
				if err := selectedMountError(&live, root, st); err != nil {
					return "", err
				}
				if stateAttached(&live, root, st) {
					return live.Status.Pod, nil
				}
				// A dynamic mount changed after the list. Keep waiting for
				// its shared informer update instead of connecting early.
			}
			if writesState(b, root, st) && !v1alpha1.Finished(b) {
				pending = b
			}
		}
		// A failed desired mount in another worker must not hide an
		// already attached writer found later in the list.
		if mountErr != nil {
			return "", mountErr
		}
		if w := st.Status.Writer; w != nil && pending == nil {
			return "", fmt.Errorf("state %s is held by an unavailable worker", st.Name)
		}
		if pending == nil {
			switch {
			case sameName == nil:
				// Recheck the state immediately before creating only a Blip.
				if _, err := s.selectedState(ctx, owner, entry, false); err != nil {
					return "", err
				}
				if err := s.Kube.Create(ctx, s.sandboxBlip(owner, st.Name)); err != nil && !apierrors.IsAlreadyExists(err) {
					return "", err
				}
				continue
			case !ownedResource(sameName, owner):
				return "", fmt.Errorf("sandbox %s is not owned by the authenticated owner", st.Name)
			case sameName.Spec.State != st.Name && !v1alpha1.Finished(sameName):
				return "", fmt.Errorf("sandbox name %s is used by a worker; its saved state has been preserved", st.Name)
			case sameName.DeletionTimestamp == nil && v1alpha1.Finished(sameName):
				if recreated {
					return "", fmt.Errorf("sandbox %s stopped while starting: %s %s", st.Name, sameName.Status.Reason, sameName.Status.Message)
				}
				recreated = true
				if err := s.recreateFinished(ctx, sameName); err != nil {
					return "", err
				}
				continue
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case _, ok := <-changes:
			if !ok {
				return "", errors.New("sandbox catalog is stopped")
			}
		}
	}
}

func selectedMountError(b *v1alpha1.Blip, root, st *v1alpha1.BlipState) error {
	if m := selectedMountStatus(b, root, st); m != nil && m.Phase == v1alpha1.MountFailed {
		return fmt.Errorf("mount of state %s in worker %s failed: %s", st.Name, b.Name, m.Message)
	}
	return nil
}
