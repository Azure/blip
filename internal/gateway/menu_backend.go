package gateway

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway/menu"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

type catalogBackend struct {
	srv   *Server
	owner string
}

func (s *Server) menuBackend(owner string) menu.Backend {
	return &catalogBackend{srv: s, owner: owner}
}

func (b *catalogBackend) List(ctx context.Context) ([]menu.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.srv.Catalog == nil {
		return nil, errors.New("sandbox catalog is not configured")
	}
	return b.srv.Catalog.List(b.owner)
}

func (b *catalogBackend) Subscribe() (<-chan struct{}, func()) {
	if b.srv.Catalog == nil {
		ch := make(chan struct{})
		close(ch)
		return ch, func() {}
	}
	return b.srv.Catalog.Subscribe(b.owner)
}

func (b *catalogBackend) ValidateName(name string) error {
	if name == "" {
		return errors.New("sandbox name is required")
	}
	if _, err := SandboxName(name); err != nil {
		return err
	}
	if !dnsLabel.MatchString(b.owner) {
		return errors.New("invalid sandbox owner")
	}
	_, err := fullSandboxName(b.owner, name)
	return err
}

func (b *catalogBackend) Create(ctx context.Context, name string) (menu.Entry, error) {
	if err := b.ValidateName(name); err != nil {
		return menu.Entry{}, err
	}
	full, err := fullSandboxName(b.owner, name)
	if err != nil {
		return menu.Entry{}, err
	}
	s := b.srv
	key := client.ObjectKey{Namespace: s.Namespace, Name: full}
	// A CLI worker may exist before its state. Do not steal its name.
	for _, obj := range []client.Object{&v1alpha1.Blip{}, &v1alpha1.BlipState{}} {
		err := s.Kube.Get(ctx, key, obj)
		if err == nil {
			return menu.Entry{}, fmt.Errorf("sandbox %q already exists", name)
		}
		if !apierrors.IsNotFound(err) {
			return menu.Entry{}, err
		}
	}
	source, err := s.baseState(ctx)
	if err != nil {
		return menu.Entry{}, err
	}
	st, err := s.forkState(ctx, b.owner, full, source)
	if err != nil {
		return menu.Entry{}, err
	}
	return stateEntry(st, b.owner), nil
}

// selectedState validates the resource name, live owner, and incarnation. The
// display name and cached Running flag are never used as authority.
func (s *Server) selectedState(ctx context.Context, owner string, entry menu.Entry, deleting bool) (*v1alpha1.BlipState, error) {
	if owner == "" || entry.ID == "" || entry.UID == "" {
		return nil, errors.New("invalid sandbox selection; refresh the menu")
	}
	var st v1alpha1.BlipState
	if err := s.Kube.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: entry.ID}, &st); err != nil {
		return nil, err
	}
	if !ownedResource(&st, owner) {
		return nil, fmt.Errorf("sandbox state %s is not owned by the authenticated owner", entry.ID)
	}
	if string(st.UID) != entry.UID {
		return nil, fmt.Errorf("sandbox state %s was replaced; refresh the menu", entry.ID)
	}
	if !deleting && st.DeletionTimestamp != nil {
		return nil, fmt.Errorf("sandbox state %s is being deleted", entry.ID)
	}
	if !deleting && st.Spec.Image != "" {
		return nil, fmt.Errorf("sandbox state %s is an imported image and cannot be run directly", entry.ID)
	}
	return &st, nil
}

func referencesState(b *v1alpha1.Blip, root, st *v1alpha1.BlipState) bool {
	if b.Spec.State == st.Name {
		return true
	}
	if w := st.Status.Writer; w != nil && w.BlipName == b.Name && w.BlipUID == string(b.UID) {
		return true
	}
	for _, m := range desiredMounts(b, root) {
		if m.State == st.Name {
			return true
		}
	}
	// A mount removed from spec can still be saving and block state deletion.
	for _, m := range b.Status.Mounts {
		if m.State == st.Name && (m.StateUID == "" || m.StateUID == string(st.UID)) {
			return true
		}
	}
	return false
}

func (s *Server) workerRoot(ctx context.Context, b *v1alpha1.Blip) (*v1alpha1.BlipState, error) {
	var root v1alpha1.BlipState
	if b.Spec.State == "" {
		return nil, nil
	}
	err := s.Kube.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: b.Spec.State}, &root)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return &root, err
}

func (b *catalogBackend) Delete(ctx context.Context, entry menu.Entry) error {
	s := b.srv
	st, err := s.selectedState(ctx, b.owner, entry, true)
	if err != nil {
		return err
	}
	var list v1alpha1.BlipList
	if err := s.Kube.List(ctx, &list, client.InNamespace(s.Namespace)); err != nil {
		return err
	}
	// Delete the pinned state first. Its normal finalizer waits for users and
	// writers to stop. Orphan propagation preserves other states and resources
	// that happen to name it (or a worker below) as an owner.
	if err := s.Kube.Delete(ctx, st,
		client.Preconditions{UID: &st.UID, ResourceVersion: &st.ResourceVersion},
		client.PropagationPolicy(metav1.DeletePropagationOrphan)); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	for i := range list.Items {
		candidate := &list.Items[i]
		if !ownedResource(candidate, b.owner) {
			continue
		}
		root, err := s.workerRoot(ctx, candidate)
		if err != nil {
			return err
		}
		if !referencesState(candidate, root, st) {
			continue
		}
		var live v1alpha1.Blip
		if err := s.Kube.Get(ctx, client.ObjectKeyFromObject(candidate), &live); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
		if live.UID != candidate.UID || !ownedResource(&live, b.owner) {
			continue
		}
		root, err = s.workerRoot(ctx, &live)
		if err != nil {
			return err
		}
		if !referencesState(&live, root, st) {
			continue
		}
		if err := s.Kube.Delete(ctx, &live,
			client.Preconditions{UID: &live.UID, ResourceVersion: &live.ResourceVersion},
			client.PropagationPolicy(metav1.DeletePropagationOrphan)); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

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
	for attempt := 0; ; attempt++ {
		startCtx, cancel := context.WithTimeout(ctx, startTimeout)
		pod, err := s.startSelectedState(startCtx, owner, entry)
		cancel()
		if err != nil {
			return nil, err
		}
		if _, err := s.selectedState(ctx, owner, entry, false); err != nil {
			return nil, err
		}
		sess, err := s.Sessions.Open(guestCtx, s.Namespace, pod, o)
		if err == nil || attempt > 0 || !errors.Is(err, session.ErrUnreachable) {
			return sess, err
		}
	}
}

func (s *Server) startSelectedState(ctx context.Context, owner string, entry menu.Entry) (string, error) {
	if s.Catalog == nil {
		return "", errors.New("sandbox catalog is not configured")
	}
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
			if !finished(b) {
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
			if writesState(b, root, st) && !finished(b) {
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
			case sameName.Spec.State != st.Name && !finished(sameName):
				return "", fmt.Errorf("sandbox name %s is used by a worker; its saved state has been preserved", st.Name)
			case sameName.DeletionTimestamp == nil && finished(sameName):
				if recreated {
					return "", fmt.Errorf("sandbox %s stopped while starting: %s %s", st.Name, sameName.Status.Reason, sameName.Status.Message)
				}
				recreated = true
				if err := s.Kube.Delete(ctx, sameName,
					client.Preconditions{UID: &sameName.UID, ResourceVersion: &sameName.ResourceVersion},
					client.PropagationPolicy(metav1.DeletePropagationOrphan)); err != nil && !apierrors.IsNotFound(err) {
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
