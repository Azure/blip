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
	return b.srv.Catalog.List(b.owner)
}

func (b *catalogBackend) Subscribe() (<-chan struct{}, func()) {
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
	if root != nil {
		for _, m := range v1alpha1.DesiredMounts(root, b) {
			if m.State == st.Name {
				return true
			}
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
