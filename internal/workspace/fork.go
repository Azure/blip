// Package workspace creates independent, durable workspace copies.
package workspace

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ForkOptions customizes the objects Fork creates.
type ForkOptions struct {
	// Owner, when set, is the owner reference of the root and every copy, so
	// that deleting the owning object also removes the workspace. A nil
	// Owner makes the workspace durable: it outlives every execution.
	Owner *metav1.OwnerReference
}

// Fork snapshots the source workspace configuration and creates a root copy
// plus an independent filesystem copy for each persistent writable mount.
// Read-only references are retained; temporary mounts and the configuration of
// mounted states are not inherited. Filesystem snapshots are taken independently
// by the state controller, rather than as an atomic multi-filesystem snapshot.
//
// The caller supplies dest's name, namespace, labels, provisioning overrides
// (size, replicas and nodeSelector) and, in opts, the owner of the new states.
// Fork sets copyFrom, runtime and mounts. It creates the root last. Only a
// definitive API rejection triggers removal of states created by this call,
// with UID preconditions protecting replaced objects. Ambiguous failures
// preserve them: the failed create may have persisted a root referencing those
// children even though its response was lost.
//
// On success Fork returns the states it created, root last. A caller that
// cannot keep the fork (for example because the new state never became usable)
// can delete every returned state without guessing the copy names. The
// returned objects carry the UIDs assigned at creation, so cleanup can guard
// against deleting a state that was replaced in the meantime.
func Fork(ctx context.Context, c client.Client, source *v1alpha1.BlipState, dest *v1alpha1.BlipState, opts *ForkOptions) ([]*v1alpha1.BlipState, error) {
	if source == nil || dest == nil || source.Name == "" || dest.Name == "" || source.Namespace != dest.Namespace {
		return nil, errors.New("fork requires named source and destination states in the same namespace")
	}
	if dest.Spec.Image != "" || len(dest.Spec.ImagePullSecrets) != 0 || len(dest.OwnerReferences) != 0 {
		return nil, errors.New("fork destination cannot have an image, image pull secrets, or owner references")
	}
	if opts == nil {
		opts = &ForkOptions{}
	}
	if err := CheckSource(source); err != nil {
		return nil, err
	}
	root := dest.DeepCopy()
	root.Spec.CopyFrom = source.Name
	root.Spec.Runtime = source.Spec.Runtime.DeepCopy()
	root.Spec.Mounts = nil
	var copies []*v1alpha1.BlipState
	for _, mount := range source.Spec.Mounts {
		if mount.BlipUID != "" {
			continue
		}
		if mount.Writable {
			var src v1alpha1.BlipState
			if err := c.Get(ctx, client.ObjectKey{Namespace: source.Namespace, Name: mount.State}, &src); err != nil {
				return nil, fmt.Errorf("read mount source %q: %w", mount.State, err)
			}
			if err := CheckSource(&src); err != nil {
				return nil, err
			}
			child := &v1alpha1.BlipState{
				ObjectMeta: metav1.ObjectMeta{Name: childName(root, mount), Namespace: root.Namespace, Labels: maps.Clone(root.Labels)},
				Spec:       v1alpha1.BlipStateSpec{CopyFrom: mount.State, Replicas: root.Spec.Replicas, NodeSelector: maps.Clone(root.Spec.NodeSelector)},
			}
			if opts.Owner != nil {
				child.OwnerReferences = []metav1.OwnerReference{*opts.Owner}
			}
			mount.State = child.Name
			copies = append(copies, child)
		}
		root.Spec.Mounts = append(root.Spec.Mounts, mount)
	}
	if opts.Owner != nil {
		root.OwnerReferences = []metav1.OwnerReference{*opts.Owner}
	}
	copies = append(copies, root)
	// Preflight every destination before any create, including root. A racing
	// create is still handled by the rollback below without touching that state.
	for _, st := range copies {
		err := c.Get(ctx, client.ObjectKeyFromObject(st), &v1alpha1.BlipState{})
		if err == nil {
			return nil, apierrors.NewAlreadyExists(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), st.Name)
		}
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
	}
	var created []*v1alpha1.BlipState
	for _, st := range copies {
		if err := c.Create(ctx, st); err != nil {
			result := fmt.Errorf("create state %q: %w", st.Name, err)
			if !createRejected(err) {
				return nil, result
			}
			for i := len(created) - 1; i >= 0; i-- {
				obj := created[i]
				opts := &client.DeleteOptions{}
				if obj.UID != "" {
					opts.Preconditions = &metav1.Preconditions{UID: &obj.UID}
				}
				if cleanupErr := c.Delete(context.WithoutCancel(ctx), obj, opts); cleanupErr != nil && !apierrors.IsNotFound(cleanupErr) {
					result = errors.Join(result, fmt.Errorf("remove newly created state %q: %w", obj.Name, cleanupErr))
				}
			}
			return nil, result
		}
		created = append(created, st)
	}
	*dest = *root
	return created, nil
}

// createRejected identifies explicit rejections that guarantee this request
// did not create a state. Transport failures, cancellation, and server errors
// cannot establish that, even when the client received no object or UID.
func createRejected(err error) bool {
	return apierrors.IsAlreadyExists(err) || apierrors.IsInvalid(err) ||
		apierrors.IsBadRequest(err) || apierrors.IsForbidden(err) ||
		apierrors.IsUnauthorized(err) || apierrors.IsConflict(err) ||
		apierrors.IsNotFound(err)
}

// CheckSource reports whether a state can be the source of a fork: it must not
// be going away, and a failed import must not be waiting for its commit.
func CheckSource(source *v1alpha1.BlipState) error {
	if source.DeletionTimestamp != nil {
		return fmt.Errorf("copy source %q is being deleted", source.Name)
	}
	if source.Status.Committed == nil && source.Status.Phase == v1alpha1.StateFailed && source.Status.Pending == nil {
		return fmt.Errorf("copy source %q failed: %s", source.Name, source.Status.Message)
	}
	return nil
}

// childName keeps the owner's prefix intact and bounds the suffix to one DNS
// label. Hashing the full root and mount identity avoids truncation collisions.
func childName(root *v1alpha1.BlipState, mount v1alpha1.Mount) string {
	prefix := ""
	if owner := root.Labels[v1alpha1.LabelOwner]; owner != "" && v1alpha1.OwnedBy(root.Name, owner) {
		prefix = v1alpha1.OwnerPrefix(owner)
	}
	name := strings.TrimPrefix(root.Name, prefix)
	name = strings.ReplaceAll(name, ".", "-")
	if len(name) > 44 {
		name = strings.TrimRight(name[:44], "-")
	}
	hash := sha256.Sum256([]byte(root.Name + "\x00" + mount.State + "\x00" + mount.Path))
	return fmt.Sprintf("%s%s-m-%x", prefix, name, hash[:8])
}
