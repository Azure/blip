// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"maps"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/streamapi"
)

// identityBackend resolves only the current, mutually bound Pod and Blip.
type identityBackend struct{ client client.Reader }

func (b identityBackend) LookupPodIdentity(ctx context.Context, namespace, name, uid string) (*streamapi.PodIdentity, error) {
	var pod corev1.Pod
	if err := b.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, identityReadError(err)
	}
	if !pod.DeletionTimestamp.IsZero() || pod.UID == "" || (uid != "" && uid != string(pod.UID)) {
		return nil, streamapi.ErrNotFound
	}
	blipName := pod.Annotations[v1.AnnotationBlip]
	if blipName == "" {
		return nil, streamapi.ErrNotFound
	}
	var blip v1.Blip
	if err := b.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: blipName}, &blip); err != nil {
		return nil, identityReadError(err)
	}
	if !blip.DeletionTimestamp.IsZero() || blip.UID == "" ||
		blip.Status.Pod != pod.Name || blip.Status.PodUID != string(pod.UID) ||
		pod.Labels[v1.LabelBlipUID] != string(blip.UID) {
		return nil, streamapi.ErrNotFound
	}
	switch blip.Status.Phase {
	case v1.BlipPending, v1.BlipRunning, v1.BlipSaving:
	default:
		return nil, streamapi.ErrNotFound
	}
	if blip.Spec.State == "" {
		return nil, streamapi.ErrNotFound
	}
	var state v1.BlipState
	if err := b.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: blip.Spec.State}, &state); err != nil {
		return nil, identityReadError(err)
	}
	if blip.Status.RootStateUID != "" && blip.Status.RootStateUID != string(state.UID) {
		return nil, streamapi.ErrNotFound
	}
	pool := blip.Spec.Pool
	if pool == "" {
		pool = "default"
	}
	return &streamapi.PodIdentity{
		TypeMeta: metav1.TypeMeta{
			APIVersion: streamapi.IdentityGroupName + "/" + streamapi.IdentityVersion,
			Kind:       "PodIdentity",
		},
		Metadata: identityMetadata(&pod),
		Blip: streamapi.BlipIdentity{
			IdentityMetadata: identityMetadata(&blip),
			Phase:            blip.Status.Phase,
			Pool:             pool,
		},
		State: identityMetadata(&state),
	}, nil
}

func identityReadError(err error) error {
	if apierrors.IsNotFound(err) {
		return streamapi.ErrNotFound
	}
	return err
}

func identityMetadata(obj client.Object) streamapi.IdentityMetadata {
	return streamapi.IdentityMetadata{
		Namespace:   obj.GetNamespace(),
		Name:        obj.GetName(),
		UID:         string(obj.GetUID()),
		Labels:      maps.Clone(obj.GetLabels()),
		Annotations: maps.Clone(obj.GetAnnotations()),
	}
}
