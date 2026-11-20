// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/workspace"
)

// Cluster is the small part of the Kubernetes API blipchat needs. Tests use a
// fake; the real implementation is kubeCluster.
type Cluster interface {
	ListSessions(ctx context.Context, namespace string) ([]v1.BlipState, error)
	ListStates(ctx context.Context, namespace string, selector labels.Selector) ([]v1.BlipState, error)
	GetSession(ctx context.Context, namespace, name string) (*v1.BlipState, error)
	DeleteSession(ctx context.Context, namespace, name string, uid types.UID, resourceVersion ...string) error
	CreateSession(ctx context.Context, namespace string, state *v1.BlipState) error
	ForkSession(ctx context.Context, namespace string, source, dest *v1.BlipState, owner *metav1.OwnerReference) error
	ListChildSessions(ctx context.Context, namespace, parent string) ([]v1.BlipState, error)
	PatchSession(ctx context.Context, namespace, name string, labels, annotations map[string]string) error
	// RecordStop advances the durable, exclusive queue cancellation boundary.
	RecordStop(ctx context.Context, namespace, name string, before uint64) error
	ListSessionBlips(ctx context.Context, namespace string) ([]v1.Blip, error)
	ListStateBlips(ctx context.Context, namespace, state string) ([]v1.Blip, error)
	CreateBlip(ctx context.Context, namespace string, blip *v1.Blip) error
	PatchBlip(ctx context.Context, namespace, name string, labels, annotations map[string]string) error
	GetBlip(ctx context.Context, namespace, name string) (*v1.Blip, error)
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
	StopBlip(ctx context.Context, namespace, name string) error
	ListEndpointMembers(ctx context.Context, namespace, service string) ([]string, error)
}

type kubeCluster struct {
	c client.Client
}

// NewKube returns a Cluster backed by a controller-runtime client.
func NewKube(c client.Client) Cluster { return &kubeCluster{c: c} }

// isChatState reports whether a session-labelled state is a chat rather than a
// hidden workspace copy. A fork copies the chat label onto the per-mount
// states but not the chat annotations, so a copy has none of these fields.
func isChatState(st *v1.BlipState) bool {
	a := st.Annotations
	return a[AnnotationProfile] != "" || a[AnnotationParent] != "" || a[AnnotationRoot] != "" || a[AnnotationTitle] != ""
}

func (k *kubeCluster) ListSessions(ctx context.Context, namespace string) ([]v1.BlipState, error) {
	var list v1.BlipStateList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{LabelSession: "true"}); err != nil {
		return nil, err
	}
	out := list.Items[:0]
	for i := range list.Items {
		if list.Items[i].DeletionTimestamp != nil {
			continue
		}
		if isChatState(&list.Items[i]) {
			out = append(out, list.Items[i])
		}
	}
	return out, nil
}

func (k *kubeCluster) ListStates(ctx context.Context, namespace string, selector labels.Selector) ([]v1.BlipState, error) {
	var list v1.BlipStateList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k *kubeCluster) GetSession(ctx context.Context, namespace, name string) (*v1.BlipState, error) {
	var state v1.BlipState
	if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (k *kubeCluster) DeleteSession(ctx context.Context, namespace, name string, uid types.UID, resourceVersion ...string) error {
	obj := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	preconditions := client.Preconditions{UID: &uid}
	for _, version := range resourceVersion {
		if version != "" {
			preconditions.ResourceVersion = &version
			break
		}
	}
	return k.c.Delete(ctx, obj, preconditions)
}

func (k *kubeCluster) CreateSession(ctx context.Context, namespace string, state *v1.BlipState) error {
	state.Namespace = namespace
	return k.c.Create(ctx, state)
}

func (k *kubeCluster) ForkSession(ctx context.Context, namespace string, source, dest *v1.BlipState, owner *metav1.OwnerReference) error {
	dest.Namespace = namespace
	_, err := workspace.Fork(ctx, k.c, source, dest, &workspace.ForkOptions{Owner: owner})
	return err
}

func (k *kubeCluster) ListChildSessions(ctx context.Context, namespace, parent string) ([]v1.BlipState, error) {
	var list v1.BlipStateList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{LabelParent: parent}); err != nil {
		return nil, err
	}
	out := list.Items[:0]
	for i := range list.Items {
		if isChatState(&list.Items[i]) {
			out = append(out, list.Items[i])
		}
	}
	return out, nil
}

func (k *kubeCluster) PatchSession(ctx context.Context, namespace, name string, labels, annotations map[string]string) error {
	patch := struct {
		Metadata struct {
			Labels      map[string]string `json:"labels,omitempty"`
			Annotations map[string]string `json:"annotations,omitempty"`
		} `json:"metadata"`
	}{}
	patch.Metadata.Labels = labels
	patch.Metadata.Annotations = annotations
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	obj := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	return k.c.Patch(ctx, obj, client.RawPatch(types.MergePatchType, data))
}

func (k *kubeCluster) ListSessionBlips(ctx context.Context, namespace string) ([]v1.Blip, error) {
	var list v1.BlipList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.HasLabels{LabelSession}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k *kubeCluster) RecordStop(ctx context.Context, namespace, name string, before uint64) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var st v1.BlipState
		if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &st); err != nil {
			return err
		}
		if stopBefore(&st) >= before {
			return nil
		}
		base := st.DeepCopy()
		if st.Annotations == nil {
			st.Annotations = map[string]string{}
		}
		st.Annotations[AnnotationStopBefore] = strconv.FormatUint(before, 10)
		return k.c.Patch(ctx, &st, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func (k *kubeCluster) ListStateBlips(ctx context.Context, namespace, state string) ([]v1.Blip, error) {
	var list v1.BlipList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{LabelSession: state}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k *kubeCluster) CreateBlip(ctx context.Context, namespace string, blip *v1.Blip) error {
	blip.Namespace = namespace
	return k.c.Create(ctx, blip)
}

func (k *kubeCluster) PatchBlip(ctx context.Context, namespace, name string, labels, annotations map[string]string) error {
	patch := struct {
		Metadata struct {
			Labels      map[string]string `json:"labels,omitempty"`
			Annotations map[string]string `json:"annotations,omitempty"`
		} `json:"metadata"`
	}{}
	patch.Metadata.Labels = labels
	patch.Metadata.Annotations = annotations
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	obj := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	return k.c.Patch(ctx, obj, client.RawPatch(types.MergePatchType, data))
}

func (k *kubeCluster) GetBlip(ctx context.Context, namespace, name string) (*v1.Blip, error) {
	var blip v1.Blip
	if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &blip); err != nil {
		return nil, err
	}
	return &blip, nil
}

func (k *kubeCluster) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	var pod corev1.Pod
	if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, err
	}
	return &pod, nil
}

func (k *kubeCluster) StopBlip(ctx context.Context, namespace, name string) error {
	obj := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	patch := fmt.Sprintf(`{"spec":{"stop":true}}`)
	return k.c.Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(patch)))
}

// ListEndpointMembers returns the pod names behind a Service. The sharder uses
// it to agree on chat ownership without a shared store.
func (k *kubeCluster) ListEndpointMembers(ctx context.Context, namespace, service string) ([]string, error) {
	var slices discoveryv1.EndpointSliceList
	if err := k.c.List(ctx, &slices, client.InNamespace(namespace), client.MatchingLabels{
		discoveryv1.LabelServiceName: service,
	}); err != nil {
		return nil, err
	}
	var members []string
	for i := range slices.Items {
		for _, endpoint := range slices.Items[i].Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" && endpoint.TargetRef.Name != "" {
				members = append(members, endpoint.TargetRef.Name)
				continue
			}
			if len(endpoint.Addresses) > 0 {
				members = append(members, endpoint.Addresses[0])
			}
		}
	}
	return members, nil
}
