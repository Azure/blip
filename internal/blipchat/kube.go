// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
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
	CreateSession(ctx context.Context, namespace string, state *v1.BlipState) error
	ForkSession(ctx context.Context, namespace string, source, dest *v1.BlipState, owner *metav1.OwnerReference) error
	ListChildSessions(ctx context.Context, namespace, parent string) ([]v1.BlipState, error)
	PatchSession(ctx context.Context, namespace, name string, labels, annotations map[string]string) error
	ListSessionBlips(ctx context.Context, namespace string) ([]v1.Blip, error)
	ListStateBlips(ctx context.Context, namespace, state string) ([]v1.Blip, error)
	CreateBlip(ctx context.Context, namespace string, blip *v1.Blip) error
	PatchBlip(ctx context.Context, namespace, name string, labels, annotations map[string]string) error
	GetBlip(ctx context.Context, namespace, name string) (*v1.Blip, error)
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
	StopBlip(ctx context.Context, namespace, name string) error
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

const pendingConfigMapPrefix = "blipchat-pending-"

func pendingConfigMapName(session string) string {
	return pendingConfigMapPrefix + session
}

// LoadPending returns prompts accepted by blipchat but not yet written to
// the agent. The payload is gzipped because a full queue can approach the
// ConfigMap size limit.
func (k *kubeCluster) LoadPending(ctx context.Context, namespace, session string) ([]PendingPrompt, error) {
	var cm corev1.ConfigMap
	if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pendingConfigMapName(session)}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	data := cm.BinaryData["queue"]
	if len(data) == 0 {
		return nil, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out []PendingPrompt
	if err := json.NewDecoder(zr).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (k *kubeCluster) SavePending(ctx context.Context, namespace, session string, prompts []PendingPrompt) error {
	name := pendingConfigMapName(session)
	if len(prompts) == 0 {
		err := k.c.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}})
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	raw, err := json.Marshal(prompts)
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	queue := compressed.Bytes()

	// Concurrent submits for the same chat can race between Get and
	// Create/Update. Retry on the transient API errors instead of failing an
	// otherwise valid user message.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		var cm corev1.ConfigMap
		err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &cm)
		if apierrors.IsNotFound(err) {
			cm = corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
					Labels:    map[string]string{"blip.dev/pending-session": session},
				},
			}
			if st, statErr := k.GetSession(ctx, namespace, session); statErr == nil {
				cm.OwnerReferences = []metav1.OwnerReference{{
					APIVersion: "blip.dev/v1alpha1",
					Kind:       "BlipState",
					Name:       st.Name,
					UID:        st.UID,
				}}
			}
			cm.BinaryData = map[string][]byte{"queue": queue}
			err = k.c.Create(ctx, &cm)
			if err == nil {
				return nil
			}
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			lastErr = err
		} else if err != nil {
			return err
		} else {
			cm.BinaryData = map[string][]byte{"queue": queue}
			err = k.c.Update(ctx, &cm)
			if err == nil {
				return nil
			}
			if !apierrors.IsConflict(err) {
				return err
			}
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return fmt.Errorf("save pending prompts: %w", lastErr)
}
