package blipchat

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Cluster is the small part of the Kubernetes API blipchat needs. Tests use a
// fake; the real implementation is kubeCluster.
type Cluster interface {
	ListSessions(ctx context.Context, namespace string) ([]v1.BlipState, error)
	GetSession(ctx context.Context, namespace, name string) (*v1.BlipState, error)
	CreateSession(ctx context.Context, namespace string, state *v1.BlipState) error
	PatchSession(ctx context.Context, namespace, name string, labels, annotations map[string]string) error
	ListSessionBlips(ctx context.Context, namespace string) ([]v1.Blip, error)
	ListStateBlips(ctx context.Context, namespace, state string) ([]v1.Blip, error)
	CreateBlip(ctx context.Context, namespace string, blip *v1.Blip) error
	GetBlip(ctx context.Context, namespace, name string) (*v1.Blip, error)
	StopBlip(ctx context.Context, namespace, name string) error
}

type kubeCluster struct {
	c client.Client
}

// NewKube returns a Cluster backed by a controller-runtime client.
func NewKube(c client.Client) Cluster { return &kubeCluster{c: c} }

func (k *kubeCluster) ListSessions(ctx context.Context, namespace string) ([]v1.BlipState, error) {
	var list v1.BlipStateList
	if err := k.c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{LabelSession: "true"}); err != nil {
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

func (k *kubeCluster) GetBlip(ctx context.Context, namespace, name string) (*v1.Blip, error) {
	var blip v1.Blip
	if err := k.c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &blip); err != nil {
		return nil, err
	}
	return &blip, nil
}

func (k *kubeCluster) StopBlip(ctx context.Context, namespace, name string) error {
	obj := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	patch := fmt.Sprintf(`{"spec":{"stop":true}}`)
	return k.c.Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(patch)))
}
