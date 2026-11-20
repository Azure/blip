// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

type createOnceClient struct {
	client.Client
	failCreate bool
}

func (c *createOnceClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.failCreate {
		c.failCreate = false
		return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "configmaps"}, obj.GetName())
	}
	return c.Client.Create(ctx, obj, opts...)
}

func TestKubeSavePendingRetriesCreateRace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &createOnceClient{Client: base, failCreate: true}
	k := &kubeCluster{c: c}
	ctx := context.Background()

	prompts := []PendingPrompt{{ID: "p1", Text: "hello", Original: "hello", User: "e2e"}}
	if err := k.SavePending(ctx, "team", "chat-race", prompts); err != nil {
		t.Fatalf("SavePending after create race: %v", err)
	}

	var cm corev1.ConfigMap
	if err := base.Get(ctx, client.ObjectKey{Namespace: "team", Name: pendingConfigMapName("chat-race")}, &cm); err != nil {
		t.Fatal(err)
	}
	raw, err := gzip.NewReader(bytes.NewReader(cm.BinaryData["queue"]))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	data, err := io.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []PendingPrompt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "p1" || got[0].Text != "hello" {
		t.Fatalf("pending prompts = %+v", got)
	}

	// A normal update of the same object must also succeed.
	prompts = append(prompts, PendingPrompt{ID: "p2", Text: "again", Original: "again", User: "e2e"})
	if err := k.SavePending(ctx, "team", "chat-race", prompts); err != nil {
		t.Fatalf("SavePending update: %v", err)
	}
}
