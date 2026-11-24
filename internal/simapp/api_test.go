// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simapp

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var ctx = context.Background()
var lostReply = errors.New("simapp: operation applied; acknowledgement lost")

// The API server and informer snapshot are different objects. All controller
// writes go to the former; only an explicit watch delivery changes the latter.
// Business decisions, including optimistic patches, are the real reconcilers'.
type apiSnapshot struct {
	Blips           v1.BlipList
	States          v1.BlipStateList
	Pools           v1.BlipPoolList
	Nodes           v1.BlipNodeList
	Pods            corev1.PodList
	KubeNodes       corev1.NodeList
	ConfigMaps      corev1.ConfigMapList
	ServiceAccounts corev1.ServiceAccountList
}

func (s *apiSnapshot) lists() []client.ObjectList {
	return []client.ObjectList{&s.Blips, &s.States, &s.Pools, &s.Nodes, &s.Pods, &s.KubeNodes, &s.ConfigMaps, &s.ServiceAccounts}
}

func (s apiSnapshot) client() client.Client {
	scheme := kruntime.NewScheme()
	must(corev1.AddToScheme(scheme))
	must(v1.AddToScheme(scheme))
	b := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1.Blip{}, &v1.BlipState{}, &v1.BlipNode{}, &v1.BlipPool{})
	for _, l := range s.lists() {
		must(meta.EachListItem(l, func(o kruntime.Object) error {
			b.WithObjects(o.DeepCopyObject().(client.Object))
			return nil
		}))
	}
	for _, ix := range controller.Indexes {
		b.WithIndex(ix.Obj, ix.Field, ix.Extract)
	}
	return b.Build()
}

func snapshot(c client.Client) apiSnapshot {
	var s apiSnapshot
	for _, l := range s.lists() {
		must(c.List(ctx, l))
	}
	return s
}

type delayedAPI struct {
	client.Client
	cache  client.Reader
	lose   bool
	lost   bool
	writes int
	loseAt int
}

func (a *delayedAPI) Get(c context.Context, k client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	return a.cache.Get(c, k, o, opts...)
}
func (a *delayedAPI) List(c context.Context, o client.ObjectList, opts ...client.ListOption) error {
	return a.cache.List(c, o, opts...)
}
func (a *delayedAPI) result(err error) error {
	if err == nil {
		a.writes++
	}
	if err == nil && (a.lose || a.loseAt == a.writes) && !a.lost {
		a.lost = true
		return lostReply
	}
	return err
}
func (a *delayedAPI) Create(c context.Context, o client.Object, opts ...client.CreateOption) error {
	if o.GetUID() == "" {
		o.SetUID(types.UID(fmt.Sprintf("%T/%s", o, o.GetName())))
	}
	return a.result(a.Client.Create(c, o, opts...))
}
func (a *delayedAPI) Patch(c context.Context, o client.Object, p client.Patch, opts ...client.PatchOption) error {
	return a.result(a.Client.Patch(c, o, p, opts...))
}
func (a *delayedAPI) Delete(c context.Context, o client.Object, opts ...client.DeleteOption) error {
	return a.result(a.Client.Delete(c, o, opts...))
}
func (a *delayedAPI) Status() client.SubResourceWriter {
	return delayedStatus{SubResourceWriter: a.Client.Status(), api: a}
}

type delayedStatus struct {
	client.SubResourceWriter
	api *delayedAPI
}

func (s delayedStatus) Patch(c context.Context, o client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
	return s.api.result(s.SubResourceWriter.Patch(c, o, p, opts...))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
