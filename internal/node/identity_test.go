// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/streamapi"
)

func identityObjects() (*corev1.Pod, *v1.Blip, *v1.BlipState) {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "vm", UID: "pod-uid",
		Labels:      map[string]string{v1.LabelBlipUID: "blip-uid", "pod-label": "value"},
		Annotations: map[string]string{v1.AnnotationBlip: "run", "pod-note": "value"},
	}}, &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "run", UID: "blip-uid",
			Labels: map[string]string{"blip-label": "value"}, Annotations: map[string]string{"blip-note": "value"},
		},
		Spec:   v1.BlipSpec{State: "root", Pool: "workers"},
		Status: v1.BlipStatus{Pod: "vm", PodUID: "pod-uid", Phase: v1.BlipRunning, RootStateUID: "state-uid"},
	}, &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "root", UID: "state-uid",
		Labels:      map[string]string{"chat.blip.dev/profile": "assistant"},
		Annotations: map[string]string{"chat.blip.dev/profile": `{"model":"example","prompt":"hello"}`},
	}}
}

func TestLookupPodIdentity(t *testing.T) {
	for _, phase := range []string{v1.BlipPending, v1.BlipRunning, v1.BlipSaving} {
		for _, uid := range []string{"", "pod-uid"} {
			t.Run(phase+"/uid="+uid, func(t *testing.T) {
				pod, blip, state := identityObjects()
				blip.Status.Phase = phase
				scheme, err := Scheme()
				if err != nil {
					t.Fatal(err)
				}
				c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, blip, state).Build()
				got, err := (identityBackend{client: c}).LookupPodIdentity(context.Background(), "ns", "vm", uid)
				if err != nil {
					t.Fatal(err)
				}
				want := &streamapi.PodIdentity{
					TypeMeta: metav1.TypeMeta{APIVersion: "identity.blip.dev/v1alpha1", Kind: "PodIdentity"},
					Metadata: streamapi.IdentityMetadata{
						Namespace: "ns", Name: "vm", UID: "pod-uid", Labels: pod.Labels, Annotations: pod.Annotations,
					},
					Blip: streamapi.BlipIdentity{
						IdentityMetadata: streamapi.IdentityMetadata{
							Namespace: "ns", Name: "run", UID: "blip-uid", Labels: blip.Labels, Annotations: blip.Annotations,
						},
						Phase: phase, Pool: "workers",
					},
					State: streamapi.IdentityMetadata{
						Namespace: "ns", Name: "root", UID: "state-uid", Labels: state.Labels, Annotations: state.Annotations,
					},
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("identity = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func TestLookupPodIdentityDefaultPool(t *testing.T) {
	pod, blip, state := identityObjects()
	blip.Spec.Pool = ""
	// An early pending claim need not have pinned the root state yet.
	blip.Status.Phase = v1.BlipPending
	blip.Status.RootStateUID = ""
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, blip, state).Build()
	got, err := (identityBackend{client: c}).LookupPodIdentity(context.Background(), "ns", "vm", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Blip.Pool != "default" {
		t.Fatalf("pool = %q, want default", got.Blip.Pool)
	}
}

func TestLookupPodIdentityNotFound(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*corev1.Pod, *v1.Blip, *v1.BlipState)
	}{
		{"missing pod", func(p *corev1.Pod, _ *v1.Blip, _ *v1.BlipState) { p.Name = "other" }},
		{"missing blip", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Name = "other" }},
		{"missing state", func(_ *corev1.Pod, _ *v1.Blip, s *v1.BlipState) { s.Name = "other" }},
		{"recreated state", func(_ *corev1.Pod, _ *v1.Blip, s *v1.BlipState) { s.UID = "new-state-uid" }},
		{"pod in other namespace", func(p *corev1.Pod, _ *v1.Blip, _ *v1.BlipState) { p.Namespace = "other" }},
		{"blip in other namespace", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Namespace = "other" }},
		{"state in other namespace", func(_ *corev1.Pod, _ *v1.Blip, s *v1.BlipState) { s.Namespace = "other" }},
		{"unclaimed pod", func(p *corev1.Pod, _ *v1.Blip, _ *v1.BlipState) { p.Annotations = nil }},
		{"no blip UID label", func(p *corev1.Pod, _ *v1.Blip, _ *v1.BlipState) { p.Labels = nil }},
		{"recreated blip", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.UID = "new-blip-uid" }},
		{"empty blip UID", func(p *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.UID = ""; p.Labels = nil }},
		{"empty pod UID", func(p *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { p.UID = ""; b.Status.PodUID = "" }},
		{"stale pod name", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Pod = "replacement" }},
		{"stale pod UID", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.PodUID = "old-pod-uid" }},
		{"unclaimed blip", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Pod = ""; b.Status.PodUID = "" }},
		{"succeeded", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Phase = v1.BlipSucceeded }},
		{"failed", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Phase = v1.BlipFailed }},
		{"unknown phase", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Phase = "Unknown" }},
		{"empty phase", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Status.Phase = "" }},
		{"no state reference", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) { b.Spec.State = "" }},
		{"terminating pod", func(p *corev1.Pod, _ *v1.Blip, _ *v1.BlipState) {
			now := metav1.Now()
			p.DeletionTimestamp, p.Finalizers = &now, []string{"test"}
		}},
		{"terminating blip", func(_ *corev1.Pod, b *v1.Blip, _ *v1.BlipState) {
			now := metav1.Now()
			b.DeletionTimestamp, b.Finalizers = &now, []string{"test"}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pod, blip, state := identityObjects()
			tt.mutate(pod, blip, state)
			scheme, err := Scheme()
			if err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, blip, state).Build()
			got, err := (identityBackend{client: c}).LookupPodIdentity(context.Background(), "ns", "vm", "")
			if got != nil || !errors.Is(err, streamapi.ErrNotFound) {
				t.Fatalf("identity = %#v, error = %v; want nil, ErrNotFound", got, err)
			}
		})
	}
}

func TestLookupPodIdentityUIDMismatch(t *testing.T) {
	pod, blip, state := identityObjects()
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, blip, state).Build()
	got, err := (identityBackend{client: c}).LookupPodIdentity(context.Background(), "ns", "vm", "old-pod-uid")
	if got != nil || !errors.Is(err, streamapi.ErrNotFound) {
		t.Fatalf("identity = %#v, error = %v; want nil, ErrNotFound", got, err)
	}
}

func TestLookupPodIdentityReadErrors(t *testing.T) {
	for _, name := range []string{"vm", "run", "root"} {
		for _, want := range []error{
			errors.New("reader failed"), context.Canceled,
			apierrors.NewForbidden(schema.GroupResource{Resource: "objects"}, name, errors.New("denied")),
		} {
			t.Run(name+"/"+want.Error(), func(t *testing.T) {
				pod, blip, state := identityObjects()
				scheme, err := Scheme()
				if err != nil {
					t.Fatal(err)
				}
				c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, blip, state).
					WithInterceptorFuncs(interceptor.Funcs{
						Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
							if key.Name == name {
								return want
							}
							return c.Get(ctx, key, obj, opts...)
						},
					}).Build()
				got, err := (identityBackend{client: c}).LookupPodIdentity(context.Background(), "ns", "vm", "")
				if got != nil || !errors.Is(err, want) {
					t.Fatalf("identity = %#v, error = %v; want nil, %v", got, err, want)
				}
			})
		}
	}
}

func TestIdentityMetadataCopiesMaps(t *testing.T) {
	pod, blip, state := identityObjects()
	for _, obj := range []client.Object{pod, blip, state} {
		metadata := identityMetadata(obj)
		for k := range metadata.Labels {
			metadata.Labels[k] = "changed"
			if obj.GetLabels()[k] == "changed" {
				t.Fatalf("%T labels alias source", obj)
			}
		}
		for k := range metadata.Annotations {
			metadata.Annotations[k] = "changed"
			if obj.GetAnnotations()[k] == "changed" {
				t.Fatalf("%T annotations alias source", obj)
			}
		}
	}
}
