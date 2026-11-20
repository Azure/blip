// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func streamTestAPIService(name string) *unstructured.Unstructured {
	api := &unstructured.Unstructured{}
	api.SetAPIVersion("apiregistration.k8s.io/v1")
	api.SetKind("APIService")
	api.SetName(name)
	return api
}

func assertStreamAPIServices(t *testing.T, e *env, ca []byte) {
	t.Helper()
	for _, registration := range []struct{ name, group, version string }{
		{"v1alpha1.stream.blip.dev", "stream.blip.dev", "v1alpha1"},
		{"v1alpha1.identity.blip.dev", "identity.blip.dev", "v1alpha1"},
	} {
		api := streamTestAPIService(registration.name)
		if err := e.c.Get(e.ctx, client.ObjectKey{Name: registration.name}, api); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"group": registration.group, "version": registration.version,
			"groupPriorityMinimum": int64(100), "versionPriority": int64(100),
			"service": map[string]any{
				"name": "blip-stream", "namespace": ns, "port": int64(7891),
			},
			"caBundle": base64.StdEncoding.EncodeToString(ca), "insecureSkipTLSVerify": false,
		}
		got, _, err := unstructured.NestedMap(api.Object, "spec")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s spec = %#v, want %#v", registration.name, got, want)
		}
	}
}

func TestStreamAPIServicesCreateAndUpdate(t *testing.T) {
	e := newEnv(t)
	r := &streamTLS{client: e.c, namespace: ns, now: func() time.Time { return e.now }}
	r.ensure(e.ctx)
	var sec corev1.Secret
	key := client.ObjectKey{Namespace: ns, Name: StreamTLSSecret}
	if err := e.c.Get(e.ctx, key, &sec); err != nil {
		t.Fatal(err)
	}
	if !validServingCert(sec.Data["tls.crt"], ns, e.now.Add(30*24*time.Hour)) {
		t.Fatal("shared serving certificate is not valid for blip-stream")
	}
	if len(sec.Data["ca.crt"]) == 0 {
		t.Fatal("missing shared CA")
	}
	assertStreamAPIServices(t, e, sec.Data["ca.crt"])

	// Repair stale routing and TLS settings for both groups and propagate a
	// rotated CA without replacing the APIService objects or their metadata.
	for _, name := range []string{StreamAPIService, IdentityAPIService} {
		api := streamTestAPIService(name)
		if err := e.c.Get(e.ctx, client.ObjectKey{Name: name}, api); err != nil {
			t.Fatal(err)
		}
		api.SetAnnotations(map[string]string{"keep": "value"})
		api.Object["spec"] = map[string]any{
			"group": "wrong.blip.dev", "version": "v9",
			"service":  map[string]any{"name": "wrong", "namespace": "wrong", "port": int64(443)},
			"caBundle": "b2xk", "insecureSkipTLSVerify": true,
		}
		if err := e.c.Update(e.ctx, api); err != nil {
			t.Fatal(err)
		}
	}
	data, err := generateServingCert(ns, e.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sec.Data = data
	if err := e.c.Update(e.ctx, &sec); err != nil {
		t.Fatal(err)
	}
	r.ensure(e.ctx)
	assertStreamAPIServices(t, e, data["ca.crt"])
	for _, name := range []string{StreamAPIService, IdentityAPIService} {
		api := streamTestAPIService(name)
		if err := e.c.Get(e.ctx, client.ObjectKey{Name: name}, api); err != nil {
			t.Fatal(err)
		}
		if api.GetAnnotations()["keep"] != "value" {
			t.Errorf("%s lost existing metadata", name)
		}
	}
}

func TestStreamAPIServicesReconcileIndependently(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, failed := range []string{StreamAPIService, IdentityAPIService} {
			t.Run(operation+"/"+failed, func(t *testing.T) {
				e := newEnv(t)
				r := &streamTLS{client: e.c, namespace: ns, now: func() time.Time { return e.now }}
				if operation == "update" {
					r.ensure(e.ctx)
				}
				// Use a valid serving cert with a new CA so successful updates
				// are observable even when the other registration fails.
				data, err := generateServingCert(ns, e.now.Add(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: StreamTLSSecret}, Data: data}
				if operation == "update" {
					var current corev1.Secret
					if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(sec), &current); err != nil {
						t.Fatal(err)
					}
					current.Data = data
					err = e.c.Update(e.ctx, &current)
				} else {
					err = e.c.Create(e.ctx, sec)
				}
				if err != nil {
					t.Fatal(err)
				}
				calls := map[string]int{}
				r.client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						calls[obj.GetName()]++
						if obj.GetName() == failed {
							return fmt.Errorf("injected create failure")
						}
						return c.Create(ctx, obj, opts...)
					},
					Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
						calls[obj.GetName()]++
						if obj.GetName() == failed {
							return fmt.Errorf("injected update failure")
						}
						return c.Update(ctx, obj, opts...)
					},
				})
				r.ensure(e.ctx)
				for _, name := range []string{StreamAPIService, IdentityAPIService} {
					if calls[name] != 1 {
						t.Errorf("%s reconciled %d times, want 1", name, calls[name])
					}
					if name == failed {
						continue
					}
					api := streamTestAPIService(name)
					if err := e.c.Get(e.ctx, client.ObjectKey{Name: name}, api); err != nil {
						t.Fatal(err)
					}
					ca, _, err := unstructured.NestedString(api.Object, "spec", "caBundle")
					if err != nil || ca != base64.StdEncoding.EncodeToString(data["ca.crt"]) {
						t.Errorf("%s CA was not reconciled: %q, %v", name, ca, err)
					}
				}
				// The next pass retries the failed registration normally.
				r.client = e.c
				r.ensure(e.ctx)
				assertStreamAPIServices(t, e, data["ca.crt"])
			})
		}
	}
}
