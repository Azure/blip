// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestTokenReviewCallersIdentify(t *testing.T) {
	const (
		namespace = "team"
		stateName = "chat-root"
		blipName  = "chat-root-g1"
		podName   = "chat-root-g1-pod"
		podUID    = "pod-uid"
		blipUID   = "blip-uid"
	)
	user := authv1.UserInfo{
		Username: "system:serviceaccount:" + namespace + ":blip-chat",
		Extra: map[string]authv1.ExtraValue{
			"authentication.kubernetes.io/pod-name": {podName},
		},
	}
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{"blipchat"},
			User:          user,
		}}, nil
	})

	for _, tt := range []struct {
		name    string
		mutate  func(*fakeCluster)
		wantErr string
	}{
		{name: "valid", mutate: func(*fakeCluster) {}},
		{
			name: "pod is not the current blip pod",
			mutate: func(f *fakeCluster) {
				b := f.blips[key(namespace, blipName)]
				b.Status.Pod = "another-pod"
			},
			wantErr: "not the blip's current pod",
		},
		{
			name: "pod uid is not the current blip pod uid",
			mutate: func(f *fakeCluster) {
				f.pods[key(namespace, podName)].UID = "another-uid"
			},
			wantErr: "not the blip's current pod",
		},
		{
			name: "pod does not carry the blip uid label",
			mutate: func(f *fakeCluster) {
				delete(f.pods[key(namespace, podName)].Labels, v1.LabelBlipUID)
			},
			wantErr: "does not belong to the blip",
		},
		{
			name: "hidden fork copy is not a chat session",
			mutate: func(f *fakeCluster) {
				st := f.states[key(namespace, stateName)]
				delete(st.Annotations, AnnotationProfile)
			},
			wantErr: "only a chat blip",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cluster := newFakeCluster()
			cluster.states[key(namespace, stateName)] = &v1.BlipState{
				ObjectMeta: metav1.ObjectMeta{
					Name:        stateName,
					Namespace:   namespace,
					Labels:      map[string]string{LabelSession: "true"},
					Annotations: map[string]string{AnnotationProfile: "default"},
				},
			}
			cluster.blips[key(namespace, blipName)] = &v1.Blip{
				ObjectMeta: metav1.ObjectMeta{
					Name:      blipName,
					Namespace: namespace,
					UID:       blipUID,
					Labels:    map[string]string{LabelSession: stateName},
				},
				Status: v1.BlipStatus{Pod: podName, PodUID: podUID},
			}
			cluster.pods[key(namespace, podName)] = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Namespace:   namespace,
					UID:         podUID,
					Labels:      map[string]string{v1.LabelBlipUID: blipUID},
					Annotations: map[string]string{v1.AnnotationBlip: blipName},
				},
			}
			tt.mutate(cluster)

			callers := &tokenReviewCallers{api: client, cluster: cluster, audience: "blipchat"}
			caller, err := callers.Identify(context.Background(), namespace, "token")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Identify() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Identify() error = %v", err)
			}
			if caller.Session.Name != stateName || caller.Blip.Name != blipName {
				t.Fatalf("Identify() = %+v", caller)
			}
		})
	}
}
