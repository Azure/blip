// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestKubeStopBlip(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(&v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "chat-1-g1"},
	}).Build()
	k := &kubeCluster{c: c}
	ctx := context.Background()

	if err := k.StopBlip(ctx, "team", "chat-1-g1"); err != nil {
		t.Fatalf("StopBlip: %v", err)
	}
	blip, err := k.GetBlip(ctx, "team", "chat-1-g1")
	if err != nil {
		t.Fatal(err)
	}
	if !blip.Spec.Stop {
		t.Fatal("spec.stop was not set")
	}
}

// A newer stop races the first conditional patch. Retrying must preserve the
// newer boundary, rather than allowing cancelled prompts to reappear.
type stopConflictClient struct {
	client.Client
	conflicted bool
}

func (c *stopConflictClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if !c.conflicted {
		c.conflicted = true
		var newer v1.BlipState
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), &newer); err != nil {
			return err
		}
		newer.Annotations[AnnotationStopBefore] = "200"
		if err := c.Client.Update(ctx, &newer); err != nil {
			return err
		}
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func TestKubeRecordStopPreservesNewerBoundaryOnConflict(t *testing.T) {
	c := &stopConflictClient{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(&v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "chat-1", Annotations: map[string]string{AnnotationStopBefore: "10", AnnotationTitle: "keep"}},
	}).Build()}
	k := &kubeCluster{c: c}
	ctx := context.Background()
	if err := k.RecordStop(ctx, "team", "chat-1", 100); err != nil {
		t.Fatal(err)
	}
	st, err := k.GetSession(ctx, "team", "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	if !c.conflicted || stopBefore(st) != 200 || st.Annotations[AnnotationTitle] != "keep" {
		t.Fatalf("concurrent stop not preserved: conflicted=%v annotations=%v", c.conflicted, st.Annotations)
	}
	if err := k.RecordStop(ctx, "team", "chat-1", 300); err != nil {
		t.Fatal(err)
	}
	st, err = k.GetSession(ctx, "team", "chat-1")
	if err != nil || stopBefore(st) != 300 {
		t.Fatalf("stop boundary did not advance: state=%v err=%v", st, err)
	}
}

func TestKubeListEndpointMembers(t *testing.T) {
	ready, notReady := true, false
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "blip-system",
			Name:      "blipchat-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "blipchat"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "blipchat-a"}},
			{Conditions: discoveryv1.EndpointConditions{Ready: &notReady}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "blipchat-b"}},
			{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, Addresses: []string{"10.0.0.3"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(slice).Build()
	k := &kubeCluster{c: c}

	members, err := k.ListEndpointMembers(context.Background(), "blip-system", "blipchat")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(members)
	want := []string{"10.0.0.3", "blipchat-a"}
	if len(members) != len(want) || members[0] != want[0] || members[1] != want[1] {
		t.Fatalf("members = %v, want %v", members, want)
	}

	members, err = k.ListEndpointMembers(context.Background(), "blip-system", "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Fatalf("other service members = %v", members)
	}
}

func TestKubeListSessionsSkipsCopies(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
		&v1.BlipState{ObjectMeta: metav1.ObjectMeta{
			Namespace:   "team",
			Name:        "chat-1",
			Labels:      map[string]string{LabelSession: "true"},
			Annotations: map[string]string{AnnotationProfile: "default"},
		}},
		&v1.BlipState{ObjectMeta: metav1.ObjectMeta{
			Namespace: "team",
			Name:      "chat-1-copy",
			Labels:    map[string]string{LabelSession: "true"},
		}},
	).Build()
	k := &kubeCluster{c: c}

	states, err := k.ListSessions(context.Background(), "team")
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Name != "chat-1" {
		t.Fatalf("sessions = %v", states)
	}
}

func TestKubePatchSession(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(&v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "chat-1"},
	}).Build()
	k := &kubeCluster{c: c}
	ctx := context.Background()

	if err := k.PatchSession(ctx, "team", "chat-1", map[string]string{LabelSession: "true"}, map[string]string{AnnotationStart: "42"}); err != nil {
		t.Fatalf("PatchSession: %v", err)
	}
	st, err := k.GetSession(ctx, "team", "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Labels[LabelSession] != "true" || st.Annotations[AnnotationStart] != "42" {
		t.Fatalf("state = %+v", st.ObjectMeta)
	}
}
