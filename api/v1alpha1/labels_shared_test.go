// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestShared(t *testing.T) {
	state := func(labels map[string]string, image string) *BlipState {
		return &BlipState{
			ObjectMeta: metav1.ObjectMeta{Name: "s", Labels: labels},
			Spec:       BlipStateSpec{Image: image},
		}
	}
	for _, tt := range []struct {
		name  string
		state *BlipState
		want  bool
	}{
		{"image state with no owner", state(nil, "reg/img:v1"), true},
		{"ownerless state labelled shared", state(map[string]string{LabelShared: "true"}, ""), true},
		{"ownerless state without the label", state(nil, ""), false},
		{"owned state labelled shared", state(map[string]string{LabelOwner: "alice", LabelShared: "true"}, ""), false},
		{"owned image state", state(map[string]string{LabelOwner: "alice"}, "reg/img:v1"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Shared(tt.state); got != tt.want {
				t.Fatalf("Shared(%+v) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}
