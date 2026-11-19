// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestDriverRestartsGenerationOnNotRunning(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-test",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationTitle:   "Test",
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, "team", state); err != nil {
		t.Fatal(err)
	}
	fw := newFakeWire()
	fw.failFirst = true
	defer fw.closeLog()

	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        fw,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   "team",
		State:       "chat-test",
		Profile:     profile,
		AutoApprove: "always",
	})
	d.start(ctx)
	defer d.Close()

	if !d.Submit("hello") {
		t.Fatal("submit rejected")
	}
	waitFor(t, "two prompt attempts and two generations", func() bool {
		return len(fw.promptIDs()) >= 2 && len(fc.blipNames()) == 2
	})
	names := fc.blipNames()
	if names[0] != "chat-test-g1" || names[1] != "chat-test-g2" {
		t.Fatalf("generations = %v", names)
	}
	ids := fw.promptIDs()
	fw.emitRPC(ids[len(ids)-1], map[string]any{"stopReason": "end_turn"})
	waitFor(t, "stdin eof", func() bool {
		for _, m := range fw.messages() {
			if m.eof {
				return true
			}
		}
		return false
	})

	var methods []string
	for _, m := range fw.messages() {
		if m.method != "" {
			methods = append(methods, m.method)
		}
	}
	joined := strings.Join(methods, ",")
	for _, want := range []string{"initialize", "session/new", "session/load"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("methods %q do not contain %q", joined, want)
		}
	}
}
