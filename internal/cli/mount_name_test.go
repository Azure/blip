// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// mount --new used to pass its scoped name straight to Create, so a malformed
// name leaked the API server's raw validation error after fetching the root.
// Reject it with the same short message as run, gather and pull, before any
// state or mount intent exists.
func TestMountNewRejectsInvalidNamesBeforeEditing(t *testing.T) {
	for _, tc := range []struct {
		label string
		name  string
		want  string
	}{
		{"whitespace", " ", "RFC 1123"},
		{"254", strings.Repeat("a", 254), "253"},
		{"300", strings.Repeat("a", 300), "253"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			h := newHarness(t, readyState("home"))
			code, _, errOut := h.run("", "mount", "--new", tc.name+":/data", "--root", "home")
			if code != 1 || !strings.Contains(errOut, "invalid state name") || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d stderr %q, want invalid state name containing %q", code, errOut, tc.want)
			}
			for _, raw := range []string{"metadata.name", "is invalid:"} {
				if strings.Contains(errOut, raw) {
					t.Fatalf("leaked raw API error %q: %s", raw, errOut)
				}
			}
			var states v1alpha1.BlipStateList
			if err := h.kube.List(context.Background(), &states, client.InNamespace(ns)); err != nil {
				t.Fatal(err)
			}
			if len(states.Items) != 1 || states.Items[0].Name != "home" {
				t.Fatalf("rejected --new created states: %+v", states.Items)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected --new wrote mount intent: %+v", mounts)
			}
		})
	}
}

// The longest legal name is still accepted, so validation does not turn into
// an off-by-one restriction.
func TestMountNewAcceptsMaxLengthName(t *testing.T) {
	h := newHarness(t, readyState("home"))
	name := strings.Repeat("a", 253)
	code, out, errOut := h.run("", "mount", "--new", name+":/data", "--root", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state "+name+" mounted on root state home at /data (writable)")
	if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].State != name || mounts[0].Path != "/data" {
		t.Fatalf("mounts %+v", mounts)
	}
}
