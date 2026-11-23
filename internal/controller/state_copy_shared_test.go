// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestCopyFromSharedCacheStateIsAccepted covers an owner forking an ownerless
// shared git cache: the copy-source ownership check must treat the cache as a
// shared state instead of failing the copy.
func TestCopyFromSharedCacheStateIsAccepted(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	cache := e.readyState("cache", "n1")
	cache.Labels = map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "repo"}
	e.must(e.c.Update(e.ctx, cache))

	e.newState("alice.copy", func(st *v1.BlipState) {
		st.Labels = map[string]string{v1.LabelOwner: "alice"}
		st.Spec.CopyFrom = "cache"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "alice.copy")

	cp := e.getState("alice.copy")
	if strings.Contains(cp.Status.Message, "is not owned by") {
		t.Fatalf("copy of shared state rejected: %+v", cp.Status)
	}
	if cp.Status.Phase == v1.StateFailed || cp.Status.Pending == nil {
		t.Fatalf("copy of shared state not planned: %+v", cp.Status)
	}
}
