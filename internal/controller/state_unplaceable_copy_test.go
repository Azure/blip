package controller

import (
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestUnplaceableCopyFailsAndReleasesSource covers a copy whose immutable
// nodeSelector matches no node. It cannot ever commit, so it must fail after
// the retry window instead of pinning its source's finalizer forever.
func TestUnplaceableCopyFailsAndReleasesSource(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("src", "n1")
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
		st.Spec.NodeSelector = map[string]string{"zone": "none"}
	})

	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.Phase != v1.StatePending || cp.Status.Pending != nil || cp.Status.UnplaceableSince == nil {
		t.Fatalf("unplaceable copy did not start its retry window: %+v", cp.Status)
	}
	if !strings.Contains(cp.Status.Message, "no eligible node") {
		t.Fatalf("unplaceable copy message: %q", cp.Status.Message)
	}

	e.now = e.now.Add(pendingTimeout + time.Second)
	e.run(e.state, ns, "cp")
	cp = e.getState("cp")
	if cp.Status.Phase != v1.StateFailed || cp.Status.Pending != nil || cp.Status.UnplaceableSince != nil {
		t.Fatalf("unplaceable copy did not fail after the bound: %+v", cp.Status)
	}
	if !strings.Contains(cp.Status.Message, "no eligible node") ||
		!strings.Contains(cp.Status.Message, `copy source "src"`) {
		t.Fatalf("unplaceable copy failure message: %q", cp.Status.Message)
	}

	e.must(e.c.Delete(e.ctx, e.getState("src")))
	e.run(e.state, ns, "src")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "src"}, &v1.BlipState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("failed copy still pins its source: %v", err)
	}
}
