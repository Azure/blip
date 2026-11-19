package controller

import (
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestDeleteMountedStateWaitsForRoot covers a state named by another root's
// persistent spec.mounts. Deleting it would leave that root unable to start or
// fork, so the finalizer must report the dependent root and only finish after
// the mount is removed.
func TestDeleteMountedStateWaitsForRoot(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("data", "n1")
	e.readyState("home", "n1")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data"}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	e.must(e.c.Delete(e.ctx, e.getState("data")))
	e.run(e.state, ns, "data")
	data := e.getState("data")
	if data.DeletionTimestamp == nil || len(data.Finalizers) == 0 {
		t.Fatalf("mounted state was deleted: %+v", data)
	}
	if !strings.Contains(data.Status.Message, `mount in root state "home"`) {
		t.Fatalf("dependent mount blocker message: %q", data.Status.Message)
	}

	root = e.getState("home")
	root.Spec.Mounts = nil
	root.Generation++
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "data")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "data"}, &v1.BlipState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("state not deleted after unmount: %v", err)
	}
}

// TestRootCleanupDoesNotWaitForItsOwnMounts keeps the normal workspace cleanup:
// deleting the root is never blocked by the mount states it still lists.
func TestRootCleanupDoesNotWaitForItsOwnMounts(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("data", "n1")
	e.readyState("home", "n1")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	e.must(e.c.Delete(e.ctx, e.getState("home")))
	e.run(e.state, ns, "home")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &v1.BlipState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("root cleanup waited for its own mounts: %v", err)
	}
	if e.getState("data").Status.Committed == nil {
		t.Fatal("mount state was affected by root cleanup")
	}
}
