package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestPendingBlipRejectsReplacedMount covers a mount state deleted and
// recreated under the same name while the Blip waits for a VM. The pinned UID
// must turn the substitution into a terminal failure, as it already does for a
// replaced root, instead of attaching the new filesystem.
func TestPendingBlipRejectsReplacedMount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
	root.Generation++
	e.must(e.c.Update(e.ctx, root))

	e.newBlip("job", withRoot("home"))
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
	old := e.getState("data").UID
	if b.Status.MountStateUIDs["data"] != string(old) {
		t.Fatalf("mount UID not pinned: %+v", b.Status.MountStateUIDs)
	}

	st := e.getState("data")
	st.Finalizers = nil
	e.must(e.c.Update(e.ctx, st))
	e.must(e.c.Delete(e.ctx, st))
	e.readyState("data", "n1")
	now := e.getState("data").UID
	if now == old {
		t.Fatal("test setup: mount state was not recreated")
	}

	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonStateNotFound)
	if !strings.Contains(b.Status.Message, "replaced") || !strings.Contains(b.Status.Message, "substituted") {
		t.Fatalf("replaced mount message: %q", b.Status.Message)
	}
	if m := mountOf(b, "data"); m != nil {
		t.Fatalf("Blip attached the substituted mount: %+v", m)
	}
}
