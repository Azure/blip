package controller

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

func TestRootRestoresMountsAfterExecutionDeleted(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	old := e.startBlip("old-name", "n1", withRoot("home"), e.withMount("data", "/data", true))
	e.run(e.pool, ns, "default")
	attachment := mountOf(old, "data").AttachmentID
	e.must(e.c.Delete(e.ctx, old))
	e.observe(old.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited})
	e.run(e.blip, ns, old.Name)
	e.saveWriter("home", "saved-home")
	e.run(e.blip, ns, old.Name)
	saving := e.getBlip(old.Name)
	expectPhase(t, saving, v1.BlipSaving, ReasonStopped)
	if m := mountOf(saving, "data"); m == nil || m.AttachmentID != attachment || m.Phase != v1.MountSaving {
		t.Fatalf("lost saving attachment: %+v", m)
	}
	e.saveWriter("data", "saved-data")
	e.run(e.blip, ns, old.Name)
	if err := e.c.Get(e.ctx, req(ns, old.Name).NamespacedName, &v1.Blip{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old execution still exists: %v", err)
	}
	root := e.getState("home")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].State != "data" {
		t.Fatalf("durable mount intent lost: %+v", root.Spec)
	}
	fresh := e.startBlip("new-name", "n1", withRoot("home"))
	m := mountOf(fresh, "data")
	if m == nil || m.AttachmentID == attachment || m.CommitID != "saved-data" || !m.Writable || m.Path != "/data" {
		t.Fatalf("restored mount: %+v", m)
	}
	if fresh.Status.StateGeneration != 0 {
		t.Fatal("unobserved mount topology acknowledged")
	}
	e.observe(fresh.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: fresh.Status.RootAttachmentID,
		Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, fresh.Name)
	if b := e.getBlip(fresh.Name); b.Status.StateGeneration != root.Generation {
		t.Fatalf("mounted generation %d, want %d", b.Status.StateGeneration, root.Generation)
	}
}

func TestRootInvalidLiveEditPreservesAttachments(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("dev", "n1", withRoot("home"), e.withMount("data", "/data", true))
	id := mountOf(b, "data").AttachmentID
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: id, Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, b.Name)
	gen := e.getBlip(b.Name).Status.StateGeneration
	e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].Path = "invalid" })
	e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	m := mountOf(b, "data")
	if m.Phase != v1.MountMounted || m.AttachmentID != id || m.Path != "/data" || b.Status.StateGeneration != gen || b.Status.Reason != ReasonInvalidSpec {
		t.Fatalf("invalid edit disrupted attachment: %+v", b.Status)
	}
	e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].Path = "/new" })
	e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	if mountOf(b, "data").Phase != v1.MountUnmounting || b.Status.StateGeneration != gen {
		t.Fatalf("path change did not start safe detach: %+v", b.Status)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: id, Phase: podapi.DiskDetached}}})
	e.run(e.blip, ns, b.Name)
	e.saveWriter("data", "new-version")
	e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	m = mountOf(b, "data")
	if m.Path != "/new" || m.CommitID != "new-version" || m.Phase != v1.MountPending || b.Status.StateGeneration != gen {
		t.Fatalf("edited mount was not restored from its save: %+v", b.Status)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, b.Name)
	if b = e.getBlip(b.Name); b.Status.StateGeneration != e.getState("home").Generation {
		t.Fatalf("completed topology not acknowledged: %+v", b.Status)
	}
}

func TestPromotionRetriesAcceptedRootIntent(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("dev", "n1", withRoot("home"), e.withMount("data", "/data", false))
	id := mountOf(b, "data").AttachmentID
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: id, Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, b.Name)
	st := e.getState("data")
	st.Status.Writer = &v1.Writer{BlipUID: "other", BlipName: "other", AttachmentID: "busy", BaseCommit: st.Status.Committed.ID}
	e.must(e.c.Status().Update(e.ctx, st))
	e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].Writable = true })
	res := e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	if m := mountOf(b, "data"); m.Phase != v1.MountMounted || !strings.Contains(m.Message, "in use") || m.Switching || res.RequeueAfter == 0 {
		t.Fatalf("busy promotion lost retry: %+v, %+v", m, res)
	}
	st = e.getState("data")
	st.Status.Writer = nil
	e.must(e.c.Status().Update(e.ctx, st))
	e.run(e.blip, ns, b.Name)
	if m := mountOf(e.getBlip(b.Name), "data"); m.Phase != v1.MountUnmounting || !m.Switching {
		t.Fatalf("accepted promotion did not resume: %+v", m)
	}
}

func TestImportedStatesRefuseWriters(t *testing.T) {
	for _, use := range []string{"root", "aux", "promote"} {
		t.Run(use, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 1, 0)
			e.newState("base", func(st *v1.BlipState) { st.Spec.Image, st.Spec.Replicas = "reg/img:v1", 0 })
			e.run(e.state, ns, "base")
			st := e.getState("base")
			e.hold("base", st.Status.Pending.CommitID, "n1")
			e.run(e.state, ns, "base")
			e.readyState("home", "n1")
			if use == "promote" {
				b := e.startBlip("dev", "n1", withRoot("home"), e.withMount("base", "/base", false))
				id := mountOf(b, "base").AttachmentID
				e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: id, Phase: podapi.DiskMounted}}})
				e.run(e.blip, ns, b.Name)
				e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].Writable = true })
				e.run(e.blip, ns, b.Name)
				b = e.getBlip(b.Name)
				if m := mountOf(b, "base"); m.Phase != v1.MountMounted || m.AttachmentID != id || b.Status.Reason != ReasonInvalidSpec {
					t.Fatalf("base promotion disrupted read-only disk: %+v", b.Status)
				}
			} else {
				mutate := []func(*v1.Blip){withRoot("base")}
				if use == "aux" {
					mutate = []func(*v1.Blip){withRoot("home"), e.withMount("base", "/base", true)}
				}
				e.newBlip("dev", mutate...)
				e.run(e.pool, ns, "default")
				e.warmOn("n1")
				e.run(e.blip, ns, "dev")
				b := e.getBlip("dev")
				expectPhase(t, b, v1.BlipFailed, ReasonInvalidSpec)
				if b.Status.Pod != "" || !strings.Contains(b.Status.Message, "fork") {
					t.Fatalf("base startup accepted: %+v", b.Status)
				}
			}
			if w := e.getState("base").Status.Writer; w != nil {
				t.Fatalf("imported base has a writer: %+v", w)
			}
		})
	}
}

func TestTemporaryMountCleanupWaitsForSaves(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	b := e.startBlip("execution", "n1", withRoot("home"), e.withMount("data", "/data", true))
	e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].BlipUID = string(b.UID) })
	e.run(e.state, ns, "home")
	if len(e.getState("home").Spec.Mounts) != 1 {
		t.Fatal("active temporary mount pruned")
	}
	e.must(e.c.Delete(e.ctx, b))
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited})
	e.run(e.blip, ns, b.Name)
	e.run(e.state, ns, "home")
	if len(e.getState("home").Spec.Mounts) != 1 {
		t.Fatal("saving temporary mount pruned")
	}
	e.saveWriter("home", newID())
	e.saveWriter("data", newID())
	e.run(e.blip, ns, b.Name)
	e.run(e.state, ns, "home")
	if len(e.getState("home").Spec.Mounts) != 0 {
		t.Fatal("finished execution's temporary mount retained")
	}
}

func TestTemporaryMountUIDCleanup(t *testing.T) {
	for _, phase := range []string{"absent", v1.BlipSucceeded, v1.BlipFailed, "stopped", "reused-name"} {
		t.Run(phase, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.readyState("home", "n1")
			e.readyState("data", "n1")
			e.readyState("durable", "n1")
			e.newBlip("exec", withRoot("home"))
			e.updateRoot("exec", func(st *v1.BlipState) {
				st.Spec.Mounts = []v1.Mount{{State: "data", Path: "/tmp-data", BlipUID: "uid-exec"}, {State: "durable", Path: "/durable"}}
			})
			b := e.getBlip("exec")
			switch phase {
			case "absent", "reused-name":
				e.must(e.c.Delete(e.ctx, b))
				if phase == "reused-name" {
					e.newBlip("exec", withRoot("home"), func(b *v1.Blip) { b.UID = types.UID("replacement") })
				}
			case "stopped":
				e.updateBlip("exec", func(b *v1.Blip) { b.Spec.Stop = true })
			default:
				e.setBlipStatus("exec", func(b *v1.Blip) { b.Status.Phase = phase })
			}
			e.run(e.state, ns, "home")
			mounts := e.getState("home").Spec.Mounts
			if len(mounts) != 1 || mounts[0].State != "durable" {
				t.Fatalf("cleanup removed durable intent or kept stale UID: %+v", mounts)
			}
		})
	}
}

func TestChildStateWatchFindsPendingRootIntent(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newState("child")
	e.newBlip("pending", withRoot("home"), e.withMount("child", "/child", true))
	e.run(e.blip, ns, "pending")
	if len(e.getBlip("pending").Status.Mounts) != 0 {
		t.Fatal("pending Blip unexpectedly published mounts")
	}
	rqs := e.blip.stateBlips(e.ctx, e.getState("child"))
	if !slices.Contains(rqs, req(ns, "pending")) {
		t.Fatalf("child did not wake root's pending Blip: %v", rqs)
	}
	if rqs := e.state.profileStates(e.ctx, e.getState("child")); !slices.Contains(rqs, req(ns, "home")) {
		t.Fatalf("child save would not wake root cleanup: %v", rqs)
	}
	if rqs := e.state.profileStates(e.ctx, e.getState("home")); !slices.Contains(rqs, req(ns, "child")) {
		t.Fatalf("root edit would not wake child reservation recovery: %v", rqs)
	}
	// Neither a profile alone nor an offline pending intent blocks deletion.
	e.must(e.c.Delete(e.ctx, e.getState("child")))
	e.run(e.state, ns, "child")
	if err := e.c.Get(e.ctx, req(ns, "child").NamespacedName, &v1.BlipState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("offline root intent blocked deletion: %v", err)
	}
}

func TestAuxiliaryProfileDoesNotExpand(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	child := e.readyState("child", "n1")
	child.Spec.Mounts = []v1.Mount{{State: "missing", Path: "invalid", Writable: true}}
	e.must(e.c.Update(e.ctx, child))
	b := e.startBlip("dev", "n1", withRoot("home"), e.withMount("child", "/child", false))
	if len(b.Status.Mounts) != 1 || b.Status.Mounts[0].State != "child" {
		t.Fatalf("auxiliary profile expanded: %+v", b.Status)
	}
}

func TestUnpublishedWriterFollowsRootIntentAndUID(t *testing.T) {
	for _, use := range []string{"wanted", "removed", "different-uid", "other-blip", "stopping", "old-temporary"} {
		t.Run(use, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			e.readyState("home", "n1")
			e.readyState("data", "n1")
			b := e.startBlip("dev", "n1", withRoot("home"))
			e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}} })
			st := e.getState("data")
			st.Status.Writer = &v1.Writer{AttachmentID: "crash-writer", BlipName: b.Name, BlipUID: string(b.UID),
				PodName: b.Status.Pod, PodUID: b.Status.PodUID, Node: b.Status.Node, BaseCommit: st.Status.Committed.ID}
			switch use {
			case "removed":
				e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts = nil })
			case "different-uid":
				st.Status.Writer.BlipUID = "former-uid"
			case "other-blip":
				st.Status.Writer.BlipUID, st.Status.Writer.BlipName = "other", "other"
			case "stopping":
				e.updateBlip(b.Name, func(b *v1.Blip) { b.Spec.Stop = true })
			case "old-temporary":
				e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts[0].BlipUID = "old-execution" })
			}
			e.must(e.c.Status().Update(e.ctx, st))
			e.run(e.state, ns, "data")
			if use == "removed" || use == "stopping" || use == "old-temporary" {
				if e.getState("data").Status.Writer == nil {
					t.Fatal("state controller released the live owner's reservation")
				}
				e.run(e.blip, ns, b.Name)
			}
			st = e.getState("data")
			if (st.Status.Writer != nil) != (use == "wanted") {
				t.Fatalf("writer recovery disagrees with root intent/UID: %+v", st.Status)
			}
			if use == "wanted" {
				e.run(e.blip, ns, b.Name)
				if m := mountOf(e.getBlip(b.Name), "data"); m == nil || m.AttachmentID != "crash-writer" {
					t.Fatalf("interrupted reservation not adopted: %+v", m)
				}
			}
		})
	}
}

func TestInheritedMountOwnership(t *testing.T) {
	for _, tt := range []struct {
		name, state, owner, image string
		writable, allowed         bool
	}{
		{"own private", "alice.data", "alice", "", true, true},
		{"own prefix foreign label read", "alice.data", "bob", "", false, false},
		{"own prefix foreign label write", "alice.data", "bob", "", true, false},
		{"own prefix unowned private", "alice.data", "", "", false, false},
		{"foreign private read", "bob.data", "bob", "", false, false},
		{"foreign private write", "bob.data", "bob", "", true, false},
		{"shared base read", "base", "", "reg/img:v1", false, true},
		{"shared base write", "base", "", "reg/img:v1", true, false},
		{"private base read", "bob.base", "bob", "reg/img:v1", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			e.ownedState("alice.home", "alice")
			st := e.readyState(tt.state, "n1")
			st.Spec.Image = tt.image
			st.Labels = map[string]string{LabelOwner: tt.owner}
			e.must(e.c.Update(e.ctx, st))
			e.newBlip("alice.dev", withRoot("alice.home"), e.withMount(tt.state, "/data", tt.writable), func(b *v1.Blip) {
				b.Labels = map[string]string{LabelOwner: "alice"}
			})
			e.run(e.blip, ns, "alice.dev")
			b := e.getBlip("alice.dev")
			if tt.allowed {
				expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
			} else {
				expectPhase(t, b, v1.BlipFailed, ReasonInvalidSpec)
				if e.getState(tt.state).Status.Writer != nil {
					t.Fatal("foreign or immutable mount took writer")
				}
			}
		})
	}
}

func TestCopyValidatesActualSharedSource(t *testing.T) {
	for _, tt := range []struct {
		name, source, owner, image string
		allowed                    bool
	}{
		{"own private", "alice.source", "alice", "", true},
		{"own prefix foreign label", "alice.source", "bob", "", false},
		{"own prefix foreign base", "alice.source", "bob", "reg/img:v1", false},
		{"own prefix unowned private", "alice.source", "", "", false},
		{"shared imported base", "base", "", "reg/img:v1", true},
		{"base name recreated as private", "base", "bob", "", false},
		{"base assigned an owner", "base", "bob", "reg/img:v1", false},
		{"foreign private", "bob.source", "bob", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			st := e.readyState(tt.source, "n1")
			st.Spec.Image = tt.image
			st.Labels = map[string]string{LabelOwner: tt.owner}
			e.must(e.c.Update(e.ctx, st))
			e.newState("alice.copy", func(st *v1.BlipState) {
				st.Spec.CopyFrom = tt.source
				st.Labels = map[string]string{LabelOwner: "alice"}
			})
			e.run(e.state, ns, "alice.copy")
			copy := e.getState("alice.copy")
			if tt.allowed {
				if copy.Status.Pending == nil || copy.Status.CopiedFrom.StateUID != string(st.UID) {
					t.Fatalf("allowed copy not pinned: %+v", copy.Status)
				}
			} else if copy.Status.Phase != v1.StateFailed || copy.Status.Pending != nil || copy.Status.CopiedFrom != nil || !strings.Contains(copy.Status.Message, "not owned") {
				t.Fatalf("foreign source accepted: %+v", copy.Status)
			}
		})
	}
}

func TestPoolWatchesBaseWithoutWaitingBlips(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)
	e.newPool("other", 0, 0)
	e.newState("base", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1" })
	rqs := e.pool.statePools(e.ctx, e.getState("base"))
	if !slices.Contains(rqs, req(ns, "default")) || !slices.Contains(rqs, req(ns, "other")) {
		t.Fatalf("base change did not wake pool authorization: %v", rqs)
	}
}

func TestNewExecutionIgnoresOldTemporaryMountStillSaving(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	data := e.readyState("data", "n1")
	data.Status.Writer = &v1.Writer{BlipUID: "old-execution", BlipName: "old", AttachmentID: "old-attachment", PodUID: "old-pod", Node: "n1"}
	e.must(e.c.Status().Update(e.ctx, data))
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true, BlipUID: "old-execution"}}
	e.must(e.c.Update(e.ctx, root))
	b := e.startBlip("new", "n1", withRoot("home"))
	if len(b.Status.Mounts) != 0 {
		t.Fatalf("new execution inherited old temporary mount: %+v", b.Status.Mounts)
	}
	if len(e.getState("home").Spec.Mounts) != 1 {
		t.Fatal("pruned a still-saving temporary reference")
	}
}

func TestTemporaryMountCleanupPrunesCountersAtomically(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("home", "n1")
	e.newBlip("active", withRoot("home"))
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{
		{State: "active", Path: "/active", BlipUID: "uid-active"},
		{State: "stale", Path: "/stale", BlipUID: "gone"},
		{State: "adopted", Path: "/adopted"},
	}
	root.Annotations = map[string]string{
		"unrelated":             "keep",
		collectMountsAnnotation: `{"active":{"blipUID":"uid-active","path":"/active","token":"live","users":2},"stale":{"blipUID":"gone","path":"/stale","token":"old","users":1},"adopted":{"blipUID":"gone","path":"/adopted","token":"old","users":1},"removed":{"blipUID":"gone","path":"/removed","token":"old","users":1}}`,
	}
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "home")
	root = e.getState("home")
	if len(root.Spec.Mounts) != 2 || root.Annotations["unrelated"] != "keep" {
		t.Fatalf("cleanup changed durable intent: %+v", root)
	}
	var users map[string]json.RawMessage
	e.must(json.Unmarshal([]byte(root.Annotations[collectMountsAnnotation]), &users))
	if len(users) != 1 || !strings.Contains(string(users["active"]), `"users":2`) || !strings.Contains(string(users["active"]), `"token":"live"`) {
		t.Fatalf("stale counters retained or active counters lost: %s", root.Annotations[collectMountsAnnotation])
	}
	// Adopting the last temporary mount cleans its counters on the next
	// reconcile even though the root no longer has any temporary references.
	root.Spec.Mounts[0].BlipUID = ""
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "home")
	root = e.getState("home")
	if _, ok := root.Annotations[collectMountsAnnotation]; ok {
		t.Fatalf("adopted mount kept stale counters: %v", root.Annotations)
	}
}

func TestTemporaryCleanupDoesNotOverwriteConcurrentAdoption(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("home", "n1")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", BlipUID: "gone"}}
	root.Annotations = map[string]string{collectMountsAnnotation: `{"data":{"blipUID":"gone","path":"/data","token":"old","users":1}}`}
	e.must(e.c.Update(e.ctx, root))
	adopted := false
	c := interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*v1.BlipState); ok && obj.GetName() == "home" && !adopted {
				adopted = true
				fresh := e.getState("home")
				fresh.Spec.Mounts[0].BlipUID = ""
				e.must(c.Update(ctx, fresh))
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
	if err := pruneTemporaryMounts(e.ctx, c, e.c, root); !apierrors.IsConflict(err) {
		t.Fatalf("cleanup overwrote concurrent adoption: %v", err)
	}
	root = e.getState("home")
	e.must(pruneTemporaryMounts(e.ctx, c, e.c, root))
	root = e.getState("home")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].BlipUID != "" || root.Annotations[collectMountsAnnotation] != "" {
		t.Fatalf("adopted mount or counter cleanup lost on retry: %+v", root)
	}
}

func TestSharedReadOnlyMountRevalidatesAttachedUID(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.ownedState("alice.home", "alice")
	base := e.readyState("base", "n1")
	base.Spec.Image = "reg/img:v1"
	e.must(e.c.Update(e.ctx, base))
	e.newBlip("alice.dev", withRoot("alice.home"), e.withMount("base", "/base", false), func(b *v1.Blip) {
		b.Labels = map[string]string{LabelOwner: "alice"}
	})
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	reads := 0
	e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if st, ok := obj.(*v1.BlipState); ok && key.Name == "base" {
				reads++
				if reads > 1 {
					st.UID = "private-replacement"
					st.Spec.Image = ""
					st.Labels = map[string]string{LabelOwner: "bob"}
				}
			}
			return nil
		},
	})
	e.run(e.blip, ns, "alice.dev")
	b := e.getBlip("alice.dev")
	expectPhase(t, b, v1.BlipFailed, ReasonInvalidSpec)
	if len(b.Status.Mounts) != 0 || b.Status.Pod != "" || e.getState("alice.home").Status.Writer != nil {
		t.Fatalf("attached private replacement after validating old base: %+v", b.Status)
	}
}

func (e *env) ownedState(name, owner string) *v1.BlipState {
	e.t.Helper()
	st := e.readyState(name, "n1")
	st.Labels = map[string]string{LabelOwner: owner}
	e.must(e.c.Update(e.ctx, st))
	return st
}

func TestSharedLiveMountRevalidatesAttachedUID(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.ownedState("alice.home", "alice")
	base := e.readyState("base", "n1")
	base.Spec.Image = "reg/img:v1"
	e.must(e.c.Update(e.ctx, base))
	b := e.startBlip("alice.dev", "n1", withRoot("alice.home"), func(b *v1.Blip) {
		b.Labels = map[string]string{LabelOwner: "alice"}
	})
	e.run(e.blip, ns, b.Name)
	gen := e.getBlip(b.Name).Status.StateGeneration
	e.updateRoot(b.Name, func(st *v1.BlipState) { st.Spec.Mounts = []v1.Mount{{State: "base", Path: "/base"}} })
	reads := 0
	e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if st, ok := obj.(*v1.BlipState); ok && key.Name == "base" {
				reads++
				if reads > 1 {
					st.UID = "private-replacement"
					st.Spec.Image = ""
					st.Labels = map[string]string{LabelOwner: "bob"}
				}
			}
			return nil
		},
	})
	e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	if len(b.Status.Mounts) != 0 || b.Status.StateGeneration != gen || !strings.Contains(b.Status.Message, "not owned") {
		t.Fatalf("live mount attached a private replacement: %+v", b.Status)
	}
}

func TestLiveRootOwnershipCheckedBeforeProfileCleanup(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.ownedState("alice.home", "alice")
	b := e.startBlip("alice.dev", "n1", withRoot("alice.home"), func(b *v1.Blip) {
		b.Labels = map[string]string{LabelOwner: "alice"}
	})
	e.run(e.blip, ns, b.Name)
	gen := e.getBlip(b.Name).Status.StateGeneration
	root := e.getState(b.Spec.State)
	root.Labels[LabelOwner] = "bob"
	root.Spec.Mounts = []v1.Mount{{State: "missing", Path: "/collect", BlipUID: "gone"}}
	root.Annotations = map[string]string{collectMountsAnnotation: `{"missing":{"blipUID":"gone","path":"/collect","users":1}}`}
	e.must(e.c.Update(e.ctx, root))
	e.run(e.blip, ns, b.Name)
	b = e.getBlip(b.Name)
	expectPhase(t, b, v1.BlipRunning, ReasonInvalidSpec)
	if b.Status.StateGeneration != gen || len(e.getState(root.Name).Spec.Mounts) != 1 || e.getState(root.Name).Annotations[collectMountsAnnotation] == "" {
		t.Fatalf("foreign root profile was applied or pruned: %+v", b.Status)
	}
}

func TestRootEditDuringWriterPublication(t *testing.T) {
	for _, phase := range []string{"pending", "running"} {
		for _, crash := range []bool{false, true} {
			name := phase
			if crash {
				name += "-interrupted"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				e.addNodes("n1")
				e.newPool("default", 1, 0)
				e.readyState("home", "n1")
				e.readyState("z-data", "n1")
				if phase == "running" {
					e.startBlip("dev", "n1", withRoot("home"))
					e.updateRoot("dev", func(st *v1.BlipState) { st.Spec.Mounts = []v1.Mount{{State: "z-data", Path: "/data", Writable: true}} })
				} else {
					e.newBlip("dev", withRoot("home"), e.withMount("z-data", "/data", true))
					e.run(e.pool, ns, "default")
					e.warmOn("n1")
				}
				interrupted := errors.New("interrupted after assignment")
				assigned := ""
				e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
					SubResourcePatch: func(ctx context.Context, c client.Client, resource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						if err := c.SubResource(resource).Patch(ctx, obj, patch, opts...); err != nil {
							return err
						}
						st, ok := obj.(*v1.BlipState)
						if !ok || st.Name != "z-data" || st.Status.Writer == nil || assigned != "" {
							return nil
						}
						assigned = st.Status.Writer.AttachmentID
						e.updateRoot("dev", func(st *v1.BlipState) { st.Spec.Mounts = nil })
						// The root watch may reconcile the state while the Blip
						// is still about to publish this attachment.
						e.run(e.state, ns, "z-data")
						if w := e.getState("z-data").Status.Writer; w == nil || w.AttachmentID != assigned {
							t.Fatalf("state controller revoked in-flight reservation: %+v", w)
						}
						if crash {
							return interrupted
						}
						return nil
					},
				})
				if crash {
					if _, err := e.blip.Reconcile(e.ctx, req(ns, "dev")); err == nil {
						t.Fatal("publication interruption was not observed")
					}
					e.blip.Client = e.c
					e.run(e.blip, ns, "dev")
					if e.getState("z-data").Status.Writer != nil || mountOf(e.getBlip("dev"), "z-data") != nil {
						t.Fatal("interrupted obsolete reservation leaked on restart")
					}
					return
				}
				e.run(e.blip, ns, "dev")
				b := e.getBlip("dev")
				m := mountOf(b, "z-data")
				w := e.getState("z-data").Status.Writer
				if m == nil || w == nil || m.AttachmentID != assigned || w.AttachmentID != assigned || w.PodUID != b.Status.PodUID {
					t.Fatalf("published attachment lost its reservation: mount=%+v writer=%+v", m, w)
				}
				expectPhase(t, b, v1.BlipRunning, "")
				// If the node attached before seeing the newer root intent,
				// removal must use the normal detach/save path. A mount the
				// node never attached is covered by the never-attached tests.
				e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: assigned, Phase: podapi.DiskMounted}}})
				e.run(e.blip, ns, "dev")
				if m := mountOf(e.getBlip("dev"), "z-data"); m == nil || m.Phase != v1.MountUnmounting {
					t.Fatalf("root edit did not safely detach published mount: %+v", m)
				}
			})
		}
	}
}
