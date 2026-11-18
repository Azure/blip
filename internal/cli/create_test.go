package cli

import (
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

func TestCreateStateDetached(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.run("", "create", "blipstate", "scratch", "-d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/scratch created")
	s := h.state("scratch")
	if s.Spec.Image != "" || s.Spec.CopyFrom != "" || s.Spec.Size != nil || s.Spec.Replicas != 0 {
		t.Fatalf("unexpected spec %+v", s.Spec)
	}
}

func TestCreateStateSettings(t *testing.T) {
	h := newHarness(t, readyState("repo"), readyState("ref"))
	code, out, errOut := h.run("", "create", "blipstate", "dev", "--size", "20Gi", "--mount", "repo:/work:rw", "--mount", "ref:/ref", "--env", "EDITOR=vim", "--workdir", "/work", "--user", "dev", "--idle-timeout", "10m", "-d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/dev created")
	s := h.state("dev")
	if s.Spec.Image != "" || s.Spec.Size == nil || s.Spec.Size.String() != "20Gi" || s.Spec.Replicas != 0 {
		t.Fatalf("unexpected spec %+v", s.Spec)
	}
	if rt := s.Spec.Runtime; rt == nil || rt.User != "dev" || rt.WorkingDir != "/work" || len(rt.Env) != 1 || rt.Env[0].Value != "vim" || rt.IdleTimeout == nil || rt.IdleTimeout.Duration.String() != "10m0s" {
		t.Fatalf("runtime %+v", rt)
	}
	if mounts := s.Spec.Mounts; len(mounts) != 2 || mounts[0].State != "repo" || !mounts[0].Writable || mounts[1].State != "ref" || mounts[1].Writable {
		t.Fatalf("mounts %+v", mounts)
	}
}

func TestCreateStateFromOwnedState(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.base"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "create", "blipstate", "repo", "--from", "base", "--replicas", "2", "-d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/repo created")
	s := h.state("alice.repo")
	if s.Spec.CopyFrom != "alice.base" || s.Spec.Replicas != 2 || s.Labels[ownerLabel] != "alice" {
		t.Fatalf("state %+v labels %v", s.Spec, s.Labels)
	}
}

func TestCreateStateWaitsForCommit(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.run("", "create", "blipstate", "ready")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/ready Ready")
	if s := h.state("ready"); s.Status.Committed == nil {
		t.Fatal("state has no commit")
	}
}

func TestCreateStateFailure(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) { c.stateFail = "no space left" })
	code, _, errOut := h.run("", "create", "blipstate", "bad")
	if code != 1 || !strings.Contains(errOut, `state "bad" failed: no space left`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestCreateStateRejectsFailedSource(t *testing.T) {
	bad := state("bad")
	bad.Status.Phase, bad.Status.Message = v1alpha1.StateFailed, "image too large"
	h := newHarness(t, bad)
	code, _, errOut := h.run("", "create", "blipstate", "copy", "--from", "bad", "-d")
	if code != 1 || !strings.Contains(errOut, `copy source "bad" failed: image too large`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestCreateStateWaitsThroughRecoverableFailure(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: retrying"
		c.stateFailPending = true
	})
	code, out, errOut := h.run("", "create", "blipstate", "flaky")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/flaky Ready")
}

func TestCreateStateDetachDoesNotWait(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) { c.paused = true })
	code, out, errOut := h.run("", "create", "blipstate", "scratch", "-d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/scratch created")
	if s := h.state("scratch"); s.Status.Phase != "" {
		t.Fatalf("state advanced to %q", s.Status.Phase)
	}
}

func TestCreateStateRejectsBadFlags(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"image removed", []string{"create", "blipstate", "x", "--image", "i"}, "unknown flag: --image"},
		{"replicas zero", []string{"create", "blipstate", "x", "--replicas", "0"}, "--replicas must be between 1 and 3"},
		{"replicas too large", []string{"create", "blipstate", "x", "--replicas", "4"}, "--replicas must be between 1 and 3"},
		{"size syntax", []string{"create", "blipstate", "x", "--size", "nope"}, "invalid --size"},
		{"size zero", []string{"create", "blipstate", "x", "--size", "0"}, "must be positive"},
		{"missing source", []string{"create", "blipstate", "x", "--from", "missing"}, `state "missing" not found`},
		{"relative mount", []string{"create", "state", "x", "--mount", "s:work"}, "invalid mount"},
		{"unclean mount", []string{"create", "state", "x", "--mount", "s:/a/../b"}, "invalid mount"},
		{"mount mode", []string{"create", "state", "x", "--mount", "s:/w:rx"}, "mode must be rw or ro"},
		{"duplicate state", []string{"create", "state", "x", "--mount", "s:/a", "--mount", "s:/b"}, "mounted twice"},
		{"duplicate path", []string{"create", "state", "x", "--mount", "s:/a", "--mount", "other:/a"}, "used twice"},
		{"negative idle", []string{"create", "state", "x", "--idle-timeout=-1s"}, "must not be negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := h.run("", tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d: %s", code, errOut)
			}
		})
	}
}

func TestCreateStateRejectsExisting(t *testing.T) {
	h := newHarness(t, readyState("taken"))
	code, _, errOut := h.run("", "create", "blipstate", "taken", "-d")
	if code != 1 || !strings.Contains(errOut, `state "taken" already exists`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestCreateFromSnapshotsWorkspaceAndOverridesDefaults(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	base.Spec.Runtime = &v1alpha1.RuntimeDefaults{
		User: "base-user", WorkingDir: "/work",
		Env: []v1alpha1.EnvVar{{Name: "KEEP", Value: "yes"}, {Name: "CHANGE", Value: "before"}},
	}
	base.Spec.Mounts = []v1alpha1.Mount{{State: "shared-tools", Path: "/tools"}, {State: "repo", Path: "/work", Writable: true}}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), base, readyState("shared-tools"), readyState("alice.shared-tools"), readyState("repo"), readyState("alice.extra"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "create", "state", "dev", "--from", "base", "--env", "CHANGE=after", "--user", "dev", "--mount", "extra:/extra:rw", "--replicas", "2")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/dev Ready")
	st := h.state("alice.dev")
	if st.Spec.CopyFrom != "base" || st.Spec.Runtime.User != "dev" || st.Spec.Runtime.WorkingDir != "/work" || len(st.Spec.Runtime.Env) != 2 || st.Spec.Runtime.Env[0].Value != "yes" || st.Spec.Runtime.Env[1].Value != "after" {
		t.Fatalf("spec %+v", st.Spec)
	}
	if len(st.Spec.Mounts) != 3 || st.Spec.Mounts[0].State != "shared-tools" {
		t.Fatalf("mounts %+v", st.Spec.Mounts)
	}
	for i, source := range []string{"repo", "alice.extra"} {
		child := h.state(st.Spec.Mounts[i+1].State)
		if child.Spec.CopyFrom != source || child.Spec.Replicas != 2 || child.Status.Committed == nil || len(child.OwnerReferences) != 0 {
			t.Fatalf("child %+v", child)
		}
	}
	if source := h.state("base"); source.Spec.Runtime.User != "base-user" || source.Spec.Runtime.Env[1].Value != "before" || len(source.Spec.Mounts) != 2 {
		t.Fatalf("source mutated: %+v", source.Spec)
	}
}

func TestCreateRejectsWritableImportedMount(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	h := newHarness(t, base)
	code, _, errOut := h.run("", "create", "state", "workspace", "--mount", "base:/tools:rw", "-d")
	if code != 1 || !strings.Contains(errOut, "fork it before mounting writable") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}
