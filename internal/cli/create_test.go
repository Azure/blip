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

func TestCreateStateFromImage(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.run("", "create", "blipstate", "dev", "--image", "registry/dev:1", "--size", "20Gi", "-d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/dev created")
	s := h.state("dev")
	if s.Spec.Image != "registry/dev:1" || s.Spec.Size == nil || s.Spec.Size.String() != "20Gi" || s.Spec.Replicas != 0 {
		t.Fatalf("unexpected spec %+v", s.Spec)
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
		{"image and from", []string{"create", "blipstate", "x", "--image", "i", "--from", "s"}, "at most one of --image and --from"},
		{"image and replicas", []string{"create", "blipstate", "x", "--image", "i", "--replicas", "1"}, "--replicas cannot be set with --image"},
		{"replicas zero", []string{"create", "blipstate", "x", "--replicas", "0"}, "--replicas must be between 1 and 3"},
		{"replicas too large", []string{"create", "blipstate", "x", "--replicas", "4"}, "--replicas must be between 1 and 3"},
		{"size syntax", []string{"create", "blipstate", "x", "--size", "nope"}, "invalid --size"},
		{"size zero", []string{"create", "blipstate", "x", "--size", "0"}, "must be positive"},
		{"missing source", []string{"create", "blipstate", "x", "--from", "missing"}, `state "missing" not found`},
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
