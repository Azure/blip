package cli

import (
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
)

func TestPullCreatesImportedBase(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.run("", "pull", "base", "registry/dev:v1", "--size", "20Gi", "--image-pull-secret", "registry-auth", "--image-pull-secret", "other-auth")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/base Ready")
	st := h.state("base")
	if st.Spec.Image != "registry/dev:v1" || st.Spec.CopyFrom != "" || st.Spec.Replicas != 0 || st.Spec.Size.String() != "20Gi" || len(st.Spec.ImagePullSecrets) != 2 || st.Spec.ImagePullSecrets[0].Name != "registry-auth" || st.Status.Committed == nil || len(st.OwnerReferences) != 0 {
		t.Fatalf("base %+v", st)
	}
}

func TestPullDetachAndFailure(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) { c.paused = true })
	code, out, errOut := h.run("", "pull", "base", "registry/dev:v1", "-d")
	if code != 0 || out != "blipstate/base created\n" || h.state("base").Status.Phase != "" {
		t.Fatalf("code %d out %q: %s", code, out, errOut)
	}
	h.ctrl.set(func(c *fakeController) { c.paused, c.stateFail = false, "pull denied" })
	code, _, errOut = h.run("", "pull", "broken", "registry/dev:v1")
	if code != 1 || !strings.Contains(errOut, "pull denied") || h.state("broken").Status.Phase != v1alpha1.StateFailed {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestPullBadOptionsAndExistingBase(t *testing.T) {
	h := newHarness(t, readyState("taken"))
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"pull", "base"}, "accepts 2 arg(s)"},
		{[]string{"pull", "base", "registry/dev:v1", "--size", "0"}, "must be positive"},
		{[]string{"pull", "base", "registry/dev:v1", "--size", "8Ei"}, "too large"},
		{[]string{"pull", "base", "registry/dev:v1", "--size", "10Ei"}, "too large"},
		{[]string{"pull", "base", "registry/dev:v1", "--size", "100Ei"}, "too large"},
		{[]string{"pull", "base", "registry/dev:v1", "--size", "9223372036854775807"}, "too large"},
		{[]string{"pull", "base", "registry/dev:v1", "--replicas", "1"}, "unknown flag: --replicas"},
		{[]string{"pull", "base", "registry/dev:v1", "--image-pull-secret", "bad/name"}, "invalid --image-pull-secret"},
		{[]string{"pull", "taken", "registry/dev:v1", "-d"}, `state "taken" already exists`},
	} {
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d: %s", tc.args, code, errOut)
		}
	}
}
