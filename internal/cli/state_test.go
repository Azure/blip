package cli

import (
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

func TestStateFailureIsTerminalWithPending(t *testing.T) {
	pending := func() *v1alpha1.BlipState {
		st := readyState("s")
		st.Status.Committed = nil
		st.Status.Phase = v1alpha1.StateFailed
		st.Status.Message = "initial version failed: needs more bytes"
		st.Status.LastError = "needs 1186988032 bytes, more than the requested 8388608"
		st.Status.Pending = &v1alpha1.PendingCommit{CommitID: "fedcba9876543210", Generation: 1}
		return st
	}
	if got, want := stateFailure(pending()), "needs 1186988032 bytes, more than the requested 8388608"; got != want {
		t.Fatalf("stateFailure = %q, want %q", got, want)
	}
	if got := stateFailure(readyState("ready")); got != "" {
		t.Fatalf("ready state classified as failed: %q", got)
	}
}

func TestPullFailedInitialVersionExits(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: needs more bytes"
		c.stateFailPending = true
		c.stateFailStuck = true
	})
	start := time.Now()
	code, _, errOut := h.run("", "pull", "smallv", "registry/dev:v1", "--size", "8Mi")
	if code != 1 || !strings.Contains(errOut, "needs more bytes") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pull waited %v for a terminal failure", elapsed)
	}
	// The controller keeps retrying the pending version. The CLI must not
	// depend on the controller clearing it before it can report failure.
	if st := h.state("smallv"); st.Status.Phase != v1alpha1.StateFailed || st.Status.Pending == nil {
		t.Fatalf("test did not leave a failed pending state: %+v", st.Status)
	}
}

func TestRunRejectsFailedSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string
	}{
		{"from", "--from"},
		{"state", "--state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.ctrl.set(func(c *fakeController) { c.stateFailStuck = true })
			bad := failedStateWithPending("bad")
			h.apply(bad)
			start := time.Now()
			code, _, errOut := h.run("", "run", "--name", "worker", tc.flag, "bad", "--", "true")
			if code != 1 || !strings.Contains(errOut, "needs more bytes") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("run waited %v for a terminal failure", elapsed)
			}
			var b v1alpha1.Blip
			if err := h.kube.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); !apierrors.IsNotFound(err) {
				t.Fatalf("blip created from failed state: %v", err)
			}
		})
	}
}

func failedStateWithPending(name string) *v1alpha1.BlipState {
	return &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status: v1alpha1.BlipStateStatus{
			Phase:     v1alpha1.StateFailed,
			Message:   "initial version failed: needs more bytes",
			LastError: "needs more bytes",
			Pending:   &v1alpha1.PendingCommit{CommitID: "fedcba9876543210", Generation: 1},
		},
	}
}
