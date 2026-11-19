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

// A Failed state with a pending commit is retrying: state.pending keeps it
// alive, so a waiter must not call it terminal. Only a Failed state with no
// pending commit can never recover.
func TestStateFailureClassification(t *testing.T) {
	pending := failedStateWithPending("s")
	if got := stateFailure(pending); got != "" {
		t.Fatalf("failed-but-pending state classified as terminal: %q", got)
	}
	if got := usableStateFailure(pending); got != "" {
		t.Fatalf("failed-but-pending state rejected as a source: %q", got)
	}
	terminal := failedStateWithPending("s")
	terminal.Status.Pending = nil
	if got, want := stateFailure(terminal), "needs more bytes"; got != want {
		t.Fatalf("terminal stateFailure = %q, want %q", got, want)
	}
	if got, want := usableStateFailure(terminal), "needs more bytes"; got != want {
		t.Fatalf("terminal usableStateFailure = %q, want %q", got, want)
	}
	if got := stateFailure(readyState("ready")); got != "" {
		t.Fatalf("ready state classified as failed: %q", got)
	}
}

// A state without a pending commit has nothing left to retry, so pull must
// fail fast instead of waiting for the state controller.
func TestPullFailedInitialVersionExits(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: needs more bytes"
	})
	start := time.Now()
	code, _, errOut := h.run("", "pull", "smallv", "registry/dev:v1", "--size", "8Mi")
	if code != 1 || !strings.Contains(errOut, "needs more bytes") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pull waited %v for a terminal failure", elapsed)
	}
	if st := h.state("smallv"); st.Status.Phase != v1alpha1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("test did not leave a terminal failed state: %+v", st.Status)
	}
}

// The same Failed phase with a pending commit is recoverable: pull waits for
// the retried commit instead of reporting a failure the controller will fix.
func TestPullWaitsForFailedPendingState(t *testing.T) {
	h := newHarness(t)
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: fetch: device busy"
		c.stateFailPending = true
	})
	code, out, errOut := h.run("", "pull", "recovered", "registry/dev:v1", "--size", "8Mi")
	if code != 0 {
		t.Fatalf("pull failed on a retryable state: code %d: %s", code, errOut)
	}
	mustContain(t, out, "blipstate/recovered Ready")
	if st := h.state("recovered"); st.Status.Pending != nil || st.Status.Committed == nil {
		t.Fatalf("recovered state did not commit: %+v", st.Status)
	}
}

// A source with no pending commit is terminal, so run rejects it before
// creating a Blip.
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
			bad := failedStateWithPending("bad")
			bad.Status.Pending = nil
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

// A Failed source that still has its retryable pending commit is usable:
// workspace.CheckSource accepts it, and run must not reject it first.
func TestRunAcceptsFailedPendingSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string
	}{
		{"from", "--from"},
		{"state", "--state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.apply(failedStateWithPending("bad"))
			code, out, errOut := h.run("", "run", "--name", "worker", tc.flag, "bad", "--", "true")
			if code != 0 {
				t.Fatalf("run rejected a failed-but-pending source: code %d: %s", code, errOut)
			}
			mustContain(t, out, "worker")
			var b v1alpha1.Blip
			if err := h.kube.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); err != nil {
				t.Fatalf("blip was not created: %v", err)
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
