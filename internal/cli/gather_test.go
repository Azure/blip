package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// finishedBlip is a blip that already ran a command.
func finishedBlip(name string, phase string, code int32) *v1alpha1.Blip {
	b := runningBlip(name)
	b.Status.Phase = phase
	b.Status.ExitCode = &code
	b.Status.FinishTime = &metav1.Time{Time: time.Now()}
	b.Status.StartTime = &metav1.Time{Time: time.Now().Add(-3 * time.Second)}
	return b
}

func (h *harness) gone(name string) bool {
	h.t.Helper()
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &v1alpha1.Blip{})
	return apierrors.IsNotFound(err)
}

func TestGatherDeletesSucceededBlips(t *testing.T) {
	h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
	code, out, errOut := h.run("", "gather", "w1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 Succeeded (exit 0)")
	if !h.gone("w1") {
		t.Fatal("blip kept")
	}
}

func TestGatherKeepsFailedBlips(t *testing.T) {
	b := finishedBlip("w1", v1alpha1.BlipFailed, 2)
	b.Status.Message = "tests failed"
	h := newHarness(t, b)
	code, out, errOut := h.run("", "gather", "w1")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "blip/w1 Failed (exit 2)")
	mustContain(t, errOut, "tests failed")
	if h.gone("w1") {
		t.Fatal("failed blip deleted")
	}
}

func TestGatherKeep(t *testing.T) {
	h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
	if code, _, errOut := h.run("", "gather", "w1", "--keep"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if h.gone("w1") {
		t.Fatal("blip deleted with --keep")
	}
}

func TestGatherDefaultsToCallerForks(t *testing.T) {
	mine := finishedBlip("alice.w1", v1alpha1.BlipSucceeded, 0)
	mine.Labels = map[string]string{v1alpha1.LabelOwner: "alice", v1alpha1.LabelParent: "box"}
	other := finishedBlip("alice.w2", v1alpha1.BlipSucceeded, 0)
	other.Labels = map[string]string{v1alpha1.LabelOwner: "alice", v1alpha1.LabelParent: "other"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), mine, other)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 Succeeded")
	if !h.gone("alice.w1") {
		t.Fatal("caller's fork kept")
	}
	if h.gone("alice.w2") {
		t.Fatal("another blip's fork gathered")
	}
}

func TestGatherOutsideBlipNeedsNames(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "gather")
	if code != 1 || !strings.Contains(errOut, "needs blip names or --selector") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestGatherSelector(t *testing.T) {
	a := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
	a.Labels = map[string]string{"team": "nightly"}
	b := finishedBlip("w2", v1alpha1.BlipSucceeded, 0)
	b.Labels = map[string]string{"team": "nightly"}
	c := finishedBlip("w3", v1alpha1.BlipSucceeded, 0)
	c.Labels = map[string]string{"team": "other"}
	h := newHarness(t, a, b, c)
	code, out, errOut := h.run("", "gather", "--selector", "team=nightly")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1", "blip/w2")
	if !h.gone("w1") || !h.gone("w2") || h.gone("w3") {
		t.Fatal("wrong blips gathered")
	}
}

func TestGatherWaitGivesUpOnRunningBlips(t *testing.T) {
	h := newHarness(t, runningBlip("w1"))
	code, _, errOut := h.run("", "gather", "w1", "--wait", "50ms")
	if code != 1 || !strings.Contains(errOut, "still running: w1") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if h.gone("w1") {
		t.Fatal("running blip deleted")
	}
}

func TestGatherRejectsNegativeWait(t *testing.T) {
	h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
	code, _, errOut := h.run("", "gather", "w1", "--wait", "-1s")
	if code != 1 || !strings.Contains(errOut, "--wait must not be negative") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if h.gone("w1") {
		t.Fatal("negative wait gathered the blip")
	}
}

func TestGatherAnyReturnsOnFirstFinish(t *testing.T) {
	h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0), runningBlip("w2"))
	code, _, errOut := h.run("", "gather", "w1", "w2", "--any")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !h.gone("w1") || h.gone("w2") {
		t.Fatal("wrong blips gathered")
	}
}

func TestGatherCollectFailureKeepsBlip(t *testing.T) {
	// The blip's root state is gone, so collecting cannot mount it.
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), finishedBlip("alice.w1", v1alpha1.BlipSucceeded, 0))
	h.self = "alice.box"
	code, _, errOut := h.run("", "gather", "w1", "--collect", "/out:./out")
	if code != 1 || !strings.Contains(errOut, "collect from w1") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if h.gone("alice.w1") {
		t.Fatal("blip deleted after failed collect")
	}
}

func TestGatherCollectNeedsBlip(t *testing.T) {
	h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
	code, _, errOut := h.run("", "gather", "w1", "--collect", "/out:./out")
	if code != 1 || !strings.Contains(errOut, "only works inside") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

// A command can finish before gather starts following it. The guest keeps the
// primary session's replay until the pod goes away, so gather must attach even
// when the blip is already Succeeded.
func TestGatherFollowReplaysFastFinishedBlip(t *testing.T) {
	h := newHarness(t, finishedBlip("fast1", v1alpha1.BlipSucceeded, 0))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("FASTOUT1\n")
		return wire.Exit{}
	}
	code, out, errOut := h.run("", "gather", "fast1", "--follow")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "FASTOUT1", "blip/fast1 Succeeded (exit 0)")
	if !h.gone("fast1") {
		t.Fatal("blip kept")
	}
	opens := h.guest.Opens()
	if len(opens) != 1 || opens[0].Open.Mode != wire.OpenAttach ||
		opens[0].Open.Session != wire.PrimarySession || !opens[0].Open.Follow {
		t.Fatalf("opens = %+v", opens)
	}
}

// When the pod is gone there is nothing left to replay; say so instead of
// silently printing only the status line.
func TestGatherFollowSaysFinishedOutputIsGone(t *testing.T) {
	b := finishedBlip("gone", v1alpha1.BlipSucceeded, 0)
	b.Status.Pod = ""
	h := newHarness(t, b)
	code, out, errOut := h.run("", "gather", "gone", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/gone Succeeded (exit 0)")
	mustContain(t, errOut, "output is no longer available")
	if !h.gone("gone") {
		t.Fatal("blip kept")
	}
}

// The hint must name the object as the API knows it, not the caller-scoped
// short name, or kubectl delete cannot find it.
func TestGatherRetentionHintUsesFullName(t *testing.T) {
	bad := finishedBlip("alice.badfork", v1alpha1.BlipFailed, 1)
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), bad)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather", "badfork")
	if code != 1 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/badfork Failed")
	mustContain(t, errOut, "delete it with kubectl delete blip alice.badfork")
}

// A Pending or Saving blip is not running; --wait must report its actual
// state instead of claiming it is running.
func TestGatherWaitReportsActualPhase(t *testing.T) {
	for _, tc := range []struct {
		phase string
		pod   string
		want  string
	}{
		{v1alpha1.BlipPending, "", "still pending: p1"},
		{v1alpha1.BlipSaving, "pod-p1", "still saving: p1"},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			h := newHarness(t, runningBlip("p1"))
			h.ctrl.set(func(c *fakeController) { c.paused = true })
			b := h.blip("p1")
			b.Status.Phase, b.Status.Pod = tc.phase, tc.pod
			if err := h.kube.Status().Update(context.Background(), b); err != nil {
				t.Fatal(err)
			}
			code, _, errOut := h.run("", "gather", "p1", "--wait", "50ms")
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if h.gone("p1") {
				t.Fatal("unfinished blip deleted")
			}
		})
	}
}

// A caller that matches its own selector must not gather itself, which would
// otherwise wait forever or delete the running caller.
func TestGatherSelectorExcludesCaller(t *testing.T) {
	caller := ownedBlip("alice.box", "alice.home")
	caller.Labels["team"] = "bulk"
	worker := finishedBlip("alice.w1", v1alpha1.BlipSucceeded, 0)
	worker.Labels = map[string]string{v1alpha1.LabelOwner: "alice", "team": "bulk"}
	h := newHarness(t, caller, worker)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather", "-l", "team=bulk")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 Succeeded")
	if !h.gone("alice.w1") {
		t.Fatal("matched blip kept")
	}
	if h.gone("alice.box") {
		t.Fatal("caller gathered itself")
	}
}
