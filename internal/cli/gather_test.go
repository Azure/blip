package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
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

// withRetainedOutputWait shortens gather's status.output fallback wait so a
// test does not have to wait for the production timeout.
func withRetainedOutputWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := retainedOutputWait
	retainedOutputWait = d
	t.Cleanup(func() { retainedOutputWait = old })
}

// setOutput writes status.output directly, like the controller does.
func (h *harness) setOutput(name, output string) {
	h.t.Helper()
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &b); err != nil {
		return
	}
	b.Status.Output = output
	_ = h.kube.Status().Update(context.Background(), &b)
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

// A failed git collect must not replace gather's exit status or hide the
// original command failure.
func TestGatherGitCollectFailureKeepsBlipError(t *testing.T) {
	requireGit(t)
	withCollectMountRoot(t)

	callerRepo := filepath.Join(t.TempDir(), "caller")
	gitInit(t, callerRepo)
	gitRun(t, callerRepo, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-q", "--allow-empty", "-m", "base")
	src := filepath.Join(collectMountRoot, "alice.w1", "home/dev/src")
	gitInit(t, src)
	gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-q", "--allow-empty", "-m", "src")

	objs := gitObjects()
	for _, o := range objs {
		b, ok := o.(*v1alpha1.Blip)
		if !ok || b.Name != "alice.w1" {
			continue
		}
		code := int32(9)
		b.Status.Phase = v1alpha1.BlipFailed
		b.Status.ExitCode = &code
		b.Status.Message = "exit code 9"
	}
	h := newHarness(t, objs...)
	h.self = "alice.box"
	t.Chdir(callerRepo)

	// Fetching into the branch the caller has checked out is refused by git.
	code, _, errOut := h.run("", "gather", "w1", "--collect", "git:/home/dev/src:main")
	if code != 1 {
		t.Fatalf("code %d, want 1 for a failed gather: %s", code, errOut)
	}
	mustContain(t, errOut, "blip w1 failed: exit code 9", "collect from w1", "git fetch")
	if h.gone("alice.w1") {
		t.Fatal("blip deleted after a failed collect")
	}
}

// Two blips collecting to the same destination would silently overwrite each
// other. gather must reject the ambiguous set before collecting or deleting.
func TestGatherRejectsDuplicateCollectDestinations(t *testing.T) {
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/a", "one", 0o644)
	writeCollectFile(t, root, "alice.w2", "/home/dev/a", "two", 0o644)
	dst := filepath.Join(t.TempDir(), "a")

	code, _, errOut := h.run("", "gather", "w1", "w2", "--collect", "/home/dev/a:"+dst)
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "w1", "w2")
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("a destination was written despite the collision: %v", err)
	}
	if h.gone("alice.w1") || h.gone("alice.w2") {
		t.Fatal("blips were deleted despite the collision")
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

// A finished VM cannot accept a session attach. Its serial console keeps the
// command's mirrored output, so -f must fall back to the pod log instead of
// reporting that output is gone.
func TestGatherFollowReplaysSerialLogWhenSessionIsGone(t *testing.T) {
	h := newHarness(t, finishedBlip("fastlog", v1alpha1.BlipSucceeded, 0))
	h.guest.OpenError = "no session"
	h.logs = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("[ 1.0] boot\nblip: FASTOUT\nblip: LASTLINE\nblip-guest: done\n")), nil
	}
	code, out, errOut := h.run("", "gather", "fastlog", "--follow")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "fastlog| FASTOUT", "fastlog| LASTLINE", "blip/fastlog Succeeded (exit 0)")
	if strings.Contains(out, "boot") || strings.Contains(out, "blip-guest") {
		t.Fatalf("serial noise leaked into output: %q", out)
	}
}

// When the pod is gone there is nothing left to replay; say so instead of
// silently printing only the status line.
func TestGatherFollowSaysFinishedOutputIsGone(t *testing.T) {
	withRetainedOutputWait(t, 50*time.Millisecond)
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

// A fast command can end before its replay reaches the follower. The
// controller publishes status.output moments later; gather must keep polling
// instead of printing only the summary.
func TestGatherFollowWaitsForDelayedStatusOutput(t *testing.T) {
	b := finishedBlip("lagged", v1alpha1.BlipSucceeded, 0)
	b.Status.Pod = ""
	h := newHarness(t, b)
	go func() {
		time.Sleep(40 * time.Millisecond)
		h.setOutput("lagged", "LATEOUT\n")
	}()
	code, out, errOut := h.run("", "gather", "lagged", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "lagged| LATEOUT", "blip/lagged Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// If a session attach yields no output and the pod log is unavailable, gather
// still waits for the retained status output rather than losing it silently.
func TestGatherFollowUsesDelayedRetainedOutputAfterEmptyReplay(t *testing.T) {
	h := newHarness(t, finishedBlip("empty", v1alpha1.BlipSucceeded, 0))
	go func() {
		time.Sleep(40 * time.Millisecond)
		h.setOutput("empty", "RETAINED\n")
	}()
	code, out, errOut := h.run("", "gather", "empty", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "empty| RETAINED", "blip/empty Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// An empty replay with no retained output must warn instead of printing only
// the summary line.
func TestGatherFollowWarnsWhenEmptyReplayHasNoOutput(t *testing.T) {
	withRetainedOutputWait(t, 50*time.Millisecond)
	h := newHarness(t, finishedBlip("empty", v1alpha1.BlipSucceeded, 0))
	code, out, errOut := h.run("", "gather", "empty", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/empty Succeeded (exit 0)")
	mustContain(t, errOut, "output is no longer available")
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

// A finished command whose pod is already gone still reports the output the
// controller retained in status.
func TestGatherFollowUsesRetainedStatusOutput(t *testing.T) {
	b := finishedBlip("retained", v1alpha1.BlipSucceeded, 0)
	b.Status.Pod = ""
	b.Status.Output = "FASTOUT\nLASTLINE\n"
	h := newHarness(t, b)
	code, out, errOut := h.run("", "gather", "retained", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "retained| FASTOUT", "retained| LASTLINE", "blip/retained Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}
