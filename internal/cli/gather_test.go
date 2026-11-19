package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
	corev1 "k8s.io/api/core/v1"
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

// withTruncatedOutputWait shortens the wait after a cut-off live stream.
func withTruncatedOutputWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := truncatedOutputWait
	truncatedOutputWait = d
	t.Cleanup(func() { truncatedOutputWait = old })
}

// withAttachFailWait shortens the wait after a failed follower attach.
func withAttachFailWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := attachFailWait
	attachFailWait = d
	t.Cleanup(func() { attachFailWait = old })
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

// Two owners can use the same short blip name in one namespace. Bare gather
// inside one owner's blip must not select the other owner's forks.
func TestGatherDefaultsStayInCallerOwner(t *testing.T) {
	victim := finishedBlip("bob.victim", v1alpha1.BlipSucceeded, 0)
	victim.Labels = map[string]string{v1alpha1.LabelOwner: "bob", v1alpha1.LabelParent: "box"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), victim)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "no blips to gather")
	if h.gone("bob.victim") {
		t.Fatal("bare gather deleted another owner's fork")
	}
}

// An explicit selector is intersected with the caller's owner, so it cannot
// list or delete another owner's blips even when their labels match.
func TestGatherSelectorStaysInCallerOwner(t *testing.T) {
	mine := finishedBlip("alice.w1", v1alpha1.BlipSucceeded, 0)
	mine.Labels = map[string]string{v1alpha1.LabelOwner: "alice", "team": "nightly"}
	other := finishedBlip("bob.victim", v1alpha1.BlipSucceeded, 0)
	other.Labels = map[string]string{v1alpha1.LabelOwner: "bob", "team": "nightly"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), mine, other)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather", "--selector", "team=nightly")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 Succeeded")
	if strings.Contains(out, "victim") {
		t.Fatalf("selector listed another owner's fork: %q", out)
	}
	if !h.gone("alice.w1") {
		t.Fatal("caller's fork kept")
	}
	if h.gone("bob.victim") {
		t.Fatal("selector gathered another owner's fork")
	}
}

// A selector that names a different owner matches nothing instead of being
// rejected or widened: the caller's owner always wins.
func TestGatherSelectorCannotCrossOwner(t *testing.T) {
	other := finishedBlip("bob.victim", v1alpha1.BlipSucceeded, 0)
	other.Labels = map[string]string{v1alpha1.LabelOwner: "bob", "team": "nightly"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), other)
	h.self = "alice.box"
	code, out, errOut := h.run("", "gather", "--selector", "blip.dev/owner=bob")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "no blips to gather")
	if h.gone("bob.victim") {
		t.Fatal("selector gathered another owner's fork")
	}
}

// A parse error must quote the selector the user wrote, without the internal
// owner term gather adds to constrain it.
func TestGatherSelectorErrorOmitsOwnerSuffix(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"))
	h.self = "alice.box"
	for _, sel := range []string{"a=b,", "foo in ("} {
		code, _, errOut := h.run("", "gather", "--selector", sel)
		if code != 1 || !strings.Contains(errOut, `invalid --selector "`+sel+`"`) {
			t.Fatalf("selector %q: code %d: %s", sel, code, errOut)
		}
		if strings.Contains(errOut, v1alpha1.LabelOwner) {
			t.Fatalf("selector %q error quotes the internal owner term: %s", sel, errOut)
		}
	}
}

// A caller without an owner (admin or an unowned blip) is unchanged: no owner
// constraint is added to its default or explicit selectors.
func TestGatherOwnerlessCallerUnchanged(t *testing.T) {
	fork := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
	fork.Labels = map[string]string{v1alpha1.LabelParent: "box"}
	selected := finishedBlip("w2", v1alpha1.BlipSucceeded, 0)
	selected.Labels = map[string]string{"team": "nightly"}
	h := newHarness(t, runningBlip("box"), fork, selected)
	h.self = "box"
	code, out, errOut := h.run("", "gather")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 Succeeded")
	if !h.gone("w1") {
		t.Fatal("ownerless caller did not gather its fork")
	}
	code, out, errOut = h.run("", "gather", "--selector", "team=nightly")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w2 Succeeded")
	if !h.gone("w2") {
		t.Fatal("ownerless caller did not gather its selector matches")
	}
}

func TestGatherOutsideBlipNeedsNames(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "gather")
	if code != 1 || !strings.Contains(errOut, "needs blip names or --selector") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

// Outside a blip, --collect is the primary mistake: the documented
// collect-only-inside error must win over the missing-target error.
func TestGatherOutsideBlipWithCollect(t *testing.T) {
	for _, op := range []string{"garbage", "a:b"} {
		h := newHarness(t)
		code, _, errOut := h.run("", "gather", "--collect", op)
		if code != 1 || !strings.Contains(errOut, "only works inside one") {
			t.Fatalf("--collect %q: code %d stderr %q", op, code, errOut)
		}
		if strings.Contains(errOut, "needs blip names") {
			t.Fatalf("--collect %q: reported the missing-target error: %q", op, errOut)
		}
	}
}

// --collect must be validated before the target set is resolved. Inside a
// blip with no forks, malformed or empty operations used to exit 0 with
// "no blips to gather".
func TestGatherValidatesCollectWithoutTargets(t *testing.T) {
	for _, op := range []string{"", " ", "garbage", "a:b:c:d"} {
		h := newHarness(t, ownedBlip("alice.box", "alice.home"))
		h.self = "alice.box"
		code, out, errOut := h.run("", "gather", "--collect", op)
		if code != 1 || !strings.Contains(errOut, "invalid operation") {
			t.Fatalf("--collect %q: code %d out %q stderr %q", op, code, out, errOut)
		}
		if strings.Contains(out, "no blips to gather") {
			t.Fatalf("--collect %q: reported an empty gather: %q", op, out)
		}
		if h.gone("alice.box") {
			t.Fatalf("--collect %q: gathered the caller", op)
		}
	}
}

// A blank shell variable expands to whitespace, which labels.Parse treats as
// "select everything". Outside a blip it must be rejected.
func TestGatherRejectsWhitespaceSelector(t *testing.T) {
	for _, sel := range []string{"", " "} {
		h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
		code, _, errOut := h.run("", "gather", "--selector", sel)
		if code != 1 || !strings.Contains(errOut, "needs blip names or --selector") {
			t.Fatalf("selector %q: code %d: %s", sel, code, errOut)
		}
		if h.gone("w1") {
			t.Fatalf("selector %q gathered a blip", sel)
		}
	}
}

// An explicitly empty selector is a mistake, not a request for the default
// set. Inside a blip it must not fall back to the caller's forks: an unset
// shell variable would then collect and delete every fork.
func TestGatherRejectsEmptySelectorInsideBlip(t *testing.T) {
	for _, sel := range []string{"", "   "} {
		mine := finishedBlip("alice.w1", v1alpha1.BlipSucceeded, 0)
		mine.Labels = map[string]string{v1alpha1.LabelOwner: "alice", v1alpha1.LabelParent: "box"}
		other := finishedBlip("alice.w2", v1alpha1.BlipSucceeded, 0)
		other.Labels = map[string]string{v1alpha1.LabelOwner: "alice", v1alpha1.LabelParent: "other"}
		h := newHarness(t, ownedBlip("alice.box", "alice.home"), mine, other)
		h.self = "alice.box"
		code, out, errOut := h.run("", "gather", "--selector", sel)
		if code != 1 || !strings.Contains(errOut, "--selector must not be empty") {
			t.Fatalf("selector %q: code %d: %s", sel, code, errOut)
		}
		if strings.Contains(out, "blip/w1") || strings.Contains(out, "blip/w2") {
			t.Fatalf("selector %q gathered a blip: %q", sel, out)
		}
		if h.gone("alice.w1") || h.gone("alice.w2") {
			t.Fatalf("selector %q deleted a fork", sel)
		}
	}
}

// Help says "blip names or --selector". Accepting both unions two sets, which
// can gather blips the user did not name, so reject the combination.
func TestGatherRejectsNamesWithSelector(t *testing.T) {
	named := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
	other := finishedBlip("w2", v1alpha1.BlipSucceeded, 0)
	other.Labels = map[string]string{"team": "y"}
	h := newHarness(t, named, other)
	code, _, errOut := h.run("", "gather", "w1", "--selector", "team=y")
	if code != 1 || !strings.Contains(errOut, "not both") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if h.gone("w1") || h.gone("w2") {
		t.Fatal("gather deleted a blip despite the invalid target set")
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

// A negated requirement matches every object that does not carry the key, so
// it normally selects every unlabelled blip in the namespace. gather deletes
// successful blips, so reject a selector that matches the empty label set.
func TestGatherRejectsSelectorMatchingEveryBlip(t *testing.T) {
	for _, sel := range []string{"team!=nightly", "!team", "team notin ()"} {
		t.Run(sel, func(t *testing.T) {
			unlabelled := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
			labelled := finishedBlip("w2", v1alpha1.BlipSucceeded, 0)
			labelled.Labels = map[string]string{"team": "nightly"}
			h := newHarness(t, unlabelled, labelled)
			code, out, errOut := h.run("", "gather", "--selector", sel)
			if code != 1 || !strings.Contains(errOut, `invalid --selector "`+sel+`"`) || !strings.Contains(errOut, "it selects every blip") {
				t.Fatalf("selector %q: code %d out %q stderr %q", sel, code, out, errOut)
			}
			if h.gone("w1") || h.gone("w2") {
				t.Fatalf("selector %q deleted a blip", sel)
			}
		})
	}
}

// Positive selectors are still accepted: only selectors that match an object
// with no labels at all are rejected.
func TestGatherAcceptsPositiveSelectors(t *testing.T) {
	cases := []struct {
		sel  string
		gone []string
	}{
		{"team=nightly", []string{"w1"}},
		{"team in (nightly)", []string{"w1"}},
		{"team", []string{"w1", "w2"}},
	}
	for _, tc := range cases {
		t.Run(tc.sel, func(t *testing.T) {
			match := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
			match.Labels = map[string]string{"team": "nightly"}
			other := finishedBlip("w2", v1alpha1.BlipSucceeded, 0)
			other.Labels = map[string]string{"team": "other"}
			unlabelled := finishedBlip("w3", v1alpha1.BlipSucceeded, 0)
			h := newHarness(t, match, other, unlabelled)
			code, out, errOut := h.run("", "gather", "--selector", tc.sel)
			if code != 0 {
				t.Fatalf("selector %q: code %d out %q stderr %q", tc.sel, code, out, errOut)
			}
			for _, name := range []string{"w1", "w2", "w3"} {
				want := false
				for _, gone := range tc.gone {
					want = want || name == gone
				}
				if h.gone(name) != want {
					t.Fatalf("selector %q: %s gone=%v, want %v (out %q)", tc.sel, name, h.gone(name), want, out)
				}
			}
		})
	}
}

// A blip that finished before gather began is finished even if --wait expires
// before the watcher observes it; gather must collect it instead of reporting
// it as "not finished".
func TestGatherWaitCollectsFinishedBlipsAtTimeout(t *testing.T) {
	for _, any := range []bool{false, true} {
		name := "wait"
		if any {
			name = "any"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, finishedBlip("w1", v1alpha1.BlipSucceeded, 0))
			args := []string{"gather", "w1", "--wait", "1ns"}
			if any {
				args = append(args, "--any")
			}
			code, out, errOut := h.run("", args...)
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			mustContain(t, out, "blip/w1 Succeeded (exit 0)")
			if strings.Contains(errOut, "not finished") {
				t.Fatalf("finished blip reported as waiting: %q", errOut)
			}
			if !h.gone("w1") {
				t.Fatal("finished blip kept")
			}
		})
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

	// Fetching a branch that does not exist fails with a git error. (The
	// branch the caller has checked out is rejected earlier, with an
	// actionable message; see the test below.)
	code, _, errOut := h.run("", "gather", "w1", "--collect", "git:/home/dev/src:missing")
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

// A destination that does not exist yet is created by the first blip, so two
// blips writing different basenames there still collide: the first creates
// DEST as a file and the second replaces it. gather must reject the pair
// before either blip is collected or deleted.
func TestGatherRejectsCrossBlipNewFileDestination(t *testing.T) {
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/src/w1.txt", "ONE\n", 0o644)
	writeCollectFile(t, root, "alice.w2", "/home/dev/src/w2.txt", "TWO\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)

	code, _, errOut := h.run("", "gather", "w1", "w2", "--collect", "/home/dev/src/{name}.txt:./out")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "w1", "w2")
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Fatalf("a destination was written despite the collision: %v", err)
	}
	if h.gone("alice.w1") || h.gone("alice.w2") {
		t.Fatal("blips were deleted despite the collision")
	}
}

// An existing destination directory gives each file its own basename child,
// so two blips collecting distinct files there do not collide.
func TestGatherAllowsCrossBlipDistinctFilesIntoExistingDirectory(t *testing.T) {
	root := withCollectMountRoot(t)
	w1 := ownedBlip("alice.w1", "alice.w1")
	w1.Status.Phase = v1alpha1.BlipSucceeded
	w2 := ownedBlip("alice.w2", "alice.w2")
	w2.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t,
		ownedBlip("alice.box", "alice.home"), w1, w2,
		readyState("alice.w1"), readyState("alice.w2"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/src/w1.txt", "ONE\n", 0o644)
	writeCollectFile(t, root, "alice.w2", "/home/dev/src/w2.txt", "TWO\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1", "w2", "--collect", "/home/dev/src/{name}.txt:./out")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, filepath.Join(dir, "out/w1.txt")); got != "ONE\n" {
		t.Fatalf("w1.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "out/w2.txt")); got != "TWO\n" {
		t.Fatalf("w2.txt = %q", got)
	}
	if !h.gone("alice.w1") || !h.gone("alice.w2") {
		t.Fatal("blips kept")
	}
}

// A file collected onto an existing directory is stored under its basename,
// so a destination that looks distinct can be the same file. gather must
// reject the pair before copying instead of letting the second overwrite the
// first.
func TestGatherRejectsCollectIntoExistingDirectoryCollision(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/src/marker", "MARKER1\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/big", "BIG-DATA\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1",
		"--collect", "/home/dev/src/marker:./out",
		"--collect", "/home/dev/big:./out/marker")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "/home/dev/src/marker", "/home/dev/big")
	if _, err := os.Stat(filepath.Join(dir, "out/marker")); !os.IsNotExist(err) {
		t.Fatalf("a colliding destination was written: %v", err)
	}
	if h.gone("alice.w1") {
		t.Fatal("blip deleted despite the collision")
	}
}

// A directory merge spreads over everything below its destination, so a
// second operation beneath that destination overlaps it even though the two
// declared destinations differ.
func TestGatherRejectsCollectDirectoryOverlap(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/tree/sub/marker", "TREE\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/marker", "MARKER2\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1",
		"--collect", "/home/dev/tree:./out",
		"--collect", "/home/dev/marker:./out/sub")
	if code != 1 {
		t.Fatalf("code %d, want 1: %s", code, errOut)
	}
	mustContain(t, errOut, "destination", "/home/dev/tree", "/home/dev/marker")
	if _, err := os.Stat(filepath.Join(dir, "out/sub")); !os.IsNotExist(err) {
		t.Fatalf("an overlapping destination was written: %v", err)
	}
	if h.gone("alice.w1") {
		t.Fatal("blip deleted despite the overlap")
	}
}

// Files with distinct names still share an existing destination directory;
// their effective destinations do not collide.
func TestGatherAllowsDistinctFilesIntoExistingDirectory(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/src/a", "AAA\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/src/b", "BBB\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1",
		"--collect", "/home/dev/src/a:./out/a",
		"--collect", "/home/dev/src/b:./out/b")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, filepath.Join(dir, "out/a")); got != "AAA\n" {
		t.Fatalf("a = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "out/b")); got != "BBB\n" {
		t.Fatalf("b = %q", got)
	}
	if !h.gone("alice.w1") {
		t.Fatal("blip kept")
	}
}

// A file collected onto an existing directory is stored under its basename,
// so a destination nested below that directory is not necessarily covered by
// it. Model the effective write paths instead of the declared destinations:
// a/file lands on out2/file and b/file on out2/sub/b.txt, which do not
// collide.
func TestGatherAllowsNestedFileDestinationUnderFileDestination(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/tree/a/file", "AAA\n", 0o644)
	writeCollectFile(t, root, "alice.w1", "/home/dev/tree/b/file", "BBB\n", 0o644)

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join(dir, "out2/sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("", "gather", "w1",
		"--collect", "/home/dev/tree/a/file:./out2",
		"--collect", "/home/dev/tree/b/file:./out2/sub/b.txt")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, filepath.Join(dir, "out2/file")); got != "AAA\n" {
		t.Fatalf("out2/file = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "out2/sub/b.txt")); got != "BBB\n" {
		t.Fatalf("out2/sub/b.txt = %q", got)
	}
	if !h.gone("alice.w1") {
		t.Fatal("blip kept")
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

// truncatedConnector serves one primary attach, writes prefix, and then drops
// the connection without a TExited frame. That is what a follower sees when
// the guest closes a finished primary session while the follower is still
// backpressured and the delivery deadline expires.
func truncatedConnector(prefix string) session.Connector {
	return func(context.Context, string, string) (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			conn := wire.NewConn(server)
			t, payload, err := conn.Read()
			if err != nil || t != wire.TOpen {
				return
			}
			var o wire.Open
			if err := wire.Decode(payload, &o); err != nil {
				return
			}
			_ = conn.WriteJSON(wire.TOpened, wire.Opened{Session: o.Session, TTY: o.TTY})
			_ = conn.Write(wire.TStdout, []byte(prefix))
		}()
		return client, nil
	}
}

// A follower that is cut off before TExited has printed only a prefix of the
// command output. The controller's retained status.output still has the tail,
// so gather -f must warn and replay it instead of silently losing it.
func TestGatherFollowReplaysRetainedOutputAfterTruncatedStream(t *testing.T) {
	b := finishedBlip("cut", v1alpha1.BlipSucceeded, 0)
	b.Status.Output = "RETAINED1\nFINAL_MARKER\n"
	h := newHarness(t, b)
	h.connect = truncatedConnector("LIVE1\nLIVE2\n")

	code, out, errOut := h.run("", "gather", "cut", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "cut| LIVE1", "cut| LIVE2", "blip/cut Succeeded (exit 0)")
	mustContain(t, errOut, "cut| RETAINED1", "cut| FINAL_MARKER", "output stream ended before the command exited", "replayed the retained output")
	if strings.Contains(out, "RETAINED1") {
		t.Fatalf("retained combined output replayed to stdout: %q", out)
	}
	if !h.gone("cut") {
		t.Fatal("blip kept")
	}
}

// The same cut with no retained output must still warn instead of looking like
// a clean, complete follow.
func TestGatherFollowWarnsWhenTruncatedOutputIsGone(t *testing.T) {
	withTruncatedOutputWait(t, 50*time.Millisecond)
	h := newHarness(t, finishedBlip("cut", v1alpha1.BlipSucceeded, 0))
	h.connect = truncatedConnector("LIVE1\n")

	code, out, errOut := h.run("", "gather", "cut", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "cut| LIVE1", "blip/cut Succeeded (exit 0)")
	mustContain(t, errOut, "output stream ended before the command exited", "rest of the output is no longer available")
}

// A clean TExited follow is complete output, not truncation; do not replay
// status.output or print the truncation warning.
func TestGatherFollowDoesNotReplayAfterCleanExit(t *testing.T) {
	b := finishedBlip("clean", v1alpha1.BlipSucceeded, 0)
	b.Status.Output = "RETAINED1\n"
	h := newHarness(t, b)
	h.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("LIVE1\n")
		return wire.Exit{}
	}

	code, out, errOut := h.run("", "gather", "clean", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "clean| LIVE1", "blip/clean Succeeded (exit 0)")
	if strings.Contains(out, "RETAINED1") {
		t.Fatalf("clean completion replayed retained output: %q", out)
	}
	if strings.Contains(errOut, "output stream ended before the command exited") {
		t.Fatalf("clean completion warned about truncation: %q", errOut)
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
	mustContain(t, out, "blip/fastlog Succeeded (exit 0)")
	mustContain(t, errOut, "fastlog| FASTOUT", "fastlog| LASTLINE")
	if strings.Contains(out, "FASTOUT") || strings.Contains(out, "LASTLINE") {
		t.Fatalf("combined serial output replayed to stdout: %q", out)
	}
	if strings.Contains(errOut, "boot") || strings.Contains(errOut, "blip-guest") {
		t.Fatalf("serial noise leaked into output: %q", errOut)
	}
}

// A fast command that finished before the follower attached leaves only a
// bounded serial window, but the controller's status.output holds the tail.
// gather -f must prefer the complete status copy instead of printing the
// truncated serial replay and losing the middle of the output.
func TestGatherFollowPrefersCompleteRetainedOutputOverTruncatedSerial(t *testing.T) {
	for _, n := range []int{300, 10000} {
		t.Run(fmt.Sprintf("%d lines", n), func(t *testing.T) {
			var all strings.Builder
			for i := 1; i <= n; i++ {
				fmt.Fprintf(&all, "%d\n", i)
			}
			b := finishedBlip("fast", v1alpha1.BlipSucceeded, 0)
			b.Status.Output = all.String()
			h := newHarness(t, b)
			h.guest.OpenError = "no session"
			// The serial console keeps only its newest window and says so.
			h.logs = func(context.Context, string) (io.ReadCloser, error) {
				start := max(1, n-255)
				var s strings.Builder
				for i := start; i <= n; i++ {
					fmt.Fprintf(&s, "blip: %d\n", i)
				}
				if dropped := start - 1; dropped > 0 {
					fmt.Fprintf(&s, "blip: %d output lines dropped\n", dropped)
				}
				return io.NopCloser(strings.NewReader(s.String())), nil
			}

			code, out, errOut := h.run("", "gather", "fast", "-f")
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if got := strings.Count(errOut, "fast| "); got != n {
				t.Fatalf("replayed %d lines, want %d: %s", got, n, errOut)
			}
			mustContain(t, out, "blip/fast Succeeded (exit 0)")
			if strings.Contains(errOut, "output is truncated") {
				t.Fatalf("warned about truncation although status.output is complete: %q", errOut)
			}
		})
	}
}

// When both the status tail and the serial replay are complete, gather -f
// prints the output once instead of concatenating both copies.
func TestGatherFollowDoesNotDuplicateCompleteRetainedOutput(t *testing.T) {
	var all strings.Builder
	for i := 1; i <= 300; i++ {
		fmt.Fprintf(&all, "%d\n", i)
	}
	b := finishedBlip("fast", v1alpha1.BlipSucceeded, 0)
	b.Status.Output = all.String()
	h := newHarness(t, b)
	h.guest.OpenError = "no session"
	h.logs = func(context.Context, string) (io.ReadCloser, error) {
		var s strings.Builder
		for i := 1; i <= 300; i++ {
			fmt.Fprintf(&s, "blip: %d\n", i)
		}
		return io.NopCloser(strings.NewReader(s.String())), nil
	}

	code, _, errOut := h.run("", "gather", "fast", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := strings.Count(errOut, "fast| "); got != 300 {
		t.Fatalf("replayed %d lines, want 300 (duplicate sources?): %s", got, errOut)
	}
	if strings.Contains(errOut, "output is truncated") {
		t.Fatalf("unexpected truncation warning: %q", errOut)
	}
}

// When both sources are truncated, gather -f prints one tail and warns that
// earlier output is gone instead of looking like a complete replay.
func TestGatherFollowWarnsWhenBothRetainedSourcesAreTruncated(t *testing.T) {
	b := finishedBlip("fast", v1alpha1.BlipSucceeded, 0)
	b.Status.Output = statusOutputTruncated + "\n299\n300\n"
	h := newHarness(t, b)
	h.guest.OpenError = "no session"
	h.logs = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("blip: 299\nblip: 300\nblip: 298 output lines dropped\n")), nil
	}

	code, _, errOut := h.run("", "gather", "fast", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, errOut, "fast| 299", "fast| 300", "output is truncated")
	if got := strings.Count(errOut, "fast| 299"); got != 1 {
		t.Fatalf("replayed the tail %d times, want once: %s", got, errOut)
	}
	if got := strings.Count(errOut, "fast| 300"); got != 1 {
		t.Fatalf("replayed the final line %d times, want once: %s", got, errOut)
	}
}

// A command that exits between waitRunning and the attach makes the attach
// fail with a container-stopped error. If the controller then reports a
// finished, empty-output Blip, losing that empty stream is not a failure:
// gather must not print "could not follow output" for a Succeeded Blip.
func TestGatherFollowSuppressesAttachErrorForFinishedEmptyBlip(t *testing.T) {
	withAttachFailWait(t, 200*time.Millisecond)
	h := newHarness(t, runningBlip("quiet"))
	h.ctrl.set(func(c *fakeController) { c.paused = true })
	h.guest.OpenError = "cannot exec in a stopped state"
	go func() {
		time.Sleep(50 * time.Millisecond)
		var b v1alpha1.Blip
		if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "quiet"}, &b); err != nil {
			return
		}
		code := int32(0)
		b.Status.Phase = v1alpha1.BlipSucceeded
		b.Status.ExitCode = &code
		b.Status.FinishTime = &metav1.Time{Time: time.Now()}
		_ = h.kube.Status().Update(context.Background(), &b)
	}()

	code, out, errOut := h.run("", "gather", "quiet", "-f", "--wait", "5s")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/quiet Succeeded (exit 0)")
	if strings.Contains(errOut, "could not follow output") {
		t.Fatalf("reported an attach failure for a successful silent Blip: %q", errOut)
	}
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("reported unavailable output for an empty stream: %q", errOut)
	}
}

// The same attach failure while the Blip is still running is real: gather -f
// must keep warning that it could not follow a running command.
func TestGatherFollowWarnsOnAttachErrorForRunningBlip(t *testing.T) {
	withAttachFailWait(t, 100*time.Millisecond)
	h := newHarness(t, runningBlip("still-running"))
	h.ctrl.set(func(c *fakeController) { c.paused = true })
	h.guest.OpenError = "no running task found"

	code, _, errOut := h.run("", "gather", "still-running", "-f", "--wait", "400ms")
	if code != 1 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, errOut, "could not follow output", "no running task found")
}

// A finished command with no output is not data loss. Do not warn that
// output is unavailable when the retained stream is empty.
func TestGatherFollowDoesNotWarnForEmptyOutput(t *testing.T) {
	withRetainedOutputWait(t, 50*time.Millisecond)
	b := finishedBlip("gone", v1alpha1.BlipSucceeded, 0)
	b.Status.Pod = ""
	h := newHarness(t, b)
	code, out, errOut := h.run("", "gather", "gone", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/gone Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
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
	mustContain(t, errOut, "lagged| LATEOUT")
	mustContain(t, out, "blip/lagged Succeeded (exit 0)")
	if strings.Contains(out, "LATEOUT") {
		t.Fatalf("retained output replayed to stdout: %q", out)
	}
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// A Blip can finish before claiming a VM, for example when it is stopped
// while pending. It never ran a command, so no status.output can arrive and
// gather -f must not wait out the retained-output poll for it.
func TestGatherFollowReturnsPromptlyWhenBlipNeverStarted(t *testing.T) {
	b := finishedBlip("nodop", v1alpha1.BlipFailed, 0)
	b.Status.Pod = ""
	b.Status.StartTime = nil
	b.Status.ExitCode = nil
	b.Status.Reason = "Stopped"
	b.Status.Message = "stopped before start"
	h := newHarness(t, b)
	start := time.Now()
	code, out, errOut := h.run("", "gather", "nodop", "-f", "--wait", "2s")
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("gather -f took %s for a Blip that never started", elapsed)
	}
	mustContain(t, out, "blip/nodop Failed")
	mustContain(t, errOut, "stopped before start")
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
	mustContain(t, errOut, "empty| RETAINED")
	mustContain(t, out, "blip/empty Succeeded (exit 0)")
	if strings.Contains(out, "RETAINED") {
		t.Fatalf("retained output replayed to stdout: %q", out)
	}
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// An empty replay with an empty retained stream is a command that printed
// nothing; do not warn.
func TestGatherFollowDoesNotWarnWhenEmptyReplayHasNoOutput(t *testing.T) {
	withRetainedOutputWait(t, 50*time.Millisecond)
	h := newHarness(t, finishedBlip("empty", v1alpha1.BlipSucceeded, 0))
	code, out, errOut := h.run("", "gather", "empty", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/empty Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// A finished command that printed nothing and whose VM pod is already gone
// cannot gain retained output later. gather -f must not spend the
// retained-output grace on it, and --wait must still bound the command.
func TestGatherFollowFinishedEmptyOutputReturnsPromptly(t *testing.T) {
	h := newHarness(t, finishedBlip("empty", v1alpha1.BlipSucceeded, 0))
	// The session is gone and the serial log is unavailable.
	h.guest.OpenError = "no session"
	start := time.Now()
	code, out, errOut := h.run("", "gather", "empty", "-f", "--wait", "200ms")
	elapsed := time.Since(start)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed > time.Second {
		t.Fatalf("gather -f took %s for a finished empty-output blip", elapsed)
	}
	mustContain(t, out, "blip/empty Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}

// Even while the VM pod outlives the finished session, --wait bounds the
// follower's retained-output poll instead of letting it run out its grace.
func TestGatherFollowWaitBoundsFinishedEmptyReplay(t *testing.T) {
	b := finishedBlip("empty", v1alpha1.BlipSucceeded, 0)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: b.Status.Pod, Namespace: ns}}
	h := newHarness(t, b, pod)
	h.guest.OpenError = "no session"
	start := time.Now()
	code, out, errOut := h.run("", "gather", "empty", "-f", "--wait", "200ms")
	elapsed := time.Since(start)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed > time.Second {
		t.Fatalf("gather -f ignored --wait for %s", elapsed)
	}
	mustContain(t, out, "blip/empty Succeeded (exit 0)")
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message after --wait: %q", errOut)
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

// Naming the caller explicitly must fail quickly instead of waiting forever
// or reporting the caller as still running.
func TestGatherExplicitNameRejectsCaller(t *testing.T) {
	caller := ownedBlip("alice.box", "alice.home")
	h := newHarness(t, caller)
	h.self = "alice.box"
	start := time.Now()
	code, out, errOut := h.run("", "gather", "alice.box")
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("gather of the caller took %s", elapsed)
	}
	mustContain(t, errOut, "cannot gather box, the blip running this gather")
	if strings.Contains(errOut, "still running") {
		t.Fatalf("caller treated as a target: %q", errOut)
	}
	if h.gone("alice.box") {
		t.Fatal("caller gathered itself")
	}
}

// A finished command whose pod is already gone still reports the output the
// controller retained in status. status.output combines stdout and stderr, so
// the replay goes to stderr while the summary stays on stdout.
func TestGatherFollowUsesRetainedStatusOutput(t *testing.T) {
	b := finishedBlip("retained", v1alpha1.BlipSucceeded, 0)
	b.Status.Pod = ""
	b.Status.Output = "FASTOUT\nLASTLINE\n"
	h := newHarness(t, b)
	code, out, errOut := h.run("", "gather", "retained", "-f")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, errOut, "retained| FASTOUT", "retained| LASTLINE")
	mustContain(t, out, "blip/retained Succeeded (exit 0)")
	if strings.Contains(out, "FASTOUT") || strings.Contains(out, "LASTLINE") {
		t.Fatalf("retained combined output replayed to stdout: %q", out)
	}
	if strings.Contains(errOut, "output is no longer available") {
		t.Fatalf("unexpected unavailable message: %q", errOut)
	}
}
