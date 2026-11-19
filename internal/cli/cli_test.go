package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// isBlipGone reports whether the blip no longer exists. Garbage collection is
// not part of the fake controller, so tests check deletions directly.
func isBlipGone(t *testing.T, h *harness, name string) bool {
	t.Helper()
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &v1alpha1.Blip{})
	return apierrors.IsNotFound(err)
}

func isStateGone(t *testing.T, h *harness, name string) bool {
	t.Helper()
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &v1alpha1.BlipState{})
	return apierrors.IsNotFound(err)
}

func TestRunCreatesBlipAndReturnsName(t *testing.T) {
	h := newHarness(t, readyState("workspace"))
	code, out, errOut := h.run("", "run", "--name", "worker-1", "--state", "workspace",
		"-w", "/work/repo", "-e", "A=B", "-u", "dev", "--pool", "big",
		"--", "sh", "-lc", "make test")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	// run prints the new blip's short name and returns without attaching.
	if strings.TrimSpace(out) != "worker-1" {
		t.Fatalf("output %q", out)
	}
	if _, stdins := h.stream.calls(); len(stdins) != 1 || !stdins[0].eof || stdins[0].state != "workspace" {
		t.Fatalf("run did not close stdin: %+v", stdins)
	}
	b := h.blip("worker-1")
	s := b.Spec
	if s.State != "workspace" || s.Pool != "big" || s.WorkingDir != "/work/repo" || s.User != "dev" {
		t.Fatalf("spec = %+v", s)
	}
	if strings.Join(s.Command, "|") != "sh|-lc|make test" || len(s.Env) != 1 || s.Env[0] != (v1alpha1.EnvVar{Name: "A", Value: "B"}) {
		t.Fatalf("command/env = %v %v", s.Command, s.Env)
	}
}

func TestRunRequiresCommand(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "run")
	if code != 1 || !strings.Contains(errOut, "requires at least 1 arg") {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

// An explicit empty or whitespace-only argv[0] is the `run -- "$CMD"`
// footgun: the guest would fail with exit 127 only after the blip and its
// fork state were created. It must be rejected before anything exists.
func TestRunRejectsEmptyCommandName(t *testing.T) {
	for _, command := range []string{"", " ", "\t\n"} {
		h := newHarness(t, readyState("base"))
		code, out, errOut := h.run("", "run", "--name", "empty", "--from", "base", "--", command)
		if code != 1 || !strings.Contains(errOut, "command name must not be empty") {
			t.Fatalf("command %q: code %d out %q stderr %q", command, code, out, errOut)
		}
		if out != "" {
			t.Fatalf("command %q: output %q", command, out)
		}
		if !isBlipGone(t, h, "empty") {
			t.Fatalf("command %q: run created a blip", command)
		}
		if !isStateGone(t, h, "empty") {
			t.Fatalf("command %q: run created a state", command)
		}
	}
}

// The empty-name check must not reject real commands or turn flags after --
// back into blip flags.
func TestRunAllowsCommandAfterEmptyNameCheck(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, out, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--", "echo", "-n", "hi")
	if code != 0 || strings.TrimSpace(out) != "worker" {
		t.Fatalf("code %d out %q stderr %q", code, out, errOut)
	}
	if got := strings.Join(h.blip("worker").Spec.Command, "|"); got != "echo|-n|hi" {
		t.Fatalf("command = %q", got)
	}
}

// pflag parses flags after the first positional. Without --, a command
// argument that matches a blip flag is silently removed from the command.
func TestRunRejectsFlagsAfterCommandWithoutDash(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, _, errOut := h.run("", "run", "--name", "argtest", "--from", "base", "echo", "-n", "ns")
	if code != 1 || !strings.Contains(errOut, `flag "-n"`) || !strings.Contains(errOut, "put -- before the command") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !isBlipGone(t, h, "argtest") {
		t.Fatal("run created a blip after rejecting its command")
	}
}

// Flags before the command need no --; only ambiguous flags after it do.
func TestRunAllowsFlagsBeforeCommandWithoutDash(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := strings.Join(h.blip("worker").Spec.Command, " "); got != "true" {
		t.Fatalf("command = %q", got)
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--name", "x", "--", "true"}, "set --from or --state"},
		{[]string{"run", "--name", "x", "--from", "base", "--state", "s", "--", "true"}, "set only one of --from and --state"},
		{[]string{"run", "--name", "x", "--from", "/", "--", "true"}, "--from / only works inside a blip"},
		{[]string{"run", "--name", "x", "--fork", "base", "--", "true"}, "unknown flag: --fork"},
		{[]string{"run", "--name", "x", "--image", "i", "--", "true"}, "unknown flag: --image"},
		{[]string{"run", "--name", "x", "--state", "s", "--mount", "s:/w", "--", "true"}, "unknown flag: --mount"},
		{[]string{"run", "--name", "x", "--state", "s", "--detach", "--", "true"}, "unknown flag: --detach"},
		{[]string{"run", "--name", "x", "--state", "s", "--idle-timeout", "5m", "--", "true"}, "unknown flag: --idle-timeout"},
	} {
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, code, errOut)
		}
	}
}

func TestRunReturnsNameWithoutAttaching(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, out, errOut := h.run("", "run", "--name", "job", "--from", "base", "--", "false")
	// run neither streams the command's output nor returns its exit code.
	if code != 0 || out != "job\n" || errOut != "" {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
	if logs, _ := h.stream.calls(); len(logs) != 0 {
		t.Fatalf("run read the stream: %+v", logs)
	}
	b := h.blip("job")
	if b.Spec.State != "job" || strings.Join(b.Spec.Command, " ") != "false" {
		t.Fatalf("blip %+v", b.Spec)
	}
	// The fork is created before run returns and is owned by the new blip.
	root := h.state("job")
	if root.Spec.CopyFrom != "base" || root.Status.Committed == nil {
		t.Fatalf("root state %+v", root)
	}
	if len(root.OwnerReferences) != 1 || root.OwnerReferences[0].Name != "job" {
		t.Fatalf("workspace ownership %+v", root.OwnerReferences)
	}
}

// Every command that takes an object name rejects an impossible one with the
// same short message instead of leaking client-go or API-server validation.
func TestInvalidNamesAreRejectedBeforeAPI(t *testing.T) {
	h := newHarness(t, readyState("base"))
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--name", "", "--from", "base", "--", "true"}, `invalid blip name ""`},
		{[]string{"gather", ""}, `invalid blip name ""`},
	} {
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, code, errOut)
		}
		for _, raw := range []string{"resource name may not be empty", "metadata.name"} {
			if strings.Contains(errOut, raw) {
				t.Errorf("%v leaked raw API error %q: %s", tc.args, raw, errOut)
			}
		}
	}
	var blips v1alpha1.BlipList
	if err := h.kube.List(context.Background(), &blips, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	if len(blips.Items) != 0 {
		t.Errorf("invalid names created blips: %v", blips.Items)
	}

	code, _, errOut := h.run("", "gather", "missing")
	if code != 1 || !strings.Contains(errOut, `blip "missing" not found in namespace "ns"`) {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestGatherFailsIfAnyFailed(t *testing.T) {
	ok, bad := runningBlip("ok"), runningBlip("bad")
	ok.Status.Phase, bad.Status.Phase = v1alpha1.BlipSucceeded, v1alpha1.BlipFailed
	zero, one := int32(0), int32(1)
	ok.Status.ExitCode, bad.Status.ExitCode = &zero, &one
	bad.Status.Message = "command failed"
	h := newHarness(t, ok, bad)
	code, out, errOut := h.run("", "gather", "ok", "bad")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "blip/ok Succeeded (exit 0)", "blip/bad Failed (exit 1)")
	mustContain(t, errOut, "command failed")
	// Successful blips are deleted; failed ones are kept for inspection.
	if !isBlipGone(t, h, "ok") || isBlipGone(t, h, "bad") {
		t.Fatalf("ok gone=%v bad gone=%v", isBlipGone(t, h, "ok"), isBlipGone(t, h, "bad"))
	}
}

func TestGatherShowsStopReason(t *testing.T) {
	stopped := runningBlip("stopped")
	stopped.Status.Phase = v1alpha1.BlipSucceeded
	stopped.Status.Reason = "Stopped"
	h := newHarness(t, stopped)
	code, out, _ := h.run("", "gather", "stopped")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "blip/stopped Succeeded (Stopped)")
}

func TestMountAddsSpecAndWaitsMounted(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	code, out, errOut := h.run("", "mount", "repo:/work:rw", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /work (writable)")
	root := h.rootState("agent")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0] != (v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}) {
		t.Fatalf("mounts = %+v", root.Spec.Mounts)
	}
	// Mounting again is a no-op; a different path is an error.
	if code, _, _ := h.run("", "mount", "repo:/work:rw", "--root", "agent-root"); code != 0 {
		t.Fatal(code)
	}
	code, _, errOut = h.run("", "mount", "repo:/other", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "already mounted") {
		t.Fatal(errOut)
	}
}

func TestMountWaitsForOldAttachmentDetach(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	// Keep the status where the test puts it: no controller progress.
	h.ctrl.set(func(c *fakeController) { c.paused = true })
	b := h.blip("agent")
	b.Status.Mounts = []v1alpha1.MountStatus{{State: "repo", Path: "/work", Phase: v1alpha1.MountMounted, AttachmentID: "old"}}
	if err := h.kube.Status().Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}

	a := &app{env: h.env(strings.NewReader(""), io.Discard, io.Discard)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.mountState(ctx, "repo", "agent-root", "/work", nil) }()

	// Re-adding the mount while the old attachment is still visible would
	// let the controller revive it instead of attaching a fresh disk.
	select {
	case err := <-done:
		t.Fatalf("mountState returned while the old attachment was still visible: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if s := h.rootState("agent"); len(s.Spec.Mounts) != 0 {
		t.Fatalf("mount was re-added before the old attachment detached: %+v", s.Spec.Mounts)
	}

	// Let the controller detach the old mount and attach the new one.
	h.ctrl.set(func(c *fakeController) { c.paused = false })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("mountState failed after the old attachment detached: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mountState did not return after the fresh attachment")
	}
	if s := h.rootState("agent"); len(s.Spec.Mounts) != 1 {
		t.Fatalf("mounts %+v", s.Spec.Mounts)
	}
}

func TestMountSwitchesExistingMode(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work"}), readyState("repo"))

	code, out, errOut := h.run("", "mount", "repo:/work:rw", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("promote code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /work (writable)")
	b := h.blip("agent")
	if mounts := h.rootState("agent").Spec.Mounts; len(mounts) != 1 || !mounts[0].Writable || len(b.Status.Mounts) != 1 || !b.Status.Mounts[0].Writable {
		t.Fatalf("promoted mounts = %+v %+v", mounts, b.Status.Mounts)
	}

	code, out, errOut = h.run("", "mount", "repo:/work:ro", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("demote code %d: %s", code, errOut)
	}
	b = h.blip("agent")
	mustContain(t, out, "state repo mounted on blip agent at /work (read-only)")
	if mounts := h.rootState("agent").Spec.Mounts; len(mounts) != 1 || mounts[0].Writable || len(b.Status.Mounts) != 1 || b.Status.Mounts[0].Writable {
		t.Fatalf("demoted mounts = %+v %+v", mounts, b.Status.Mounts)
	}
	if st := h.state("repo"); st.Status.Committed == nil || st.Status.Committed.ID != b.Status.Mounts[0].CommitID {
		t.Fatalf("state did not commit demoted version: %+v", st.Status)
	}

	// No mode leaves the existing mode alone.
	code, out, errOut = h.run("", "mount", "repo:/work", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("unchanged code %d: %s", code, errOut)
	}
	mustContain(t, out, "(read-only)")
}

func TestMountSwitchBusyRetainsIntent(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.unmountFail = "target is busy" })
	code, _, errOut := h.run("", "mount", "repo:/work:ro", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "processes are still using /work") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	root := h.rootState("agent")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].Writable {
		t.Fatalf("desired mode lost: %+v", root.Spec.Mounts)
	}
}

func TestMountFailureIsReported(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = "no space left on device" })
	code, _, errOut := h.run("", "mount", "repo:/work", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, `mount of state "repo" on blip "agent" failed: no space left on device`) {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

func TestMountBusyAndBadPath(t *testing.T) {
	s := readyState("repo")
	s.Status.Writer = &v1alpha1.Writer{BlipName: "other"}
	h := newHarness(t, runningBlip("agent"), s)
	h.ctrl.set(func(c *fakeController) { c.mountFail = "state is busy" })
	code, _, errOut := h.run("", "mount", "repo:/work:rw", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "processes are still using /work") {
		t.Fatal(errOut)
	}
	code, _, errOut = h.run("", "mount", "repo:work", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "clean absolute path") {
		t.Fatal(errOut)
	}
}

func TestUnmountWaitsUntilSaved(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}), readyState("repo"))
	code, out, errOut := h.run("", "mount", "--rm", "repo", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo unmounted from blip agent")
	mustContain(t, errOut, "saving repo")
	b := h.blip("agent")
	if mounts := h.rootState("agent").Spec.Mounts; len(mounts) != 0 || len(b.Status.Mounts) != 0 {
		t.Fatalf("mounts = %+v %+v", mounts, b.Status.Mounts)
	}
	code, _, errOut = h.run("", "mount", "--rm", "repo", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "not mounted") {
		t.Fatal(errOut)
	}
}

func TestUnmountBusy(t *testing.T) {
	for _, writable := range []bool{true, false} {
		t.Run(modeName(writable), func(t *testing.T) {
			h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: writable}), readyState("repo"))
			h.ctrl.set(func(c *fakeController) { c.unmountFail = "target is busy" })
			code, _, errOut := h.run("", "mount", "--rm", "repo", "--root", "agent-root")
			if code != 1 || !strings.Contains(errOut, `could not unmount state "repo" from blip "agent": processes are still using /work`) {
				t.Fatalf("code %d err %q", code, errOut)
			}

			// A busy runtime attachment does not restore removed intent.
			b := h.blip("agent")
			if mounts := h.rootState("agent").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("desired removal lost: %+v", mounts)
			}
			if len(b.Status.Mounts) != 1 {
				t.Fatalf("status after busy unmount: %+v", b.Status.Mounts)
			}
			m := b.Status.Mounts[0]
			if m.Phase != v1alpha1.MountUnmounting || m.Path != "/work" || m.Writable != writable || m.Message == "" {
				t.Fatalf("mount after busy unmount: %+v", m)
			}

			// Once the holder stops, the pending removal completes.
			h.ctrl.set(func(c *fakeController) { c.unmountFail = "" })
			waitForCond(t, func() bool { return len(h.blip("agent").Status.Mounts) == 0 })
			b = h.blip("agent")
			if mounts := h.rootState("agent").Spec.Mounts; len(mounts) != 0 || len(b.Status.Mounts) != 0 {
				t.Fatalf("mounts after retry: %+v %+v", mounts, b.Status.Mounts)
			}
		})
	}
}

func TestUnmountFailedMountClearsState(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = "no space left on device" })
	code, _, errOut := h.run("", "mount", "repo:/work", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "no space left on device") {
		t.Fatalf("mount code %d err %q", code, errOut)
	}
	if b := h.blip("agent"); len(b.Status.Mounts) != 1 || b.Status.Mounts[0].Phase != v1alpha1.MountFailed {
		t.Fatalf("failed mount: %+v", b.Status.Mounts)
	}

	// Removing a mount that never attached drops its failed entry, so the
	// unmount completes instead of reporting the old attach error forever.
	h.ctrl.set(func(c *fakeController) { c.mountFail = "" })
	code, out, errOut := h.run("", "mount", "--rm", "repo", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("unmount code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo unmounted from blip agent")
	if b := h.blip("agent"); len(h.rootState("agent").Spec.Mounts) != 0 || len(b.Status.Mounts) != 0 {
		t.Fatalf("mounts after unmount: %+v %+v", h.rootState("agent").Spec.Mounts, b.Status.Mounts)
	}

	// The state can now be mounted again at another path.
	code, out, errOut = h.run("", "mount", "repo:/other", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("remount code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /other")
	if root := h.rootState("agent"); len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].Path != "/other" {
		t.Fatalf("remounted spec: %+v", root.Spec.Mounts)
	}
}

// TestGitWorkflow runs the fan-out/fan-in Git workflow against fakes,
// creating states the way kubectl apply would.
func TestGitWorkflow(t *testing.T) {
	requireGit(t)
	withCollectMountRoot(t)
	h := newHarness(t, runningBlip("agent"))
	h.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	repo := state("repo")
	worker := state("worker-1")
	worker.Spec.CopyFrom = "repo"
	h.apply(repo)
	steps := [][]string{
		{"mount", "repo:/work:rw", "--root", "agent-root"},
		{"mount", "--rm", "repo", "--root", "agent-root"},
	}
	for _, args := range steps {
		if code, _, errOut := h.run("", args...); code != 0 {
			t.Fatalf("%v: code %d: %s", args, code, errOut)
		}
	}
	h.apply(worker)
	if code, _, errOut := h.run("", "run", "--name", "worker-1", "--state", "worker-1", "-w", "/work/repo", "--", "sh", "-lc", "make fix"); code != 0 {
		t.Fatalf("run: code %d: %s", code, errOut)
	}
	if w := h.waitBlip("worker-1"); w.Status.Phase != v1alpha1.BlipSucceeded {
		t.Fatalf("worker phase = %s", w.Status.Phase)
	}

	// Collect the worker's changes from its durable root filesystem.
	dst := filepath.Join(t.TempDir(), "dst")
	gitInit(t, dst)
	commit := gitRepo(t, filepath.Join(collectMountRoot, "worker-1", "work", "repo"))
	h.self = "agent"
	t.Chdir(dst)
	if code, _, errOut := h.collect("worker-1", "git:/work/repo:w1"); code != 0 {
		t.Fatalf("collect: code %d: %s", code, errOut)
	}
	if got := gitRun(t, dst, "rev-parse", "w1"); got != commit {
		t.Fatalf("w1 = %s, want %s", got, commit)
	}
	assertCollectReleased(t, h, "agent", "worker-1")

	if w := h.blip("worker-1"); w.Status.Phase != v1alpha1.BlipSucceeded {
		t.Fatalf("worker phase = %s", w.Status.Phase)
	}
}

func TestRunReportsMissingPoolAndState(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "run", "--name", "x", "--pool", "nope", "--from", "base", "--", "true")
	if code == 0 {
		t.Fatal("run succeeded without a pool")
	}
	mustContain(t, errOut, `pool "nope" not found`)
	code, _, errOut = h.run("", "run", "--name", "x", "--state", "home", "--", "true")
	if code == 0 {
		t.Fatal("run succeeded without a state")
	}
	mustContain(t, errOut, `state "home" not found`)
}
