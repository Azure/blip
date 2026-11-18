package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

func TestRunDetachedCreatesBlipFromFlags(t *testing.T) {
	h := newHarness(t, state("worker-1"), state("ref"))
	code, out, errOut := h.run("", "run", "worker-1", "--image", "reg/img:1", "-d", "--mount", "worker-1:/work:rw",
		"--mount", "ref:/ref", "-w", "/work/repo", "-e", "A=B", "-u", "dev", "--pool", "big", "--idle-timeout", "5m",
		"--", "sh", "-lc", "make test")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/worker-1 created")
	b := h.blip("worker-1")
	s := b.Spec
	if s.Image != "reg/img:1" || s.State != "" || s.Pool != "big" || s.WorkingDir != "/work/repo" || s.User != "dev" || s.TTY {
		t.Fatalf("spec = %+v", s)
	}
	if strings.Join(s.Command, "|") != "sh|-lc|make test" || len(s.Env) != 1 || s.Env[0] != (v1alpha1.EnvVar{Name: "A", Value: "B"}) {
		t.Fatalf("command/env = %v %v", s.Command, s.Env)
	}
	want := []v1alpha1.Mount{{State: "worker-1", Path: "/work", Writable: true}, {State: "ref", Path: "/ref"}}
	if len(s.Mounts) != 2 || s.Mounts[0] != want[0] || s.Mounts[1] != want[1] {
		t.Fatalf("mounts = %+v", s.Mounts)
	}
	if s.IdleTimeout == nil || s.IdleTimeout.Duration != 5*time.Minute {
		t.Fatalf("idle = %v", s.IdleTimeout)
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "x", "-d"}, "exactly one of --image"},
		{[]string{"run", "x", "--image", "i", "--state", "s", "-d"}, "exactly one of --image"},
		{[]string{"run", "x", "--image", "i", "--mount", "s:work", "-d"}, "invalid mount"},
		{[]string{"run", "x", "--image", "i", "--mount", "s:/a/../b", "-d"}, "invalid mount"},
		{[]string{"run", "x", "--image", "i", "--mount", "s:/w:rx", "-d"}, "mode must be rw or ro"},
		{[]string{"run", "x", "--image", "i", "--mount", "s:/a", "--mount", "s:/b", "-d"}, "mounted twice"},
		{[]string{"run", "x", "--image", "i", "--idle-timeout=-5s", "-d"}, "must not be negative"},
	} {
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, code, errOut)
		}
	}
}

func TestRunAttachesToCommandAndExitsWithItsCode(t *testing.T) {
	h := newHarness(t)
	h.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("hello\n")
		s.Stderr("oops\n")
		h.ctrl.set(func(c *fakeController) { c.exited["job"] = 3 })
		return wire.Exit{Code: 3}
	}
	code, out, errOut := h.run("", "run", "job", "--image", "img", "--", "false")
	if code != 3 || out != "hello\n" {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
	mustContain(t, errOut, "oops", "waiting for a VM")
	o := h.guest.Opens()[0]
	if o.Pod != "pod-job" || o.Open.Mode != wire.OpenAttach || o.Open.Session != wire.PrimarySession {
		t.Fatalf("open = %+v", o)
	}
	if b := h.blip("job"); b.Status.Phase != v1alpha1.BlipFailed {
		t.Fatalf("run returned before the blip finished: %s", b.Status.Phase)
	}
}

func TestRunWithoutCommandOpensShell(t *testing.T) {
	h := newHarness(t, state("home"))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{Code: 0} }
	code, _, errOut := h.run("", "run", "sbx", "--state", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	o := h.guest.Opens()[0].Open
	if o.Mode != wire.OpenExec || len(o.Argv) != 0 || o.TTY {
		t.Fatalf("open = %+v", o)
	}
	if b := h.blip("sbx"); b.Spec.State != "home" || len(b.Spec.Command) != 0 {
		t.Fatalf("spec = %+v", b.Spec)
	}
}

func TestExecForwardsStdinAndExitCode(t *testing.T) {
	h := newHarness(t, runningBlip("agent"))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout(strings.ToUpper(s.ReadAll()))
		return wire.Exit{Code: 5}
	}
	code, out, _ := h.run("data", "exec", "agent", "-w", "/work", "-u", "root", "-e", "X=1", "--", "tr", "a-z", "A-Z")
	if code != 5 || out != "DATA" {
		t.Fatalf("code %d out %q", code, out)
	}
	o := h.guest.Opens()[0]
	if o.Pod != "pod-agent" || o.Open.Mode != wire.OpenExec || strings.Join(o.Open.Argv, " ") != "tr a-z A-Z" ||
		o.Open.WorkingDir != "/work" || o.Open.User != "root" || o.Open.Env[0] != "X=1" || o.Open.TTY {
		t.Fatalf("open = %+v", o)
	}
}

func TestExecWithoutCommandOpensLoginShell(t *testing.T) {
	h := newHarness(t, runningBlip("agent"))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	if code, _, errOut := h.run("", "exec", "agent", "-u", "dev"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if code, _, errOut := h.run("", "exec", "agent", "-t"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	opens := h.guest.Opens()
	if o := opens[0].Open; o.Mode != wire.OpenExec || len(o.Argv) != 0 || o.User != "dev" || o.TTY {
		t.Fatalf("open = %+v", o)
	}
	if o := opens[1].Open; !o.TTY {
		t.Fatalf("-t did not request a terminal: %+v", o)
	}
}

func TestExecSignalExitCode(t *testing.T) {
	h := newHarness(t, runningBlip("agent"))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{Signal: "KILL"} }
	if code, _, _ := h.run("", "exec", "agent", "--", "sleep", "1"); code != 137 {
		t.Fatalf("code %d", code)
	}
}

func TestExecOnFinishedOrMissingBlipIsFriendly(t *testing.T) {
	b := runningBlip("agent")
	b.Status.Phase, b.Status.Pod = v1alpha1.BlipSucceeded, ""
	h := newHarness(t, b)
	code, _, errOut := h.run("", "exec", "agent", "--", "true")
	if code != 1 || !strings.Contains(errOut, `blip "agent" has finished (Succeeded)`) {
		t.Fatalf("code %d err %q", code, errOut)
	}
	code, _, errOut = h.run("", "exec", "missing", "--", "true")
	if code != 1 || !strings.Contains(errOut, `blip "missing" not found`) {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

func TestAttachAndSessions(t *testing.T) {
	h := newHarness(t, runningBlip("agent"))
	h.guest.Sessions = []wire.SessionInfo{{ID: "main", Argv: []string{"make"}, Clients: 1}, {ID: "s2", TTY: true, Exited: true}}
	h.guest.Run = func(s *fakeguest.Session) wire.Exit { s.Stdout("replay"); return wire.Exit{} }
	code, out, _ := h.run("", "attach", "agent", "--session", "s2")
	if code != 0 || out != "replay" || h.guest.Opens()[0].Open.Session != "s2" {
		t.Fatalf("code %d out %q", code, out)
	}
	code, out, _ = h.run("", "sessions", "agent")
	if code != 0 {
		t.Fatal(code)
	}
	mustContain(t, out, "ID", "main", "Running", "make", "s2", "Exited", "(login shell)")
}

func TestWaitFailsIfAnyFailed(t *testing.T) {
	ok, bad := runningBlip("ok"), runningBlip("bad")
	ok.Status.Phase, bad.Status.Phase = v1alpha1.BlipSucceeded, v1alpha1.BlipFailed
	zero, one := int32(0), int32(1)
	ok.Status.ExitCode, bad.Status.ExitCode = &zero, &one
	bad.Status.Message = "command failed"
	h := newHarness(t, ok, bad)
	code, out, _ := h.run("", "wait", "ok", "bad")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "blip/ok Succeeded (exit 0)", "blip/bad Failed (exit 1): command failed")
}

func TestWaitShowsStopReason(t *testing.T) {
	stopped := runningBlip("stopped")
	stopped.Status.Phase = v1alpha1.BlipSucceeded
	stopped.Status.Reason = "Stopped"
	h := newHarness(t, stopped)
	code, out, _ := h.run("", "wait", "stopped")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "blip/stopped Succeeded (Stopped)")
}

func TestMountAddsSpecAndWaitsMounted(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	code, out, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--write")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /work (writable)")
	b := h.blip("agent")
	if len(b.Spec.Mounts) != 1 || b.Spec.Mounts[0] != (v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}) {
		t.Fatalf("mounts = %+v", b.Spec.Mounts)
	}
	// Mounting again is a no-op; a different path is an error.
	if code, _, _ := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--write"); code != 0 {
		t.Fatal(code)
	}
	code, _, errOut = h.run("", "mount", "repo", "--blip", "agent", "--path", "/other")
	if code != 1 || !strings.Contains(errOut, "already mounted") {
		t.Fatal(errOut)
	}
}

func TestMountSwitchesExistingMode(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work"}), readyState("repo"))

	code, out, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--write")
	if code != 0 {
		t.Fatalf("promote code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /work (writable)")
	b := h.blip("agent")
	if len(b.Spec.Mounts) != 1 || !b.Spec.Mounts[0].Writable || len(b.Status.Mounts) != 1 || !b.Status.Mounts[0].Writable {
		t.Fatalf("promoted mounts = %+v %+v", b.Spec.Mounts, b.Status.Mounts)
	}

	code, out, errOut = h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--read-only")
	if code != 0 {
		t.Fatalf("demote code %d: %s", code, errOut)
	}
	b = h.blip("agent")
	mustContain(t, out, "state repo mounted on blip agent at /work (read-only)")
	if len(b.Spec.Mounts) != 1 || b.Spec.Mounts[0].Writable || len(b.Status.Mounts) != 1 || b.Status.Mounts[0].Writable {
		t.Fatalf("demoted mounts = %+v %+v", b.Spec.Mounts, b.Status.Mounts)
	}
	if st := h.state("repo"); st.Status.Committed == nil || st.Status.Committed.ID != b.Status.Mounts[0].CommitID {
		t.Fatalf("state did not commit demoted version: %+v", st.Status)
	}

	// No flag leaves the existing mode alone.
	code, out, errOut = h.run("", "mount", "repo", "--blip", "agent", "--path", "/work")
	if code != 0 {
		t.Fatalf("unchanged code %d: %s", code, errOut)
	}
	mustContain(t, out, "(read-only)")
}

func TestMountSwitchBusyRevertsSpec(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.unmountFail = "target is busy" })
	code, _, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--read-only")
	if code != 1 || !strings.Contains(errOut, "processes are still using /work") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	b := h.blip("agent")
	if len(b.Spec.Mounts) != 1 || !b.Spec.Mounts[0].Writable {
		t.Fatalf("spec not reverted: %+v", b.Spec.Mounts)
	}
}

func TestMountFailureIsReported(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = "no space left on device" })
	code, _, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work")
	if code != 1 || !strings.Contains(errOut, `mount of state "repo" on blip "agent" failed: no space left on device`) {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

func TestMountBusyAndBadPath(t *testing.T) {
	s := readyState("repo")
	s.Status.Writer = &v1alpha1.Writer{BlipName: "other"}
	h := newHarness(t, runningBlip("agent"), s)
	code, _, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work", "--write")
	if code != 1 || !strings.Contains(errOut, "busy") {
		t.Fatal(errOut)
	}
	code, _, errOut = h.run("", "mount", "repo", "--blip", "agent", "--path", "work")
	if code != 1 || !strings.Contains(errOut, "invalid path") {
		t.Fatal(errOut)
	}
}

func TestUnmountWaitsUntilSaved(t *testing.T) {
	h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: true}), readyState("repo"))
	code, out, errOut := h.run("", "unmount", "repo", "--blip", "agent")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo unmounted from blip agent")
	mustContain(t, errOut, "saving repo")
	b := h.blip("agent")
	if len(b.Spec.Mounts) != 0 || len(b.Status.Mounts) != 0 {
		t.Fatalf("mounts = %+v %+v", b.Spec.Mounts, b.Status.Mounts)
	}
	code, _, errOut = h.run("", "unmount", "repo", "--blip", "agent")
	if code != 1 || !strings.Contains(errOut, "not mounted") {
		t.Fatal(errOut)
	}
}

func TestUnmountBusy(t *testing.T) {
	for _, writable := range []bool{true, false} {
		t.Run(modeName(writable), func(t *testing.T) {
			h := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work", Writable: writable}), readyState("repo"))
			h.ctrl.set(func(c *fakeController) { c.unmountFail = "target is busy" })
			code, _, errOut := h.run("", "unmount", "repo", "--blip", "agent")
			if code != 1 || !strings.Contains(errOut, `could not unmount state "repo" from blip "agent": processes are still using /work`) {
				t.Fatalf("code %d err %q", code, errOut)
			}

			// The failed unmount must leave the original mount in the spec
			// and usable, not just report the error.
			b := h.blip("agent")
			if len(b.Spec.Mounts) != 1 || b.Spec.Mounts[0].State != "repo" ||
				b.Spec.Mounts[0].Path != "/work" || b.Spec.Mounts[0].Writable != writable {
				t.Fatalf("spec after busy unmount: %+v", b.Spec.Mounts)
			}
			if len(b.Status.Mounts) != 1 {
				t.Fatalf("status after busy unmount: %+v", b.Status.Mounts)
			}
			m := b.Status.Mounts[0]
			if m.Phase != v1alpha1.MountMounted || m.Path != "/work" || m.Writable != writable || m.Message != "" {
				t.Fatalf("mount after busy unmount: %+v", m)
			}

			// Once the holder stops, unmounting removes it again.
			h.ctrl.set(func(c *fakeController) { c.unmountFail = "" })
			code, out, errOut := h.run("", "unmount", "repo", "--blip", "agent")
			if code != 0 {
				t.Fatalf("retry code %d: %s", code, errOut)
			}
			mustContain(t, out, "state repo unmounted from blip agent")
			if b = h.blip("agent"); len(b.Spec.Mounts) != 0 || len(b.Status.Mounts) != 0 {
				t.Fatalf("mounts after retry: %+v %+v", b.Spec.Mounts, b.Status.Mounts)
			}
		})
	}
}

func TestUnmountFailedMountClearsState(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = "no space left on device" })
	code, _, errOut := h.run("", "mount", "repo", "--blip", "agent", "--path", "/work")
	if code != 1 || !strings.Contains(errOut, "no space left on device") {
		t.Fatalf("mount code %d err %q", code, errOut)
	}
	if b := h.blip("agent"); len(b.Status.Mounts) != 1 || b.Status.Mounts[0].Phase != v1alpha1.MountFailed {
		t.Fatalf("failed mount: %+v", b.Status.Mounts)
	}

	// Removing a mount that never attached drops its failed entry, so the
	// unmount completes instead of reporting the old attach error forever.
	h.ctrl.set(func(c *fakeController) { c.mountFail = "" })
	code, out, errOut := h.run("", "unmount", "repo", "--blip", "agent")
	if code != 0 {
		t.Fatalf("unmount code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo unmounted from blip agent")
	if b := h.blip("agent"); len(b.Spec.Mounts) != 0 || len(b.Status.Mounts) != 0 {
		t.Fatalf("mounts after unmount: %+v %+v", b.Spec.Mounts, b.Status.Mounts)
	}

	// The state can now be mounted again at another path.
	code, out, errOut = h.run("", "mount", "repo", "--blip", "agent", "--path", "/other")
	if code != 0 {
		t.Fatalf("remount code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip agent at /other")
	if b := h.blip("agent"); len(b.Spec.Mounts) != 1 || b.Spec.Mounts[0].Path != "/other" {
		t.Fatalf("remounted spec: %+v", b.Spec.Mounts)
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
	steps := []struct {
		apply *v1alpha1.BlipState
		args  []string
	}{
		{apply: repo},
		{args: []string{"mount", "repo", "--blip", "agent", "--path", "/work", "--write"}},
		{args: []string{"exec", "agent", "--", "sh", "-lc", "git clone https://example.com/repo /work/repo"}},
		{args: []string{"unmount", "repo", "--blip", "agent"}},
		{apply: worker},
		{args: []string{"run", "worker-1", "--image", "img", "-d", "--mount", "worker-1:/work:rw", "-w", "/work/repo", "--", "sh", "-lc", "make fix"}},
		{args: []string{"wait", "worker-1"}},
	}
	for _, s := range steps {
		if s.apply != nil {
			h.apply(s.apply)
			continue
		}
		if code, _, errOut := h.run("", s.args...); code != 0 {
			t.Fatalf("%v: code %d: %s", s.args, code, errOut)
		}
	}

	// Collect the worker's changes: the worker has its state mounted at
	// /work, so /work/repo is the repository in it.
	dst := filepath.Join(t.TempDir(), "dst")
	gitInit(t, dst)
	commit := gitRepo(t, filepath.Join(collectMountRoot, "worker-1", "repo"))
	h.self = "agent"
	t.Chdir(dst)
	if code, _, errOut := h.run("", "collect", "worker-1", "git:/work/repo:w1"); code != 0 {
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
	code, _, errOut := h.run("", "run", "x", "--pool", "nope", "--image", "img", "--", "true")
	if code == 0 {
		t.Fatal("run succeeded without a pool")
	}
	mustContain(t, errOut, `pool "nope" not found`)
	code, _, errOut = h.run("", "run", "x", "--state", "home", "--", "true")
	if code == 0 {
		t.Fatal("run succeeded without a state")
	}
	mustContain(t, errOut, `state "home" not found`, "kubectl blip create blipstate")
}
