package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// shortenOpenRetry keeps retry tests fast and restores the real bounds.
func shortenOpenRetry(t *testing.T, window, first time.Duration) {
	t.Helper()
	oldWindow, oldFirst := openRetryWindow, openRetryFirst
	openRetryWindow, openRetryFirst = window, first
	t.Cleanup(func() {
		openRetryWindow, openRetryFirst = oldWindow, oldFirst
	})
}

func TestAttachRetriesTransientVMErrors(t *testing.T) {
	shortenOpenRetry(t, 2*time.Second, time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
	h.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("replay")
		return wire.Exit{}
	}
	base := h.guest.Connect
	var calls atomic.Int32
	h.connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		// The first two attempts hit the vsock bridge while the VM is
		// still coming up or tearing down.
		if calls.Add(1) <= 2 {
			return nil, errors.New(`pod pod-agent exec: command terminated with exit code 1: blip-runtime: vsock handshake: read unix @->/run/blip/vsock/vsock.sock: read: connection reset by peer`)
		}
		return base(ctx, namespace, pod)
	}

	code, out, errOut := h.run("", "attach", "agent")
	if code != 0 || out != "replay" {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("connect calls = %d, want 3", got)
	}
	if opens := h.guest.Opens(); len(opens) != 1 || opens[0].Open.Mode != wire.OpenAttach {
		t.Fatalf("opens = %+v", opens)
	}
}

func TestAttachOnFinishedBlipNamesTheReason(t *testing.T) {
	b := runningBlip("agent")
	b.Status.Phase, b.Status.Pod = v1alpha1.BlipFailed, ""
	b.Status.Reason, b.Status.Message = "Stopped", "stopped before start"
	h := newHarness(t, b)

	code, _, errOut := h.run("", "attach", "agent")
	if code != 1 || !strings.Contains(errOut, `blip "agent" has finished (Failed: Stopped)`) {
		t.Fatalf("code %d err %q", code, errOut)
	}
	if opens := h.guest.Opens(); len(opens) != 0 {
		t.Fatalf("attach opened a session on a finished blip: %+v", opens)
	}
}

func TestAttachRetryGivesUpWithLastError(t *testing.T) {
	shortenOpenRetry(t, 40*time.Millisecond, 5*time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
	var mu sync.Mutex
	var attempts atomic.Int32
	last := ""
	h.connect = func(context.Context, string, string) (io.ReadWriteCloser, error) {
		mu.Lock()
		last = fmt.Sprintf("pod pod-agent exec: attempt %d: OCI runtime exec failed: error executing setns process: exit status 1", attempts.Add(1))
		mu.Unlock()
		return nil, errors.New(last)
	}

	start := time.Now()
	code, _, errOut := h.run("", "attach", "agent")
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("code %d err %q", code, errOut)
	}
	mu.Lock()
	want := last
	mu.Unlock()
	if !strings.Contains(errOut, want) {
		t.Fatalf("stderr %q does not contain the last error %q", errOut, want)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("retry took %v, want a bounded wait", elapsed)
	}
}

func TestExecIsNeverRetried(t *testing.T) {
	shortenOpenRetry(t, 2*time.Second, time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
	base := h.guest.Connect
	var calls atomic.Int32
	h.connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		// A retry here could run the command twice, so exec must return
		// the failure immediately.
		if calls.Add(1) == 1 {
			return nil, errors.New(`pod pod-agent exec: blip-runtime: dial unix /run/blip/vsock/vsock.sock: connect: no such file or directory`)
		}
		return base(ctx, namespace, pod)
	}

	code, _, errOut := h.run("", "exec", "agent", "--", "true")
	if code != 1 || !strings.Contains(errOut, "no such file or directory") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("exec retried: %d connection attempts", got)
	}
	if opens := h.guest.Opens(); len(opens) != 0 {
		t.Fatalf("exec opened a session despite the failure: %+v", opens)
	}
}

// TestSessionsRetriesTeardownAndExplainsStopping covers list opens during a
// VM teardown: a transient 137 is retried, and one that persists becomes a
// clear "is stopping" error instead of a raw pod exec failure.
func TestSessionsRetriesTeardownAndExplainsStopping(t *testing.T) {
	shortenOpenRetry(t, 40*time.Millisecond, 5*time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
	h.guest.Sessions = []wire.SessionInfo{{ID: "main", Argv: []string{"make"}}}
	base := h.guest.Connect
	var calls atomic.Int32
	h.connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New(`pod pod-agent exec: command terminated with exit code 137`)
		}
		return base(ctx, namespace, pod)
	}
	if code, out, errOut := h.run("", "sessions", "agent"); code != 0 || !strings.Contains(out, "main") {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}

	// The same failure every time: after the bounded retry the user gets a
	// stopping explanation, and the underlying error is still visible.
	calls.Store(0)
	h.connect = func(context.Context, string, string) (io.ReadWriteCloser, error) {
		calls.Add(1)
		return nil, errors.New(`pod pod-agent exec: command terminated with exit code 137`)
	}
	code, _, errOut := h.run("", "sessions", "agent")
	if code != 1 || !strings.Contains(errOut, `blip "agent" is stopping`) || !strings.Contains(errOut, "exit code 137") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	if calls.Load() < 2 {
		t.Fatalf("sessions did not retry: %d calls", calls.Load())
	}
}

// TestOpenRetryRecognizesTransientErrors pins the error classification: the
// raw pod exec failures seen around VM startup and teardown are retried, while
// a definitive guest answer is not.
func TestOpenRetryRecognizesTransientErrors(t *testing.T) {
	for _, msg := range []string{
		`pod p exec: ... read: connection reset by peer`,
		`pod p exec: blip-runtime: dial unix /run/blip/vsock/vsock.sock: connect: no such file or directory`,
		`open session: unexpected EOF`,
		`open session: blip has finished`,
		`pod p exec: OCI runtime exec failed: ... error executing setns process: exit status 1`,
		`pod p exec: command terminated with exit code 137`,
	} {
		if !transientOpenError(errors.New(msg)) {
			t.Errorf("not transient: %q", msg)
		}
	}
	for _, msg := range []string{
		`no session "typo"`,
		`blip "agent" has stopped and is saving`,
		`permission denied`,
	} {
		if transientOpenError(errors.New(msg)) {
			t.Errorf("unexpectedly transient: %q", msg)
		}
	}
	if !transientOpenError(fmt.Errorf("x: %w", session.ErrUnreachable)) {
		t.Error("ErrUnreachable is not transient")
	}
}
