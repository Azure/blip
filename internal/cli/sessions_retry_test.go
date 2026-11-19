package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
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

// TestSessionsAttachRetriesTransientErrors covers the attach path that
// gather --follow uses: temporary VM lifecycle failures are retried until the
// session opens.
func TestSessionsAttachRetriesTransientErrors(t *testing.T) {
	shortenOpenRetry(t, 2*time.Second, time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
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

	a := h.app(strings.NewReader(""), io.Discard, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := a.openPrimary(ctx, "agent", "pod-agent")
	if err != nil {
		t.Fatalf("openPrimary: %v", err)
	}
	s.Close()
	if got := calls.Load(); got != 3 {
		t.Fatalf("connect calls = %d, want 3", got)
	}
	if opens := h.guest.Opens(); len(opens) != 1 || opens[0].Open.Mode != wire.OpenAttach || opens[0].Open.Session != wire.PrimarySession {
		t.Fatalf("opens = %+v", opens)
	}
}

func TestSessionsAttachRetryGivesUpWithLastError(t *testing.T) {
	shortenOpenRetry(t, 40*time.Millisecond, 5*time.Millisecond)
	h := newHarness(t, runningBlip("agent"))
	var attempts atomic.Int32
	last := ""
	h.connect = func(context.Context, string, string) (io.ReadWriteCloser, error) {
		last = fmt.Sprintf("pod pod-agent exec: attempt %d: OCI runtime exec failed: error executing setns process: exit status 1", attempts.Add(1))
		return nil, errors.New(last)
	}

	a := h.app(strings.NewReader(""), io.Discard, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := a.openPrimary(ctx, "agent", "pod-agent")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), last) {
		t.Fatalf("err %v does not contain the last error %q", err, last)
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
