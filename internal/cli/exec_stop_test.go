package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/wire"
)

// ackThenError acknowledges an exec open and then ends the stream with err.
// It models the pod-exec bridge dying before the guest can deliver TExited,
// as happens when the VM shuts down while the client is backpressured.
type ackThenError struct {
	frame []byte
	err   error
}

func (c *ackThenError) Read(p []byte) (int, error) {
	if len(c.frame) > 0 {
		n := copy(p, c.frame)
		c.frame = c.frame[n:]
		return n, nil
	}
	return 0, c.err
}

func (c *ackThenError) Write(p []byte) (int, error) { return len(p), nil }
func (c *ackThenError) Close() error                { return nil }

func openedFrame(t *testing.T, id string) []byte {
	t.Helper()
	var buf bytes.Buffer
	conn := wire.NewConn(writeBuffer{&buf})
	if err := conn.WriteJSON(wire.TOpened, wire.Opened{Session: id}); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

type writeBuffer struct{ *bytes.Buffer }

func (w writeBuffer) Read([]byte) (int, error) { return 0, io.EOF }

// A stop that tears down the pod-exec bridge before the guest can send the exit
// status must look like a normal stopped command (143 and the stopped
// progress line), not like a local session failure. Backpressured output makes
// the guest miss its chance to deliver TExited.
func TestExecStreamLostDuringStopReportsStopped(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"disconnected", io.EOF},
		{"pod-exec-137", errors.New("pod pod-agent exec: command terminated with exit code 137")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("agent")
			b.Spec.Stop = true
			h := newHarness(t, b)
			frame := openedFrame(t, "s1")
			h.connect = func(context.Context, string, string) (io.ReadWriteCloser, error) {
				return &ackThenError{frame: append([]byte(nil), frame...), err: tc.err}, nil
			}

			var errOut bytes.Buffer
			a := h.app(strings.NewReader(""), io.Discard, &errOut)
			err := a.execSession(context.Background(), "agent", "pod-agent", []string{"yes"}, &execFlags{}, false)
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != 143 {
				t.Fatalf("stream error = %v, want exit status 143", err)
			}
			if !strings.Contains(errOut.String(), "blip agent stopped") {
				t.Fatalf("progress output %q does not report the stop", errOut.String())
			}
		})
	}
}

// The same bridge failure without a user stop must stay a real error instead
// of being reported as a clean stop.
func TestExecStreamLostWithoutStopKeepsError(t *testing.T) {
	b := runningBlip("agent")
	h := newHarness(t, b)
	frame := openedFrame(t, "s1")
	h.connect = func(context.Context, string, string) (io.ReadWriteCloser, error) {
		return &ackThenError{
			frame: append([]byte(nil), frame...),
			err:   errors.New("pod pod-agent exec: command terminated with exit code 137"),
		}, nil
	}

	var errOut bytes.Buffer
	a := h.app(strings.NewReader(""), io.Discard, &errOut)
	err := a.execSession(context.Background(), "agent", "pod-agent", []string{"yes"}, &execFlags{}, false)
	var exit *ExitError
	if errors.As(err, &exit) {
		t.Fatalf("stream error = %v, want the raw transport failure", err)
	}
	if err == nil || !strings.Contains(err.Error(), "command terminated with exit code 137") {
		t.Fatalf("stream error = %v, want the pod-exec failure", err)
	}
	if strings.Contains(errOut.String(), "stopped") {
		t.Fatalf("progress output %q reports an unrequested stop", errOut.String())
	}
}
