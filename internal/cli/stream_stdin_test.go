package cli

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// errorReader models local stdin that fails for a reason other than io.EOF,
// such as a write-only descriptor (EBADF) or a hung-up terminal (EIO).
type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

// A stdin read failure means no more input can arrive, so the client must send
// stdin EOF. Without it the remote command waits on an open pipe forever.
func TestExecStdinReadErrorSendsEOF(t *testing.T) {
	guest := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		_, _ = io.Copy(io.Discard, s.Stdin)
		return wire.Exit{}
	}}
	client := &session.Client{Connect: guest.Connect}
	s, err := client.Open(context.Background(), "ns", "pod", wire.Open{
		Mode: wire.OpenExec, Argv: []string{"cat"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a := &app{env: &Env{In: errorReader{err: errors.New("bad file descriptor")}, Out: io.Discard, Err: io.Discard}}
	done := make(chan error, 1)
	go func() { done <- a.stream(context.Background(), s, streamOpts{blip: "agent", sendEOF: true}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream returned %v", err)
		}
	case <-time.After(3 * time.Second):
		s.Close()
		t.Fatal("exec hung because a non-EOF stdin read error did not send EOF")
	}
}
