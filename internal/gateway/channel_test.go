package gateway

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// captureEOFConn records the Open frame and then behaves like a transport
// that failed after delivering it but before the guest answered.
type captureEOFConn struct {
	opens chan<- wire.Open
}

func (captureEOFConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c captureEOFConn) Write(p []byte) (int, error) {
	if len(p) >= 5 && wire.Type(p[0]) == wire.TOpen {
		n := int(binary.BigEndian.Uint32(p[1:5]))
		if 5+n <= len(p) {
			var o wire.Open
			if wire.Decode(p[5:5+n], &o) == nil {
				select {
				case c.opens <- o:
				default:
				}
			}
		}
	}
	return len(p), nil
}

func (captureEOFConn) Close() error { return nil }

// The recreate-and-retry must reuse the OpenID assigned to the logical open,
// or the guest cannot tell the retry from a second, independent command.
func TestSessionOpenRetryReusesOpenID(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	captured := make(chan wire.Open, 1)
	orig := e.srv.Sessions.Connect
	var first atomic.Bool
	e.srv.Sessions.Connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		if first.CompareAndSwap(false, true) {
			return captureEOFConn{opens: captured}, nil
		}
		return orig(ctx, namespace, pod)
	}

	c, err := e.dial("", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.Run("echo hi"); err != nil {
		t.Fatal(err)
	}

	var failed wire.Open
	select {
	case failed = <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("the failed attempt did not send an open")
	}
	opens := e.guest.Opens()
	if len(opens) != 1 {
		t.Fatalf("guest opened %d sessions, want 1", len(opens))
	}
	got := opens[0].Open
	if failed.OpenID == "" || got.OpenID != failed.OpenID {
		t.Fatalf("retry OpenID = %q, first attempt = %q; want the same non-empty ID", got.OpenID, failed.OpenID)
	}
	if got.Mode != wire.OpenExec || got.Argv[0] != "/bin/sh" {
		t.Fatalf("retry open = %+v", got)
	}
}

// A guest that ignores HUP must still be killed: the gateway has to wait out
// the grace period and send KILL before it closes the transport.
func TestHangupSessionKillsAfterGrace(t *testing.T) {
	oldGrace := hangupGrace
	hangupGrace = 10 * time.Millisecond
	t.Cleanup(func() { hangupGrace = oldGrace })

	events := make(chan string, 8)
	guest := &fakeguest.Guest{}
	guest.Run = func(s *fakeguest.Session) wire.Exit {
		// Deliberately ignore HUP, like a shell that inherited SIG_IGN.
		for ev := range s.Events {
			switch {
			case ev.Signal != "":
				events <- "signal:" + ev.Signal
			case ev.Disconnected:
				events <- "disconnect"
				return wire.Exit{}
			}
		}
		return wire.Exit{}
	}
	client := &session.Client{Connect: guest.Connect}
	sess, err := client.Open(context.Background(), ns, "pod-hangup", wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	start := time.Now()
	hangupSession(log, sess)
	if elapsed := time.Since(start); elapsed < hangupGrace {
		t.Fatalf("hangup returned after %v, before the grace period", elapsed)
	}

	var got []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			got = append(got, ev)
			if ev != "disconnect" {
				continue
			}
			want := []string{"signal:HUP", "signal:KILL", "disconnect"}
			if len(got) != len(want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("events = %v, want %v", got, want)
				}
			}
			return
		case <-timeout:
			t.Fatalf("events = %v, want HUP, KILL, then disconnect", got)
		}
	}
}
