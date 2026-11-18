package gateway

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"sync"
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

// trackingConn models session.podexec: the transport is pinned to ctx, so a
// cancelled context closes the underlying stream and rejects further frames.
// It records the signal frames the gateway writes and the eventual close, so
// a test can assert HUP, then KILL, then teardown on the same transport.
type trackingConn struct {
	io.ReadWriteCloser
	ctx       context.Context
	stop      func() bool
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	seq       []string
}

func newTrackingConn(ctx context.Context, inner io.ReadWriteCloser) *trackingConn {
	c := &trackingConn{ReadWriteCloser: inner, ctx: ctx, closed: make(chan struct{})}
	c.stop = context.AfterFunc(ctx, func() {
		c.markClosed()
		inner.Close()
	})
	return c
}

func (c *trackingConn) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) >= 5 && wire.Type(p[0]) == wire.TSignal {
		var sig wire.Signal
		if wire.Decode(p[5:], &sig) == nil {
			c.record("signal:" + sig.Name)
		}
	}
	return c.ReadWriteCloser.Write(p)
}

func (c *trackingConn) Close() error {
	c.stop()
	c.markClosed()
	c.record("close")
	return c.ReadWriteCloser.Close()
}

func (c *trackingConn) markClosed() { c.closeOnce.Do(func() { close(c.closed) }) }

func (c *trackingConn) record(ev string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq = append(c.seq, ev)
}

func (c *trackingConn) events() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seq...)
}

// trackGuestTransport wraps the environment's connector like session.podexec:
// the transport outlives neither its context nor an explicit close. The
// returned function reports the most recently opened transport.
func trackGuestTransport(e *env) func() *trackingConn {
	connect := e.srv.Sessions.Connect
	var mu sync.Mutex
	var conn *trackingConn
	e.srv.Sessions.Connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		inner, err := connect(ctx, namespace, pod)
		if err != nil {
			return nil, err
		}
		tc := newTrackingConn(ctx, inner)
		mu.Lock()
		conn = tc
		mu.Unlock()
		return tc, nil
	}
	return func() *trackingConn {
		mu.Lock()
		defer mu.Unlock()
		return conn
	}
}

// hupIgnoringGuest models a shell that inherited SIG_IGN: HUP and TERM are
// recorded but ignored, and only KILL ends the process.
func hupIgnoringGuest(events chan<- string, killed *atomic.Bool) func(*fakeguest.Session) wire.Exit {
	return func(g *fakeguest.Session) wire.Exit {
		g.Stdout("READY\n")
		for ev := range g.Events {
			switch {
			case ev.Disconnected:
				events <- "disconnect"
				return wire.Exit{}
			case ev.Signal == "HUP" || ev.Signal == "TERM":
				events <- "ignored:" + ev.Signal
			case ev.Signal == "KILL":
				killed.Store(true)
				events <- "killed"
				return wire.Exit{Signal: "KILL"}
			}
		}
		return wire.Exit{}
	}
}

// assertHungUpKilled checks that the guest ignored HUP, then received KILL,
// and that the same transport saw HUP, KILL and finally close.
func assertHungUpKilled(t *testing.T, events <-chan string, killed *atomic.Bool, conn func() *trackingConn) {
	t.Helper()
	for i, want := range []string{"ignored:HUP", "killed"} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("guest event %d = %q, want %q", i, got, want)
			}
		case <-time.After(sshTestTimeout):
			t.Fatalf("guest never received %q after the SSH connection dropped; got %v", want, drainEvents(events))
		}
	}
	if !killed.Load() {
		t.Fatal("guest process would still be running: KILL was never delivered")
	}
	tc := conn()
	if tc == nil {
		t.Fatal("guest transport was never opened")
	}
	select {
	case <-tc.closed:
	case <-time.After(sshTestTimeout):
		t.Fatal("guest transport was not closed after KILL")
	}
	if got, want := tc.events(), []string{"signal:HUP", "signal:KILL", "close"}; !equalEvents(got, want) {
		t.Fatalf("transport observed %v, want %v", got, want)
	}
}

// An abrupt SSH disconnect (the TCP connection dies, so the gateway never sees
// a channel close) must still deliver HUP, wait out the grace period, deliver
// KILL over a live transport and only then close that transport. A guest that
// ignores HUP (like a shell that inherited SIG_IGN) only dies on KILL.
func TestSSHConnectionDropKillsHUPIgnoringGuest(t *testing.T) {
	e := newEnv(t)
	conn := trackGuestTransport(e)
	events := make(chan string, 8)
	var killed atomic.Bool
	e.guest.Run = hupIgnoringGuest(events, &killed)

	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out := newSSHOutput()
	s.Stdout, s.Stderr = out, out
	done := make(chan error, 1)
	go func() { done <- s.Run(`trap '' HUP TERM; while :; do sleep 1; done`) }()
	out.waitFor(t, 0, "READY")

	// Drop the TCP connection under the SSH session: no channel close and no
	// SSH disconnect message reach the gateway.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	assertHungUpKilled(t, events, &killed, conn)

	select {
	case <-done:
	case <-time.After(sshTestTimeout):
		t.Fatal("SSH session did not return after the connection dropped")
	}
}

// The menu path opens guest shells through openState and relays them through
// relayInteractive, so an abrupt connection drop there needs the same
// independent transport and HUP/KILL sequence.
func TestSSHInteractiveConnectionDropKillsHUPIgnoringGuest(t *testing.T) {
	e := newEnv(t)
	conn := trackGuestTransport(e)
	events := make(chan string, 8)
	var killed atomic.Bool
	e.guest.Run = hupIgnoringGuest(events, &killed)

	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	s.create(t, e, "drop")
	s.output.waitFor(t, 0, "READY")

	if err := s.client.Close(); err != nil {
		t.Fatal(err)
	}
	assertHungUpKilled(t, events, &killed, conn)
}

func drainEvents(ch <-chan string) []string {
	var got []string
	for {
		select {
		case ev := <-ch:
			got = append(got, ev)
		default:
			return got
		}
	}
}

func equalEvents(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
