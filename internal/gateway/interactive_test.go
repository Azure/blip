package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

const (
	sshTestTimeout = 5 * time.Second
	menuLogoLine   = "| |__ | (_)_ __"
)

// SSH copies stdout and stderr on separate goroutines. Keep both writes and
// assertions synchronized, and wake waiters when a new render arrives.
type sshOutput struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
}

func newSSHOutput() *sshOutput {
	return &sshOutput{changed: make(chan struct{}, 1)}
}

func (o *sshOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	n, err := o.buf.Write(p)
	o.mu.Unlock()
	select {
	case o.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (o *sshOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *sshOutput) mark() int { return len(o.String()) }

func (o *sshOutput) waitFor(t *testing.T, from int, text string) {
	t.Helper()
	timer := time.NewTimer(sshTestTimeout)
	defer timer.Stop()
	for {
		if strings.Contains(ansi.Strip(o.String()[from:]), text) {
			return
		}
		select {
		case <-o.changed:
		case <-timer.C:
			t.Fatalf("SSH output did not contain %q:\n%s", text, ansi.Strip(o.String()[from:]))
		}
	}
}

type interactiveSSH struct {
	client *ssh.Client
	*ssh.Session
	input  io.WriteCloser
	output *sshOutput
	done   <-chan error
}

func startInteractiveSSH(t *testing.T, e *env, user string) *interactiveSSH {
	t.Helper()
	return startInteractiveSSHSize(t, e, user, 40, 100)
}

func startInteractiveSSHSize(t *testing.T, e *env, user string, rows, cols int) *interactiveSSH {
	t.Helper()
	c, err := e.dial(user, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	input, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output := newSSHOutput()
	s.Stdout, s.Stderr = output, output
	if err := s.Setenv("LANG", "C.UTF-8"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- s.Shell() }()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("start interactive shell: %v\n%s", err, output.String())
		}
	case <-time.After(sshTestTimeout):
		t.Fatalf("interactive shell did not start:\n%s", output.String())
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	return &interactiveSSH{client: c, Session: s, input: input, output: output, done: done}
}

func (s *interactiveSSH) typeKeys(t *testing.T, text string) {
	t.Helper()
	if _, err := io.WriteString(s.input, text); err != nil {
		t.Fatalf("send SSH input %q: %v", text, err)
	}
}

func (s *interactiveSSH) quit(t *testing.T) {
	t.Helper()
	s.typeKeys(t, "q")
	s.waitForExit(t)
}

func (s *interactiveSSH) waitForExit(t *testing.T) {
	t.Helper()
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatalf("menu quit must exit SSH with status zero: %v\n%s", err, ansi.Strip(s.output.String()))
		}
	case <-time.After(sshTestTimeout):
		t.Fatalf("SSH did not exit after menu quit:\n%s", ansi.Strip(s.output.String()))
	}
}

func (s *interactiveSSH) create(t *testing.T, e *env, name string) {
	t.Helper()
	mark := s.output.mark()
	s.typeKeys(t, "n")
	s.output.waitFor(t, mark, "Name:")
	assertNoSandboxes(t, e)
	s.typeKeys(t, name+"\r")
}

func sandboxResources(t *testing.T, e *env) ([]v1alpha1.BlipState, []v1alpha1.Blip) {
	t.Helper()
	var states v1alpha1.BlipStateList
	if err := e.kube.List(context.Background(), &states, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	var blips v1alpha1.BlipList
	if err := e.kube.List(context.Background(), &blips, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	return states.Items, blips.Items
}

func assertNoSandboxes(t *testing.T, e *env) {
	t.Helper()
	states, blips := sandboxResources(t, e)
	if len(states) != 0 || len(blips) != 0 || len(e.guest.Opens()) != 0 {
		t.Fatalf("viewing the menu allocated resources: states=%d blips=%d guest sessions=%d", len(states), len(blips), len(e.guest.Opens()))
	}
}

func TestSSHInteractiveEmptyMenuDoesNotAllocate(t *testing.T) {
	e := newEnv(t)
	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	s.output.waitFor(t, 0, "No blips yet.")
	assertNoSandboxes(t, e)
	// An empty selection must not implicitly create the SSH user's sandbox.
	s.typeKeys(t, "\r")
	s.quit(t)
	assertNoSandboxes(t, e)
}

func TestSSHInteractiveMenuUsesCRLF(t *testing.T) {
	e := newEnv(t)
	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	out := ansi.Strip(s.output.String())
	if bare := strings.ReplaceAll(out, "\r\n", ""); strings.Contains(bare, "\n") {
		t.Fatalf("menu output contains a bare LF, which stair-steps in a raw SSH terminal:\n%q", out)
	}
	s.quit(t)
}

func TestSSHInteractiveZeroSizePTYMenuUsable(t *testing.T) {
	e := newEnv(t)
	s := startInteractiveSSHSize(t, e, "dev", 0, 0)
	s.output.waitFor(t, 0, menuLogoLine)
	s.output.waitFor(t, 0, "No blips yet.")
	mark := s.output.mark()
	s.typeKeys(t, "n")
	s.output.waitFor(t, mark, "Name:")
	assertNoSandboxes(t, e)
	mark = s.output.mark()
	s.typeKeys(t, "\x1b")
	s.output.waitFor(t, mark, "No blips yet.")
	s.quit(t)
	assertNoSandboxes(t, e)
}

func TestSSHInteractiveQuitDrainsDecoder(t *testing.T) {
	for _, tt := range []struct {
		name, keys string
	}{
		{name: "burst", keys: "q" + strings.Repeat("x", 64)},
		{name: "partial escape", keys: "q\x1b["},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			s := startInteractiveSSH(t, e, "dev")
			s.output.waitFor(t, 0, menuLogoLine)
			catalog := e.srv.Catalog
			catalog.mu.Lock()
			before := len(catalog.subs["alice"])
			catalog.mu.Unlock()
			if before != 1 {
				t.Fatalf("menu subscriptions = %d, want 1", before)
			}
			// The decoder may be blocked forwarding a second event or reading
			// the rest of an escape sequence when the first key quits the menu.
			s.typeKeys(t, tt.keys)
			s.waitForExit(t)
			catalog.mu.Lock()
			after := len(catalog.subs["alice"])
			catalog.mu.Unlock()
			if after != 0 {
				t.Fatalf("menu subscriptions after SSH exit = %d, want 0", after)
			}
			assertNoSandboxes(t, e)
		})
	}
}

func TestSSHInteractiveCreateReturnAndReconnect(t *testing.T) {
	e := newEnv(t)
	inputs := []string{"echo first-guest nq\n", "printf second-guest\\n\n"}
	type readResult struct {
		round int
		text  string
		err   error
	}
	read := make(chan readResult, len(inputs))
	release := make([]chan struct{}, len(inputs))
	for i := range release {
		release[i] = make(chan struct{}, 1)
		t.Cleanup(func() { close(release[i]) })
	}
	var round atomic.Int32
	e.guest.Run = func(g *fakeguest.Session) wire.Exit {
		i := int(round.Add(1)) - 1
		if i >= len(inputs) {
			return wire.Exit{Code: 99}
		}
		g.Stdout(fmt.Sprintf("guest-%d ready\r\n", i+1))
		buf := make([]byte, len(inputs[i]))
		n, err := io.ReadFull(g.Stdin, buf)
		read <- readResult{round: i, text: string(buf[:n]), err: err}
		<-release[i]
		return wire.Exit{Code: 7 + i}
	}
	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	s.output.waitFor(t, 0, "No blips yet.")
	assertNoSandboxes(t, e)

	const stateName = "alice.created"
	for i, input := range inputs {
		mark := s.output.mark()
		if i == 0 {
			s.create(t, e, "created")
		} else {
			// Send exactly one Enter. A reader left blocked in the previous
			// guest must not consume this menu input.
			s.typeKeys(t, "\r")
		}
		s.output.waitFor(t, mark, fmt.Sprintf("guest-%d ready", i+1))
		states, blips := sandboxResources(t, e)
		if len(states) != 1 || len(blips) != 1 {
			t.Fatalf("round %d: states=%d blips=%d, want one of each", i+1, len(states), len(blips))
		}
		if states[0].Name != stateName || states[0].Labels[ownerLabel] != "alice" ||
			states[0].Spec.Image != e.srv.Image || states[0].Spec.CopyFrom != "" || blips[0].Spec.State != stateName {
			t.Fatalf("round %d: state=%+v blip=%+v", i+1, states[0], blips[0])
		}
		// Likewise, a reader left in the menu must not consume guest bytes.
		s.typeKeys(t, input)
		select {
		case got := <-read:
			if got.round != i || got.text != input || got.err != nil {
				t.Fatalf("guest input = %+v, want round %d input %q", got, i, input)
			}
		case <-time.After(sshTestTimeout):
			t.Fatalf("guest %d did not receive its input:\n%s", i+1, ansi.Strip(s.output.String()))
		}
		mark = s.output.mark()
		release[i] <- struct{}{}
		s.output.waitFor(t, mark, menuLogoLine)
		s.output.waitFor(t, mark, strings.TrimPrefix(stateName, "alice."))
	}

	s.quit(t)
	opens := e.guest.Opens()
	if len(opens) != len(inputs) {
		t.Fatalf("guest opens = %d, want %d", len(opens), len(inputs))
	}
	for _, o := range opens {
		if o.Pod != "pod-"+stateName || !o.Open.TTY || o.Open.Argv != nil || o.Open.Rows != 40 || o.Open.Cols != 100 ||
			!slices.Contains(o.Open.Env, "TERM=xterm-256color") || !slices.Contains(o.Open.Env, "LANG=C.UTF-8") {
			t.Errorf("interactive guest open = %+v", o)
		}
	}
}

func TestSSHInteractiveResizeAndHangup(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			var objects []client.Object
			if existing {
				objects = append(objects, &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{
					Name: "alice.saved", Namespace: ns, UID: "saved-uid", Labels: map[string]string{ownerLabel: "alice"},
				}})
			}
			e := newEnv(t, objects...)
			resizes := make(chan wire.Resize, 4)
			hangup := make(chan fakeguest.Event, 1)
			e.guest.Run = func(g *fakeguest.Session) wire.Exit {
				g.Stdout("guest ready\r\n")
				for {
					ev := g.NextEvent()
					if ev.Resize != nil {
						resizes <- *ev.Resize
					}
					if ev.Signal == "HUP" || ev.Disconnected {
						hangup <- ev
						return wire.Exit{Code: 129}
					}
				}
			}
			s := startInteractiveSSH(t, e, "unrelated")
			s.output.waitFor(t, 0, menuLogoLine)
			if existing {
				s.output.waitFor(t, 0, "saved")
			}
			// Request an acknowledgement so the resize is handled before the
			// menu's connect action, without depending on goroutine timing.
			ok, err := s.SendRequest("window-change", true, ssh.Marshal(struct {
				Cols, Rows, Width, Height uint32
			}{Cols: 123, Rows: 51}))
			if err != nil || !ok {
				t.Fatalf("resize menu: accepted=%v err=%v", ok, err)
			}
			if existing {
				s.typeKeys(t, "\r")
			} else {
				s.create(t, e, "resized")
			}
			s.output.waitFor(t, 0, "guest ready")
			opens := e.guest.Opens()
			if len(opens) != 1 {
				t.Fatalf("guest opens = %d, want 1", len(opens))
			}
			o := opens[0]
			if !o.Open.TTY || o.Open.Rows != 51 || o.Open.Cols != 123 || o.Open.Argv != nil {
				t.Fatalf("guest did not inherit menu dimensions: %+v", o)
			}
			if existing && o.Pod != "pod-alice.saved" {
				t.Fatalf("selected sandbox reached %q, want pod-alice.saved", o.Pod)
			}
			if err := s.WindowChange(62, 141); err != nil {
				t.Fatal(err)
			}
			select {
			case size := <-resizes:
				if size.Rows != 62 || size.Cols != 141 {
					t.Fatalf("live resize = %+v, want 62 rows and 141 columns", size)
				}
			case <-time.After(sshTestTimeout):
				t.Fatal("guest did not receive live resize")
			}
			if err := s.client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case ev := <-hangup:
				if ev.Signal != "HUP" {
					t.Fatalf("SSH disconnect must send HUP before closing the guest: %+v", ev)
				}
			case <-time.After(sshTestTimeout):
				t.Fatal("guest did not receive HUP on SSH disconnect")
			}
		})
	}
}

// Match the real connector's cancellation behavior, including rejecting a
// write immediately after cancellation rather than racing an AfterFunc close.
type contextGuestConn struct {
	io.ReadWriteCloser
	ctx  context.Context
	stop func() bool
}

func (c *contextGuestConn) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.ReadWriteCloser.Write(p)
}

func (c *contextGuestConn) Close() error {
	c.stop()
	return c.ReadWriteCloser.Close()
}

func TestSSHInteractiveChannelCloseSendsHUP(t *testing.T) {
	e := newEnv(t)
	connect := e.srv.Sessions.Connect
	e.srv.Sessions.Connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		conn, err := connect(ctx, namespace, pod)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		return &contextGuestConn{ReadWriteCloser: conn, ctx: ctx, stop: stop}, nil
	}
	hangup := make(chan fakeguest.Event, 1)
	e.guest.Run = func(g *fakeguest.Session) wire.Exit {
		if g.Open.Argv != nil {
			g.Stdout("connection survived\n")
			return wire.Exit{}
		}
		g.Stdout("guest ready\r\n")
		for {
			ev := g.NextEvent()
			if ev.Signal == "HUP" || ev.Disconnected {
				hangup <- ev
				return wire.Exit{Code: 129}
			}
		}
	}
	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	s.create(t, e, "channel")
	s.output.waitFor(t, 0, "guest ready")
	// Close only the channel: canceling its context before HUP would close
	// the connector and detach the guest instead of hanging up its shell.
	if err := s.Session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-hangup:
		if ev.Signal != "HUP" {
			t.Fatalf("channel close disconnected guest before HUP: %+v", ev)
		}
	case <-time.After(sshTestTimeout):
		t.Fatal("guest did not receive HUP after channel close")
	}
	done := make(chan error, 1)
	go func() {
		next, err := s.client.NewSession()
		if err != nil {
			done <- err
			return
		}
		defer next.Close()
		out, err := next.CombinedOutput("true")
		if err == nil && string(out) != "connection survived\n" {
			err = fmt.Errorf("second session output = %q", out)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SSH connection did not survive channel close: %v", err)
		}
	case <-time.After(sshTestTimeout):
		t.Fatal("second SSH channel did not complete")
	}
}

type stalledResizeConn struct {
	io.ReadWriteCloser
	blocked chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *stalledResizeConn) Write(p []byte) (int, error) {
	if len(p) >= 5 && wire.Type(p[0]) == wire.TResize {
		select {
		case c.blocked <- struct{}{}:
		default:
		}
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.ReadWriteCloser.Write(p)
}

func (c *stalledResizeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.ReadWriteCloser.Close()
}

func TestSSHInteractiveStalledResizeDoesNotBlockChannelClose(t *testing.T) {
	e := newEnv(t)
	blocked, closed := make(chan struct{}, 1), make(chan struct{})
	connect := e.srv.Sessions.Connect
	e.srv.Sessions.Connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		conn, err := connect(ctx, namespace, pod)
		if err != nil {
			return nil, err
		}
		wrapped := &stalledResizeConn{ReadWriteCloser: conn, blocked: blocked, closed: closed}
		t.Cleanup(func() { wrapped.Close() })
		return wrapped, nil
	}
	e.guest.Run = func(g *fakeguest.Session) wire.Exit {
		g.Stdout("guest ready\r\n")
		for !g.NextEvent().Disconnected {
		}
		return wire.Exit{}
	}
	s := startInteractiveSSH(t, e, "dev")
	s.output.waitFor(t, 0, menuLogoLine)
	s.create(t, e, "stalled")
	s.output.waitFor(t, 0, "guest ready")
	if err := s.WindowChange(51, 123); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(sshTestTimeout):
		t.Fatal("guest resize did not reach the stalled transport")
	}
	if err := s.Session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(sshTestTimeout):
		t.Fatal("stalled guest resize prevented channel teardown from closing the transport")
	}
}
