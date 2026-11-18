package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// startTimeout bounds waiting for a sandbox to run.
const startTimeout = 10 * time.Minute

// retryUnreachable starts a sandbox and connects to its guest. ErrUnreachable
// means no process observed the open, so the sandbox is recreated and the open
// retried once. start receives a context bounded by startTimeout; open receives
// the running pod. On a retry, a non-nil onRetry sees the pod that was lost.
func retryUnreachable[T any](ctx context.Context, onRetry func(pod string), start func(context.Context) (string, error), open func(pod string) (T, error)) (T, error) {
	var zero T
	for attempt := 0; ; attempt++ {
		startCtx, cancel := context.WithTimeout(ctx, startTimeout)
		pod, err := start(startCtx)
		cancel()
		if err != nil {
			return zero, err
		}
		v, err := open(pod)
		if err == nil || attempt > 0 || !errors.Is(err, session.ErrUnreachable) {
			return v, err
		}
		if onRetry != nil {
			onRetry(pod)
		}
	}
}

// sftpCommand runs the image's sftp-server.
var sftpCommand = []string{"/bin/sh", "-c", `for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do [ -x "$p" ] && exec "$p"; done; exec sftp-server`}

type sessionChannel struct {
	srv     *Server
	owner   string
	sandbox string
	name    string // short sandbox name, for messages
	ch      ssh.Channel
	// connCtx ends with the SSH connection. adopt checks it so a guest opened
	// while the connection was going away is not used.
	connCtx context.Context

	// guestCtx owns the guest transport for this channel. It deliberately
	// ignores the SSH connection's cancellation: after an abrupt disconnect
	// the gateway still has to deliver HUP and then KILL over a live
	// transport. handleSession cancels it once teardown is complete.
	guestCtx context.Context

	mu      sync.Mutex
	open    wire.Open
	sess    *session.Session
	started bool
	exited  bool
	closing bool
	// hangupOnce makes the relay and the channel teardown agree on one
	// HUP/grace/KILL sequence for the channel's current guest session.
	hangupOnce sync.Once
	resized    chan struct{} // coalesced menu window changes
}

func (s *Server) handleSession(ctx context.Context, owner, sandbox, name string, nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The guest transport outlives the SSH connection, but only until this
	// hangup path has finished. context.WithoutCancel also keeps its values.
	guestCtx, guestCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer guestCancel()
	c := &sessionChannel{srv: s, owner: owner, sandbox: sandbox, name: name, ch: ch, connCtx: ctx, guestCtx: guestCtx, open: wire.Open{Mode: wire.OpenExec}, resized: make(chan struct{}, 1)}
	for req := range reqs {
		c.handle(ctx, req)
	}
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.hangup()
	ch.Close()
}

// hangup ends the channel's guest session when the SSH side went away before
// the guest exited. The relay and the channel teardown can both observe that
// loss; hangupOnce lets exactly one of them send HUP, wait out the grace
// period and send KILL while the transport is still open. A nil session (no
// guest opened yet, or already handed back to the menu) leaves the guard
// untouched so a later open can still use it.
func (c *sessionChannel) hangup() {
	c.mu.Lock()
	sess, exited := c.sess, c.exited
	c.mu.Unlock()
	if sess == nil || exited {
		return
	}
	c.hangupOnce.Do(func() { hangupSession(c.srv.Log, sess) })
}

func (c *sessionChannel) handle(ctx context.Context, req *ssh.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := false
	switch req.Type {
	case "env":
		var p struct{ Name, Value string }
		if ssh.Unmarshal(req.Payload, &p) == nil && !c.started {
			c.open.Env = append(c.open.Env, p.Name+"="+p.Value)
			ok = true
		}
	case "pty-req":
		var p struct {
			Term                    string
			Cols, Rows, Width, High uint32
			Modes                   string
		}
		if ssh.Unmarshal(req.Payload, &p) == nil && !c.started {
			c.open.TTY, c.open.Rows, c.open.Cols = true, uint16(p.Rows), uint16(p.Cols)
			if p.Term != "" {
				c.open.Env = append(c.open.Env, "TERM="+p.Term)
			}
			ok = true
		}
	case "window-change":
		var p struct{ Cols, Rows, Width, High uint32 }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			c.open.Rows, c.open.Cols = uint16(p.Rows), uint16(p.Cols)
			select {
			case c.resized <- struct{}{}:
			default:
			}
			ok = true
		}
	case "signal":
		var p struct{ Signal string }
		if ssh.Unmarshal(req.Payload, &p) == nil && c.sess != nil {
			c.sess.Signal(p.Signal)
			ok = true
		}
	case "shell", "exec", "subsystem":
		if c.started {
			break
		}
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if ssh.Unmarshal(req.Payload, &p) != nil {
				break
			}
			c.open.Argv = []string{"/bin/sh", "-c", p.Command}
		case "subsystem":
			var p struct{ Name string }
			if ssh.Unmarshal(req.Payload, &p) != nil || p.Name != "sftp" {
				break
			}
			c.open.Argv, c.open.TTY = sftpCommand, false
		}
		if req.Type != "shell" && c.open.Argv == nil {
			break
		}
		c.started = true
		if req.Type == "shell" && c.open.TTY {
			go c.runInteractive(ctx, req)
		} else {
			go c.run(ctx, req, c.open)
		}
		return
	}
	req.Reply(ok, nil)
}

type startResult struct {
	pod string
	err error
}

// start makes sure the sandbox is running. It tells the user only when that
// takes unusually long; warm starts print nothing about allocation.
func (c *sessionChannel) start(ctx context.Context, nl string, tty bool) (string, error) {
	if c.srv.StartNoticeDelay <= 0 {
		return c.srv.ensureSandbox(ctx, c.owner, c.sandbox)
	}
	done := make(chan startResult, 1)
	go func() {
		pod, err := c.srv.ensureSandbox(ctx, c.owner, c.sandbox)
		done <- startResult{pod, err}
	}()
	timer := time.NewTimer(c.srv.StartNoticeDelay)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.pod, r.err
	case <-timer.C:
		if tty {
			fmt.Fprintf(c.ch.Stderr(), "blip: still starting %q; the first connect can take a minute or two...%s", c.name, nl)
		}
		r := <-done
		return r.pod, r.err
	}
}

// newOpenID names one logical exec open. The gateway generates it once and
// reuses it across the recreate-and-retry loops, so a guest that already
// received the open can attach instead of starting the command twice.
func newOpenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// open ensures the sandbox is running and opens a guest session. The
// sandbox can start stopping after ensureSandbox observed it Running but
// before pod exec reaches it, often when a user reconnects during the idle
// save window. ErrUnreachable means no process reported an outcome, so
// recreate the sandbox and try once more.
//
// Starting the sandbox follows ctx, which ends with the SSH request, but the
// transport itself uses c.guestCtx so a hangup can still signal the guest
// after the SSH connection has disappeared.
func (c *sessionChannel) openSession(ctx context.Context, o wire.Open, nl string) (*session.Session, error) {
	if o.OpenID == "" {
		o.OpenID = newOpenID()
	}
	return retryUnreachable(ctx,
		func(pod string) { c.srv.Log.Info("sandbox stopped while opening; recreating", "pod", pod) },
		func(startCtx context.Context) (string, error) {
			return c.start(startCtx, nl, o.TTY)
		},
		func(pod string) (*session.Session, error) {
			return c.srv.Sessions.Open(c.guestCtx, c.srv.Namespace, pod, o)
		})
}

// adopt makes sess the channel's current guest session. It reports false when
// the SSH side is already gone; the caller must then hang up and close sess.
func (c *sessionChannel) adopt(sess *session.Session) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sess = sess
	return !c.closing && c.connCtx.Err() == nil
}

// run starts the guest session, answers req, and relays until the session
// exits.
func (c *sessionChannel) run(ctx context.Context, req *ssh.Request, o wire.Open) {
	defer c.ch.Close()
	nl := "\n"
	if o.TTY {
		nl = "\r\n"
	}
	sess, err := c.openSession(ctx, o, nl)
	if err != nil {
		fmt.Fprintf(c.ch.Stderr(), "blip: %v%s", err, nl)
		req.Reply(false, nil)
		return
	}
	if !c.adopt(sess) {
		c.hangup()
		sess.Close()
		return
	}
	stopResize := c.resizeGuest(ctx, sess, o)
	// Close only after the hangup path below has had a chance to signal the
	// guest. hangupSession closes the transport itself; Close is idempotent.
	defer func() {
		sess.Close()
		stopResize()
	}()
	req.Reply(true, nil)

	go func() {
		if _, err := io.Copy(sess, c.ch); err == nil {
			sess.CloseStdin()
		}
	}()
	exit, err := sess.Copy(c.ch, c.ch.Stderr(), func(m string) {
		fmt.Fprintf(c.ch.Stderr(), "blip: %s%s", m, nl)
	})
	if err != nil {
		// A write to the (now dead) SSH channel failed: the guest may still
		// be running, so HUP/KILL it over the independent transport before
		// this function closes that transport. ErrDisconnected instead means
		// the guest stream itself ended; there is nothing left to signal.
		if !errors.Is(err, session.ErrDisconnected) {
			c.hangup()
		}
		fmt.Fprintf(c.ch.Stderr(), "blip: %v%s", err, nl)
		exit = &wire.Exit{Code: 255}
	} else {
		// Only a real exit status means the guest is gone and teardown must
		// not signal it.
		c.mu.Lock()
		c.exited = true
		c.mu.Unlock()
	}
	if exit.Reason == wire.ReasonStopped {
		fmt.Fprintf(c.ch.Stderr(), "blip: %q stopped; reconnect to resume.%s", c.name, nl)
	}
	if exit.Signal != "" {
		c.ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Error      string
			Lang       string
		}{Signal: exit.Signal}))
	} else {
		c.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exit.Code)}))
	}
	c.ch.CloseWrite()
}

// Request handling must never block behind a guest's stdin/resize writes.
// Each terminal phase joins its worker before handing off the resize queue.
func (c *sessionChannel) forwardResizes(ctx context.Context, send func(rows, cols uint16)) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c.mu.Lock()
			rows, cols := c.open.Rows, c.open.Cols
			c.mu.Unlock()
			send(rows, cols)
			select {
			case <-ctx.Done():
				return
			case <-c.resized:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (c *sessionChannel) resizeGuest(ctx context.Context, sess *session.Session, opened wire.Open) func() {
	return c.forwardResizes(ctx, func(rows, cols uint16) {
		if rows != opened.Rows || cols != opened.Cols {
			sess.Resize(rows, cols)
			opened.Rows, opened.Cols = rows, cols
		}
	})
}

// hangupGrace is how long a hung-up guest gets to exit after HUP before the
// gateway kills it. Tests shorten it.
var hangupGrace = time.Second

// hangupSignalTimeout bounds one signal write. A transport blocked behind an
// earlier frame must not hold up teardown; Close unblocks the write.
var hangupSignalTimeout = time.Second

// hangupSession ends a guest session whose SSH client went away. Closing the
// transport alone only detaches the process, so ask the guest to exit and then
// force it: the guest starts sessions in their own process group and may
// inherit an ignored HUP/TERM disposition, which makes HUP advisory only.
// Close waits for the KILL frame unless the transport stopped draining.
func hangupSession(log *slog.Logger, sess *session.Session) {
	start := time.Now()
	if !signalSession(log, sess, "HUP", hangupGrace, "hangup: HUP") {
		sess.Close()
		return
	}
	// Let the guest use the rest of its grace period before escalating. A
	// shell that inherited SIG_IGN will still be alive here.
	if wait := hangupGrace - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
	signalSession(log, sess, "KILL", hangupSignalTimeout, "hangup: KILL")
	if err := sess.Close(); err != nil {
		log.Debug("hangup: close failed", "error", err)
	}
}

// signalSession writes one signal frame, giving up if the transport does not
// drain within timeout. It reports whether the write completed.
func signalSession(log *slog.Logger, sess *session.Session, name string, timeout time.Duration, what string) bool {
	done := make(chan error, 1)
	go func() { done <- sess.Signal(name) }()
	select {
	case err := <-done:
		if err != nil {
			log.Debug(what+" failed", "error", err)
		}
		return true
	case <-time.After(timeout):
		log.Debug(what + " write stalled")
		return false
	}
}

func (s *Server) handleDirectTCPIP(ctx context.Context, owner, sandbox string, nch ssh.NewChannel, log *slog.Logger) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
		nch.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
		return
	}
	st, err := retryUnreachable(ctx,
		func(pod string) { log.Info("sandbox stopped while dialing; recreating", "pod", pod) },
		func(startCtx context.Context) (string, error) {
			return s.ensureSandbox(startCtx, owner, sandbox)
		},
		func(pod string) (*session.Stream, error) {
			return s.Sessions.Dial(ctx, s.Namespace, pod, p.Host, int(p.Port))
		})
	if err != nil {
		log.Info("direct-tcpip failed", "host", p.Host, "port", p.Port, "error", err)
		nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer st.Close()
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	go func() {
		if _, err := io.Copy(st, ch); err == nil {
			st.CloseWrite()
		}
	}()
	io.Copy(ch, st)
	ch.CloseWrite()
}
