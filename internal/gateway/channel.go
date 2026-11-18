package gateway

import (
	"context"
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

// sftpCommand runs the image's sftp-server.
var sftpCommand = []string{"/bin/sh", "-c", `for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do [ -x "$p" ] && exec "$p"; done; exec sftp-server`}

type sessionChannel struct {
	srv     *Server
	owner   string
	sandbox string
	name    string // short sandbox name, for messages
	ch      ssh.Channel

	mu      sync.Mutex
	open    wire.Open
	sess    *session.Session
	started bool
	exited  bool
	closing bool
	resized chan struct{} // coalesced menu window changes
}

func (s *Server) handleSession(ctx context.Context, owner, sandbox, name string, nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &sessionChannel{srv: s, owner: owner, sandbox: sandbox, name: name, ch: ch, open: wire.Open{Mode: wire.OpenExec}, resized: make(chan struct{}, 1)}
	for req := range reqs {
		c.handle(ctx, req)
	}
	c.mu.Lock()
	c.closing = true
	sess, exited := c.sess, c.exited
	c.mu.Unlock()
	if sess != nil && !exited {
		hangupSession(sess)
	}
	ch.Close()
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

// open ensures the sandbox is running and opens a guest session. The
// sandbox can start stopping after ensureSandbox observed it Running but
// before pod exec reaches it, often when a user reconnects during the idle
// save window. ErrUnreachable means no process reported an outcome, so
// recreate the sandbox and try once more.
func (c *sessionChannel) openSession(ctx context.Context, o wire.Open, nl string) (*session.Session, error) {
	for attempt := 0; ; attempt++ {
		startCtx, cancel := context.WithTimeout(ctx, startTimeout)
		pod, err := c.start(startCtx, nl, o.TTY)
		cancel()
		if err != nil {
			return nil, err
		}
		sess, err := c.srv.Sessions.Open(ctx, c.srv.Namespace, pod, o)
		if err == nil || attempt > 0 || !errors.Is(err, session.ErrUnreachable) {
			return sess, err
		}
		c.srv.Log.Info("sandbox stopped while opening; recreating", "pod", pod)
	}
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
	defer sess.Close()
	c.mu.Lock()
	if c.closing || ctx.Err() != nil {
		c.mu.Unlock()
		hangupSession(sess)
		return
	}
	c.sess = sess
	c.mu.Unlock()
	stopResize := c.resizeGuest(ctx, sess, o)
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
	c.mu.Lock()
	c.exited = true
	c.mu.Unlock()
	if err != nil {
		fmt.Fprintf(c.ch.Stderr(), "blip: %v%s", err, nl)
		exit = &wire.Exit{Code: 255}
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

// A stalled guest must not prevent SSH channel teardown. Give HUP a chance
// before closing its transport (closing alone only detaches the process).
func hangupSession(sess *session.Session) {
	timer := time.AfterFunc(time.Second, func() { sess.Close() })
	sess.Signal("HUP")
	timer.Stop()
	sess.Close()
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
	var st *session.Stream
	var err error
	for attempt := 0; ; attempt++ {
		startCtx, cancel := context.WithTimeout(ctx, startTimeout)
		pod, aerr := s.ensureSandbox(startCtx, owner, sandbox)
		cancel()
		if aerr != nil {
			err = aerr
			break
		}
		st, err = s.Sessions.Dial(ctx, s.Namespace, pod, p.Host, int(p.Port))
		if err == nil || attempt > 0 || !errors.Is(err, session.ErrUnreachable) {
			break
		}
		log.Info("sandbox stopped while dialing; recreating", "pod", pod)
	}
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
