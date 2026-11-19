package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// signalGrace bounds how long a forwarded termination signal may go
// unacknowledged by the guest. A command that ignores the signal (an
// interactive shell ignores SIGTERM) would otherwise leave the client alive
// forever, so a supervisor could only SIGKILL it and skip terminal restore.
const signalGrace = 2 * time.Second

// terminal returns stdin as a terminal file, or nil.
func (a *app) terminal() *os.File {
	f, ok := a.env.In.(*os.File)
	if !a.env.Terminal || !ok || !term.IsTerminal(int(f.Fd())) {
		return nil
	}
	return f
}

func (a *app) termSize() (rows, cols uint16) {
	if f := a.terminal(); f != nil {
		if c, r, err := term.GetSize(int(f.Fd())); err == nil && r > 0 && c > 0 {
			return uint16(r), uint16(c)
		}
	}
	return 0, 0
}

// ttyOpen fills the terminal fields of an exec Open.
func (a *app) ttyOpen(o *wire.Open, tty bool) {
	if !tty {
		return
	}
	o.TTY = true
	o.Rows, o.Cols = a.termSize()
	if t := os.Getenv("TERM"); t != "" && a.terminal() != nil {
		o.Env = append(o.Env, "TERM="+t)
	}
}

type streamOpts struct {
	blip string
	// sendEOF forwards the end of local stdin to the session.
	sendEOF bool
}

// stream connects the local terminal or stdio to s until the session exits.
// It returns an ExitError for nonzero exits.
func (a *app) stream(ctx context.Context, s *session.Session, opts streamOpts) error {
	defer s.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tty := s.Opened.TTY
	f := a.terminal()
	if tty && f != nil {
		old, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(f.Fd()), old)
		if rows, cols := a.termSize(); rows > 0 {
			s.Resize(rows, cols)
		}
		go a.forwardResize(ctx, s)
	}
	// Forward termination signals in every mode, including a TTY session. A
	// TTY client makes the terminal raw, so its process no longer dies from
	// SIGTERM/SIGHUP by default and would leave both the remote command and
	// the local terminal behind. Interactive Ctrl-C still arrives as a stdin
	// byte in raw mode and is delivered by the guest's terminal.
	detached := make(chan string, 1)
	if tty || a.env.Terminal {
		go forwardSignals(ctx, s, detached)
	}

	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := a.env.In.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				// No more input can arrive, whatever ended the read (EOF,
				// EBADF, EIO). Leaving stdin open would let a command that
				// waits for input hang forever.
				if opts.sendEOF {
					s.CloseStdin()
				}
				return
			}
		}
	}()

	exit, err := s.Copy(a.env.Out, a.env.Err, func(m string) { a.progress("blip: %s", m) })
	if err != nil {
		if name, ok := detachedSignal(detached); ok {
			// The forwarded signal was not acknowledged within the grace
			// period, so the stream detached and closed the transport. The
			// command may still be running in the guest; a detached exec
			// command is terminated by the guest. Report the signal the
			// caller sent rather than a generic lost connection.
			code := 1
			if n := unix.SignalNum("SIG" + strings.TrimPrefix(name, "SIG")); n != 0 {
				code = 128 + int(n)
			}
			exit = &wire.Exit{Code: code, Signal: strings.TrimPrefix(name, "SIG")}
		} else if !a.stopped(ctx, opts.blip) {
			return fmt.Errorf("session %s: %w", s.Opened.Session, err)
		} else {
			// The VM stopped before the guest could deliver TExited (for
			// example while the session was backpressured). Report the same
			// result as a stop that did deliver it.
			exit = &wire.Exit{Code: 128 + int(unix.SIGTERM), Signal: "TERM", Reason: wire.ReasonStopped}
		}
	}
	if exit.Reason == wire.ReasonStopped {
		a.progress("\rblip %s stopped\r", opts.blip)
	}
	if code := exitCode(exit); code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

func exitCode(e *wire.Exit) int {
	if e.Code == 0 && e.Signal != "" {
		if n := unix.SignalNum("SIG" + strings.TrimPrefix(e.Signal, "SIG")); n != 0 {
			return 128 + int(n)
		}
		return 1
	}
	return e.Code
}

func (a *app) forwardResize(ctx context.Context, s *session.Session) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if rows, cols := a.termSize(); rows > 0 {
				s.Resize(rows, cols)
			}
		}
	}
}

// detachedSignal reports the signal that made the stream detach, if any. The
// forwarder publishes the signal just before closing the transport, so a value
// here means the session ended because the signal was not acknowledged.
func detachedSignal(ch <-chan string) (string, bool) {
	select {
	case name := <-ch:
		return name, true
	default:
		return "", false
	}
}

// forwardSignals forwards termination signals and bounds how long it waits
// for the guest to end the session. A guest process may ignore the signal (an
// interactive shell ignores SIGTERM), so after signalGrace the transport is
// closed. That detaches the exec session, which makes the guest terminate the
// command group, and lets stream return so the deferred terminal restore runs.
func forwardSignals(ctx context.Context, s *session.Session, detached chan<- string) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(ch)
	for {
		var sig os.Signal
		select {
		case <-ctx.Done():
			return
		case sig = <-ch:
		}
		name := strings.TrimPrefix(unix.SignalName(sig.(syscall.Signal)), "SIG")
		_ = s.Signal(name)

		// Keep forwarding signals while waiting, but do not let a repeated
		// signal extend the grace indefinitely.
		timer := time.NewTimer(signalGrace)
	wait:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				break wait
			case more := <-ch:
				_ = s.Signal(strings.TrimPrefix(unix.SignalName(more.(syscall.Signal)), "SIG"))
			}
		}
		// Publish first: the channel is buffered, and stream only consults
		// it after Copy returns an error caused by the close below.
		detached <- name
		_ = s.Close()
		return
	}
}
