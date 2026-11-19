package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

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
	if !tty && a.env.Terminal {
		go forwardSignals(ctx, s)
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
				if opts.sendEOF && errors.Is(err, io.EOF) {
					s.CloseStdin()
				}
				return
			}
		}
	}()

	exit, err := s.Copy(a.env.Out, a.env.Err, func(m string) { a.progress("blip: %s", m) })
	if err != nil {
		return fmt.Errorf("session %s: %w", s.Opened.Session, err)
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

func forwardSignals(ctx context.Context, s *session.Session) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-ch:
			s.Signal(strings.TrimPrefix(unix.SignalName(sig.(syscall.Signal)), "SIG"))
		}
	}
}
