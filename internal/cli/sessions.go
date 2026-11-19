package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// finishedError explains that a blip can no longer be attached to. It names
// the reason (for example "Stopped" or "Idle") so a teardown race looks
// different from a blip that never existed.
func finishedError(b *v1alpha1.Blip) error {
	detail := string(b.Status.Phase)
	if b.Status.Reason != "" {
		detail += ": " + b.Status.Reason
	}
	return fmt.Errorf("blip %q has finished (%s)", b.Name, detail)
}

// runningPod returns the VM pod of a running blip. It waits while the
// blip is still starting and reports a terminal blip instead of opening a
// session in a pod that is already gone.
func (a *app) runningPod(ctx context.Context, name string) (string, error) {
	b, err := a.getBlip(ctx, name)
	if err != nil {
		return "", err
	}
	if b.Status.Phase == "" || b.Status.Phase == v1alpha1.BlipPending {
		if b, err = a.waitRunning(ctx, name); err != nil {
			return "", err
		}
	}
	if v1alpha1.Finished(b) {
		return "", finishedError(b)
	}
	return podFor(b)
}

// podFor returns the VM pod of a running blip, or an error that explains why
// it has none.
func podFor(b *v1alpha1.Blip) (string, error) {
	switch b.Status.Phase {
	case v1alpha1.BlipRunning:
		if b.Status.Pod != "" {
			return b.Status.Pod, nil
		}
		return "", fmt.Errorf("blip %q is not running yet", b.Name)
	case v1alpha1.BlipSaving:
		return "", fmt.Errorf("blip %q has stopped and is saving", b.Name)
	case v1alpha1.BlipSucceeded, v1alpha1.BlipFailed:
		return "", fmt.Errorf("blip %q has finished (%s)", b.Name, b.Status.Phase)
	}
	msg := ""
	if b.Status.Message != "" {
		msg = ": " + b.Status.Message
	}
	return "", fmt.Errorf("blip %q is not running yet%s", b.Name, msg)
}

func (a *app) open(ctx context.Context, pod string, o wire.Open) (*session.Session, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	return c.Sessions.Open(ctx, c.Namespace, pod, o)
}

// Attach opens are idempotent, so a VM that is still starting or already
// shutting down can be retried. Exec must never use these: without a stable
// OpenID a retry could start the command twice.
var (
	openRetryWindow = 10 * time.Second
	openRetryFirst  = 50 * time.Millisecond
	openRetryMax    = 500 * time.Millisecond
)

// transientOpenError reports whether err describes a VM lifecycle race: the
// vsock bridge or OCI exec setup failed, the VM went away mid-open, or the
// guest is tearing the blip down. Any definitive answer from the guest (such
// as "no session") is not transient.
func transientOpenError(err error) bool {
	if errors.Is(err, session.ErrUnreachable) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{
		"connection reset",
		"connect: no such file or directory",
		"unexpected EOF",
		"has finished",
		"OCI runtime exec failed",
		"setns",
		"command terminated with exit code 137",
		"container not found",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func openRetryable(err error, retryNoSession bool) bool {
	if retryNoSession && strings.Contains(err.Error(), "no session") {
		return true
	}
	return transientOpenError(err)
}

// openRetrying opens a session, retrying transient startup/teardown failures
// for a bounded time. Only attach opens may use it. With retryNoSession it
// also covers the gap between a blip reporting Running and its command session
// registering; a session that never appears still ends with the guest's
// "no session" error.
func (a *app) openRetrying(ctx context.Context, name, pod string, o wire.Open, retryNoSession bool) (*session.Session, error) {
	deadline := time.Now().Add(openRetryWindow)
	delay := openRetryFirst
	for {
		s, err := a.open(ctx, pod, o)
		if err == nil {
			return s, nil
		}
		if !openRetryable(err, retryNoSession) {
			return nil, err
		}
		// The open may have failed because the blip just stopped. Report
		// that clearly instead of retrying a VM that no longer exists.
		if b, gerr := a.getBlip(ctx, name); gerr == nil && v1alpha1.Finished(b) {
			return nil, finishedError(b)
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, openRetryMax)
	}
}

// stopped reports whether a broken session stream ended because the blip was
// stopped or deleted rather than because its command failed. Shutting the VM
// down can kill the pod-exec bridge before the guest delivers TExited, so the
// client has to classify that transport failure from the requested lifecycle.
func (a *app) stopped(ctx context.Context, name string) bool {
	if name == "" {
		return false
	}
	// The stream context dies with the transport; the Blip lookup must still
	// be able to answer.
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	b, err := a.getBlip(qctx, name)
	if err != nil {
		return false
	}
	return b.Spec.Stop || b.DeletionTimestamp != nil ||
		b.Status.Phase == v1alpha1.BlipSaving || b.Status.Reason == wire.ReasonStopped
}

// openPrimary attaches to a command blip's main session. The VM can report
// Running just before its command session is registered, and a very fast
// command can finish in that window; retry briefly so its replayed output is
// not lost.
func (a *app) openPrimary(ctx context.Context, name, pod string) (*session.Session, error) {
	return a.openRetrying(ctx, name, pod, wire.Open{Mode: wire.OpenAttach, Session: wire.PrimarySession}, true)
}

// execSession starts argv (a login shell when empty) in a running blip and
// streams it.
func (a *app) execSession(ctx context.Context, name, pod string, argv []string, f *execFlags, tty bool) error {
	env, err := parseEnv(f.env)
	if err != nil {
		return err
	}
	o := wire.Open{Mode: wire.OpenExec, Argv: argv, WorkingDir: f.workdir, User: f.user, Env: envStrings(env)}
	a.ttyOpen(&o, tty)
	s, err := a.open(ctx, pod, o)
	if err != nil {
		// A start failure has a conventional shell status. Print the
		// explanation, then return that status so a script can distinguish
		// "not found" (127) or "not executable" (126) from a command that
		// ran and exited 1.
		var oe *session.OpenError
		if errors.As(err, &oe) {
			fmt.Fprintf(a.env.Err, "error: %v\n", err)
			return &ExitError{Code: oe.Code}
		}
		return err
	}
	return a.stream(ctx, s, streamOpts{blip: name, sendEOF: true})
}

type execFlags struct {
	tty, noTTY bool
	workdir    string
	user       string
	env        []string
}

func (f *execFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&f.tty, "tty", "t", false, "allocate a terminal")
	cmd.Flags().BoolVarP(&f.noTTY, "no-tty", "T", false, "never allocate a terminal")
	cmd.Flags().StringVarP(&f.workdir, "workdir", "w", "", "working directory")
	cmd.Flags().StringVarP(&f.user, "user", "u", "", "user name or uid")
	cmd.Flags().StringArrayVarP(&f.env, "env", "e", nil, "environment variable KEY=VALUE (repeatable)")
}

// shellTTY reports whether a login shell gets a terminal: by default when
// the local side has one.
func (a *app) shellTTY(f *execFlags) bool {
	return !f.noTTY && (f.tty || a.terminal() != nil)
}

func (a *app) execCommand() *cobra.Command {
	var f execFlags
	cmd := &cobra.Command{
		Use:   "exec NAME [flags] [-- CMD [ARG...]]",
		Short: "Run a command or open a login shell in a running blip",
		Long: `Run a command in a running blip as a new session. Without a command,
open a login shell, with a terminal when the local side has one.`,
		Example: `  kubectl blip exec dev
  kubectl blip exec dev -- make test`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.scope(&args[0]); err != nil {
				return err
			}
			pod, err := a.runningPod(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			tty := f.tty && !f.noTTY
			if len(args) == 1 {
				tty = a.shellTTY(&f)
			}
			return a.execSession(cmd.Context(), args[0], pod, args[1:], &f, tty)
		},
	}
	f.add(cmd)
	return cmd
}
