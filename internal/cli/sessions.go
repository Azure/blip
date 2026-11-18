package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

func (a *app) getBlip(ctx context.Context, name string) (*v1alpha1.Blip, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	var b v1alpha1.Blip
	if err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, &b); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("blip %q not found in namespace %q", name, c.Namespace)
		}
		return nil, err
	}
	return &b, nil
}

// runningPod returns the VM pod of a running blip. It waits while the
// blip is still starting.
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
	return session.PodFor(b)
}

func (a *app) open(ctx context.Context, pod string, o wire.Open) (*session.Session, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	return c.Sessions.Open(ctx, c.Namespace, pod, o)
}

// openPrimary attaches to a command blip's main session. The VM can report
// Running just before its command session is registered, and a very fast
// command can finish in that window; retry briefly so its replayed output is
// not lost.
func (a *app) openPrimary(ctx context.Context, pod string) (*session.Session, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := a.open(ctx, pod, wire.Open{Mode: wire.OpenAttach, Session: wire.PrimarySession})
		if err == nil || !strings.Contains(err.Error(), "no session") || time.Now().After(deadline) {
			return s, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
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

func (a *app) attachCommand() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "attach NAME",
		Short: "Join a session (default: the main command); Ctrl-] detaches",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.scope(&args[0]); err != nil {
				return err
			}
			pod, err := a.runningPod(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			s, err := a.open(cmd.Context(), pod, wire.Open{Mode: wire.OpenAttach, Session: id})
			if err != nil {
				return err
			}
			return a.stream(cmd.Context(), s, streamOpts{blip: args[0]})
		},
	}
	cmd.Flags().StringVar(&id, "session", "", "session ID (default main)")
	return cmd
}

func (a *app) sessionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions NAME",
		Short: "List the sessions of a running blip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.scope(&args[0]); err != nil {
				return err
			}
			pod, err := a.runningPod(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			c, _ := a.clients()
			list, err := c.Sessions.List(cmd.Context(), c.Namespace, pod)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(a.env.Out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tTTY\tCLIENTS\tCOMMAND")
			for _, s := range list {
				status := "Running"
				if s.Exited {
					status = "Exited"
				}
				argv := strings.Join(s.Argv, " ")
				if argv == "" {
					argv = "(login shell)"
				}
				fmt.Fprintf(w, "%s\t%s\t%t\t%d\t%s\n", s.ID, status, s.TTY, s.Clients, argv)
			}
			return w.Flush()
		},
	}
}
