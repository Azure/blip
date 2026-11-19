package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/workspace"
)

type runFlags struct {
	execFlags
	state, pool, fork string
}

// blipFromFlags builds the Blip that `kubectl blip run` creates.
func blipFromFlags(name, namespace string, f *runFlags, command []string) (*v1alpha1.Blip, error) {
	if (f.fork == "") == (f.state == "") {
		return nil, errors.New("set exactly one of --state (existing workspace) and --fork (copy a workspace)")
	}
	env, err := parseEnv(f.env)
	if err != nil {
		return nil, err
	}
	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.BlipSpec{
			Pool:       f.pool,
			State:      f.state,
			Command:    command,
			Env:        env,
			WorkingDir: f.workdir,
			User:       f.user,
			TTY:        f.tty && !f.noTTY,
		},
	}
	if f.fork != "" {
		b.Spec.State = name
	}
	// The CLI always attaches, so tell the guest to hold the primary
	// command's output until the caller connects. Otherwise a fast command
	// could outrun the caller and overflow the replay ring.
	if b.Annotations == nil {
		b.Annotations = map[string]string{}
	}
	b.Annotations[v1alpha1.AnnotationWaitForClient] = "true"
	return b, nil
}

func envStrings(env []v1alpha1.EnvVar) []string {
	var out []string
	for _, e := range env {
		out = append(out, e.Name+"="+e.Value)
	}
	return out
}

func (a *app) runCommand() *cobra.Command {
	f := &runFlags{}
	cmd := &cobra.Command{
		Use:   "run NAME [flags] -- CMD [ARG...]",
		Short: "Create a blip that runs a command and attach to it",
		Long: `Create a blip that runs one command, stream its output, and exit with
its exit code.`,
		Example: `  kubectl blip pull base ghcr.io/me/dev:latest
  kubectl blip run job1 --fork base -w /work -- make test
  kubectl blip run dev --state dev-home -- bash
  blip run w1 --fork dev-home -- sh -c "git switch -c w1 && make fix && git commit -qam w1"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd.Context(), args[0], args[1:], f)
		},
	}
	f.add(cmd)
	fl := cmd.Flags()
	fl.StringVar(&f.state, "state", "", "existing writable workspace")
	fl.StringVar(&f.pool, "pool", "", "VM pool (default \"default\")")
	fl.StringVar(&f.fork, "fork", "", "copy SOURCE_STATE into a new workspace named NAME (inside a blip, / means its root)")
	return cmd
}

// preflight reports a missing pool before creating workspace states or a Blip.
func (a *app) preflight(ctx context.Context, kube client.Client, b *v1alpha1.Blip) error {
	pool := b.Spec.Pool
	if pool == "" {
		pool = "default"
	}
	err := kube.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: pool}, &v1alpha1.BlipPool{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("pool %q not found in namespace %s", pool, b.Namespace)
	}
	if err != nil {
		return err
	}
	return nil
}

func (a *app) run(ctx context.Context, name string, command []string, f *runFlags) error {
	if err := a.scope(&name); err != nil {
		return err
	}
	if len(command) == 0 {
		return errors.New("a command is required: kubectl blip run NAME -- CMD [ARG...]")
	}
	c, _ := a.clients()
	b, err := blipFromFlags(name, c.Namespace, f, command)
	if err != nil {
		return err
	}
	a.label(b)
	if b.Spec.Pool == "" && a.self != nil && f.fork != "" {
		b.Spec.Pool = a.self.Spec.Pool
	}
	if err := a.preflight(ctx, c.Kube, b); err != nil {
		return err
	}
	// Check the execution name before creating its durable workspace. A later
	// execution-create failure leaves the successfully created workspace intact.
	err = c.Kube.Get(ctx, client.ObjectKeyFromObject(b), &v1alpha1.Blip{})
	if err == nil {
		return fmt.Errorf("blip %q already exists; delete it or choose another name", a.short(name))
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	if f.fork != "" {
		sourceName := f.fork
		if sourceName == "/" {
			if a.self == nil {
				return errors.New("--fork / only works inside a blip; use --fork SOURCE_STATE")
			}
			sourceName = a.self.Spec.State
		}
		source, err := a.resolveState(ctx, sourceName)
		if err != nil {
			return err
		}
		fork := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace}}
		a.label(fork)
		if err := workspace.Fork(ctx, c.Kube, source, fork); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("state for workspace %q already exists; delete it or choose another name: %w", a.short(name), err)
			}
			return err
		}
	} else {
		root, err := a.resolveState(ctx, f.state)
		if err != nil {
			return err
		}
		if root.Spec.Image != "" {
			return fmt.Errorf("state %q is an imported base and cannot be executed directly; use --fork %s", a.short(root.Name), a.short(root.Name))
		}
		if root.DeletionTimestamp != nil {
			return fmt.Errorf("state %q is being deleted", a.short(root.Name))
		}
		for _, mount := range root.Spec.Mounts {
			if mount.BlipUID != "" {
				continue
			}
			mounted, err := a.getState(ctx, mount.State)
			if err != nil {
				return err
			}
			if mount.Writable && mounted.Spec.Image != "" {
				return fmt.Errorf("mount state %q is an imported base and cannot be written directly; use --fork %s", a.short(mounted.Name), a.short(root.Name))
			}
		}
		b.Spec.State = root.Name
	}
	if err := c.Kube.Create(ctx, b); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("blip %q already exists; delete it or choose another name", a.short(name))
		}
		return err
	}
	b, err = a.waitRunning(ctx, name)
	if err != nil {
		return err
	}

	var sessErr error
	if b.Status.Phase == v1alpha1.BlipRunning {
		s, err := a.openPrimary(ctx, name, b.Status.Pod)
		if err == nil {
			sessErr = a.stream(ctx, s, streamOpts{blip: name, sendEOF: true})
		} else {
			a.progress("blip %s: could not attach to the command: %v", name, err)
		}
	}
	fin, err := a.waitFinished(ctx, name, false)
	if err != nil {
		return err
	}
	var exit *ExitError
	if errors.As(sessErr, &exit) {
		return exit
	}
	if sessErr != nil {
		a.progress("blip %s: %v", name, sessErr)
	}
	code := 0
	if fin.Status.ExitCode != nil {
		code = int(*fin.Status.ExitCode)
	}
	if code != 0 {
		return &ExitError{Code: code}
	}
	if fin.Status.Phase == v1alpha1.BlipFailed {
		return fmt.Errorf("blip %q failed: %s", name, describe(fin))
	}
	return nil
}

// describe summarizes a blip's reason and message.
func describe(b *v1alpha1.Blip) string {
	switch {
	case b.Status.Message != "":
		return b.Status.Message
	case b.Status.Reason != "":
		return b.Status.Reason
	}
	return b.Status.Phase
}
