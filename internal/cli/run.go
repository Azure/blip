package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

type runFlags struct {
	execFlags
	image, state, pool string
	fork               string
	mounts             []string
	detach             bool
	idle               time.Duration
}

// blipFromFlags builds the Blip that `kubectl blip run` creates.
func blipFromFlags(name, namespace string, f *runFlags, command []string) (*v1alpha1.Blip, error) {
	if (f.image == "") == (f.state == "") {
		return nil, errors.New("set exactly one of --image (throwaway root) and --state (durable root)")
	}
	env, err := parseEnv(f.env)
	if err != nil {
		return nil, err
	}
	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.BlipSpec{
			Pool:       f.pool,
			Image:      f.image,
			State:      f.state,
			Command:    command,
			Env:        env,
			WorkingDir: f.workdir,
			User:       f.user,
			TTY:        len(command) > 0 && f.tty && !f.noTTY,
		},
	}
	for _, m := range f.mounts {
		mount, err := parseMount(m)
		if err != nil {
			return nil, err
		}
		for _, other := range b.Spec.Mounts {
			if other.State == mount.State {
				return nil, fmt.Errorf("state %q is mounted twice", mount.State)
			}
		}
		b.Spec.Mounts = append(b.Spec.Mounts, mount)
	}
	if f.idle > 0 {
		b.Spec.IdleTimeout = &metav1.Duration{Duration: f.idle}
	}
	return b, nil
}

// parseMount parses STATE:/path[:rw|:ro].
func parseMount(s string) (v1alpha1.Mount, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || !strings.HasPrefix(parts[1], "/") ||
		parts[1] == "/" || path.Clean(parts[1]) != parts[1] {
		return v1alpha1.Mount{}, fmt.Errorf("invalid mount %q: want STATE:/clean/absolute/path[:rw]", s)
	}
	m := v1alpha1.Mount{State: parts[0], Path: parts[1]}
	if len(parts) == 3 {
		switch parts[2] {
		case "rw":
			m.Writable = true
		case "ro":
		default:
			return v1alpha1.Mount{}, fmt.Errorf("invalid mount %q: mode must be rw or ro", s)
		}
	}
	return m, nil
}

// parseEnv parses KEY=VALUE; a bare KEY takes the local value.
func parseEnv(list []string) ([]v1alpha1.EnvVar, error) {
	var env []v1alpha1.EnvVar
	for _, e := range list {
		k, v, ok := strings.Cut(e, "=")
		if k == "" {
			return nil, fmt.Errorf("invalid environment variable %q", e)
		}
		if !ok {
			v = os.Getenv(k)
		}
		env = append(env, v1alpha1.EnvVar{Name: k, Value: v})
	}
	return env, nil
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
		Use:   "run NAME [flags] [-- CMD [ARG...]]",
		Short: "Create a blip and attach to it",
		Long: `Create a blip. With a command, wait for it to run, stream its output,
and exit with its exit code. Without a command, the blip is an interactive
sandbox and you get a login shell. With -d, return right after creating it.`,
		Example: `  kubectl blip run tmp --image ghcr.io/me/dev:latest
  kubectl blip run job1 --image $IMG --mount repo:/work:rw -w /work -- make test
  kubectl blip run dev --state dev-home -d --idle-timeout 30m
  blip run w1 --fork / -- sh -c "git switch -c w1 && make fix && git commit -qam w1"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd.Context(), args[0], args[1:], f)
		},
	}
	f.add(cmd)
	fl := cmd.Flags()
	fl.StringVar(&f.image, "image", "", "root filesystem image (throwaway)")
	fl.StringVar(&f.state, "state", "", "durable root filesystem state")
	fl.StringVar(&f.pool, "pool", "", "VM pool (default \"default\")")
	fl.StringArrayVar(&f.mounts, "mount", nil, "mount a state: STATE:/path[:rw] (repeatable)")
	fl.StringVar(&f.fork, "fork", "", "inside a blip: start from a copy of this blip's root (/) or of the state mounted at PATH")
	fl.BoolVarP(&f.detach, "detach", "d", false, "do not wait or attach")
	fl.DurationVar(&f.idle, "idle-timeout", 0, "stop an interactive blip after this long with no sessions or processes (default 30s)")
	return cmd
}

// preflight reports a missing pool or state before creating the Blip, which
// would otherwise wait for them. The state named skip is created later.
func (a *app) preflight(ctx context.Context, kube client.Client, b *v1alpha1.Blip, skip string) error {
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
	states := []string{b.Spec.State}
	for _, m := range b.Spec.Mounts {
		states = append(states, m.State)
	}
	for _, s := range states {
		if s == "" || s == skip {
			continue
		}
		err := kube.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: s}, &v1alpha1.BlipState{})
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("state %q not found in namespace %s (create a BlipState with kubectl apply; see examples/state-from-image.yaml)", s, b.Namespace)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *app) run(ctx context.Context, name string, command []string, f *runFlags) error {
	if err := a.scope(&name, &f.state); err != nil {
		return err
	}
	c, _ := a.clients()
	var fork *v1alpha1.BlipState
	var forkPath string
	if f.fork != "" {
		var err error
		if fork, forkPath, err = a.forkFlags(ctx, name, f); err != nil {
			return err
		}
	}
	b, err := blipFromFlags(name, c.Namespace, f, command)
	if err != nil {
		return err
	}
	for i := range b.Spec.Mounts {
		b.Spec.Mounts[i].State = a.full(b.Spec.Mounts[i].State)
	}
	if fork != nil && forkPath != "/" {
		b.Spec.Mounts = append(b.Spec.Mounts, v1alpha1.Mount{State: fork.Name, Path: forkPath, Writable: true})
	}
	a.label(b)
	skip := ""
	if fork != nil {
		skip = fork.Name
	}
	if err := a.preflight(ctx, c.Kube, b, skip); err != nil {
		return err
	}
	if fork != nil {
		// The worker waits for its copy, which is created owned by it so
		// that deleting the worker deletes the copy. A state that already
		// exists must not be picked up by the new blip.
		err := c.Kube.Get(ctx, client.ObjectKeyFromObject(fork), &v1alpha1.BlipState{})
		if err == nil {
			return fmt.Errorf("state %q already exists; delete it or choose another name", a.short(name))
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
	}
	if err := c.Kube.Create(ctx, b); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("blip %q already exists; delete it or choose another name", a.short(name))
		}
		return err
	}
	if fork != nil {
		no := false
		fork.OwnerReferences = []metav1.OwnerReference{{APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip",
			Name: b.Name, UID: b.UID, Controller: &no, BlockOwnerDeletion: &no}}
		if err := c.Kube.Create(ctx, fork); err != nil {
			_ = c.Kube.Delete(context.WithoutCancel(ctx), b)
			if apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("state %q already exists; delete it or choose another name", a.short(name))
			}
			return fmt.Errorf("create state %q: %w", a.short(name), err)
		}
	}
	if f.detach {
		fmt.Fprintf(a.env.Out, "blip/%s created\n", a.short(name))
		return nil
	}
	b, err = a.waitRunning(ctx, name)
	if err != nil {
		return err
	}
	if len(command) == 0 {
		if b.Status.Phase != v1alpha1.BlipRunning {
			return fmt.Errorf("blip %q stopped before it was ready (%s)", name, describe(b))
		}
		return a.execSession(ctx, name, b.Status.Pod, nil, &execFlags{}, a.shellTTY(&f.execFlags))
	}

	var sessErr error
	if b.Status.Phase == v1alpha1.BlipRunning {
		s, err := a.openPrimary(ctx, b.Status.Pod)
		if err == nil {
			sessErr = a.stream(ctx, s, streamOpts{blip: name, sendEOF: true})
		} else {
			a.progress("blip %s: could not attach to the command: %v", name, err)
		}
		if errors.Is(sessErr, errDetached) {
			return sessErr
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

// forkFlags fills in the flags of a worker forked from the blip the command
// runs in. It returns the state to create and where the worker sees it.
func (a *app) forkFlags(ctx context.Context, name string, f *runFlags) (*v1alpha1.BlipState, string, error) {
	self := a.self
	if self == nil {
		return nil, "", errors.New("--fork only works inside a blip")
	}
	if f.state != "" {
		return nil, "", errors.New("--fork and --state cannot be combined")
	}
	p := path.Clean(f.fork)
	src := ""
	if p == "/" {
		if f.image != "" {
			return nil, "", errors.New("--image cannot be combined with --fork /: the root is a copy of this blip's")
		}
		if src = self.Spec.State; src == "" {
			return nil, "", errors.New("--fork / needs a blip with a state root")
		}
		f.state = name
	} else {
		for _, m := range self.Spec.Mounts {
			if m.Path == p {
				src = m.State
			}
		}
		if src == "" {
			return nil, "", fmt.Errorf("--fork %s: no state is mounted at %s", p, p)
		}
		if f.image == "" {
			img, err := a.imageOf(ctx, self)
			if err != nil {
				return nil, "", err
			}
			if img == "" {
				return nil, "", fmt.Errorf("--fork %s: cannot tell the image of this blip; set --image", p)
			}
			f.image = img
		}
	}
	if f.pool == "" {
		f.pool = self.Spec.Pool
	}
	if f.user == "" {
		f.user = self.Spec.User
	}
	if f.workdir == "" {
		f.workdir, _ = os.Getwd()
		if p != "/" && f.workdir != p && !strings.HasPrefix(f.workdir, p+"/") {
			// Only the state at p is copied; a cwd outside it does not
			// exist in the worker. Start at the fork's root instead of
			// failing every command with ENOENT.
			f.workdir = p
		}
	}
	st := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: self.Namespace},
		Spec:       v1alpha1.BlipStateSpec{CopyFrom: src, Replicas: 1},
	}
	a.label(st)
	return st, p, nil
}

// imageOf returns the image of a blip's root: its image, or the image its
// root state was made from.
func (a *app) imageOf(ctx context.Context, b *v1alpha1.Blip) (string, error) {
	name := b.Spec.State
	if b.Spec.Image != "" || name == "" {
		return b.Spec.Image, nil
	}
	for range 16 {
		s, err := a.getState(ctx, name)
		if err != nil {
			return "", err
		}
		if s.Spec.Image != "" || s.Spec.CopyFrom == "" {
			return s.Spec.Image, nil
		}
		name = s.Spec.CopyFrom
	}
	return "", nil
}
