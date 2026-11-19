package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/workspace"
)

// Forks started inside a blip expire on their own. A caller that dies without
// gathering its forks then still stops them and frees their workspaces.
const (
	defaultForkTimeout = 2 * time.Hour
	defaultForkTTL     = time.Hour
)

type runFlags struct {
	workdir, user, pool, name string
	from, state               string
	env, labels               []string
	timeout, ttl              time.Duration
	timeoutSet, ttlSet        bool
	keep                      bool
}

func (a *app) runCommand() *cobra.Command {
	f := &runFlags{}
	cmd := &cobra.Command{
		Use:   "run [flags] -- CMD [ARG...]",
		Short: "Start a command in a new blip and return its name",
		Long: `Create a blip that runs one command and return as soon as its workspace is
ready, printing the blip's name. Use blip gather to wait for it, collect its
results, and delete it.

Inside a blip, run defaults to --from /: a copy of the caller's own root,
including its working directory, uncommitted changes, and the effects of
earlier commands. Several runs from one caller fork the same snapshot and do
not see each other's changes. The caller's pool is inherited.

--from copies an existing workspace or imported base. --state runs in an
existing workspace; only one blip can run a workspace at a time.

Forks started inside a blip stop after --timeout and are deleted --ttl after
they finish, so an abandoned fork cannot leak its workspace.`,
		Example: `  blip run -- sh -c "make test"
  blip run --name fix-lint -- sh -c "git switch -c fix-lint && ./lint.sh"
  blip gather --collect "git:/home/dev/src:{name}" --wait 30m
  blip run --name dev --from base -- sleep infinity`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.timeoutSet = cmd.Flags().Changed("timeout")
			f.ttlSet = cmd.Flags().Changed("ttl")
			return a.run(cmd.Context(), args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "blip name (default <caller>-<random>)")
	fl.StringVar(&f.from, "from", "", "copy workspace SRC into a new one (inside a blip, / is the caller's root)")
	fl.StringVar(&f.state, "state", "", "run in existing workspace WS")
	fl.StringVar(&f.pool, "pool", "", "VM pool (default \"default\")")
	fl.StringVarP(&f.workdir, "workdir", "w", "", "working directory (inside a blip, the current directory)")
	fl.StringVarP(&f.user, "user", "u", "", "user name or uid")
	fl.StringArrayVarP(&f.env, "env", "e", nil, "environment variable KEY=VALUE (repeatable)")
	fl.StringArrayVar(&f.labels, "label", nil, "label KEY=VALUE for the blip (repeatable)")
	fl.DurationVar(&f.timeout, "timeout", 0, "stop the blip after this long (default 2h inside a blip; 0 disables)")
	fl.DurationVar(&f.ttl, "ttl", 0, "delete the blip this long after it finishes (default 1h inside a blip; 0 disables)")
	fl.BoolVar(&f.keep, "keep", false, "leave the new workspace in place after the blip is deleted")
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

func envStrings(env []v1alpha1.EnvVar) []string {
	var out []string
	for _, e := range env {
		out = append(out, e.Name+"="+e.Value)
	}
	return out
}

// cwdPath is the caller's working directory inside its own filesystem, which
// is also its path in a fork of that filesystem.
func cwdPath() (string, error) {
	return os.Getwd()
}

// blipRef is the owner reference from a fork to the blip that started it.
func blipRef(o *v1alpha1.Blip) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "Blip",
		Name:       o.Name,
		UID:        o.UID,
	}
}

// forkName names a blip after the caller and a short random suffix, so
// concurrent forks of one caller never collide.
func (a *app) forkName() string {
	base := "run"
	if a.self != nil {
		base = a.short(a.self.Name)
		if len(base) > 40 {
			base = strings.TrimRight(base[:40], "-.")
		}
	}
	return base + "-" + randSuffix(5)
}

const randAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

func randSuffix(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("x", n)
	}
	for i := range b {
		b[i] = randAlphabet[int(b[i])%len(randAlphabet)]
	}
	return string(b)
}

// labelFlags applies user labels, refusing the reserved blip.dev namespace.
func labelFlags(b *v1alpha1.Blip, values []string) error {
	for _, value := range values {
		k, v, ok := strings.Cut(value, "=")
		if !ok || k == "" {
			return fmt.Errorf("invalid --label %q: want KEY=VALUE", value)
		}
		if strings.HasPrefix(k, "blip.dev/") {
			return fmt.Errorf("invalid --label %q: the blip.dev/ prefix is reserved", k)
		}
		if b.Labels == nil {
			b.Labels = map[string]string{}
		}
		b.Labels[k] = v
	}
	return nil
}

func (a *app) run(ctx context.Context, command []string, f *runFlags) error {
	if len(command) == 0 {
		return errors.New("a command is required: blip run -- CMD [ARG...]")
	}
	if f.timeout > 0 && f.timeout < time.Second {
		return errors.New("--timeout must be at least 1s")
	}
	if f.ttl > 0 && f.ttl < time.Second {
		return errors.New("--ttl must be at least 1s")
	}
	if f.from != "" && f.state != "" {
		return errors.New("set only one of --from and --state")
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	name := f.name
	if name == "" {
		name = a.forkName()
	}
	if err := a.scope(&name); err != nil {
		return err
	}
	env, err := parseEnv(f.env)
	if err != nil {
		return err
	}
	workdir := f.workdir
	if workdir == "" && a.self != nil {
		// The caller's root is the fork's root, so its directory exists.
		if cwd, err := cwdPath(); err == nil {
			workdir = cwd
		}
	}
	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace},
		Spec: v1alpha1.BlipSpec{
			Pool:       f.pool,
			Command:    command,
			Env:        env,
			WorkingDir: workdir,
			User:       f.user,
		},
	}
	a.label(b)
	if a.self != nil {
		if b.Labels == nil {
			b.Labels = map[string]string{}
		}
		b.Labels[v1alpha1.LabelParent] = a.short(a.self.Name)
		if !f.keep {
			b.OwnerReferences = []metav1.OwnerReference{blipRef(a.self)}
		}
	}
	if err := labelFlags(b, f.labels); err != nil {
		return err
	}
	// Forks expire on their own unless the caller asked for something else.
	timeout, ttl := f.timeout, f.ttl
	if a.self != nil {
		if !f.timeoutSet {
			timeout = defaultForkTimeout
		}
		if !f.ttlSet {
			ttl = defaultForkTTL
		}
	}
	if timeout > 0 {
		seconds := int64(timeout / time.Second)
		b.Spec.ActiveDeadlineSeconds = &seconds
	}
	if ttl > 0 {
		seconds := int32(ttl / time.Second)
		b.Spec.TTLSecondsAfterFinished = &seconds
	}

	from, state := f.from, f.state
	if from == "" && state == "" {
		if a.self == nil {
			return errors.New("set --from or --state, or run inside a blip to fork its workspace")
		}
		from = "/"
	}
	if b.Spec.Pool == "" && a.self != nil && from != "" {
		b.Spec.Pool = a.self.Spec.Pool
	}
	if err := a.preflight(ctx, c.Kube, b); err != nil {
		return err
	}
	// Check the blip name before creating the durable workspace it owns.
	err = c.Kube.Get(ctx, client.ObjectKeyFromObject(b), &v1alpha1.Blip{})
	if err == nil {
		return fmt.Errorf("blip %q already exists; choose another name", a.short(name))
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	var source *v1alpha1.BlipState
	if from != "" {
		src := from
		if src == "/" {
			if a.self == nil {
				return errors.New("--from / only works inside a blip; use --from SOURCE")
			}
			src = a.self.Spec.State
		}
		if source, err = a.resolveState(ctx, src); err != nil {
			return err
		}
		// The fork root takes the blip's name.
		b.Spec.State = name
	} else {
		root, err := a.resolveState(ctx, state)
		if err != nil {
			return err
		}
		if root.Spec.Image != "" {
			return fmt.Errorf("state %q is an imported base and cannot be executed directly; use --from %s", a.short(root.Name), a.short(root.Name))
		}
		if root.DeletionTimestamp != nil {
			return fmt.Errorf("state %q is being deleted", a.short(root.Name))
		}
		for _, mount := range root.Spec.Mounts {
			if mount.BlipUID != "" || !mount.Writable {
				continue
			}
			mounted, err := a.getState(ctx, mount.State)
			if err != nil {
				return err
			}
			if mounted.Spec.Image != "" {
				return fmt.Errorf("mount state %q is an imported base and cannot be written directly; use --from %s", a.short(mounted.Name), a.short(root.Name))
			}
		}
		b.Spec.State = root.Name
	}

	if err := c.Kube.Create(ctx, b); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("blip %q already exists; choose another name", a.short(name))
		}
		return err
	}
	if err := a.launch(ctx, b, source, !f.keep); err != nil {
		// The blip owns its workspace; deleting it removes the copies too.
		delErr := c.Kube.Delete(context.WithoutCancel(ctx), b)
		if delErr != nil && !apierrors.IsNotFound(delErr) {
			err = errors.Join(err, fmt.Errorf("remove blip %q: %w", a.short(name), delErr))
		}
		return err
	}
	fmt.Fprintln(a.env.Out, a.short(b.Name))
	return nil
}

// launch creates the fork's states and waits until their first version is
// usable, which is the snapshot the caller relies on. It is a no-op when the
// blip runs in an existing workspace.
func (a *app) launch(ctx context.Context, b *v1alpha1.Blip, source *v1alpha1.BlipState, owned bool) error {
	if source == nil {
		return nil
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	fork := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: b.Name, Namespace: b.Namespace}}
	a.label(fork)
	var opts *workspace.ForkOptions
	if owned {
		ref := blipRef(b)
		opts = &workspace.ForkOptions{Owner: &ref}
	}
	if err := workspace.Fork(ctx, c.Kube, source, fork, opts); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state for blip %q already exists: %w", a.short(b.Name), err)
		}
		return err
	}
	if _, err := a.waitStateCommitted(ctx, b.Name); err != nil {
		return err
	}
	for _, mount := range fork.Spec.Mounts {
		if !mount.Writable {
			continue
		}
		if _, err := a.waitStateCommitted(ctx, mount.State); err != nil {
			return err
		}
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
	return string(b.Status.Phase)
}
