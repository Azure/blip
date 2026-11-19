// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
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
	nameSet                   bool
	fromSet, stateSet         bool
	keep                      bool
	interactive               bool
}

func (a *app) runCommand() *cobra.Command {
	f := &runFlags{}
	cmd := &cobra.Command{
		Use:   "run [flags] -- CMD [ARG...]",
		Short: "Start a command in a new blip and return its name",
		Long: `Create a blip that runs one command and return as soon as its workspace is
ready, printing the blip's name. By default run also closes the command's
stdin, so a one-shot command never waits for input. Use --interactive to leave
stdin open and feed it with blip send. Use blip logs to read output, and blip
gather to wait for the blip, collect its results, and delete it.

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
  blip logs --follow worker-1
  blip gather --collect "git:/home/dev/src:{name}" --wait 30m
  blip run --name chat --interactive --state ws -- cat`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.rejectAmbiguousCommandFlags(cmd, "blip run [flags] -- CMD [ARG...]"); err != nil {
				return err
			}
			f.timeoutSet = cmd.Flags().Changed("timeout")
			f.ttlSet = cmd.Flags().Changed("ttl")
			f.nameSet = cmd.Flags().Changed("name")
			f.fromSet = cmd.Flags().Changed("from")
			f.stateSet = cmd.Flags().Changed("state")
			// A run that is interrupted before it returns must not leave a
			// VM behind, so turn the signal into cancellation instead of
			// letting the default handler kill the process.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return a.run(ctx, args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "blip name (default <caller>-<random> inside a blip, run-<random> otherwise)")
	fl.StringVar(&f.from, "from", "", "copy workspace SRC into a new one (inside a blip, / is the caller's root)")
	fl.StringVar(&f.state, "state", "", "run in existing workspace WS")
	fl.StringVar(&f.pool, "pool", "", "VM pool (default \"default\"; inside a blip, the caller's pool)")
	fl.StringVarP(&f.workdir, "workdir", "w", "", "working directory (inside a blip, the current directory)")
	fl.StringVarP(&f.user, "user", "u", "", "user name or uid")
	fl.StringArrayVarP(&f.env, "env", "e", nil, "environment variable KEY=VALUE (repeatable)")
	fl.StringArrayVar(&f.labels, "label", nil, "label KEY=VALUE for the blip (repeatable)")
	fl.DurationVar(&f.timeout, "timeout", 0, "stop the blip after this long (default 2h inside a blip; 0 disables)")
	fl.DurationVar(&f.ttl, "ttl", 0, "delete the blip this long after it finishes (default 1h inside a blip; 0 disables)")
	fl.BoolVar(&f.keep, "keep", false, "leave the new workspace in place after the blip is deleted")
	fl.BoolVar(&f.interactive, "interactive", false, "leave stdin open so blip send can feed the command")
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

// labelFlags applies user labels, refusing the reserved blip.dev namespace
// and validating keys and values before the Blip reaches the API server.
func labelFlags(b *v1alpha1.Blip, values []string) error {
	for _, value := range values {
		k, v, ok := strings.Cut(value, "=")
		if !ok || k == "" {
			return fmt.Errorf("invalid --label %q: want KEY=VALUE", value)
		}
		if strings.HasPrefix(k, "blip.dev/") {
			return fmt.Errorf("invalid --label %q: the blip.dev/ prefix is reserved", k)
		}
		if problems := validation.IsQualifiedName(k); len(problems) > 0 {
			return fmt.Errorf("invalid --label %q: %s", k, strings.Join(problems, "; "))
		}
		if problems := validation.IsValidLabelValue(v); len(problems) > 0 {
			return fmt.Errorf("invalid --label %q: invalid value: %s", k, strings.Join(problems, "; "))
		}
		if b.Labels == nil {
			b.Labels = map[string]string{}
		}
		b.Labels[k] = v
	}
	return nil
}

// The CRD stores these fields in whole seconds. --ttl is an int32, so a
// larger value would wrap to a small or negative TTL and delete a finished
// Blip (including a failed one) almost immediately. --timeout is an int64
// whose maximum is the largest value that does not overflow a time.Duration.
// Reject out-of-range values instead of letting the API server do it (or,
// worse, silently wrapping them).
const (
	maxTTLSeconds     = int64(math.MaxInt32)
	maxTimeoutSeconds = int64(math.MaxInt64 / int64(time.Second))
)

// wholeSeconds validates a duration that is stored in whole seconds. A
// negative value would silently disable the field that the flag is meant to
// set, a fractional value would be truncated, and a value above the CRD's
// maximum would wrap or fail at the API server, so all three are rejected.
func wholeSeconds(flag string, d time.Duration, max int64) error {
	switch {
	case d < 0:
		return fmt.Errorf("%s must not be negative: %s", flag, d)
	case d%time.Second != 0:
		return fmt.Errorf("%s must be a whole number of seconds: %s", flag, d)
	case int64(d/time.Second) > max:
		return fmt.Errorf("%s must be at most %ds: %s", flag, max, d)
	}
	return nil
}

var errInvalidUTF8 = errors.New("run requires valid UTF-8")

// validateRun rejects a run request whose strings JSON would silently rewrite.
// env is checked as name/value pairs so the error names the invalid part.
func validateRun(command []string, env []v1alpha1.EnvVar, workdir, user string) error {
	for i, e := range env {
		if !utf8.ValidString(e.Name) {
			return fmt.Errorf("%w: env[%d] name contains invalid UTF-8", errInvalidUTF8, i)
		}
		if !utf8.ValidString(e.Value) {
			return fmt.Errorf("%w: env[%d] value contains invalid UTF-8", errInvalidUTF8, i)
		}
	}
	for i, s := range command {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%w: argv[%d] contains invalid UTF-8", errInvalidUTF8, i)
		}
	}
	for i, s := range envStrings(env) {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%w: env[%d] contains invalid UTF-8", errInvalidUTF8, i)
		}
	}
	if !utf8.ValidString(workdir) {
		return fmt.Errorf("%w: workingDir contains invalid UTF-8", errInvalidUTF8)
	}
	if !utf8.ValidString(user) {
		return fmt.Errorf("%w: user contains invalid UTF-8", errInvalidUTF8)
	}
	return nil
}

func (a *app) run(ctx context.Context, command []string, f *runFlags) error {
	if len(command) == 0 {
		return errors.New("a command is required: blip run -- CMD [ARG...]")
	}
	// An unset shell variable expands to an empty argument, which the guest
	// reports as exit 127 only after the blip and its fork state exist. Reject
	// it before anything is created, like an explicitly empty --from/--state.
	if strings.TrimSpace(command[0]) == "" {
		return errors.New("command name must not be empty: blip run -- CMD [ARG...]")
	}
	if err := wholeSeconds("--timeout", f.timeout, maxTimeoutSeconds); err != nil {
		return err
	}
	if err := wholeSeconds("--ttl", f.ttl, maxTTLSeconds); err != nil {
		return err
	}
	// An explicitly empty source is a mistake, not a request for the
	// default source. Inside a blip the default is a fork of the caller's
	// root, so an unset shell variable would silently run in a throwaway
	// workspace.
	if f.fromSet && strings.TrimSpace(f.from) == "" {
		return errors.New("--from must not be empty")
	}
	if f.stateSet && strings.TrimSpace(f.state) == "" {
		return errors.New("--state must not be empty")
	}
	if f.from != "" && f.state != "" {
		return errors.New("set only one of --from and --state")
	}
	env, err := parseEnv(f.env)
	if err != nil {
		return err
	}
	// Reject a request the API server would silently alter before clients()
	// can read the caller's blip or create anything.
	if err := validateRun(command, env, f.workdir, f.user); err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	name := f.name
	if name == "" && !f.nameSet {
		name = a.forkName()
	}
	if err := a.scope(&name); err != nil {
		return err
	}
	// Blip is a Kubernetes object, so its name is a DNS subdomain of at most
	// 253 characters. Reject an impossible name before creating a workspace.
	// An explicitly empty --name is a mistake, not a request to generate one.
	if err := a.validateName("blip", name); err != nil {
		return err
	}
	workdir := f.workdir
	if workdir == "" && a.self != nil {
		// The caller's root is the fork's root, so its directory exists.
		if cwd, err := cwdPath(); err == nil {
			workdir = cwd
		}
	}
	// The inherited directory is local, not a flag, so it is validated after
	// the caller's blip is known but still before the Blip is created.
	if workdir != f.workdir && !utf8.ValidString(workdir) {
		return fmt.Errorf("%w: workingDir contains invalid UTF-8", errInvalidUTF8)
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
		if b.Annotations == nil {
			b.Annotations = map[string]string{}
		}
		parent := a.short(a.self.Name)
		b.Labels[v1alpha1.LabelParent] = v1alpha1.ParentLabel(parent)
		b.Annotations[v1alpha1.AnnotationParent] = parent
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
	// Inside a blip, a fork runs in the caller's pool whether it forks the
	// caller's root (--from /), another workspace (--from), or runs an
	// existing one (--state). An explicit --pool still wins.
	if b.Spec.Pool == "" && a.self != nil {
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
		if msg := usableStateFailure(source); msg != "" {
			return fmt.Errorf("state %q failed: %s", a.short(source.Name), msg)
		}
		// The fork root takes the blip's name.
		b.Spec.State = name
	} else {
		root, err := a.resolveState(ctx, state)
		if err != nil {
			return err
		}
		if msg := usableStateFailure(root); msg != "" {
			return fmt.Errorf("state %q failed: %s", a.short(root.Name), msg)
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
	created, err := a.launch(ctx, b, source, !f.keep)
	if err != nil {
		// launch may have created the fork's states before it failed. They
		// must not outlive a run that never printed the blip: with --keep
		// they have no owner reference, so nothing would ever remove them.
		// The blip owns its workspace otherwise, so deleting it removes the
		// copies too.
		a.removeCreatedStates(ctx, created)
		delErr := c.Kube.Delete(context.WithoutCancel(ctx), b)
		if delErr != nil && !apierrors.IsNotFound(delErr) {
			err = errors.Join(err, fmt.Errorf("remove blip %q: %w", a.short(name), delErr))
		}
		return err
	}
	// An interrupt can arrive after the last wait. Remove the blip before
	// returning so an interrupted run does not leave a VM running. The
	// workspace of a --keep run has no owner, so remove it explicitly too.
	if err := ctx.Err(); err != nil {
		a.removeCreatedStates(ctx, created)
		delErr := c.Kube.Delete(context.WithoutCancel(ctx), b)
		if delErr != nil && !apierrors.IsNotFound(delErr) {
			err = errors.Join(err, fmt.Errorf("remove blip %q: %w", a.short(name), delErr))
		}
		return err
	}
	// A blip is a one-shot command executor. Close its stdin as soon as it
	// exists unless the caller asked to feed it with blip send. The guest may
	// not be connected yet; closeStdin retries briefly and gives up quietly.
	if !f.interactive {
		a.closeStdin(ctx, streamTarget{namespace: c.Namespace, state: b.Spec.State, blip: b.Name})
	}
	fmt.Fprintln(a.env.Out, a.short(b.Name))
	return nil
}

// launch creates the fork's states and waits until their first version is
// usable, which is the snapshot the caller relies on. It is a no-op when the
// blip runs in an existing workspace. It returns the states it created even
// when it fails, so the caller can remove a fork it cannot use.
func (a *app) launch(ctx context.Context, b *v1alpha1.Blip, source *v1alpha1.BlipState, owned bool) ([]*v1alpha1.BlipState, error) {
	if source == nil {
		return nil, nil
	}
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	fork := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: b.Name, Namespace: b.Namespace}}
	a.label(fork)
	var opts *workspace.ForkOptions
	if owned {
		ref := blipRef(b)
		opts = &workspace.ForkOptions{Owner: &ref}
	}
	created, err := workspace.Fork(ctx, c.Kube, source, fork, opts)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("state for blip %q already exists: %w", a.short(b.Name), err)
		}
		return nil, err
	}
	if _, err := a.waitStateCommitted(ctx, b.Name); err != nil {
		return created, err
	}
	for _, mount := range fork.Spec.Mounts {
		if !mount.Writable {
			continue
		}
		if _, err := a.waitStateCommitted(ctx, mount.State); err != nil {
			return created, err
		}
	}
	return created, nil
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
