package cli

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/workspace"
)

type createStateFlags struct {
	from, size    string
	replicas      int32
	detach        bool
	mounts, env   []string
	workdir, user string
	idle          time.Duration
	idleSet       bool
}

func (a *app) createCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create blip resources",
	}
	cmd.AddCommand(a.createStateCommand())
	return cmd
}

func (a *app) createStateCommand() *cobra.Command {
	f := &createStateFlags{}
	cmd := &cobra.Command{
		Use:     "blipstate NAME",
		Aliases: []string{"state", "bst"},
		Short:   "Create a durable state",
		Long: `Create a BlipState: one durable ext4 filesystem for a root or a mount.

With no source flag the state starts empty. --from copies a workspace's root,
runtime defaults and persistent mounts, including a separate live snapshot of
each writable filesystem. Read-only mounts keep their references. Use blip pull
to import a container image as a shared base.

--mount STATE:/path[:rw] adds a persistent mount to the new state. --mount
/path[:rw|ro] also attaches the new state to the Blip this command runs in,
writable unless :ro is given. Attaching waits for the first commit, so it cannot
be combined with --detach.`,
		Example: `  kubectl blip create blipstate repo --from base
  kubectl blip create blipstate dev --from base --size 20Gi --env EDITOR=vim
  kubectl blip create blipstate cache --size 20Gi --mount /cache
  blip create blipstate scratch -d`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.idleSet = cmd.Flags().Changed("idle-timeout")
			return a.createState(cmd.Context(), args[0], f, cmd.Flags().Changed("replicas"))
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.from, "from", "", "fork an existing workspace or imported base")
	fl.StringVar(&f.size, "size", "", "filesystem size, e.g. 20Gi (default 10Gi, or the source size)")
	fl.Int32Var(&f.replicas, "replicas", 0, "nodes holding each committed version, 1-3 (default 3)")
	fl.BoolVarP(&f.detach, "detach", "d", false, "return right after creating the state")
	fl.StringArrayVar(&f.mounts, "mount", nil, "mount STATE:/path[:rw] in the new state, or /path[:rw|ro] to attach the new state to this blip (writable by default; repeatable, but /path at most once)")
	fl.StringArrayVarP(&f.env, "env", "e", nil, "default environment variable KEY=VALUE (repeatable)")
	fl.StringVarP(&f.workdir, "workdir", "w", "", "default working directory")
	fl.StringVarP(&f.user, "user", "u", "", "default user name or uid")
	fl.DurationVar(&f.idle, "idle-timeout", 0, "default interactive idle timeout")
	return cmd
}

// selfMount is --mount /path: attach the new state to the blip this command
// runs in instead of configuring the new state.
type selfMount struct {
	path     string
	writable bool
}

// parseMountFlags splits --mount values into mounts configured on the new
// state and an optional attachment to the current blip.
func parseMountFlags(values []string) ([]v1alpha1.Mount, *selfMount, error) {
	var mounts []v1alpha1.Mount
	var attach *selfMount
	for _, value := range values {
		if !strings.HasPrefix(value, "/") {
			m, err := parseMount(value)
			if err != nil {
				return nil, nil, err
			}
			mounts = append(mounts, m)
			continue
		}
		if attach != nil {
			return nil, nil, errors.New("--mount PATH attaches the new state to this blip and can be used only once")
		}
		m, err := parseSelfMount(value)
		if err != nil {
			return nil, nil, err
		}
		attach = m
	}
	return mounts, attach, nil
}

// parseSelfMount parses /path[:rw|ro]. The attachment is writable by default.
func parseSelfMount(s string) (*selfMount, error) {
	p, mode, hasMode := strings.Cut(s, ":")
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return nil, fmt.Errorf("invalid mount %q: want /clean/absolute/path[:rw|ro]", s)
	}
	m := &selfMount{path: p, writable: true}
	if !hasMode {
		return m, nil
	}
	switch mode {
	case "rw":
	case "ro":
		m.writable = false
	default:
		return nil, fmt.Errorf("invalid mount %q: mode must be rw or ro", s)
	}
	return m, nil
}

func stateFromFlags(name, namespace string, f *createStateFlags, mounts []v1alpha1.Mount, replicasSet bool) (*v1alpha1.BlipState, error) {
	if replicasSet && (f.replicas < 1 || f.replicas > 3) {
		return nil, errors.New("--replicas must be between 1 and 3")
	}
	spec := v1alpha1.BlipStateSpec{CopyFrom: f.from}
	if replicasSet {
		spec.Replicas = f.replicas
	}
	if f.size != "" {
		size, err := resource.ParseQuantity(f.size)
		if err != nil {
			return nil, fmt.Errorf("invalid --size %q: %w", f.size, err)
		}
		if size.Sign() <= 0 {
			return nil, fmt.Errorf("invalid --size %q: must be positive", f.size)
		}
		spec.Size = &size
	}
	st := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}
	if err := applyStateSettings(st, f, mounts); err != nil {
		return nil, err
	}
	return st, nil
}

func applyStateSettings(st *v1alpha1.BlipState, f *createStateFlags, mounts []v1alpha1.Mount) error {
	if f.idle < 0 {
		return errors.New("--idle-timeout must not be negative")
	}
	env, err := parseEnv(f.env)
	if err != nil {
		return err
	}
	if len(env) > 0 || f.workdir != "" || f.user != "" || f.idleSet || f.idle > 0 {
		if st.Spec.Runtime == nil {
			st.Spec.Runtime = &v1alpha1.RuntimeDefaults{}
		}
		rt := st.Spec.Runtime
		for _, e := range env {
			found := false
			for i := range rt.Env {
				if rt.Env[i].Name == e.Name {
					rt.Env[i], found = e, true
					break
				}
			}
			if !found {
				rt.Env = append(rt.Env, e)
			}
		}
		if f.workdir != "" {
			rt.WorkingDir = f.workdir
		}
		if f.user != "" {
			rt.User = f.user
		}
		if f.idleSet || f.idle > 0 {
			rt.IdleTimeout = &metav1.Duration{Duration: f.idle}
		}
	}
	for _, m := range mounts {
		for _, existing := range st.Spec.Mounts {
			if existing.BlipUID != "" {
				continue
			}
			if existing.State == m.State {
				return fmt.Errorf("state %q is mounted twice", m.State)
			}
			if existing.Path == m.Path {
				return fmt.Errorf("mount path %q is used twice", m.Path)
			}
		}
		st.Spec.Mounts = append(st.Spec.Mounts, m)
	}
	return nil
}

func (a *app) createState(ctx context.Context, name string, f *createStateFlags, replicasSet bool) error {
	mounts, attach, err := parseMountFlags(f.mounts)
	if err != nil {
		return err
	}
	if attach != nil && f.detach {
		return fmt.Errorf("--detach cannot be combined with --mount %s; the new state must commit before it can be attached", attach.path)
	}
	if err := a.scope(&name); err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	st, err := stateFromFlags(name, c.Namespace, f, mounts, replicasSet)
	if err != nil {
		return err
	}
	a.label(st)
	if attach != nil {
		if a.self == nil {
			return fmt.Errorf("--mount %s attaches the new state to the current blip, but this command is not running inside one; use --mount STATE:%s or blip mount STATE [ROOT_STATE] --path %s", attach.path, attach.path, attach.path)
		}
		root, err := a.getState(ctx, a.self.Spec.State)
		if err != nil {
			return err
		}
		for _, m := range root.Spec.Mounts {
			if m.Path == attach.path {
				return fmt.Errorf("root state %q already has state %q mounted at %s", a.short(root.Name), a.short(m.State), m.Path)
			}
		}
	}
	var src *v1alpha1.BlipState
	existing := 0
	if f.from != "" {
		src, err = a.resolveState(ctx, f.from)
		if err != nil {
			return err
		}
		// Configure the snapshot before creating it. Fork will copy each
		// persistent writable mount, including mounts supplied with --mount.
		existing = len(src.Spec.Mounts)
		if err := applyStateSettings(src, f, mounts); err != nil {
			return err
		}
	}
	settings := st
	if src != nil {
		settings = src
	}
	for i := range settings.Spec.Mounts {
		mount := &settings.Spec.Mounts[i]
		if mount.BlipUID != "" {
			continue
		}
		var mounted *v1alpha1.BlipState
		var err error
		if src != nil && i < existing {
			// Existing references are already namespace-qualified names;
			// owner-local names must not shadow shared mount references.
			mounted, err = a.getState(ctx, mount.State)
		} else {
			mounted, err = a.resolveState(ctx, mount.State)
		}
		if err != nil {
			return err
		}
		mount.State = mounted.Name
		if src == nil && mount.Writable && mounted.Spec.Image != "" {
			return fmt.Errorf("state %q is an imported base; fork it before mounting writable", a.short(mounted.Name))
		}
	}
	if src != nil {
		err = workspace.Fork(ctx, c.Kube, src, st)
	} else {
		err = c.Kube.Create(ctx, st)
	}
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state %q already exists; delete it or choose another name", a.short(name))
		}
		return err
	}
	if f.detach {
		fmt.Fprintf(a.env.Out, "blipstate/%s created\n", a.short(name))
		return nil
	}
	if src != nil {
		for _, mount := range st.Spec.Mounts {
			if mount.Writable {
				if _, err := a.waitStateCommitted(ctx, mount.State); err != nil {
					return err
				}
			}
		}
	}
	st, err = a.waitStateCommitted(ctx, name)
	if err != nil {
		return err
	}
	if attach != nil {
		if err := a.attachToSelf(ctx, st.Name, attach); err != nil {
			return fmt.Errorf("blipstate/%s was created but could not be attached: %w", a.short(name), err)
		}
	}
	fmt.Fprintf(a.env.Out, "blipstate/%s %s\n", a.short(name), st.Status.Phase)
	return nil
}

// attachToSelf attaches a just-created state to the blip this command runs in.
// mountState accepts an offline root and defers the mount; require the current
// execution to be live so the command's promise is kept.
func (a *app) attachToSelf(ctx context.Context, state string, attach *selfMount) error {
	root, err := a.getState(ctx, a.self.Spec.State)
	if err != nil {
		return err
	}
	b, err := a.rootWriter(ctx, root)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("blip %q is not running root state %q", a.short(a.self.Name), a.short(root.Name))
	}
	return a.mountState(ctx, state, root.Name, attach.path, &attach.writable)
}

// stateFailure returns why a state cannot commit, or "" while it can still
// make progress. A failed first version with a pending commit is retried by
// the controller, so it is not terminal.
func stateFailure(s *v1alpha1.BlipState) string {
	if s.Status.Phase != v1alpha1.StateFailed || s.Status.Pending != nil {
		return ""
	}
	if s.Status.Message != "" {
		return s.Status.Message
	}
	return "creation failed"
}

// waitStateCommitted waits until the state's first commit is usable, whether
// it is Ready or already attached by a concurrent blip.
func (a *app) waitStateCommitted(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	r := &reporter{a: a}
	defer r.stop()
	var got *v1alpha1.BlipState
	err := a.waitState(ctx, name, func(s *v1alpha1.BlipState) (bool, error) {
		if s == nil {
			return false, fmt.Errorf("state %q was deleted", a.short(name))
		}
		got = s
		// The first commit is what makes a state usable, whether it is Ready
		// or already attached by a concurrent blip.
		if s.Status.Committed != nil {
			return true, nil
		}
		if msg := stateFailure(s); msg != "" {
			return false, fmt.Errorf("state %q failed: %s", a.short(name), msg)
		}
		if s.Status.Message != "" {
			r.say("waiting for state %s: %s", a.short(name), s.Status.Message)
		}
		return false, nil
	})
	return got, err
}
