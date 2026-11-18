package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

type createStateFlags struct {
	image, from, size string
	replicas          int32
	detach            bool
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

With no source flag the state starts empty. --image initializes it from a
container image; --from copies an existing state, including a live snapshot
when that state is being written.`,
		Example: `  kubectl blip create blipstate repo --from base
  kubectl blip create blipstate dev --image ghcr.io/me/dev:latest --size 20Gi
  blip create blipstate scratch -d`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.createState(cmd.Context(), args[0], f, cmd.Flags().Changed("replicas"))
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.image, "image", "", "initialize the filesystem from a container image")
	fl.StringVar(&f.from, "from", "", "copy an existing state (fork)")
	fl.StringVar(&f.size, "size", "", "filesystem size, e.g. 20Gi (default 10Gi, or the source size)")
	fl.Int32Var(&f.replicas, "replicas", 0, "nodes holding each committed version, 1-3 (default 3)")
	fl.BoolVarP(&f.detach, "detach", "d", false, "return right after creating the state")
	return cmd
}

func stateFromFlags(name, namespace string, f *createStateFlags, replicasSet bool) (*v1alpha1.BlipState, error) {
	if f.image != "" && f.from != "" {
		return nil, errors.New("set at most one of --image and --from")
	}
	if f.image != "" && replicasSet {
		return nil, errors.New("--replicas cannot be set with --image: image states are held by every eligible node")
	}
	if replicasSet && (f.replicas < 1 || f.replicas > 3) {
		return nil, errors.New("--replicas must be between 1 and 3")
	}
	spec := v1alpha1.BlipStateSpec{Image: f.image, CopyFrom: f.from}
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
	return &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}, nil
}

func (a *app) createState(ctx context.Context, name string, f *createStateFlags, replicasSet bool) error {
	if err := a.scope(&name); err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	f.from = a.full(f.from)
	st, err := stateFromFlags(name, c.Namespace, f, replicasSet)
	if err != nil {
		return err
	}
	if f.from != "" {
		// Fail a typo before creating anything. A live source is allowed:
		// the controller freezes it and takes a snapshot.
		src, err := a.getState(ctx, f.from)
		if err != nil {
			return err
		}
		if src.DeletionTimestamp != nil {
			return fmt.Errorf("copy source %q is being deleted", a.short(f.from))
		}
		if src.Status.Committed == nil {
			if msg := stateFailure(src); msg != "" {
				return fmt.Errorf("copy source %q failed: %s", a.short(f.from), msg)
			}
		}
	}
	a.label(st)
	if err := c.Kube.Create(ctx, st); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state %q already exists; delete it or choose another name", a.short(name))
		}
		return err
	}
	if f.detach {
		fmt.Fprintf(a.env.Out, "blipstate/%s created\n", a.short(name))
		return nil
	}
	st, err = a.waitState(ctx, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.env.Out, "blipstate/%s %s\n", a.short(name), st.Status.Phase)
	return nil
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

func (a *app) waitState(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	r := &reporter{a: a}
	defer r.stop()
	var got *v1alpha1.BlipState
	err = waitFor(ctx, c.Kube, &v1alpha1.BlipStateList{}, client.ObjectKey{Namespace: c.Namespace, Name: name},
		func() *v1alpha1.BlipState { return &v1alpha1.BlipState{} },
		func(s *v1alpha1.BlipState) (bool, error) {
			if s == nil {
				return false, fmt.Errorf("state %q was deleted", a.short(name))
			}
			got = s
			// The first commit is what makes a state usable, whether it is
			// Ready or already attached by a concurrent blip.
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
