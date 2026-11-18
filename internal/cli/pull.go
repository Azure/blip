package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

type pullFlags struct {
	size    string
	secrets []string
	detach  bool
}

func (a *app) pullCommand() *cobra.Command {
	f := &pullFlags{}
	cmd := &cobra.Command{
		Use:   "pull BASE OCI_REF",
		Short: "Import an OCI image as a shared base state",
		Long: `Import an OCI image into a named, read-only base state. Wait for the
initial version to be ready unless --detach is set. Run --fork BASE creates an
independent writable workspace from it.`,
		Example: `  kubectl blip pull base ghcr.io/me/dev:latest --size 20Gi
  kubectl blip run dev --fork base`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.pull(cmd.Context(), args[0], args[1], f)
		},
	}
	cmd.Flags().StringVar(&f.size, "size", "", "filesystem size, e.g. 20Gi (default 10Gi)")
	cmd.Flags().StringArrayVar(&f.secrets, "image-pull-secret", nil, "registry credential Secret in this namespace (repeatable)")
	cmd.Flags().BoolVarP(&f.detach, "detach", "d", false, "return right after creating the base state")
	return cmd
}

func (a *app) pull(ctx context.Context, name, image string, f *pullFlags) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("OCI_REF must not be empty")
	}
	if err := a.scope(&name); err != nil {
		return err
	}
	c, _ := a.clients()
	st, err := stateFromFlags(name, c.Namespace, &createStateFlags{size: f.size}, false)
	if err != nil {
		return err
	}
	st.Spec.Image = image
	for _, secret := range f.secrets {
		if problems := validation.IsDNS1123Subdomain(secret); len(problems) > 0 {
			return fmt.Errorf("invalid --image-pull-secret %q: %s", secret, strings.Join(problems, "; "))
		}
		st.Spec.ImagePullSecrets = append(st.Spec.ImagePullSecrets, corev1.LocalObjectReference{Name: secret})
	}
	a.label(st)
	if err := c.Kube.Create(ctx, st); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("state %q already exists; choose another base name", a.short(name))
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
