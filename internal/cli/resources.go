package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// validateName rejects a name that can never be a Kubernetes object name with
// the same short message every command uses. Without it, an empty or malformed
// name reaches client-go or the API server and leaks a raw validation error.
func (a *app) validateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("invalid %s name %q: must not be empty", kind, name)
	}
	if problems := validation.IsDNS1123Subdomain(name); len(problems) > 0 {
		msg := fmt.Sprintf("invalid %s name %q: %s", kind, name, strings.Join(problems, "; "))
		// A scoped name is checked with its owner prefix. If the name the
		// user typed would be valid on its own, say why scoping rejected it
		// instead of quoting the short form against a limit it meets.
		if short := a.short(name); short != name && len(validation.IsDNS1123Subdomain(short)) == 0 {
			msg += fmt.Sprintf("; the %q owner prefix is part of the name and counts toward the limit, so use a shorter name", a.prefix)
		}
		return errors.New(msg)
	}
	return nil
}

// get fetches the named object into obj. It returns the API error unchanged, so
// callers can fall back or ignore NotFound before reporting it with notFound.
func get[T client.Object](ctx context.Context, c *Clients, name string, obj T) (T, error) {
	var zero T
	if err := c.Kube.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, obj); err != nil {
		return zero, err
	}
	return obj, nil
}

// notFound turns a missing object into the command's standard message. Any
// other error, including nil, passes through.
func notFound(kind, name, namespace string, err error) error {
	if err != nil && apierrors.IsNotFound(err) {
		return fmt.Errorf("%s %q not found in namespace %q", kind, name, namespace)
	}
	return err
}

func (a *app) getBlip(ctx context.Context, name string) (*v1alpha1.Blip, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	b, err := get(ctx, c, name, &v1alpha1.Blip{})
	return b, notFound("blip", name, c.Namespace, err)
}

func (a *app) getState(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	s, err := get(ctx, c, name, &v1alpha1.BlipState{})
	return s, notFound("state", name, c.Namespace, err)
}

func findMount(list []v1alpha1.MountStatus, state string) *v1alpha1.MountStatus {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
}

func findSpecMount(list []v1alpha1.Mount, state string) *v1alpha1.Mount {
	for i := range list {
		if list[i].State == state {
			return &list[i]
		}
	}
	return nil
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
