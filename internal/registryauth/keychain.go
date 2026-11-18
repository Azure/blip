// Package registryauth builds registry keychains from Kubernetes image pull
// secrets. Both the controller (to resolve digests and image config) and the
// node agent (to pull layers) use it, so a private image behaves the same in
// both places.
package registryauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PullSecret names a Kubernetes secret holding registry credentials.
type PullSecret struct {
	Namespace string
	Name      string
}

// Keychain merges credentials from secrets over the process's default
// keychain. A missing or unusable secret is an error: silently falling back to
// anonymous access would present a confusing registry failure instead.
func Keychain(ctx context.Context, r client.Reader, secrets []PullSecret) (authn.Keychain, error) {
	if len(secrets) == 0 {
		return authn.DefaultKeychain, nil
	}
	creds := map[string]authn.Authenticator{}
	seen := map[PullSecret]bool{}
	for _, ref := range secrets {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		var secret corev1.Secret
		if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &secret); err != nil {
			return nil, fmt.Errorf("image pull secret %s/%s: %w", ref.Namespace, ref.Name, err)
		}
		data, ok := secret.Data[corev1.DockerConfigJsonKey]
		if !ok {
			return nil, fmt.Errorf("image pull secret %s/%s: type %s has no %s",
				ref.Namespace, ref.Name, secret.Type, corev1.DockerConfigJsonKey)
		}
		var cfg dockerConfigJSON
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("image pull secret %s/%s: invalid %s: %w",
				ref.Namespace, ref.Name, corev1.DockerConfigJsonKey, err)
		}
		for registry, auth := range cfg.Auths {
			if host := Host(registry); host != "" {
				creds[host] = authn.FromConfig(auth)
			}
		}
	}
	return authn.NewMultiKeychain(secretKeychain{creds: creds}, authn.DefaultKeychain), nil
}

// RefList converts Kubernetes image pull secret references to namespaced
// PullSecrets.
func RefList(namespace string, refs []corev1.LocalObjectReference) []PullSecret {
	out := make([]PullSecret, 0, len(refs))
	for _, ref := range refs {
		if ref.Name != "" {
			out = append(out, PullSecret{Namespace: namespace, Name: ref.Name})
		}
	}
	return out
}

type dockerConfigJSON struct {
	Auths map[string]authn.AuthConfig `json:"auths"`
}

type secretKeychain struct {
	creds map[string]authn.Authenticator
}

func (k secretKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if a, ok := k.creds[Host(target.RegistryStr())]; ok {
		return a, nil
	}
	return authn.Anonymous, nil
}

// Host normalizes a credential key or registry string to the host used by
// image references.
func Host(s string) string {
	s = strings.TrimSpace(s)
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return name.DefaultRegistry
	}
	return s
}
