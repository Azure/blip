package node

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/internal/registryauth"
)

// pullSecret names a Kubernetes secret holding registry credentials.
type pullSecret struct {
	Namespace string
	Name      string
}

// imageKeychain merges credentials from the given image pull secrets over the
// process's default keychain. A missing or unusable secret is an error.
func imageKeychain(ctx context.Context, r client.Reader, secrets []pullSecret) (authn.Keychain, error) {
	refs := make([]registryauth.PullSecret, 0, len(secrets))
	for _, ref := range secrets {
		refs = append(refs, registryauth.PullSecret{Namespace: ref.Namespace, Name: ref.Name})
	}
	return registryauth.Keychain(ctx, r, refs)
}

// registryHost normalizes a credential key or registry string to the host
// used by image references.
func registryHost(s string) string { return registryauth.Host(s) }
