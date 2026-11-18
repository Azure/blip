package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/registryauth"
)

// ErrImageNotFound means the registry has no such image.
var ErrImageNotFound = errors.New("not found")

// ErrInvalidImage means the image reference itself cannot be parsed. Retrying
// cannot fix it.
var ErrInvalidImage = errors.New("invalid image reference")

// Registry resolves container image references.
type Registry interface {
	// Digest returns the pinned reference repo@sha256:... for ref. For a
	// multi-platform image it is the digest of the index; nodes pick their
	// platform.
	Digest(ctx context.Context, ref string) (string, error)
}

// RemoteRegistry talks to OCI registries. Registries in Insecure (host or
// host:port) are reached over plain HTTP.
type RemoteRegistry struct {
	Insecure []string
	// Reader loads image pull secrets. The controller sets it from the API
	// reader; tests that do not use secrets may leave it nil.
	Reader client.Reader
}

// SecretRegistry resolves images with namespace-scoped pull secrets.
type SecretRegistry interface {
	DigestWithPullSecrets(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error)
	ImageConfigWithPullSecrets(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (*v1.ImageConfig, error)
}

func (r RemoteRegistry) parse(ref string) (name.Reference, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidImage, err)
	}
	if slices.Contains(r.Insecure, parsed.Context().RegistryStr()) {
		parsed, err := name.ParseReference(ref, name.Insecure)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidImage, err)
		}
		return parsed, nil
	}
	return parsed, nil
}

func (r RemoteRegistry) options(ctx context.Context, kc authn.Keychain) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(kc)}
}

func (r RemoteRegistry) keychain(ctx context.Context, namespace string, secrets []corev1.LocalObjectReference) (authn.Keychain, error) {
	if len(secrets) == 0 {
		return authn.DefaultKeychain, nil
	}
	if r.Reader == nil {
		return nil, fmt.Errorf("image pull secrets %s: no secret reader configured", namespace)
	}
	return registryauth.Keychain(ctx, r.Reader, registryauth.RefList(namespace, secrets))
}

func (r RemoteRegistry) Digest(ctx context.Context, ref string) (string, error) {
	return r.digest(ctx, ref, authn.DefaultKeychain)
}

func (r RemoteRegistry) DigestWithPullSecrets(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error) {
	kc, err := r.keychain(ctx, namespace, secrets)
	if err != nil {
		return "", err
	}
	return r.digest(ctx, ref, kc)
}

func (r RemoteRegistry) digest(ctx context.Context, ref string, kc authn.Keychain) (string, error) {
	parsed, err := r.parse(ref)
	if err != nil {
		return "", err
	}
	if d, ok := parsed.(name.Digest); ok {
		return d.String(), nil
	}
	opts := r.options(ctx, kc)
	desc, err := remote.Head(parsed, opts...)
	if err != nil {
		full, gerr := remote.Get(parsed, opts...)
		if gerr != nil {
			var terr *transport.Error
			if errors.As(gerr, &terr) && terr.StatusCode == http.StatusNotFound {
				return "", fmt.Errorf("image %s: %w", ref, ErrImageNotFound)
			}
			return "", gerr
		}
		desc = &full.Descriptor
	}
	return parsed.Context().Digest(desc.Digest.String()).String(), nil
}

// digestImage resolves ref using the registry's pull-secret support when
// available. Tests and other registries keep the plain interface.
func digestImage(ctx context.Context, reg Registry, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error) {
	if sr, ok := reg.(SecretRegistry); ok {
		return sr.DigestWithPullSecrets(ctx, ref, namespace, secrets)
	}
	return reg.Digest(ctx, ref)
}
