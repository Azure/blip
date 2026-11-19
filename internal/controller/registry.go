package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"slices"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociv1 "github.com/google/go-containerregistry/pkg/v1"
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

// terminalImageError reports whether an image resolution error is permanent.
// Image references are immutable on a state, so a missing image or an
// unparsable reference can never recover by retrying. Other registry errors
// remain transient.
func terminalImageError(err error) bool {
	return errors.Is(err, ErrImageNotFound) ||
		errors.Is(err, ErrInvalidImage)
}

// notFound reports whether err is a permanent registry lookup failure. A 404
// or an unknown manifest/name/blob is content-addressed: retrying the same
// reference cannot succeed. Temporary errors are never terminal.
func notFound(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) || terr.Temporary() {
		return false
	}
	if terr.StatusCode == http.StatusNotFound {
		return true
	}
	for _, d := range terr.Errors {
		switch d.Code {
		case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode, transport.BlobUnknownErrorCode:
			return true
		}
	}
	return false
}

// Registry resolves container image references.
type Registry interface {
	// Digest returns the pinned reference repo@sha256:... for ref. For a
	// multi-platform image it is the digest of the index; nodes pick their
	// platform.
	Digest(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error)
	// ImageConfig returns the runtime configuration of ref's platform image.
	// The controller stores it in state status so copies and image states keep
	// their defaults after the image reference or source state is gone.
	ImageConfig(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (*v1.ImageConfig, error)
}

// RemoteRegistry talks to OCI registries. Registries in Insecure (host or
// host:port) are reached over plain HTTP.
type RemoteRegistry struct {
	Insecure []string
	// Reader loads image pull secrets. The controller sets it from the API
	// reader; tests that do not use secrets may leave it nil.
	Reader client.Reader
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

func (r RemoteRegistry) Digest(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error) {
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
	opts := r.options(ctx, kc)
	desc, err := remote.Head(parsed, opts...)
	if err != nil {
		full, gerr := remote.Get(parsed, opts...)
		if gerr != nil {
			if notFound(gerr) {
				return "", fmt.Errorf("image %s: %w", ref, ErrImageNotFound)
			}
			return "", gerr
		}
		desc = &full.Descriptor
	}
	return parsed.Context().Digest(desc.Digest.String()).String(), nil
}

func (r RemoteRegistry) ImageConfig(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (*v1.ImageConfig, error) {
	kc, err := r.keychain(ctx, namespace, secrets)
	if err != nil {
		return nil, err
	}
	return r.imageConfig(ctx, ref, kc)
}

func (r RemoteRegistry) imageConfig(ctx context.Context, ref string, kc authn.Keychain) (*v1.ImageConfig, error) {
	parsed, err := r.parse(ref)
	if err != nil {
		return nil, err
	}
	opts := append(r.options(ctx, kc), remote.WithPlatform(ociv1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	img, err := remote.Image(parsed, opts...)
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("image config %s: %v: %w", ref, err, ErrImageNotFound)
		}
		return nil, fmt.Errorf("image config %s: %w", ref, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("image config %s: %v: %w", ref, err, ErrImageNotFound)
		}
		return nil, fmt.Errorf("image config %s: %w", ref, err)
	}
	c := cf.Config
	return &v1.ImageConfig{
		Env:        c.Env,
		Entrypoint: c.Entrypoint,
		Cmd:        c.Cmd,
		WorkingDir: c.WorkingDir,
		User:       c.User,
	}, nil
}
