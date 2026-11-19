package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strings"

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

// ErrUnsupportedImage means the pinned image has no manifest for the node's
// platform. Both the image digest and the node architecture are fixed, so
// retrying the same reference can never succeed.
var ErrUnsupportedImage = errors.New("image has no manifest for this platform")

// ErrAuthRejected means the registry rejected the image pull credentials the
// state supplied. The imagePullSecrets reference is immutable, so the same
// credentials are retried forever on every reconcile while `blip pull` waits
// on Pending. Mark it terminal so the user sees the auth error and can fix the
// Secret.
var ErrAuthRejected = errors.New("registry rejected image pull credentials")

// terminalImageError reports whether an image resolution error is permanent.
// Image references and imagePullSecrets are immutable on a state, so a
// missing image, an unparsable reference, an image without a manifest for the
// node platform, an unusable pull secret, or a rejected pull credential can
// never recover by retrying. Other registry errors remain transient.
func terminalImageError(err error) bool {
	return errors.Is(err, ErrImageNotFound) ||
		errors.Is(err, ErrInvalidImage) ||
		errors.Is(err, ErrUnsupportedImage) ||
		errors.Is(err, ErrAuthRejected) ||
		errors.Is(err, registryauth.ErrUnusableSecret) ||
		platformMismatch(err)
}

// classifyAuthRejection marks a 401/403 from the registry as terminal when the
// state supplied image pull secrets: retrying the same rejected credentials
// cannot succeed. Without supplied secrets the existing retry path is kept,
// and transient network/5xx errors are never reclassified.
func classifyAuthRejection(err error, ref string, secrets []corev1.LocalObjectReference) error {
	if err == nil || len(secrets) == 0 {
		return err
	}
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return err
	}
	if terr.StatusCode != http.StatusUnauthorized && terr.StatusCode != http.StatusForbidden {
		return err
	}
	return fmt.Errorf("%w for image %s: %v", ErrAuthRejected, ref, err)
}

// platformMismatch reports whether err is go-containerregistry's "no child
// with platform ..." error. It is a plain error, not a *transport.Error, so
// notFound cannot classify it.
func platformMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no child with platform ")
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
		return nil, registryauth.UnusableSecret(fmt.Errorf("image pull secrets %s: no secret reader configured", namespace))
	}
	return registryauth.Keychain(ctx, r.Reader, registryauth.RefList(namespace, secrets))
}

func (r RemoteRegistry) Digest(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (string, error) {
	kc, err := r.keychain(ctx, namespace, secrets)
	if err != nil {
		return "", err
	}
	pinned, err := r.digest(ctx, ref, kc)
	if err != nil {
		return "", classifyAuthRejection(err, ref, secrets)
	}
	return pinned, nil
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
	cfg, err := r.imageConfig(ctx, ref, kc)
	if err != nil {
		return nil, classifyAuthRejection(err, ref, secrets)
	}
	return cfg, nil
}

func (r RemoteRegistry) imageConfig(ctx context.Context, ref string, kc authn.Keychain) (*v1.ImageConfig, error) {
	parsed, err := r.parse(ref)
	if err != nil {
		return nil, err
	}
	opts := append(r.options(ctx, kc), remote.WithPlatform(ociv1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	img, err := remote.Image(parsed, opts...)
	if err != nil {
		if platformMismatch(err) {
			return nil, fmt.Errorf("%w: image config %s: %v", ErrUnsupportedImage, ref, err)
		}
		if notFound(err) {
			return nil, fmt.Errorf("image config %s: %v: %w", ref, err, ErrImageNotFound)
		}
		return nil, fmt.Errorf("image config %s: %w", ref, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		if platformMismatch(err) {
			return nil, fmt.Errorf("%w: image config %s: %v", ErrUnsupportedImage, ref, err)
		}
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
