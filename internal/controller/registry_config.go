package controller

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	ociv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	corev1 "k8s.io/api/core/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// ImageConfig returns the runtime configuration of ref's platform image. The
// controller stores it in state status so copies and image states keep their
// defaults after the image reference or source state is gone.
func (r RemoteRegistry) ImageConfig(ctx context.Context, ref string) (*v1.ImageConfig, error) {
	return r.imageConfig(ctx, ref, authn.DefaultKeychain)
}

// ImageConfigWithPullSecrets is ImageConfig authenticated by image pull
// secrets in namespace.
func (r RemoteRegistry) ImageConfigWithPullSecrets(ctx context.Context, ref, namespace string, secrets []corev1.LocalObjectReference) (*v1.ImageConfig, error) {
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
	img, err := remote.Image(parsed,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
		remote.WithPlatform(ociv1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	if err != nil {
		return nil, fmt.Errorf("image config %s: %w", ref, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
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

// imageConfigFor resolves ref through an optional secret-aware registry.
func imageConfigFor(ctx context.Context, reg Registry, ref, namespace string, secrets []corev1.LocalObjectReference) (*v1.ImageConfig, error) {
	rr, ok := reg.(imageConfigResolver)
	if !ok {
		return nil, nil
	}
	if sr, ok := reg.(SecretRegistry); ok {
		return sr.ImageConfigWithPullSecrets(ctx, ref, namespace, secrets)
	}
	return rr.ImageConfig(ctx, ref)
}
