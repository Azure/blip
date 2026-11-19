package registryauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Azure/blip/internal/registryauth"
)

const ns = "default"

func secretFor(t *testing.T, name, key, data string) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{key: []byte(data)},
	}
}

func TestKeychain(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	pull := secretFor(t, "pull", corev1.DockerConfigJsonKey,
		`{"auths":{"registry.local":{"auth":"`+auth+`"},"https://index.docker.io/v1/":{"username":"hub","password":"pw"}}}`)
	bad := secretFor(t, "bad", corev1.DockerConfigJsonKey, `{`)
	empty := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "opaque"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"other": []byte("x")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pull, bad, empty).Build()
	ctx := context.Background()

	kc, err := registryauth.Keychain(ctx, c, []registryauth.PullSecret{{Namespace: ns, Name: "pull"}})
	if err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string][2]string{
		"registry.local/repo:tag":       {"user", "pass"},
		"index.docker.io/library/x:tag": {"hub", "pw"},
	} {
		parsed, err := name.ParseReference(ref)
		if err != nil {
			t.Fatal(err)
		}
		a, err := authn.Resolve(ctx, kc, parsed.Context())
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := a.Authorization()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Username != want[0] || cfg.Password != want[1] {
			t.Errorf("%s: got %q/%q, want %q/%q", ref, cfg.Username, cfg.Password, want[0], want[1])
		}
	}
	// An unknown registry falls through to the default keychain, which has no
	// credentials for this test registry.
	parsed, err := name.ParseReference("other.example.com/library/x:y")
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.Resolve(ctx, kc, parsed.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := a.Authorization(); cfg.Username != "" || cfg.Password != "" {
		t.Fatalf("unexpected credentials for an unlisted registry: %+v", cfg)
	}

	for name, want := range map[string]string{
		"missing": "image pull secret default/missing",
		"bad":     "invalid",
		"opaque":  "has no .dockerconfigjson",
	} {
		_, err := registryauth.Keychain(ctx, c, []registryauth.PullSecret{{Namespace: ns, Name: name}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
		if !errors.Is(err, registryauth.ErrUnusableSecret) {
			t.Errorf("%s: err = %v is not classified as an unusable secret", name, err)
		}
	}
}

type failingReader struct{ err error }

func (r failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return r.err
}

func (r failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return r.err
}

// TestKeychainTransientReadErrorIsRetryable keeps an API server outage from
// turning an otherwise valid pull secret into a permanent state failure.
func TestKeychainTransientReadErrorIsRetryable(t *testing.T) {
	_, err := registryauth.Keychain(context.Background(), failingReader{apierrors.NewServiceUnavailable("try later")},
		[]registryauth.PullSecret{{Namespace: ns, Name: "pull"}})
	if err == nil {
		t.Fatal("transient secret read succeeded")
	}
	if errors.Is(err, registryauth.ErrUnusableSecret) {
		t.Fatalf("transient secret read classified as permanent: %v", err)
	}
}

func TestHost(t *testing.T) {
	for in, want := range map[string]string{
		"registry.local":                 "registry.local",
		"https://registry.local":         "registry.local",
		"https://registry.local/v1/":     "registry.local",
		"https://index.docker.io/v1/":    "index.docker.io",
		"docker.io":                      "index.docker.io",
		"registry.local:5000/repository": "registry.local:5000",
	} {
		if got := registryauth.Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}
