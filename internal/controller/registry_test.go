package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ociv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRemoteRegistry(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	repo, err := name.NewRepository(u.Host + "/blip/base")
	if err != nil {
		t.Fatal(err)
	}

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(repo.Tag("v1"), img); err != nil {
		t.Fatal(err)
	}
	idx, err := random.Index(1024, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(repo.Tag("multi"), idx); err != nil {
		t.Fatal(err)
	}
	imgDigest, _ := img.Digest()
	idxDigest, _ := idx.Digest()

	r := RemoteRegistry{}
	ctx := context.Background()
	for tag, want := range map[string]string{"v1": imgDigest.String(), "multi": idxDigest.String()} {
		pinned, err := r.Digest(ctx, repo.Tag(tag).String(), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if pinned != repo.String()+"@"+want {
			t.Fatalf("%s pinned %q, want digest %s", tag, pinned, want)
		}
		if again, _ := r.Digest(ctx, pinned, "", nil); again != pinned {
			t.Errorf("digest reference not kept: %q", again)
		}
	}
	if _, err := r.Digest(ctx, repo.Tag("missing").String(), "", nil); !errors.Is(err, ErrImageNotFound) {
		t.Errorf("missing tag: %v", err)
	}
	missingDigest := repo.Digest("sha256:" + strings.Repeat("1", 64)).String()
	if _, err := r.Digest(ctx, missingDigest, "", nil); !errors.Is(err, ErrImageNotFound) {
		t.Errorf("missing digest: %v", err)
	}
	if _, err := r.ImageConfig(ctx, missingDigest, "", nil); !errors.Is(err, ErrImageNotFound) {
		t.Errorf("missing digest config: %v", err)
	}
	_, parseErr := name.ParseReference("bad image!!")
	if _, err := r.Digest(ctx, "bad image!!", "", nil); !errors.Is(err, ErrInvalidImage) {
		t.Errorf("invalid reference not classified: %v", err)
	} else if !strings.Contains(err.Error(), parseErr.Error()) {
		t.Errorf("invalid reference lost the parse error: %v", err)
	}

	insecure := RemoteRegistry{Insecure: []string{"registry.kind:5000"}}
	ref, err := insecure.parse("registry.kind:5000/blip/base:v1")
	if err != nil || ref.Context().Scheme() != "http" {
		t.Errorf("insecure registry scheme %v %v", ref, err)
	}
	ref, _ = insecure.parse("registry.example:5000/blip/base:v1")
	if ref.Context().Scheme() != "https" {
		t.Errorf("secure registry scheme %s", ref.Context().Scheme())
	}
}

// TestPlatformMismatchIsTerminal: an index whose only child targets another
// architecture can never resolve on this node. It must be classified as a
// permanent image error rather than retried forever.
func TestPlatformMismatchIsTerminal(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	repo, err := name.NewRepository(u.Host + "/blip/base")
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: img,
		Descriptor: ociv1.Descriptor{Platform: &ociv1.Platform{
			OS:           "linux",
			Architecture: runtime.GOARCH + "-other",
		}},
	})
	if err := remote.WriteIndex(repo.Tag("other"), idx); err != nil {
		t.Fatal(err)
	}

	r := RemoteRegistry{}
	ctx := context.Background()
	pinned, err := r.Digest(ctx, repo.Tag("other").String(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ImageConfig(ctx, pinned, "", nil)
	if !errors.Is(err, ErrUnsupportedImage) {
		t.Fatalf("platform mismatch = %v, want ErrUnsupportedImage", err)
	}
	if !terminalImageError(err) {
		t.Fatalf("platform mismatch classified as retryable: %v", err)
	}
	if !terminalImageError(errors.New("no child with platform linux/amd64 in index x")) {
		t.Fatal("plain platform mismatch classified as retryable")
	}
	if !strings.Contains(err.Error(), "no child with platform") {
		t.Fatalf("platform mismatch lost the registry detail: %v", err)
	}
}

// TestNotFoundClassification keeps transient registry errors retryable while
// permanent not-found responses become terminal.
func TestNotFoundClassification(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"404", &transport.Error{StatusCode: http.StatusNotFound}, true},
		{"manifest unknown", &transport.Error{StatusCode: http.StatusInternalServerError,
			Errors: []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}}}, true},
		{"name unknown", &transport.Error{StatusCode: http.StatusNotFound,
			Errors: []transport.Diagnostic{{Code: transport.NameUnknownErrorCode}}}, true},
		{"unavailable", &transport.Error{StatusCode: http.StatusServiceUnavailable}, false},
		{"too many requests", &transport.Error{StatusCode: http.StatusTooManyRequests,
			Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode}}}, false},
		{"generic", errors.New("connection reset"), false},
	} {
		if got := notFound(tt.err); got != tt.want {
			t.Errorf("%s: notFound = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestAuthRejectionIsTerminal: a registry that rejects the state's
// imagePullSecrets with 401/403 can never succeed on a retry, because the
// secret reference is immutable. It must be classified as terminal so the
// controller fails the state instead of leaving `blip pull` waiting on
// Pending forever. Server errors stay retryable.
func TestAuthRejectionIsTerminal(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int
		terminal bool
	}{
		{"unauthorized", http.StatusUnauthorized, true},
		{"forbidden", http.StatusForbidden, true},
		{"server error", http.StatusInternalServerError, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, `{"details":"incorrect username or password"}`)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "badcred"},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(
					fmt.Sprintf(`{"auths":{%q:{"username":"nouser","password":"definitely-wrong"}}}`, u.Host))},
			}
			c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(secret).Build()
			r := RemoteRegistry{Reader: c}
			ctx := context.Background()
			ref := u.Host + "/library/hello-world:latest"
			secrets := []corev1.LocalObjectReference{{Name: "badcred"}}

			_, err := r.Digest(ctx, ref, ns, secrets)
			if err == nil {
				t.Fatal("Digest succeeded against a rejecting registry")
			}
			if got := terminalImageError(err); got != tt.terminal {
				t.Fatalf("Digest error %v: terminal = %v, want %v", err, got, tt.terminal)
			}
			if tt.terminal {
				if !errors.Is(err, ErrAuthRejected) {
					t.Fatalf("rejected credentials not classified: %v", err)
				}
				if !strings.Contains(err.Error(), "incorrect username or password") {
					t.Fatalf("terminal error lost the registry detail: %v", err)
				}
			}

			_, err = r.ImageConfig(ctx, ref, ns, secrets)
			if err == nil {
				t.Fatal("ImageConfig succeeded against a rejecting registry")
			}
			if got := terminalImageError(err); got != tt.terminal {
				t.Fatalf("image config error %v: terminal = %v, want %v", err, got, tt.terminal)
			}
			if tt.terminal && !errors.Is(err, ErrAuthRejected) {
				t.Fatalf("rejected credentials not classified: %v", err)
			}
		})
	}
}

// TestAuthRejectionClassification pins the classification itself, including
// that a 401 without supplied credentials is left to the existing retry path.
func TestAuthRejectionClassification(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"401", &transport.Error{StatusCode: http.StatusUnauthorized}, true},
		{"403", &transport.Error{StatusCode: http.StatusForbidden}, true},
		{"401 with detail", &transport.Error{StatusCode: http.StatusUnauthorized,
			Errors: []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode, Message: "incorrect username or password"}}}, true},
		{"500", &transport.Error{StatusCode: http.StatusInternalServerError}, false},
		{"503", &transport.Error{StatusCode: http.StatusServiceUnavailable}, false},
		{"timeout", &transport.Error{StatusCode: http.StatusGatewayTimeout}, false},
		{"network", errors.New("connection reset"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := classifyAuthRejection(tt.err, "reg/img:latest", []corev1.LocalObjectReference{{Name: "creds"}})
			if got := terminalImageError(wrapped); got != tt.want {
				t.Fatalf("terminalImageError(%v) = %v, want %v", wrapped, got, tt.want)
			}
			if tt.want && !errors.Is(wrapped, ErrAuthRejected) {
				t.Fatalf("%v not marked ErrAuthRejected", wrapped)
			}
		})
	}
	if got := terminalImageError(classifyAuthRejection(
		&transport.Error{StatusCode: http.StatusUnauthorized}, "reg/img:latest", nil)); got {
		t.Fatal("anonymous 401 classified as terminal without supplied credentials")
	}
}
