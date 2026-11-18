package controller

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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
