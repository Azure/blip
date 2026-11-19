package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"k8s.io/client-go/rest"
)

func TestDiscoverAPIServerAudiences(t *testing.T) {
	const issuer = "https://oidc.prod-aks.azure.com/tenant/cluster/"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","jwks_uri":"https://example.invalid/jwks"}`))
	}))
	defer server.Close()
	if got := discoverAPIServerAudiences(context.Background(), &rest.Config{Host: server.URL}); !reflect.DeepEqual(got, []string{issuer}) {
		t.Fatalf("audiences = %v, want %q", got, issuer)
	}
}

func TestDiscoverAPIServerAudiencesFailureIsEmpty(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	if got := discoverAPIServerAudiences(context.Background(), &rest.Config{Host: server.URL}); got != nil {
		t.Fatalf("audiences = %v, want none", got)
	}
	if got := discoverAPIServerAudiences(context.Background(), nil); got != nil {
		t.Fatalf("nil config audiences = %v", got)
	}
}
