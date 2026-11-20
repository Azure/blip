// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func requestWithTLS(method, target string, certs ...*x509.Certificate) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return req
}

func TestUnauthenticated(t *testing.T) {
	s := New(Options{Backend: &fakeBackend{}})
	rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if st := decodeStatus(t, rec); st.Reason != metav1.StatusReasonUnauthorized || st.Code != 401 {
		t.Fatalf("status: %+v", st)
	}
	// Discovery is public: the API server must be able to aggregate the
	// group before it has a user to impersonate.
	rec = serve(s, http.MethodGet, "/apis")
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status %d", rec.Code)
	}
}

func TestInjectedAuthorizerAllowAndDeny(t *testing.T) {
	var got authorizer.Attributes
	allow := authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		got = a
		return authorizer.DecisionAllow, "", nil
	})
	s := New(Options{Backend: &fakeBackend{}, Insecure: true, Authorizer: allow})
	rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/team/blipstreams/demo/log?offset=4")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got.GetUser().GetName() != user.Anonymous {
		t.Fatalf("user = %q", got.GetUser().GetName())
	}
	if got.GetVerb() != "get" || got.GetAPIGroup() != GroupName || got.GetAPIVersion() != Version ||
		got.GetResource() != Resource || got.GetSubresource() != "log" ||
		got.GetNamespace() != "team" || got.GetName() != "demo" || !got.IsResourceRequest() {
		t.Fatalf("attributes = %+v", got)
	}

	got = nil
	rec = serve(s, http.MethodPost, "/apis/"+GroupVersion+"/namespaces/team/blipstreams/demo/stdin")
	if rec.Code != http.StatusOK {
		t.Fatalf("stdin status %d: %s", rec.Code, rec.Body)
	}
	if got.GetVerb() != "create" || got.GetSubresource() != "stdin" {
		t.Fatalf("stdin attributes = %+v", got)
	}

	deny := authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionDeny, "not yours", nil
	})
	s = New(Options{Backend: &fakeBackend{}, Insecure: true, Authorizer: deny})
	rec = serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/team/blipstreams/demo/log")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	st := decodeStatus(t, rec)
	if st.Reason != metav1.StatusReasonForbidden || st.Message != "forbidden: not yours" {
		t.Fatalf("status = %+v", st)
	}
}

func TestBearerTokenAndDelegatedSAR(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "alice",
					UID:      "u1",
					Groups:   []string{"devs"},
				},
			},
		}, nil
	})
	var sar *authorizationv1.SubjectAccessReview
	client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar = action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		return true, &authorizationv1.SubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})

	s := New(Options{Backend: &fakeBackend{}, Client: client})
	req := httptest.NewRequest(http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if sar == nil {
		t.Fatal("no SubjectAccessReview was sent")
	}
	if sar.Spec.User != "alice" || sar.Spec.UID != "u1" || len(sar.Spec.Groups) != 1 || sar.Spec.Groups[0] != "devs" {
		t.Fatalf("SAR user = %+v", sar.Spec)
	}
	ra := sar.Spec.ResourceAttributes
	if ra == nil || ra.Group != GroupName || ra.Version != Version || ra.Resource != Resource ||
		ra.Subresource != "log" || ra.Namespace != "ns" || ra.Name != "demo" || ra.Verb != "get" {
		t.Fatalf("SAR attributes = %+v", ra)
	}

	// An unauthenticated token is not accepted, and no SAR is made.
	sar = nil
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: false}}, nil
	})
	req = httptest.NewRequest(http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status %d: %s", rec.Code, rec.Body)
	}
	if sar != nil {
		t.Fatal("SAR sent for an unauthenticated token")
	}
}

func TestClientCertificateAuthentication(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeaf(t, ca, caKey, "alice", []string{"devs", "ops"})
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	var got user.Info
	s := New(Options{
		Backend:  &fakeBackend{},
		ClientCA: pool,
		Authorizer: authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			got = a.GetUser()
			return authorizer.DecisionAllow, "", nil
		}),
	})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, requestWithTLS(http.MethodGet,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", leaf))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got == nil || got.GetName() != "alice" || len(got.GetGroups()) != 2 ||
		!slices.Contains(got.GetGroups(), "devs") || !slices.Contains(got.GetGroups(), "ops") {
		t.Fatalf("user = %+v", got)
	}

	// A certificate from another CA is rejected.
	otherCA, otherKey := newCA(t)
	bad, _ := newLeaf(t, otherCA, otherKey, "mallory", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, requestWithTLS(http.MethodGet,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", bad))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted cert status %d: %s", rec.Code, rec.Body)
	}

	// With no authorizer and not insecure, access is denied by default.
	s = New(Options{Backend: &fakeBackend{}, ClientCA: pool})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, requestWithTLS(http.MethodGet,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", leaf))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("default deny status %d: %s", rec.Code, rec.Body)
	}
	if st := decodeStatus(t, rec); st.Reason != metav1.StatusReasonForbidden {
		t.Fatalf("status = %+v", st)
	}

	// A certificate without a configured CA is only accepted by insecure mode.
	s = New(Options{Backend: &fakeBackend{}})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, requestWithTLS(http.MethodGet,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log", leaf))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cert without CA status %d", rec.Code)
	}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, orgs []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
