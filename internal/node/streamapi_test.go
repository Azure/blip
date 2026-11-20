// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Azure/blip/internal/stream"
	"github.com/Azure/blip/internal/streamapi"
)

const testLogPath = "/apis/" + streamapi.GroupVersion + "/namespaces/ns/blipstreams/demo/log"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
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
	return testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca testCA) issue(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

type streamTestBackend struct{}

func (streamTestBackend) Log(context.Context, string, string, uint64, bool, func(stream.Record) error) error {
	return nil
}

func (streamTestBackend) Stdin(context.Context, string, string, []byte, bool, bool, uint64) (uint64, error) {
	return 0, nil
}

// streamTestServer drives the aggregated API and records the authenticated
// user of the last request.
type streamTestServer struct {
	server *streamapi.Server
	user   user.Info
}

func newStreamTestServer() *streamTestServer {
	s := &streamTestServer{}
	s.server = streamapi.New(streamapi.Options{
		Backend:           streamTestBackend{},
		TrustProxyHeaders: true,
		Authorizer: authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
			s.user = attrs.GetUser()
			return authorizer.DecisionAllow, "", nil
		}),
	})
	return s
}

func (s *streamTestServer) do(t *testing.T, cert *x509.Certificate, remoteUser string) *httptest.ResponseRecorder {
	t.Helper()
	s.user = nil
	req := httptest.NewRequest(http.MethodGet, testLogPath, nil)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	if remoteUser != "" {
		req.Header.Set("X-Remote-User", remoteUser)
	}
	rec := httptest.NewRecorder()
	s.server.Handler().ServeHTTP(rec, req)
	return rec
}

func authConfigMap(resourceVersion string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       authConfigMapNamespace,
			Name:            authConfigMapName,
			ResourceVersion: resourceVersion,
		},
		Data: data,
	}
}

func TestParseClientAuth(t *testing.T) {
	headerCA := newTestCA(t)
	clientCA := newTestCA(t)
	auth, err := parseClientAuth(map[string]string{
		"requestheader-client-ca-file": string(headerCA.pem),
		"requestheader-allowed-names":  "front-proxy-client, system:master, ",
		"client-ca-file":               string(clientCA.pem),
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.requestHeaderCA == nil || auth.clientCA == nil {
		t.Fatalf("missing CA pools: %+v", auth)
	}
	if want := []string{"front-proxy-client", "system:master"}; !slices.Equal(auth.allowedNames, want) {
		t.Fatalf("allowed names = %q, want %q", auth.allowedNames, want)
	}
	if _, err := headerCA.cert.Verify(x509.VerifyOptions{Roots: auth.requestHeaderCA}); err != nil {
		t.Fatalf("request-header CA: %v", err)
	}
	if _, err := clientCA.cert.Verify(x509.VerifyOptions{Roots: auth.clientCA}); err != nil {
		t.Fatalf("client CA: %v", err)
	}

	// A missing request-header CA disables proxy headers but keeps the
	// client CA.
	auth, err = parseClientAuth(map[string]string{"client-ca-file": string(clientCA.pem)})
	if err != nil {
		t.Fatal(err)
	}
	if auth.requestHeaderCA != nil || auth.clientCA == nil || len(auth.allowedNames) != 0 {
		t.Fatalf("missing request-header CA = %+v", auth)
	}

	// An unparseable bundle is an error so the previous credentials stay.
	if _, err := parseClientAuth(map[string]string{"requestheader-client-ca-file": "not a certificate"}); err == nil {
		t.Fatal("invalid request-header CA was accepted")
	}
	if _, err := parseClientAuth(map[string]string{"client-ca-file": "not a certificate"}); err == nil {
		t.Fatal("invalid client CA was accepted")
	}
}

func TestReloadClientAuthSwapsCA(t *testing.T) {
	first := newTestCA(t)
	second := newTestCA(t)
	firstProxy := first.issue(t, "front-proxy-client")
	secondProxy := second.issue(t, "front-proxy-client")

	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	client := fake.NewClientset(authConfigMap("1", map[string]string{
		"requestheader-client-ca-file": string(first.pem),
	}))
	srv := newStreamTestServer()

	rv, err := reloadClientAuth(ctx, client, srv.server, "", log)
	if err != nil || rv != "1" {
		t.Fatalf("initial reload = %q, %v", rv, err)
	}
	if rec := srv.do(t, firstProxy, "admin"); rec.Code != http.StatusOK || srv.user.GetName() != "admin" {
		t.Fatalf("first CA: status %d, user %+v: %s", rec.Code, srv.user, rec.Body)
	}
	if rec := srv.do(t, secondProxy, "admin"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("second CA before swap: status %d: %s", rec.Code, rec.Body)
	}

	cm, err := client.CoreV1().ConfigMaps(authConfigMapNamespace).Get(ctx, authConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.ResourceVersion = "2"
	cm.Data = map[string]string{
		"requestheader-client-ca-file": string(second.pem),
		"requestheader-allowed-names":  "front-proxy-client",
	}
	if _, err := client.CoreV1().ConfigMaps(authConfigMapNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	rv, err = reloadClientAuth(ctx, client, srv.server, rv, log)
	if err != nil || rv != "2" {
		t.Fatalf("reload after update = %q, %v", rv, err)
	}
	if rec := srv.do(t, firstProxy, "admin"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first CA after swap: status %d: %s", rec.Code, rec.Body)
	}
	if rec := srv.do(t, secondProxy, "admin"); rec.Code != http.StatusOK || srv.user.GetName() != "admin" {
		t.Fatalf("second CA after swap: status %d, user %+v: %s", rec.Code, srv.user, rec.Body)
	}

	// An unchanged resource version keeps the current credentials without
	// reparsing.
	cm, err = client.CoreV1().ConfigMaps(authConfigMapNamespace).Get(ctx, authConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data = map[string]string{"requestheader-client-ca-file": string(first.pem)}
	if _, err := client.CoreV1().ConfigMaps(authConfigMapNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := reloadClientAuth(ctx, client, srv.server, rv, log); err != nil || got != rv {
		t.Fatalf("unchanged reload = %q, %v", got, err)
	}
	if rec := srv.do(t, secondProxy, "admin"); rec.Code != http.StatusOK {
		t.Fatalf("unchanged version swapped CA: status %d", rec.Code)
	}
}

func TestStreamAuthFromConfigMap(t *testing.T) {
	headerCA := newTestCA(t)
	clientCA := newTestCA(t)
	proxy := headerCA.issue(t, "front-proxy-client")
	other := headerCA.issue(t, "workload")
	client := clientCA.issue(t, "alice")

	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	clientSet := fake.NewClientset()
	srv := newStreamTestServer()

	// Without the ConfigMap no CA is configured, so proxy headers are
	// rejected even when the caller presents a certificate.
	if _, err := reloadClientAuth(ctx, clientSet, srv.server, "", log); err == nil {
		t.Fatal("reload succeeded without the ConfigMap")
	}
	if rec := srv.do(t, proxy, "admin"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no CA: status %d: %s", rec.Code, rec.Body)
	}

	// A client CA without a request-header CA still rejects proxy headers
	// but verifies direct client certificates.
	cm := authConfigMap("1", map[string]string{"client-ca-file": string(clientCA.pem)})
	if _, err := clientSet.CoreV1().ConfigMaps(authConfigMapNamespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reloadClientAuth(ctx, clientSet, srv.server, "", log); err != nil {
		t.Fatal(err)
	}
	if rec := srv.do(t, proxy, "admin"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("client CA only: status %d: %s", rec.Code, rec.Body)
	}
	if rec := srv.do(t, client, ""); rec.Code != http.StatusOK || srv.user.GetName() != "alice" {
		t.Fatalf("client certificate: status %d, user %+v: %s", rec.Code, srv.user, rec.Body)
	}
	// A direct certificate cannot forge proxy identity headers.
	if rec := srv.do(t, client, "admin"); rec.Code != http.StatusOK || srv.user.GetName() != "alice" {
		t.Fatalf("forged headers: status %d, user %+v: %s", rec.Code, srv.user, rec.Body)
	}

	// Publishing the request-header CA and an allowed name enables proxy
	// identity, and a certificate with another common name is rejected.
	cm, err := clientSet.CoreV1().ConfigMaps(authConfigMapNamespace).Get(ctx, authConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.ResourceVersion = "2"
	cm.Data["requestheader-client-ca-file"] = string(headerCA.pem)
	cm.Data["requestheader-allowed-names"] = "front-proxy-client"
	if _, err := clientSet.CoreV1().ConfigMaps(authConfigMapNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reloadClientAuth(ctx, clientSet, srv.server, "1", log); err != nil {
		t.Fatal(err)
	}
	if rec := srv.do(t, proxy, "admin"); rec.Code != http.StatusOK || srv.user.GetName() != "admin" {
		t.Fatalf("allowed proxy: status %d, user %+v: %s", rec.Code, srv.user, rec.Body)
	}
	if rec := srv.do(t, other, "admin"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disallowed proxy CN: status %d: %s", rec.Code, rec.Body)
	}
}
