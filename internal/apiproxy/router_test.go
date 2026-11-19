// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package apiproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) issue(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range dnsNames {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// endpointTLSUpstream serves TLS with a certificate for localhost and returns
// the CA PEM for pinning.
func endpointTLSUpstream(t *testing.T, handler http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()
	ca := newTestCA(t, "test endpoint CA")
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "localhost")},
		MinVersion:   tls.VersionTLS12,
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, ca.pem
}

type observedRequest struct {
	method string
	host   string
	uri    string
	sni    string
	auth   string
	header http.Header
	body   string
}

func closeTransports(transports []*http.Transport) {
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func serveHandler(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestRouterRoutesAPIHost(t *testing.T) {
	observed := make(chan observedRequest, 2)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/test-ns/pods/test-pod":
			_, _ = io.WriteString(w, `{"metadata":{"name":"test-pod",`+
				`"annotations":{"blip.dev/blip":"owner.blip"},`+
				`"labels":{"blip.dev/blip-uid":"uid-test"}}}`)
			return
		case "/apis/blip.dev/v1alpha1/namespaces/test-ns/blips/owner.blip":
			_, _ = io.WriteString(w, `{"metadata":{"name":"owner.blip","uid":"uid-test",`+
				`"labels":{"blip.dev/owner":"owner"}}}`)
			return
		}
		observed <- observedRequest{method: r.Method, host: r.Host, uri: r.RequestURI, auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(t, upstream)
	handler, transports, err := newRouter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransports(transports)

	for _, host := range []string{"kube-apiserver", "KUBE-APISERVER.:80"} {
		req := httptest.NewRequest(http.MethodGet, "http://kube-apiserver/api/v1/namespaces/test-ns/pods?watch=true", nil)
		req.Host = host
		recorder := serveHandler(handler, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("Host %q: status = %d body=%q", host, recorder.Code, recorder.Body.String())
		}
		got := <-observed
		if got.host != cfg.API.Address || got.auth != "Bearer projected-secret" ||
			!strings.HasPrefix(got.uri, "/api/v1/namespaces/test-ns/pods?") ||
			!strings.Contains(got.uri, "watch=true") || !strings.Contains(got.uri, "labelSelector=") {
			t.Errorf("Host %q: upstream request = %+v", host, got)
		}
	}
}

func TestRouterRoutesEndpointHost(t *testing.T) {
	var requests atomic.Int32
	observed := make(chan observedRequest, 8)
	upstream, caPEM := endpointTLSUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		observed <- observedRequest{
			method: r.Method, host: r.Host, uri: r.RequestURI,
			sni: r.TLS.ServerName, auth: r.Header.Get("Authorization"),
			header: r.Header.Clone(), body: string(body),
		}
		w.WriteHeader(http.StatusNoContent)
	})
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "endpoint-ca.crt")
	writeFile(t, caFile, caPEM)
	tokenFile := filepath.Join(dir, "endpoint-token")
	writeFile(t, tokenFile, []byte("endpoint-secret\n"))
	endpointURL := "https://localhost:" + port
	cfg := Config{Endpoints: []Endpoint{
		{Name: "payments", URL: endpointURL, TokenFile: tokenFile, CAFile: caFile},
		{Name: "a", URL: endpointURL, CAFile: caFile},
	}}
	handler, transports, err := newRouter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransports(transports)
	wantHost := "localhost:" + port

	for _, host := range []string{"payments", "payments:80", "Payments.:80"} {
		req := httptest.NewRequest(http.MethodPost, "http://payments/path/a%2Fb?x=1&x=two+words", strings.NewReader("payload"))
		req.Host = host
		for _, key := range []string{
			"Authorization", "Proxy-Authorization", "Impersonate-User", "Impersonate-Group",
			"X-Remote-User", "X-Remote-Group", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
			"X-Forwarded-Proto", "X-Real-IP", "Via",
		} {
			req.Header.Set(key, "caller-controlled")
		}
		req.Header.Set("Connection", "keep-alive, Authorization, Impersonate-User, X-Remote-User, X-Forwarded-For")
		req.Header.Set("X-Endpoint-Safe", "preserved")
		recorder := serveHandler(handler, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("Host %q: status = %d body=%q", host, recorder.Code, recorder.Body.String())
		}
		got := <-observed
		if got.method != http.MethodPost || got.host != wantHost || got.sni != "localhost" ||
			got.uri != "/path/a%2Fb?x=1&x=two+words" || got.body != "payload" ||
			got.auth != "Bearer endpoint-secret" {
			t.Errorf("Host %q: upstream request = %+v", host, got)
		}
		for key := range req.Header {
			if key != "Authorization" && key != "X-Endpoint-Safe" && got.header.Get(key) != "" {
				t.Errorf("Host %q: caller header survived: %s: %q", host, key, got.header.Values(key))
			}
		}
		if got.header.Get("X-Endpoint-Safe") != "preserved" {
			t.Errorf("Host %q: ordinary header lost", host)
		}
	}

	// A token is optional: without one, no Authorization header reaches the
	// endpoint even if the caller supplied one.
	req := httptest.NewRequest(http.MethodGet, "http://a/resource", nil)
	req.Host = "a"
	req.Header.Set("Authorization", "Bearer caller-controlled")
	req.Header.Set("Impersonate-User", "caller-controlled")
	req.Header.Set("X-Remote-User", "caller-controlled")
	recorder := serveHandler(handler, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("tokenless endpoint status = %d", recorder.Code)
	}
	got := <-observed
	if got.auth != "" || got.header.Get("Impersonate-User") != "" || got.header.Get("X-Remote-User") != "" {
		t.Errorf("tokenless endpoint received identity: auth=%q headers=%v", got.auth, got.header)
	}

	// Unknown or invalid hosts are rejected before any upstream contact.
	before := requests.Load()
	for _, host := range []string{"payments:8080", "payments:443", "unknown", "a.b", "", "[::1]:80", "payments..", "payments:80.", "payments..:80"} {
		req := httptest.NewRequest(http.MethodGet, "http://payments/resource", nil)
		req.Host = host
		recorder := serveHandler(handler, req)
		if recorder.Code != http.StatusMisdirectedRequest || recorder.Body.String() != "unknown host\n" {
			t.Errorf("Host %q: status = %d body=%q", host, recorder.Code, recorder.Body.String())
		}
	}
	if got := requests.Load(); got != before {
		t.Errorf("rejected hosts contacted the upstream %d times", got-before)
	}

	connect := httptest.NewRequest(http.MethodConnect, "http://payments:443", nil)
	connect.Host = "payments"
	recorder = serveHandler(handler, connect)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT status = %d", recorder.Code)
	}
	if got := requests.Load(); got != before {
		t.Error("CONNECT reached the upstream")
	}
}

func TestNormalizeHost(t *testing.T) {
	for _, test := range []struct {
		host string
		name string
		ok   bool
	}{
		{"kube-apiserver", "kube-apiserver", true},
		{"KUBE-APISERVER", "kube-apiserver", true},
		{"payments.", "payments", true},
		{"payments:80", "payments", true},
		{"Payments.:80", "payments", true},
		{"payments:8080", "", false},
		{"payments:443", "", false},
		{"payments:", "", false},
		{"", "", false},
		{"[::1]", "::1", true},
		{"[::1]:80", "::1", true},
		{"[::1]:443", "", false},
		{"[::1", "", false},
		{"::1", "", false},
		{"a.b", "a.b", true},
		// Malformed authorities: more than one trailing dot, a dot after the
		// port, a leading-zero port, and invalid DNS labels.
		{"payments..", "", false},
		{"payments:80.", "", false},
		{"payments..:80", "", false},
		{"payments:080", "", false},
		{"payments:8a", "", false},
		{"pay-ments", "pay-ments", true},
		{"-payments", "", false},
		{"payments-", "", false},
		{"pay_ments", "", false},
	} {
		name, ok := normalizeHost(test.host)
		if name != test.name || ok != test.ok {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q, %v", test.host, name, ok, test.name, test.ok)
		}
	}
}

func TestRouterConfigErrors(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty":      {},
		"bad-scheme": {Endpoints: []Endpoint{{Name: "a", URL: "http://localhost"}}},
		"bad-api":    {API: &API{Address: "not-an-address"}, PodName: "p", PodNamespace: "ns"},
	} {
		t.Run(name, func(t *testing.T) {
			if handler, transports, err := newRouter(cfg); err == nil {
				closeTransports(transports)
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://kube-apiserver/", nil))
				t.Fatal("invalid router config accepted")
			}
		})
	}
}
