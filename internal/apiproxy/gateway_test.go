package apiproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
		SerialNumber:          big.NewInt(1),
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
	return testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca testCA) issue(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		DNSNames:     []string{"gateway.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// gatewayTLSUpstream serves TLS with a certificate for gateway.test (and
// loopback IPs) signed by a test CA whose PEM is returned for pinning.
func gatewayTLSUpstream(t *testing.T, handler http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()
	ca := newTestCA(t, "test gateway CA")
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t)},
		MinVersion:   tls.VersionTLS12,
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, ca.pem
}

func testGatewayConfig(t *testing.T, upstream *httptest.Server, caPEM []byte) GatewayConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := GatewayConfig{
		SocketPath: filepath.Join(dir, "vsock", "vsock.sock_1027"),
		Address:    strings.TrimPrefix(upstream.URL, "https://"),
		ServerName: "gateway.test",
		CAFile:     filepath.Join(dir, "gateway-ca.crt"),
		TokenFile:  filepath.Join(dir, "gateway-token"),
	}
	writeFile(t, cfg.CAFile, caPEM)
	writeFile(t, cfg.TokenFile, []byte("gateway-secret\n"))
	return cfg
}

func unixClient(socket string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestGatewayConfigFromEnv(t *testing.T) {
	t.Setenv("BLIP_DIR", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("BLIP_GATEWAY_ADDRESS", "gateway.example:8443")
	t.Setenv("BLIP_GATEWAY_SERVER_NAME", "gateway.test")
	t.Setenv("BLIP_GATEWAY_CA_FILE", "/etc/gateway/ca.crt")
	t.Setenv("BLIP_GATEWAY_TOKEN_FILE", "/var/run/gateway/token")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway == nil {
		t.Fatal("gateway config missing")
	}
	want := GatewayConfig{
		SocketPath: "/run/blip/vsock/vsock.sock_1027",
		Address:    "gateway.example:8443",
		ServerName: "gateway.test",
		CAFile:     "/etc/gateway/ca.crt",
		TokenFile:  "/var/run/gateway/token",
	}
	if *cfg.Gateway != want {
		t.Fatalf("gateway config = %+v", *cfg.Gateway)
	}

	t.Setenv("BLIP_DIR", "/custom")
	cfg, err = ConfigFromEnv()
	if err != nil || cfg.Gateway.SocketPath != "/custom/vsock/vsock.sock_1027" {
		t.Fatalf("custom gateway config: %+v, %v", cfg.Gateway, err)
	}

	t.Setenv("BLIP_GATEWAY_TOKEN_FILE", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted gateway address without a token file")
	}

	t.Setenv("BLIP_GATEWAY_ADDRESS", "")
	t.Setenv("BLIP_GATEWAY_TOKEN_FILE", "/var/run/gateway/token")
	cfg, err = ConfigFromEnv()
	if err != nil || cfg.Gateway != nil {
		t.Fatalf("gateway disabled: %+v, %v", cfg.Gateway, err)
	}
}

func TestGatewayHostHeader(t *testing.T) {
	for _, test := range []struct{ serverName, port, want string }{
		{"gateway.test", "443", "gateway.test"},
		{"gateway.test", "8443", "gateway.test:8443"},
		{"127.0.0.1", "443", "127.0.0.1"},
		{"fd00::1", "443", "[fd00::1]"},
		{"fd00::1", "8443", "[fd00::1]:8443"},
	} {
		if got := gatewayHostHeader(test.serverName, test.port); got != test.want {
			t.Errorf("gatewayHostHeader(%q, %q) = %q, want %q", test.serverName, test.port, got, test.want)
		}
	}
}

func TestGatewayServerNameValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		ok   bool
	}{
		{"gateway.test", true},
		{"gateway.test.", true},
		{"127.0.0.1", true},
		{"fd00::1", true},
		{"", false},
		{"gateway.test:443", false},
		{"https://gateway.test", false},
		{"[fd00::1]", false},
		{"gate way", false},
		{"gateway.test\n", false},
		{"网关.test", false},
	} {
		if err := validateServerName(test.name); (err == nil) != test.ok {
			t.Errorf("validateServerName(%q) = %v, want ok=%v", test.name, err, test.ok)
		}
	}
}

type gatewayObservation struct {
	method string
	host   string
	uri    string
	sni    string
	auth   string
	header http.Header
	body   string
}

func TestGatewayIdentityTokenAndTarget(t *testing.T) {
	observed := make(chan gatewayObservation, 1)
	upstream, caPEM := gatewayTLSUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		observed <- gatewayObservation{
			method: r.Method, host: r.Host, uri: r.RequestURI,
			sni: r.TLS.ServerName, auth: r.Header.Get("Authorization"),
			header: r.Header.Clone(), body: string(body),
		}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testGatewayConfig(t, upstream, caPEM)
	handler, transport, err := newGatewayProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	_, port, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	wantHost := net.JoinHostPort(cfg.ServerName, port)

	for i, token := range []string{"gateway-secret", "rotated-gateway-secret"} {
		if i != 0 {
			writeFile(t, cfg.TokenFile+".next", []byte(token))
			if err := os.Rename(cfg.TokenFile+".next", cfg.TokenFile); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(http.MethodPost, "http://attacker.invalid/gateway/path/a%2Fb?x=1&x=two+words", strings.NewReader("body"))
		req.Host = "another-attacker.invalid"
		for _, key := range []string{
			"Authorization", "Proxy-Authorization", "Impersonate-User", "Impersonate-Group", "X-Remote-User",
			"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "Via",
		} {
			req.Header.Set(key, "caller-controlled")
		}
		req.Header.Set("Connection", "keep-alive, Authorization, Impersonate-User, X-Forwarded-For")
		req.Header.Set("X-Gateway-Safe", "preserved")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d body=%q", recorder.Code, recorder.Body.String())
		}
		got := <-observed
		if got.method != http.MethodPost || got.body != "body" {
			t.Errorf("method/body = %s/%q", got.method, got.body)
		}
		if got.host != wantHost {
			t.Errorf("Host = %q, want %q", got.host, wantHost)
		}
		if got.sni != cfg.ServerName {
			t.Errorf("SNI = %q, want %q", got.sni, cfg.ServerName)
		}
		if got.uri != "/gateway/path/a%2Fb?x=1&x=two+words" {
			t.Errorf("request URI = %q", got.uri)
		}
		if got.auth != "Bearer "+token {
			t.Errorf("Authorization = %q, want bearer %q", got.auth, token)
		}
		for key := range req.Header {
			if key != "Authorization" && key != "X-Gateway-Safe" && got.header.Get(key) != "" {
				t.Errorf("caller header survived: %s: %q", key, got.header.Values(key))
			}
		}
		if got.header.Get("X-Gateway-Safe") != "preserved" {
			t.Error("ordinary header lost")
		}
	}
}

func TestGatewayTLSVerification(t *testing.T) {
	for _, kind := range []string{"trusted", "default-server-name", "wrong-ca", "wrong-server-name", "system-roots"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			upstream, caPEM := gatewayTLSUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			cfg := testGatewayConfig(t, upstream, caPEM)
			switch kind {
			case "default-server-name":
				cfg.ServerName = ""
			case "wrong-ca":
				writeFile(t, cfg.CAFile, newTestCA(t, "unrelated CA").pem)
			case "wrong-server-name":
				cfg.ServerName = "wrong.test"
			case "system-roots":
				cfg.CAFile = ""
			}
			handler, transport, err := newGatewayProxy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://guest/api", nil))
			wantStatus := http.StatusBadGateway
			if kind == "trusted" || kind == "default-server-name" {
				wantStatus = http.StatusNoContent
			}
			if recorder.Code != wantStatus {
				t.Fatalf("status = %d body=%q", recorder.Code, recorder.Body.String())
			}
			if wantStatus == http.StatusBadGateway && recorder.Body.String() != "gateway unavailable\n" {
				t.Errorf("error body = %q", recorder.Body.String())
			}
			wantRequests := int32(0)
			if wantStatus == http.StatusNoContent {
				wantRequests = 1
			}
			if requests.Load() != wantRequests {
				t.Errorf("upstream requests = %d, want %d", requests.Load(), wantRequests)
			}
		})
	}
}

func TestGatewayCONNECTRejected(t *testing.T) {
	var requests atomic.Int32
	upstream, caPEM := gatewayTLSUpstream(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	cfg := testGatewayConfig(t, upstream, caPEM)
	handler, transport, err := newGatewayProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodConnect, "http://guest:443", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT status = %d", recorder.Code)
	}
	if requests.Load() != 0 {
		t.Fatal("CONNECT was forwarded")
	}
}

func TestGatewayInvalidConfig(t *testing.T) {
	upstream, caPEM := gatewayTLSUpstream(t, func(http.ResponseWriter, *http.Request) {})
	for _, test := range []struct {
		name   string
		mutate func(*GatewayConfig)
	}{
		{"url-address", func(cfg *GatewayConfig) { cfg.Address = "https://gateway.example" }},
		{"missing-port", func(cfg *GatewayConfig) { cfg.Address = "gateway.example" }},
		{"missing-token", func(cfg *GatewayConfig) { cfg.TokenFile = filepath.Join(t.TempDir(), "absent") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testGatewayConfig(t, upstream, caPEM)
			test.mutate(&cfg)
			if _, transport, err := newGatewayProxy(cfg); err == nil {
				transport.CloseIdleConnections()
				t.Fatal("invalid gateway config accepted")
			}
		})
	}
}

func TestRunServesGatewayAndAPISockets(t *testing.T) {
	apiUpstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	observed := make(chan gatewayObservation, 1)
	gatewayUpstream, caPEM := gatewayTLSUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		observed <- gatewayObservation{host: r.Host, sni: r.TLS.ServerName, auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(t, apiUpstream)
	gatewayCfg := testGatewayConfig(t, gatewayUpstream, caPEM)
	cfg.Gateway = &gatewayCfg
	p := startProxy(t, cfg)

	resp, err := p.client.Get("http://guest/api")
	if err != nil {
		t.Fatal(err)
	}
	_ = responseBody(t, resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("API status = %d", resp.StatusCode)
	}

	gatewayClient := unixClient(cfg.Gateway.SocketPath)
	resp, err = gatewayClient.Get("http://guest/gateway/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = responseBody(t, resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("gateway status = %d", resp.StatusCode)
	}
	got := <-observed
	if got.sni != "gateway.test" || got.auth != "Bearer gateway-secret" || got.host != gatewayHostHeader("gateway.test", portOf(t, cfg.Gateway.Address)) {
		t.Errorf("gateway request: %+v", got)
	}
	gatewayClient.Transport.(*http.Transport).CloseIdleConnections()

	p.stop(t)
	for _, socket := range []string{cfg.SocketPath, cfg.Gateway.SocketPath} {
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket %s survived shutdown: %v", socket, err)
		}
	}
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestRunCleansUpWhenGatewaySocketFails(t *testing.T) {
	apiUpstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	gatewayUpstream, caPEM := gatewayTLSUpstream(t, func(http.ResponseWriter, *http.Request) {})
	cfg := testConfig(t, apiUpstream)
	gatewayCfg := testGatewayConfig(t, gatewayUpstream, caPEM)
	gatewayCfg.SocketPath = filepath.Join(t.TempDir(), "not-a-socket")
	writeFile(t, gatewayCfg.SocketPath, []byte("do not delete"))
	cfg.Gateway = &gatewayCfg
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("gateway listener setup failure was ignored")
	}
	if _, err := os.Lstat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("API socket survived failed startup: %v", err)
	}
	if data, err := os.ReadFile(gatewayCfg.SocketPath); err != nil || string(data) != "do not delete" {
		t.Errorf("ordinary gateway path was changed: %q, %v", data, err)
	}
}
