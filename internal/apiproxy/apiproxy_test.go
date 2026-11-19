package apiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
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

func tlsUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true // The proxy must still negotiate HTTP/1 upgrades.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func testConfig(t *testing.T, upstream *httptest.Server) Config {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		SocketPath: filepath.Join(dir, "vsock", "api.sock"),
		API: &API{
			Address:   strings.TrimPrefix(upstream.URL, "https://"),
			TokenFile: filepath.Join(dir, "token"),
			CAFile:    filepath.Join(dir, "ca.crt"),
		},
	}
	writeFile(t, cfg.API.TokenFile, []byte("projected-secret\n"))
	writeFile(t, cfg.API.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
	return cfg
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

type runningProxy struct {
	cfg    Config
	client *http.Client
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func startProxy(t *testing.T, cfg Config) *runningProxy {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &runningProxy{cfg: cfg, cancel: cancel, done: make(chan struct{})}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
		},
	}
	p.client = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	go func() {
		p.err = Run(ctx, cfg)
		close(p.done)
	}()
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		p.stop(t)
	})
	sockets := []string{cfg.SocketPath}
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			t.Fatalf("proxy exited before listening: %v", p.err)
		case <-deadline:
			t.Fatal("proxy did not start listening")
		case <-ticker.C:
			ready := true
			for _, socket := range sockets {
				conn, err := net.Dial("unix", socket)
				if err != nil {
					ready = false
					break
				}
				_ = conn.Close()
			}
			if ready {
				return p
			}
		}
	}
}

func (p *runningProxy) stop(t *testing.T) {
	t.Helper()
	p.cancel()
	select {
	case <-p.done:
		if p.err != nil {
			t.Errorf("Run: %v", p.err)
		}
	case <-time.After(8 * time.Second):
		t.Error("proxy did not stop")
	}
}

func responseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("BLIP_DIR", "")
	t.Setenv("BLIP_KUBE_API", "1")
	t.Setenv("BLIP_ENDPOINTS", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("POD_NAME", "vm-0")
	t.Setenv("POD_NAMESPACE", "blip-sandbox")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API == nil || cfg.API.Address != "10.96.0.1:443" || cfg.SocketPath != "/run/blip/vsock/vsock.sock_1027" ||
		cfg.API.TokenFile != serviceAccountDir+"/token" || cfg.API.CAFile != serviceAccountDir+"/ca.crt" ||
		cfg.PodName != "vm-0" || cfg.PodNamespace != "blip-sandbox" || len(cfg.Endpoints) != 0 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	// The trusted identity is all-or-nothing.
	t.Setenv("POD_NAMESPACE", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted a partial pod identity")
	}
	t.Setenv("POD_NAME", "")
	t.Setenv("POD_NAMESPACE", "blip-sandbox")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted a partial pod identity")
	}
	t.Setenv("POD_NAME", "../escape")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted an invalid pod name")
	}
	t.Setenv("POD_NAME", "")
	t.Setenv("POD_NAMESPACE", "")

	// An idle sidecar with neither route is a configuration error.
	t.Setenv("BLIP_KUBE_API", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted a config with no API or endpoints")
	}

	// A JSON endpoint list alone is valid.
	t.Setenv("BLIP_ENDPOINTS", `[{"name":"payments","url":"https://payments.example:8443","tokenFile":"/t","caFile":"/c"}]`)
	cfg, err = ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Endpoint{Name: "payments", URL: "https://payments.example:8443", TokenFile: "/t", CAFile: "/c"}
	if cfg.API != nil || len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != want {
		t.Fatalf("endpoint config: %+v, %v", cfg, err)
	}

	// IPv6 API address and custom directory.
	t.Setenv("BLIP_ENDPOINTS", "")
	t.Setenv("BLIP_KUBE_API", "1")
	t.Setenv("BLIP_DIR", "/custom")
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00::1")
	cfg, err = ConfigFromEnv()
	if err != nil || cfg.API.Address != "[fd00::1]:443" || cfg.SocketPath != "/custom/vsock/vsock.sock_1027" {
		t.Fatalf("IPv6/custom config: %+v, %v", cfg, err)
	}
	for _, test := range []struct{ host, port string }{
		{"", "443"}, {"https://example.com", "443"}, {"user@example.com", "443"},
		{"example.com/path", "443"}, {"example.com#fragment", "443"},
		{"example.com", ""}, {"example.com", "0"}, {"example.com", "65536"}, {"example.com", "https"},
	} {
		t.Setenv("KUBERNETES_SERVICE_HOST", test.host)
		t.Setenv("KUBERNETES_SERVICE_PORT", test.port)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("accepted host=%q port=%q", test.host, test.port)
		}
	}

	// Endpoint parsing and validation.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("BLIP_KUBE_API", "")
	for _, endpoints := range []string{
		`[`,
		`null`,
		`{}`,
		`{"name":"payments","url":"https://payments.example"}`,
		`[{"name":"payments","url":"https://payments.example"},{"name":"payments","url":"https://other.example"}]`,
		`[{"name":"Bad","url":"https://payments.example"}]`,
		`[{"name":"-bad","url":"https://payments.example"}]`,
		`[{"name":"` + strings.Repeat("a", 64) + `","url":"https://payments.example"}]`,
		`[{"name":"blip","url":"https://payments.example"}]`,
		`[{"name":"kube-apiserver","url":"https://payments.example"}]`,
		`[{"name":"localhost","url":"https://payments.example"}]`,
		`[{"name":"payments","url":"http://payments.example"}]`,
		`[{"name":"payments","url":"https://user@payments.example"}]`,
		`[{"name":"payments","url":"https://payments.example?x=1"}]`,
		`[{"name":"payments","url":"https://payments.example#f"}]`,
		`[{"name":"payments","url":"https://payments.example/path"}]`,
		`[{"name":"payments","url":"https://127.0.0.1"}]`,
		`[{"name":"payments","url":"https://[::1]"}]`,
		`[{"name":"payments","url":"https://payments.example:0"}]`,
		`[{"name":"payments","url":"https://payments.example:65536"}]`,
		`[{"name":"payments","url":"https://"}]`,
	} {
		t.Setenv("BLIP_ENDPOINTS", endpoints)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("accepted endpoints %s", endpoints)
		}
	}
	t.Setenv("BLIP_ENDPOINTS", `[{"name":"payments","url":"https://payments.example/"}]`)
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatalf("rejected a root-path endpoint URL: %v", err)
	}
}

func TestIdentityHeadersAndTokenRotation(t *testing.T) {
	observed := make(chan http.Header, 1)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)
	for i, token := range []string{"projected-secret", "rotated-secret"} {
		if i != 0 {
			// Projected volumes rotate by replacing files/symlinks, not by
			// modifying an open file descriptor.
			writeFile(t, cfg.API.TokenFile+".next", []byte(token))
			if err := os.Rename(cfg.API.TokenFile+".next", cfg.API.TokenFile); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequest(http.MethodGet, "http://kube-apiserver/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{
			"Authorization", "Proxy-Authorization", "Impersonate-User", "Impersonate-Group", "Impersonate-Uid",
			"Impersonate-Extra-Scopes", "Impersonate-Extra-A%2fb", "X-Remote-User", "X-Remote-Group", "X-Remote-Extra-Scopes",
			"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "Via",
			"X-Auth-Request-User", "X-Auth-Request-Groups", "Remote-User", "Remote-Groups", "Remote-Email",
			"Tailscale-User-Login", "Tailscale-User-Name", "Cf-Access-Authenticated-User-Email",
			"Cf-Access-Jwt-Assertion", "X-Authentik-Username", "X-Ssl-Client-S-Dn", "Client-Cert", "X-Pomerium-Jwt-Assertion",
			"X-Amzn-Oidc-Data", "X-Amzn-Oidc-Identity", "X-Amzn-Oidc-Accesstoken",
			"X-Ms-Token-Aad-Access-Token", "X-Auth-Email", "X-Authenticated-User", "X-Scope", "X-Userinfo",
			// Underscore spellings that frameworks expose as HTTP_X_*.
			"X_User", "X_Forwarded_User", "X_Remote_User",
		} {
			req.Header.Set(key, "caller-controlled")
		}
		req.Header.Set("Connection", "keep-alive, Authorization, Impersonate-User, X-Remote-User, X-Forwarded-For")
		req.Header.Set("X-Kubernetes-Safe", "preserved")
		resp, err := p.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = responseBody(t, resp)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		headers := <-observed
		if got := headers.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+token {
			t.Errorf("incorrect service account authorization: %q", got)
		}
		for key := range req.Header {
			if key != "Authorization" && key != "X-Kubernetes-Safe" && headers.Get(key) != "" {
				t.Errorf("caller header survived: %s: %q", key, headers.Values(key))
			}
		}
		if headers.Get("X-Kubernetes-Safe") != "preserved" {
			t.Error("ordinary header lost")
		}
	}
}

func TestFixedTargetAndOrdinaryMethods(t *testing.T) {
	type request struct{ method, host, uri, auth, body string }
	observed := make(chan request, 1)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		observed <- request{r.Method, r.Host, r.RequestURI, r.Header.Get("Authorization"), string(body)}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		req, err := http.NewRequest(method, "http://attacker.invalid/api/v1/pods/name/exec?command=sh&command=-c", strings.NewReader("body"))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "kube-apiserver"
		resp, err := p.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = responseBody(t, resp)
		got := <-observed
		if got.method != method || got.host != cfg.API.Address || got.body != "body" || got.uri != "/api/v1/pods/name/exec?command=sh&command=-c" {
			t.Errorf("unexpected upstream request: %+v", got)
		}
	}
	for _, target := range []string{
		"https://kube-apiserver:80/api/a%2Fb?x=%2F&x=two+words&semi=a;b",
		"http://user:password@kube-apiserver:80/api/a%2Fb?x=%2F&x=two+words&semi=a;b",
		"//kube-apiserver/api/a%2Fb?x=%2F&x=two+words&semi=a;b",
	} {
		conn, err := net.Dial("unix", cfg.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: kube-apiserver\r\nConnection: close\r\n\r\n", target)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = responseBody(t, resp)
		_ = conn.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("target %q: status %d", target, resp.StatusCode)
		}
		got := <-observed
		wantURI := "/api/a%2Fb?x=%2F&x=two+words&semi=a;b"
		if strings.HasPrefix(target, "//") {
			wantURI = "//kube-apiserver" + wantURI
		}
		if got.host != cfg.API.Address || got.uri != wantURI || got.auth != "Bearer projected-secret" {
			t.Errorf("target %q reached upstream as %+v", target, got)
		}
	}
	connect, _ := http.NewRequest(http.MethodConnect, "http://attacker.invalid:443", nil)
	resp, err := p.client.Do(connect)
	if err != nil {
		t.Fatal(err)
	}
	_ = responseBody(t, resp)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	select {
	case got := <-observed:
		t.Fatalf("CONNECT was forwarded: %+v", got)
	default:
	}
}

func TestNoEnvironmentProxyOrRedirectFollowing(t *testing.T) {
	var escaped atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(other.Close)
	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"} {
		t.Setenv(name, other.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/redirected", http.StatusTemporaryRedirect)
	})
	cfg := testConfig(t, upstream)
	// Avoid localhost's implicit exemption in http.ProxyFromEnvironment.
	// The test certificate covers example.com; the dialer stands in for DNS.
	cfg.API.Address = "example.com:443"
	handler, transport, err := newAPIProxy(cfg.API, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("transport has a proxy selector")
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != cfg.API.Address {
			return nil, fmt.Errorf("unexpected outbound address: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(upstream.URL, "https://"))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://kube-apiserver/api", nil))
	resp := recorder.Result()
	_ = responseBody(t, resp)
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != other.URL+"/redirected" || escaped.Load() != 0 {
		t.Fatalf("status=%d location=%q unexpected requests=%d", resp.StatusCode, resp.Header.Get("Location"), escaped.Load())
	}
}

func TestTLSVerification(t *testing.T) {
	var requests atomic.Int32
	upstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	for _, kind := range []string{"trusted", "untrusted-ca", "wrong-hostname"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig(t, upstream)
			switch kind {
			case "untrusted-ca":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				cert := &x509.Certificate{
					SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated CA"},
					NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
					IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				}
				der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, cfg.API.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			case "wrong-hostname":
				_, port, _ := net.SplitHostPort(cfg.API.Address)
				cfg.API.Address = net.JoinHostPort("localhost", port)
			}
			p := startProxy(t, cfg)
			resp, err := p.client.Get("http://kube-apiserver/api")
			if err != nil {
				t.Fatal(err)
			}
			body := responseBody(t, resp)
			wantStatus := http.StatusBadGateway
			if kind == "trusted" {
				wantStatus = http.StatusNoContent
			}
			if resp.StatusCode != wantStatus || strings.Contains(body, "projected-secret") {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
		})
	}
	if requests.Load() != 1 {
		t.Errorf("upstream got %d requests, want only the verified request", requests.Load())
	}
}

func TestTokenReadFailuresDoNotLeakOrForward(t *testing.T) {
	var requests atomic.Int32
	upstream := tlsUpstream(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)
	for _, contents := range []string{"", "a-secret\nAuthorization: another-secret", "missing-file"} {
		writeFile(t, cfg.API.TokenFile, []byte(contents))
		if contents == "missing-file" {
			if err := os.Remove(cfg.API.TokenFile); err != nil {
				t.Fatal(err)
			}
		}
		resp, err := p.client.Get("http://kube-apiserver/api")
		if err != nil {
			t.Fatal(err)
		}
		if body := responseBody(t, resp); resp.StatusCode != http.StatusBadGateway || body != "Kubernetes API unavailable\n" {
			t.Errorf("status=%d body=%q", resp.StatusCode, body)
		}
	}
	if requests.Load() != 0 {
		t.Errorf("forwarded %d requests without a usable token", requests.Load())
	}
}

func TestStreamingWatchAndShutdown(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"type\":\"ADDED\"}\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)
	resp, err := p.client.Get("http://kube-apiserver/api/v1/pods?watch=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "{\"type\":\"ADDED\"}\n" {
		t.Fatalf("first watch event: %q, %v", line, err)
	}
	p.stop(t)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("watch remained open after shutdown")
	}
	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Error("upstream watch was not canceled")
	}
	if _, err := os.Lstat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket survived shutdown: %v", err)
	}
}

func TestRequestBodyStreamsWithoutBuffering(t *testing.T) {
	firstBytes := make(chan struct{})
	const bodySize = 4 << 20
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, first); err != nil {
			t.Error(err)
			return
		}
		close(firstBytes)
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || string(first) != "first" || n != bodySize {
			t.Errorf("body prefix=%q remaining=%d err=%v", first, n, err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	p := startProxy(t, testConfig(t, upstream))
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ := http.NewRequest(http.MethodPost, "http://kube-apiserver/api/v1/configmaps", reader)
	result := make(chan error, 1)
	go func() {
		resp, err := p.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				err = fmt.Errorf("status = %d", resp.StatusCode)
			}
		}
		result <- err
	}()
	if _, err := io.WriteString(writer, "first"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstBytes: // The rest of the upload does not exist yet.
	case <-time.After(2 * time.Second):
		t.Fatal("proxy buffered the request instead of forwarding its first bytes")
	}
	if _, err := io.Copy(writer, bytes.NewReader(bytes.Repeat([]byte("x"), bodySize))); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeAndShutdown(t *testing.T) {
	for _, protocol := range []string{"websocket", "SPDY/3.1"} {
		t.Run(protocol, func(t *testing.T) {
			upstreamDone := make(chan struct{})
			upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				if r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer projected-secret" || r.Header.Get("Upgrade") != protocol {
					t.Errorf("upgrade request: protocol=%s headers=%v", r.Proto, r.Header)
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", protocol)
				_ = rw.Flush()
				_, _ = io.Copy(conn, rw)
			})
			cfg := testConfig(t, upstream)
			p := startProxy(t, cfg)
			conn, err := net.Dial("unix", cfg.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprintf(conn, "GET /api/v1/pods/p/exec HTTP/1.1\r\nHost: kube-apiserver\r\nConnection: Upgrade, Authorization\r\nUpgrade: %s\r\nAuthorization: attacker\r\n\r\n", protocol)
			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != protocol {
				t.Fatalf("upgrade response: %+v", resp)
			}
			if _, err := io.WriteString(conn, "bidirectional stream"); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, len("bidirectional stream"))
			if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "bidirectional stream" {
				t.Fatalf("upgrade stream echo=%q err=%v", echo, err)
			}
			p.stop(t)
			if _, err := reader.ReadByte(); err == nil {
				t.Error("hijacked client stream stayed open after cancellation")
			} else if err, ok := err.(net.Error); ok && err.Timeout() {
				t.Error("hijacked client stream timed out instead of closing")
			}
			select {
			case <-upstreamDone:
			case <-time.After(time.Second):
				t.Error("hijacked upstream stream stayed open after cancellation")
			}
		})
	}
}

func TestUpgradeBackendHalfClose(t *testing.T) {
	const payload = "guest data after backend EOF"
	upstreamDone := make(chan error, 1)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		if err == nil {
			err = conn.(*tls.Conn).CloseWrite()
		}
		if err != nil {
			upstreamDone <- err
			return
		}
		got, err := io.ReadAll(rw)
		if err == nil && string(got) != payload {
			err = fmt.Errorf("upgraded request = %q, want %q", got, payload)
		}
		upstreamDone <- err
	})
	cfg := testConfig(t, upstream)
	startProxy(t, cfg)
	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET /api/v1/pods/p/exec HTTP/1.1\r\nHost: kube-apiserver\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}
	// Wait for the backend's half-close to reach the guest before writing.
	// A full close here would discard the still-active request direction.
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("backend half-close = %v, want EOF", err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write after backend half-close: %v", err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not receive guest data and EOF after half-closing")
	}
}

func TestSocketLifecycle(t *testing.T) {
	upstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)
	info, err := os.Lstat(cfg.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: info=%v err=%v", info, err)
	}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("second proxy replaced an active listener")
	}
	resp, err := p.client.Get("http://kube-apiserver/api")
	if err != nil {
		t.Fatal(err)
	}
	_ = responseBody(t, resp)
	p.stop(t)
	if _, err := os.Lstat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed: %v", err)
	}

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	p = startProxy(t, cfg)
	p.stop(t)

	writeFile(t, cfg.SocketPath, []byte("do not delete"))
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("proxy replaced an ordinary file")
	}
	data, err := os.ReadFile(cfg.SocketPath)
	if err != nil || string(data) != "do not delete" {
		t.Fatalf("ordinary file was changed: %q %v", data, err)
	}
}

func TestAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Config{}); err != nil {
		t.Fatal(err)
	}
}

// TestClientHalfCloseKeepsRequest is the regression test for a client that
// writes a complete request and then half-closes its write side. net/http
// cancels the request context when the read side reaches EOF, but the guest
// is still waiting for the response; the proxy must not turn that into 502.
func TestClientHalfCloseKeepsRequest(t *testing.T) {
	observed := make(chan string, 1)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		observed <- string(body)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	cfg := testConfig(t, upstream)
	startProxy(t, cfg)
	for _, tt := range []struct {
		method string
		body   string
	}{
		{http.MethodGet, ""},
		{http.MethodPost, "hello"},
	} {
		t.Run(tt.method, func(t *testing.T) {
			conn, err := net.Dial("unix", cfg.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			request := tt.method + " /halfbody HTTP/1.1\r\nHost: kube-apiserver\r\n"
			if tt.body != "" {
				request += fmt.Sprintf("Content-Length: %d\r\n", len(tt.body))
			}
			request += "\r\n" + tt.body
			if _, err := io.WriteString(conn, request); err != nil {
				t.Fatal(err)
			}
			if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d body %q", resp.StatusCode, body)
			}
			if got := <-observed; got != tt.body {
				t.Fatalf("upstream body = %q, want %q", got, tt.body)
			}
		})
	}
}

// TestClientCloseCancelsUpstream checks that closing the guest connection, as
// opposed to half-closing it, ends an in-flight watch. net/http alone only
// reports read-side EOF, which the wave-4 half-close behaviour must tolerate;
// the proxy distinguishes a full close and cancels the upstream request.
func TestClientCloseCancelsUpstream(t *testing.T) {
	upstreamDone := make(chan struct{}, 1)
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"type\":\"ADDED\"}\n")
		w.(http.Flusher).Flush()
		// An idle watch produces no further bytes, so only cancellation can
		// end this handler before the guard.
		select {
		case <-r.Context().Done():
			upstreamDone <- struct{}{}
		case <-time.After(20 * time.Second):
		}
	})
	cfg := testConfig(t, upstream)
	p := startProxy(t, cfg)

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /api/v1/pods?watch=true HTTP/1.1\r\nHost: kube-apiserver\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response headers: %v", err)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "{\"type\":\"ADDED\"}\n" {
		t.Fatalf("first watch event %q: %v", line, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Error("upstream watch still running 1s after the guest closed the connection")
	}
	p.stop(t)
}

func TestStripIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		kept bool
	}{
		// Identity assertions from authenticating front proxies.
		{"X-Goog-Authenticated-User-Email", false},
		{"X-Goog-Authenticated-User-Id", false},
		{"X-Goog-Iap-Jwt-Assertion", false},
		{"X-Ms-Client-Principal", false},
		{"X-Ms-Client-Principal-Name", false},
		{"X-Webauth-User", false},
		{"X-Client-Cert", false},
		{"X-Client-Dn", false},
		{"X-Original-User", false},
		{"X-Auth-User", false},
		{"X-Envoy-Peer-Metadata", false},
		{"X-User", false},
		{"X-Email", false},
		// AWS ALB OIDC and Azure AD assertion families.
		{"X-Amzn-Oidc-Data", false},
		{"X-Amzn-Oidc-Identity", false},
		{"X-Amzn-Oidc-Accesstoken", false},
		{"X-Ms-Token-Aad-Access-Token", false},
		{"X-Auth-Email", false},
		{"X-Authenticated-User", false},
		{"X-Scope", false},
		{"X-Userinfo", false},
		// Underscore spellings must not bypass the denylist.
		{"X_User", false},
		{"X_Forwarded_User", false},
		{"X_Remote_User", false},
		{"X_Auth_Email", false},
		{"Authorization", false},
		{"X-Forwarded-For", false},
		{"X-Remote-User", false},
		// Ordinary caller headers, including lookalikes of the fixed names,
		// must survive.
		{"User-Agent", true},
		{"X-User-Agent", true},
		{"X-Safe", true},
		{"X-Client-Version", true},
		{"X-Email-Digest", true},
		{"X-Scope-Id", true},
	} {
		headers := http.Header{}
		// Store the spelling as written so matching is genuinely
		// case-insensitive rather than relying on Header.Set canonicalization.
		headers[test.name] = []string{"value"}
		stripIdentity(headers)
		_, present := headers[test.name]
		if present != test.kept {
			t.Errorf("stripIdentity(%q): present = %v, want kept = %v", test.name, present, test.kept)
		}
	}
}
