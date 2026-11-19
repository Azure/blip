package apiproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// W6-17: the owner-scope identity client must use the CA-aware transport like
// the proxied path does. Otherwise its idle TLS connection, trusted under the
// old CA, keeps authenticating identity reads after a projected CA
// rotation/revocation. The first proxied request after the rotation could also
// reuse that connection because caTransport treated generation 0 as "unset".
//
// The name records the defect this test rules out: a scope client that ignores
// CA rotation.
func TestW617ScopeClientIgnoresCARotation(t *testing.T) {
	var scopedReads atomic.Int32
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/ns/pods/pod-1" {
			scopedReads.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"kind":"Status","status":"Failure","reason":"NotFound","code":404}`)
	})
	cfg := testConfig(t, upstream)
	cfg.PodName = "pod-1"
	cfg.PodNamespace = "ns"
	p := startProxy(t, cfg)

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := p.client.Get("http://kube-apiserver" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	// Warm the scope client's idle TLS connection against the original CA.
	if code, body := get("/api/v1/namespaces/ns/pods/other"); code != http.StatusForbidden {
		t.Fatalf("initial scoped read: %d %q, want 403", code, body)
	}
	if scopedReads.Load() == 0 {
		t.Fatal("scope never read its own pod")
	}

	// Rotate the projected CA to an unrelated CA, as a revocation would.
	other := newTestCA(t, "unrelated")
	writeFileAt(t, cfg.API.CAFile, other.pem, time.Unix(1234, 0))

	// The scope client must not keep authenticating identity reads over the
	// connection trusted under the revoked CA.
	code, body := get("/api/v1/namespaces/ns/pods/other")
	if code != http.StatusBadGateway {
		t.Errorf("scoped read after CA revocation: %d %q, want 502", code, body)
	}

	// The proxied request must not reuse the scope client's revoked-CA
	// connection either, even though no proxied request ran before the
	// rotation.
	code, body = get("/version")
	if code != http.StatusBadGateway {
		t.Errorf("proxied request after CA revocation: %d %q, want 502", code, body)
	}
}

// Control for TestW617ScopeClientIgnoresCARotation: rotating the projected CA
// and the upstream certificate together must keep identity reads and proxied
// requests working. Invalidation must not turn every CA change into a failure.
func TestW617ScopeClientValidCARotationControl(t *testing.T) {
	caA := newTestCA(t, "CA A")
	caB := newTestCA(t, "CA B")
	certA := caA.issue(t, "127.0.0.1")
	certB := caB.issue(t, "127.0.0.1")

	var served atomic.Pointer[tls.Certificate]
	served.Store(&certA)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/version" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","status":"Failure","reason":"NotFound","code":404}`)
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return served.Load(), nil
			},
			MinVersion: tls.VersionTLS12,
		}))
	}()
	t.Cleanup(func() { _ = server.Close() })

	dir := t.TempDir()
	cfg := Config{
		SocketPath:   filepath.Join(dir, "vsock", "api.sock"),
		PodName:      "pod-1",
		PodNamespace: "ns",
		API: &API{
			Address:   listener.Addr().String(),
			TokenFile: filepath.Join(dir, "token"),
			CAFile:    filepath.Join(dir, "ca.crt"),
		},
	}
	writeFile(t, cfg.API.TokenFile, []byte("projected-secret\n"))
	writeFileAt(t, cfg.API.CAFile, caA.pem, time.Unix(1, 0))
	p := startProxy(t, cfg)

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := p.client.Get("http://kube-apiserver" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	if code, body := get("/api/v1/namespaces/ns/pods/other"); code != http.StatusForbidden {
		t.Fatalf("initial scoped read: %d %q, want 403", code, body)
	}

	// Rotate the upstream certificate and the projected CA together.
	served.Store(&certB)
	writeFileAt(t, cfg.API.CAFile, caB.pem, time.Unix(2, 0))

	if code, body := get("/api/v1/namespaces/ns/pods/other"); code != http.StatusForbidden {
		t.Errorf("scoped read after valid CA rotation: %d %q, want 403", code, body)
	}
	if code, body := get("/version"); code != http.StatusNoContent {
		t.Errorf("proxied request after valid CA rotation: %d %q, want 204", code, body)
	}
}
