// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/blip/internal/nvme"
)

func testPeer(node string, i *Identity) Peer {
	return Peer{Node: node, PublicKey: i.PublicKey(), Endpoint: "127.0.0.1"}
}

func startTLSTestServer(t *testing.T, i *Identity, peers *Registry, addr string, handler http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	if addr != "" {
		ts.Listener.Close()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		ts.Listener = ln
	}
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.TLS = i.serverTLS(peers)
	cert, err := i.certificate()
	if err != nil {
		t.Fatal(err)
	}
	// Prevent httptest from installing its default non-Ed25519 certificate
	// when an IP-address dial omits SNI.
	ts.TLS.Certificates = []tls.Certificate{*cert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func testHTTPClient(t *testing.T, cfg *tls.Config) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: cfg}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestTLSPinnedIdentityAndRevocationOnReusedConnection(t *testing.T) {
	serverID, clientID := testIdentity(t), testIdentity(t)
	r := NewRegistry()
	r.SetPeers([]Peer{testPeer("exporter", serverID), testPeer("reader", clientID)})
	s := &Server{cfg: ServerConfig{Peers: r}}
	var connections atomic.Int32
	ts := startTLSTestServer(t, serverID, r, "", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		node, ok := s.caller(w, req)
		if ok {
			fmt.Fprint(w, node)
		}
	}))
	cfg := clientID.clientTLS(r, "exporter")
	cfg.ServerName = "not-the-certificate-name.example"
	c := testHTTPClient(t, cfg)
	get := func() (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "spoofed-node.example"
		req.Header.Set("X-Forwarded-For", "192.0.2.3")
		// Prove that revocation is checked on a previously authenticated
		// connection rather than by a second TLS handshake.
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if !info.Reused {
					connections.Add(1)
				}
			},
		}))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if status, body := get(); status != http.StatusOK || body != "reader" {
		t.Fatalf("authenticated caller = %d %q", status, body)
	}
	// A key's registry node mapping, never its certificate name or source IP,
	// determines the caller on each request.
	r.SetPeers([]Peer{testPeer("exporter", serverID), testPeer("renamed-reader", clientID)})
	if status, body := get(); status != http.StatusOK || body != "renamed-reader" {
		t.Fatalf("updated caller = %d %q", status, body)
	}
	r.SetPeers([]Peer{testPeer("exporter", serverID)})
	if status, _ := get(); status != http.StatusForbidden {
		t.Fatalf("revoked client accepted: %d", status)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("test used %d connections, want one reused TLS connection", got)
	}
}

func TestTLSRejectsUntrustedPeersAndDowngrades(t *testing.T) {
	serverID, clientID, stranger := testIdentity(t), testIdentity(t), testIdentity(t)
	serverPeers := NewRegistry()
	serverPeers.SetPeers([]Peer{testPeer("reader", clientID)})
	var requests atomic.Int32
	ts := startTLSTestServer(t, serverID, serverPeers, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	for _, name := range []string{"missing-client", "unknown-client", "unknown-server", "wrong-server", "tls12"} {
		t.Run(name, func(t *testing.T) {
			peers := NewRegistry()
			peers.SetPeers([]Peer{testPeer("exporter", serverID)})
			cfg := clientID.clientTLS(peers, "exporter")
			switch name {
			case "missing-client":
				cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
			case "unknown-client":
				cfg = stranger.clientTLS(peers, "exporter")
			case "unknown-server":
				peers.SetPeers(nil)
			case "wrong-server":
				// The actual server key belongs to a different registered node:
				// trusting any known key would incorrectly accept this server.
				peers.SetPeers([]Peer{testPeer("exporter", stranger), testPeer("another-node", serverID)})
			case "tls12":
				cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			}
			resp, err := testHTTPClient(t, cfg).Get(ts.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("untrusted or downgraded TLS request succeeded")
			}
		})
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(strings.Replace(ts.URL, "https://", "http://", 1))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plaintext request succeeded")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("unauthenticated request reached handler")
	}
}

func TestClientResolvesCurrentEndpointAndPin(t *testing.T) {
	serverID, clientID, replacement := testIdentity(t), testIdentity(t), testIdentity(t)
	r := NewRegistry()
	reader := testPeer("reader", clientID)
	first := testPeer("exporter", serverID)
	first.Endpoint = "127.0.0.21"
	second := first
	second.Endpoint = "127.0.0.22"
	r.SetPeers([]Peer{reader, first})
	s := &Server{cfg: ServerConfig{Peers: r}}
	var one, two atomic.Int32
	handler := func(counter *atomic.Int32) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := s.caller(w, req); ok {
				counter.Add(1)
				fmt.Fprint(w, "{}")
			}
		})
	}
	startTLSTestServer(t, serverID, r, net.JoinHostPort(first.Endpoint, fmt.Sprint(ExportPort)), handler(&one))
	startTLSTestServer(t, serverID, r, net.JoinHostPort(second.Endpoint, fmt.Sprint(ExportPort)), handler(&two))
	c := NewClient(clientID, r, nil)
	t.Cleanup(c.Close)
	if err := c.post(t.Context(), "exporter", "/v1/release", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	r.SetPeers([]Peer{reader, second})
	if err := c.post(t.Context(), "exporter", "/v1/release", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	second.PublicKey = replacement.PublicKey()
	r.SetPeers([]Peer{reader, second})
	if err := c.post(t.Context(), "exporter", "/v1/release", struct{}{}, nil); err == nil {
		t.Fatal("old server key accepted after registry rotation")
	}
	if one.Load() != 1 || two.Load() != 1 {
		t.Fatalf("endpoint calls = %d, %d; want 1, 1", one.Load(), two.Load())
	}
}

func TestRecoveredLeaseWorkWaitsForRegistry(t *testing.T) {
	serverID, clientID := testIdentity(t), testIdentity(t)
	r := NewRegistry()
	serverPeers := NewRegistry()
	serverPeers.SetPeers([]Peer{testPeer("reader", clientID)})
	exporter := testPeer("exporter", serverID)
	exporter.Endpoint = "127.0.0.23"
	requests := make(chan string, 4)
	startTLSTestServer(t, serverID, serverPeers, net.JoinHostPort(exporter.Endpoint, fmt.Sprint(ExportPort)), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests <- req.URL.Path
		fmt.Fprint(w, "{}")
	}))
	c := NewClient(clientID, r, nil)
	t.Cleanup(c.Close)
	// Deliberately use the retry helper: no kernel disconnect is needed to
	// verify release recovery's asynchronous readiness and retry lifecycle.
	released := make(chan struct{})
	go func() {
		c.releaseWithRetry(c.ctx, exporter.Node, "release", "test")
		close(released)
	}()
	c.ResumeRemote(exporter.Node + "/renew/" + nvme.SubsystemNQN(exporter.Node, "renew"))
	select {
	case <-released:
		t.Fatal("recovery release finished before discovery")
	case path := <-requests:
		t.Fatalf("request before discovery: %s", path)
	case <-time.After(30 * time.Millisecond):
	}
	r.SetPeers([]Peer{exporter})
	want := map[string]bool{"/v1/release": true, "/v1/leases/renew/renew": true}
	for range 2 {
		select {
		case path := <-requests:
			if !want[path] {
				t.Fatalf("unexpected request: %s", path)
			}
			delete(want, path)
		case <-time.After(3 * time.Second):
			t.Fatal("recovery did not resume after discovery")
		}
	}
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("successful recovery release did not finish")
	}
}

func TestClientCloseCancelsDiscoveryAndSeparatesNodeLeases(t *testing.T) {
	c := NewClient(testIdentity(t), NewRegistry(), nil)
	one := c.startRenewal("one", "same-id", false)
	c.startRenewal("two", "same-id", false)
	one()
	if _, ok := c.active.Load(leaseKey{"two", "same-id"}); !ok {
		t.Fatal("stopping one node's lease stopped another node's same-named lease")
	}
	done := make(chan error, 1)
	go func() { done <- c.post(context.Background(), "one", "/v1/release", struct{}{}, nil) }()
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed client accepted a request")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client close did not cancel discovery wait")
	}
}
