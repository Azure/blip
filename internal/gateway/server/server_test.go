package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/sshca"
)

// testCA holds ephemeral CA material written to temp files for a single test.
type testCA struct {
	KeyPath     string
	PubKeyPath  string
	HostKeyPath string
	Signer      ssh.Signer
}

// newTestCA generates a fresh CA keypair and a stable host key, writing all
// key files into dir.
func newTestCA(t *testing.T, dir string) testCA {
	t.Helper()
	privPEM, pubAuth, err := sshca.GenerateCAKeypair()
	require.NoError(t, err)

	keyPath := filepath.Join(dir, "ca")
	require.NoError(t, os.WriteFile(keyPath, privPEM, 0600))

	pubPath := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(pubPath, []byte(pubAuth), 0644))

	signer, err := ssh.ParsePrivateKey(privPEM)
	require.NoError(t, err)

	// Generate a stable host key, same as the keygen controller does.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostPEM, err := ssh.MarshalPrivateKey(hostPriv, "")
	require.NoError(t, err)
	hostKeyPath := filepath.Join(dir, "host_key")
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(hostPEM), 0600))

	return testCA{KeyPath: keyPath, PubKeyPath: pubPath, HostKeyPath: hostKeyPath, Signer: signer}
}

// validConfig returns a Config wired to the given CA with a random listen port.
func validConfig(ca testCA) Config {
	return Config{
		ListenAddr:         "127.0.0.1:0",
		CAKeyPath:          ca.KeyPath,
		CAPubKeyPath:       ca.PubKeyPath,
		HostKeyPath:        ca.HostKeyPath,
		PodName:            "test-pod",
		HostPrincipals:     []string{"localhost", "127.0.0.1"},
		MaxSessionDuration: 10 * time.Minute,
		LoginGraceTime:     5 * time.Second,
		MaxAuthTries:       3,
	}
}

// signedClientConfig creates an SSH client config that authenticates with
// a CA-signed user certificate.
func signedClientConfig(t *testing.T, ca testCA) *ssh.ClientConfig {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	cert, err := sshca.SignUserKey(ca.Signer, signer.PublicKey(), "test-user", []string{"runner"}, time.Hour)
	require.NoError(t, err)

	certSigner, err := ssh.NewCertSigner(cert, signer)
	require.NoError(t, err)

	return &ssh.ClientConfig{
		User:            "runner",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
}

// ---------- Tests ----------

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config, string) // mutate config and/or temp dir before New
		wantErr string
	}{
		{
			name:   "valid config starts server",
			mutate: nil,
		},
		{
			name: "missing CA private key",
			mutate: func(c *Config, _ string) {
				c.CAKeyPath = "/nonexistent/ca"
			},
			wantErr: "read CA key",
		},
		{
			name: "missing CA public key",
			mutate: func(c *Config, _ string) {
				c.CAPubKeyPath = "/nonexistent/ca.pub"
			},
			wantErr: "read CA public key",
		},
		{
			name: "corrupt CA private key",
			mutate: func(c *Config, dir string) {
				bad := filepath.Join(dir, "bad_ca")
				require.NoError(t, os.WriteFile(bad, []byte("not-a-pem"), 0600))
				c.CAKeyPath = bad
			},
			wantErr: "parse CA key",
		},
		{
			name: "corrupt CA public key",
			mutate: func(c *Config, dir string) {
				bad := filepath.Join(dir, "bad_ca.pub")
				require.NoError(t, os.WriteFile(bad, []byte("not-a-pubkey"), 0644))
				c.CAPubKeyPath = bad
			},
			wantErr: "parse CA public key",
		},
		{
			name: "missing host key",
			mutate: func(c *Config, _ string) {
				c.HostKeyPath = "/nonexistent/host_key"
			},
			wantErr: "load host key",
		},
		{
			name: "corrupt host key",
			mutate: func(c *Config, dir string) {
				bad := filepath.Join(dir, "bad_host_key")
				require.NoError(t, os.WriteFile(bad, []byte("not-a-pem"), 0600))
				c.HostKeyPath = bad
			},
			wantErr: "load host key",
		},
		{
			name: "no host principals fails signing",
			mutate: func(c *Config, _ string) {
				c.HostPrincipals = nil
			},
			wantErr: "sign host key",
		},
		{
			name: "invalid listen address",
			mutate: func(c *Config, _ string) {
				c.ListenAddr = "256.256.256.256:99999"
			},
			wantErr: "listen on",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ca := newTestCA(t, dir)
			cfg := validConfig(ca)

			if tt.mutate != nil {
				tt.mutate(&cfg, dir)
			}

			srv, err := New(cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			defer srv.Close()
			assert.NotNil(t, srv.Addr())
		})
	}
}

func TestServe_AuthenticatedClientReceivesCallback(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		handlerCalled atomic.Bool
		handlerDone   sync.WaitGroup
	)
	handlerDone.Add(1)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, sc *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			defer handlerDone.Done()
			handlerCalled.Store(true)
			assert.Equal(t, "runner", sc.User())
			assert.NotEmpty(t, sc.Permissions.Extensions["auth-fingerprint"])
			assert.Equal(t, "test-user", sc.Permissions.Extensions["auth-identity"])
			sc.Close()
		})
	}()

	// Dial and authenticate
	clientCfg := signedClientConfig(t, ca)
	conn, err := ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	require.NoError(t, err)
	conn.Close()

	// Wait for handler, then shut down
	handlerDone.Wait()
	cancel()
	require.NoError(t, <-serveErr)
	assert.True(t, handlerCalled.Load())
}

func TestServe_GracefulShutdownDrainsConnections(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	handlerStarted := make(chan struct{})
	handlerRelease := make(chan struct{})

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, sc *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			close(handlerStarted)
			<-handlerRelease
			sc.Close()
		})
	}()

	clientCfg := signedClientConfig(t, ca)
	conn, err := ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	require.NoError(t, err)
	defer conn.Close()

	<-handlerStarted

	// Cancel context — Serve should block waiting for the active handler.
	cancel()

	// Serve should NOT have returned yet.
	select {
	case <-serveErr:
		t.Fatal("Serve returned before handler finished")
	case <-time.After(100 * time.Millisecond):
		// expected
	}

	// Release the handler; Serve should now return.
	close(handlerRelease)
	require.NoError(t, <-serveErr)
}

func TestServe_UnauthenticatedClientRejected(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, _ *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			t.Error("handler should not be called for unauthenticated client")
		})
	}()

	// Try connecting with a random, unsigned key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	clientCfg := &ssh.ClientConfig{
		User:            "runner",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	_, err = ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	assert.Error(t, err)

	cancel()
	require.NoError(t, <-serveErr)
}

func TestServe_ConcurrentClients(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numClients = 5
	var counter atomic.Int32
	var wg sync.WaitGroup
	wg.Add(numClients)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, sc *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			counter.Add(1)
			wg.Done()
			sc.Close()
		})
	}()

	for i := 0; i < numClients; i++ {
		clientCfg := signedClientConfig(t, ca)
		conn, err := ssh.Dial("tcp", srv.Addr().String(), clientCfg)
		require.NoError(t, err)
		conn.Close()
	}

	wg.Wait()
	cancel()
	require.NoError(t, <-serveErr)
	assert.Equal(t, int32(numClients), counter.Load())
}

func TestServe_HandshakeTimeout(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)
	cfg.LoginGraceTime = 200 * time.Millisecond

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handlerCalled := atomic.Bool{}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, _ *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			handlerCalled.Store(true)
		})
	}()

	// Open a raw TCP connection but never complete the SSH handshake.
	// Just sit idle — the server should close it after LoginGraceTime.
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	require.NoError(t, err)

	// Read until EOF or error — the server should kill the connection
	// once the handshake deadline expires.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, readErr := conn.Read(buf)
		if readErr != nil {
			break
		}
	}
	conn.Close()

	cancel()
	require.NoError(t, <-serveErr)
	assert.False(t, handlerCalled.Load(), "handler should not be called for timed-out handshake")
}

func TestServe_ExpiredCertRejected(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, _ *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			t.Error("handler should not be called for expired certificate")
		})
	}()

	// Create a client cert that expired 1 hour ago.
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(userPriv)
	require.NoError(t, err)

	// Sign with a validity of 1 nanosecond — it will already be expired
	// by the time we try to use it (the cert's ValidBefore will be in the
	// past since SignUserKey uses time.Now() + validity, and 1ns is negligible).
	cert, err := sshca.SignUserKey(ca.Signer, signer.PublicKey(), "expired-user", []string{"runner"}, 1*time.Nanosecond)
	require.NoError(t, err)
	// Ensure the cert is actually expired by waiting a moment.
	time.Sleep(10 * time.Millisecond)

	certSigner, err := ssh.NewCertSigner(cert, signer)
	require.NoError(t, err)

	clientCfg := &ssh.ClientConfig{
		User:            "runner",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	_, err = ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	assert.Error(t, err)

	cancel()
	require.NoError(t, <-serveErr)
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	addr := srv.Addr().String()

	// Close the server; new connections should be refused.
	require.NoError(t, srv.Close())

	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	assert.Error(t, err)
}

func TestAddr(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)
	defer srv.Close()

	addr := srv.Addr()
	require.NotNil(t, addr)

	tcpAddr, ok := addr.(*net.TCPAddr)
	require.True(t, ok)
	assert.NotZero(t, tcpAddr.Port, "port should be non-zero when using :0")
	assert.Equal(t, "127.0.0.1", tcpAddr.IP.String())
}

func TestLoadSigner(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(string) string // returns path
		wantErr string
	}{
		{
			name: "valid PEM key",
			setup: func(dir string) string {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				blk, err := ssh.MarshalPrivateKey(priv, "")
				require.NoError(t, err)
				p := filepath.Join(dir, "key")
				require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(blk), 0600))
				return p
			},
		},
		{
			name: "nonexistent file",
			setup: func(_ string) string {
				return "/no/such/file"
			},
			wantErr: "read",
		},
		{
			name: "invalid PEM data",
			setup: func(dir string) string {
				p := filepath.Join(dir, "bad")
				require.NoError(t, os.WriteFile(p, []byte("garbage"), 0600))
				return p
			},
			wantErr: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.setup(dir)
			signer, err := loadSigner(path, "test key")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, signer)
		})
	}
}

func TestLoadCAPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(string) string
		wantErr string
	}{
		{
			name: "valid authorized_keys format",
			setup: func(dir string) string {
				_, pubAuth, err := sshca.GenerateCAKeypair()
				require.NoError(t, err)
				p := filepath.Join(dir, "ca.pub")
				require.NoError(t, os.WriteFile(p, []byte(pubAuth), 0644))
				return p
			},
		},
		{
			name: "nonexistent file",
			setup: func(_ string) string {
				return "/no/such/ca.pub"
			},
			wantErr: "read CA public key",
		},
		{
			name: "invalid public key data",
			setup: func(dir string) string {
				p := filepath.Join(dir, "bad.pub")
				require.NoError(t, os.WriteFile(p, []byte("not a key"), 0644))
				return p
			},
			wantErr: "parse CA public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.setup(dir)
			pub, err := loadCAPublicKey(path)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, pub)
		})
	}
}

func TestNewHostCertSigner(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)

	cfg := validConfig(ca)
	cfg.PodName = "my-pod"

	signer, err := newHostCertSigner(ca.Signer, cfg)
	require.NoError(t, err)

	// The signer should present a host certificate.
	pubKey := signer.PublicKey()
	cert, ok := pubKey.(*ssh.Certificate)
	require.True(t, ok, "public key should be a certificate")
	assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
	assert.Equal(t, "gateway-host:my-pod", cert.KeyId)
	assert.Contains(t, cert.ValidPrincipals, "localhost")
	assert.Contains(t, cert.ValidPrincipals, "127.0.0.1")

	// Validity window should be approximately MaxSessionDuration + 1 hour.
	validDuration := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0))
	expected := cfg.MaxSessionDuration + 1*time.Hour + 5*time.Minute // +5 min clock skew grace
	assert.InDelta(t, expected.Seconds(), validDuration.Seconds(), 2)
}

func TestServe_MultipleSequentialSessions(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir)
	cfg := validConfig(ca)

	srv, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var identities []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, sc *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			mu.Lock()
			identities = append(identities, sc.Permissions.Extensions["auth-identity"])
			mu.Unlock()
			wg.Done()
			sc.Close()
		})
	}()

	// Connect with 3 differently-signed clients sequentially.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		_, userPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(userPriv)
		require.NoError(t, err)

		keyID := fmt.Sprintf("user-%d", i)
		cert, err := sshca.SignUserKey(ca.Signer, signer.PublicKey(), keyID, []string{"runner"}, time.Hour)
		require.NoError(t, err)
		certSigner, err := ssh.NewCertSigner(cert, signer)
		require.NoError(t, err)

		clientCfg := &ssh.ClientConfig{
			User:            "runner",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}

		conn, err := ssh.Dial("tcp", srv.Addr().String(), clientCfg)
		require.NoError(t, err)
		conn.Close()
		wg.Wait()
	}

	cancel()
	require.NoError(t, <-serveErr)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"user-0", "user-1", "user-2"}, identities)
}
