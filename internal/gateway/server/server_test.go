package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
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

	"github.com/project-unbounded/blip/internal/gateway/auth"
)

// testHostKey holds ephemeral key material written to temp files for a single test.
type testHostKey struct {
	HostKeyPath string
	Signer      ssh.Signer
}

// newTestHostKey generates a fresh host key and writes it to a temp file.
func newTestHostKey(t *testing.T, dir string) testHostKey {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostPEM, err := ssh.MarshalPrivateKey(hostPriv, "")
	require.NoError(t, err)
	hostKeyPath := filepath.Join(dir, "host_key")
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(hostPEM), 0600))

	signer, err := ssh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	return testHostKey{HostKeyPath: hostKeyPath, Signer: signer}
}

// newTestAuthWatcher creates an AuthWatcher with the given pubkey fingerprints allowed.
// The map value is the comment (username) associated with the fingerprint.
func newTestAuthWatcher(fingerprints map[string]string) *auth.AuthWatcher {
	return auth.NewTestAuthWatcher(fingerprints)
}

// validConfig returns a Config wired to the given host key with a random listen port.
func validConfig(hk testHostKey) Config {
	return Config{
		ListenAddr:         "127.0.0.1:0",
		HostKeyPath:        hk.HostKeyPath,
		PodName:            "test-pod",
		MaxSessionDuration: 10 * time.Minute,
		LoginGraceTime:     5 * time.Second,
		MaxAuthTries:       3,
	}
}

// allowedPubkeyClientConfig creates an SSH client config with a fresh key pair
// and returns both the config and the pubkey fingerprint for allowing.
func allowedPubkeyClientConfig(t *testing.T) (*ssh.ClientConfig, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	fp := ssh.FingerprintSHA256(sshPub)

	return &ssh.ClientConfig{
		User:            "runner",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}, fp
}

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
			name: "missing host key",
			mutate: func(c *Config, _ string) {
				c.HostKeyPath = "/nonexistent/host_key"
			},
			wantErr: "read host key",
		},
		{
			name: "corrupt host key",
			mutate: func(c *Config, dir string) {
				bad := filepath.Join(dir, "bad_host_key")
				require.NoError(t, os.WriteFile(bad, []byte("not-a-pem"), 0600))
				c.HostKeyPath = bad
			},
			wantErr: "parse host key",
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
			hk := newTestHostKey(t, dir)
			cfg := validConfig(hk)

			if tt.mutate != nil {
				tt.mutate(&cfg, dir)
			}

			srv, err := New(context.Background(), cfg)
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
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	clientCfg, fp := allowedPubkeyClientConfig(t)
	cfg.AuthWatcher = newTestAuthWatcher(map[string]string{fp: "runner@test"})

	srv, err := New(context.Background(), cfg)
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
			assert.Equal(t, "pubkey:runner@test", sc.Permissions.Extensions["auth-identity"])
			sc.Close()
		})
	}()

	conn, err := ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	require.NoError(t, err)
	conn.Close()

	handlerDone.Wait()
	cancel()
	require.NoError(t, <-serveErr)
	assert.True(t, handlerCalled.Load())
}

func TestServe_GracefulShutdownDrainsConnections(t *testing.T) {
	dir := t.TempDir()
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	clientCfg, fp := allowedPubkeyClientConfig(t)
	cfg.AuthWatcher = newTestAuthWatcher(map[string]string{fp: "runner@test"})

	srv, err := New(context.Background(), cfg)
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
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	// Allow a specific key, then connect with a different one.
	cfg.AuthWatcher = newTestAuthWatcher(map[string]string{"SHA256:allowed-key": "someone@host"})

	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, func(_ context.Context, _ *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
			t.Error("handler should not be called for unauthenticated client")
		})
	}()

	// Try connecting with a random key not in the allowed list.
	clientCfg, _ := allowedPubkeyClientConfig(t) // generates a key not in the allowed set
	_, err = ssh.Dial("tcp", srv.Addr().String(), clientCfg)
	assert.Error(t, err)

	cancel()
	require.NoError(t, <-serveErr)
}

func TestServe_ConcurrentClients(t *testing.T) {
	dir := t.TempDir()
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	const numClients = 5

	// Pre-generate client configs and fingerprints.
	type clientInfo struct {
		cfg *ssh.ClientConfig
		fp  string
	}
	clients := make([]clientInfo, numClients)
	fpSet := make(map[string]string)
	for i := range numClients {
		cc, fp := allowedPubkeyClientConfig(t)
		clients[i] = clientInfo{cfg: cc, fp: fp}
		fpSet[fp] = fmt.Sprintf("user%d@host", i)
		_ = i
	}
	cfg.AuthWatcher = newTestAuthWatcher(fpSet)

	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		conn, err := ssh.Dial("tcp", srv.Addr().String(), clients[i].cfg)
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
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)
	cfg.LoginGraceTime = 200 * time.Millisecond

	srv, err := New(context.Background(), cfg)
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
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	require.NoError(t, err)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.ReadAll(conn)
	conn.Close()

	cancel()
	require.NoError(t, <-serveErr)
	assert.False(t, handlerCalled.Load(), "handler should not be called for timed-out handshake")
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)

	addr := srv.Addr().String()

	require.NoError(t, srv.Close())

	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	assert.Error(t, err)
}

func TestAddr(t *testing.T) {
	dir := t.TempDir()
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer srv.Close()

	addr := srv.Addr()
	require.NotNil(t, addr)

	assert.IsType(t, &net.TCPAddr{}, addr)
	tcpAddr := addr.(*net.TCPAddr)
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
			signer, err := LoadSigner(path, "test key")
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

func TestServe_MultipleSequentialSessions(t *testing.T) {
	dir := t.TempDir()
	hk := newTestHostKey(t, dir)
	cfg := validConfig(hk)

	const numClients = 3
	type clientInfo struct {
		cfg      *ssh.ClientConfig
		fp       string
		username string
	}
	clients := make([]clientInfo, numClients)
	fpSet := make(map[string]string)
	for i := range numClients {
		cc, fp := allowedPubkeyClientConfig(t)
		username := fmt.Sprintf("user%d@host", i)
		clients[i] = clientInfo{cfg: cc, fp: fp, username: username}
		fpSet[fp] = username
		_ = i
	}
	cfg.AuthWatcher = newTestAuthWatcher(fpSet)

	srv, err := New(context.Background(), cfg)
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

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		conn, err := ssh.Dial("tcp", srv.Addr().String(), clients[i].cfg)
		require.NoError(t, err)
		conn.Close()
		wg.Wait()
	}

	cancel()
	require.NoError(t, <-serveErr)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, identities, numClients)
	for i, id := range identities {
		assert.Equal(t, fmt.Sprintf("pubkey:%s", clients[i].username), id)
	}
}
