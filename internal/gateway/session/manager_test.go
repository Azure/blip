package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/proxy"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

type sshEndpoints struct {
	client     *ssh.Client
	serverConn *ssh.ServerConn
	chans      <-chan ssh.NewChannel
	reqs       <-chan *ssh.Request
}

func sshPipe(t *testing.T) sshEndpoints {
	t.Helper()
	return sshPipeWithUser(t, "test-user")
}

func sshPipeWithUser(t *testing.T, user string) sshEndpoints {
	t.Helper()
	signer := generateSigner(t)

	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	clientCfg := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	var (
		sc    *ssh.ServerConn
		sCh   <-chan ssh.NewChannel
		sReqs <-chan *ssh.Request
		sErr  error
		ready = make(chan struct{})
	)
	go func() {
		tcpConn, err := ln.Accept()
		if err != nil {
			sErr = err
			close(ready)
			return
		}
		sc, sCh, sReqs, sErr = ssh.NewServerConn(tcpConn, serverCfg)
		close(ready)
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	cc, cCh, cReqs, err := ssh.NewClientConn(tcpConn, ln.Addr().String(), clientCfg)
	require.NoError(t, err)
	<-ready
	require.NoError(t, sErr)

	client := ssh.NewClient(cc, cCh, cReqs)
	t.Cleanup(func() {
		client.Close()
		sc.Close()
	})

	return sshEndpoints{
		client:     client,
		serverConn: sc,
		chans:      sCh,
		reqs:       sReqs,
	}
}

// openAndAcceptChannel opens a channel from the client side and accepts it
// on the server side. It handles the goroutine coordination needed because
// OpenChannel blocks until Accept is called.
func openAndAcceptChannel(t *testing.T, ep sshEndpoints) (clientCh, serverCh ssh.Channel) {
	t.Helper()

	type result struct {
		ch  ssh.Channel
		err error
	}
	clientResult := make(chan result, 1)
	go func() {
		ch, _, err := ep.client.OpenChannel("session", nil)
		clientResult <- result{ch, err}
	}()

	newChan := <-ep.chans
	require.NotNil(t, newChan)

	sCh, _, err := newChan.Accept()
	require.NoError(t, err)

	cr := <-clientResult
	require.NoError(t, cr.err)

	return cr.ch, sCh
}

// fakeNewChannel implements ssh.NewChannel for testing waitForSessionChannel.
type fakeNewChannel struct {
	chanType string
}

func (f *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) { return nil, nil, nil }
func (f *fakeNewChannel) Reject(ssh.RejectionReason, string) error          { return nil }
func (f *fakeNewChannel) ChannelType() string                               { return f.chanType }
func (f *fakeNewChannel) ExtraData() []byte                                 { return nil }

// ---------------------------------------------------------------------------
// Session ID generation and validation
// ---------------------------------------------------------------------------

func TestSessionID_GenerateAndValidate(t *testing.T) {
	seen := make(map[string]struct{})
	for range 20 {
		id := generateSessionID()

		assert.True(t, isSessionID(id), "generated ID %q should be valid", id)
		assert.Contains(t, id, sessionIDPrefix)

		_, dup := seen[id]
		assert.False(t, dup, "duplicate session ID generated: %s", id)
		seen[id] = struct{}{}
	}
}

func TestIsSessionID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"blip-a3f29c04b1", true},
		{"blip-0000000000", true},
		{"blip-ffffffffff", true},
		{"blip-", false},
		{"blip-short", false},
		{"blip-a3f29c04b1x", false},
		{"blip-A3F29C04B1", false},
		{"blip-a3f29c04g1", false},
		{"other-a3f29c04b1", false},
		{"", false},
		{"runner", false},
		{"blip-a3f29c04b!", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, isSessionID(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// extractAuthExtensions
// ---------------------------------------------------------------------------

func TestExtractAuthExtensions(t *testing.T) {
	tests := []struct {
		name         string
		perms        *ssh.Permissions
		wantFP       string
		wantID       string
		wantVMClient bool
	}{
		{
			name: "both extensions present",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					auth.ExtFingerprint: "SHA256:abc",
					auth.ExtIdentity:    "user@example.com",
				},
			},
			wantFP:       "SHA256:abc",
			wantID:       "user@example.com",
			wantVMClient: false,
		},
		{
			name:         "nil permissions",
			perms:        nil,
			wantFP:       "",
			wantID:       "",
			wantVMClient: false,
		},
		{
			name:         "nil extensions map",
			perms:        &ssh.Permissions{},
			wantFP:       "",
			wantID:       "",
			wantVMClient: false,
		},
		{
			name: "only fingerprint",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					auth.ExtFingerprint: "SHA256:xyz",
				},
			},
			wantFP:       "SHA256:xyz",
			wantID:       "",
			wantVMClient: false,
		},
		{
			name: "VM client key auth",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					auth.ExtFingerprint: "SHA256:vm-key",
					auth.ExtIdentity:    "pubkey:alice@laptop",
					auth.ExtIsVMClient:  "true",
				},
			},
			wantFP:       "SHA256:vm-key",
			wantID:       "pubkey:alice@laptop",
			wantVMClient: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := sshPipe(t)
			ep.serverConn.Permissions = tt.perms
			fp, id, isVM := extractAuthExtensions(ep.serverConn)
			assert.Equal(t, tt.wantFP, fp)
			assert.Equal(t, tt.wantID, id)
			assert.Equal(t, tt.wantVMClient, isVM)
		})
	}
}

// ---------------------------------------------------------------------------
// waitForSessionChannel
// ---------------------------------------------------------------------------

func TestWaitForSessionChannel(t *testing.T) {
	t.Run("session channel arrives first", func(t *testing.T) {
		ch := make(chan ssh.NewChannel, 1)
		ch <- &fakeNewChannel{chanType: "session"}
		close(ch)

		first, queued := waitForSessionChannel(ch, false)
		require.NotNil(t, first)
		assert.Equal(t, "session", first.ChannelType())
		assert.Empty(t, queued)
	})

	t.Run("non-session channels queued before session", func(t *testing.T) {
		ch := make(chan ssh.NewChannel, 3)
		ch <- &fakeNewChannel{chanType: "direct-tcpip"}
		ch <- &fakeNewChannel{chanType: "forwarded-tcpip"}
		ch <- &fakeNewChannel{chanType: "session"}
		close(ch)

		first, queued := waitForSessionChannel(ch, false)
		require.NotNil(t, first)
		assert.Equal(t, "session", first.ChannelType())
		assert.Len(t, queued, 2)
		assert.Equal(t, "direct-tcpip", queued[0].ChannelType())
		assert.Equal(t, "forwarded-tcpip", queued[1].ChannelType())
	})

	t.Run("channel closed before session arrives", func(t *testing.T) {
		ch := make(chan ssh.NewChannel, 2)
		ch <- &fakeNewChannel{chanType: "direct-tcpip"}
		close(ch)

		first, queued := waitForSessionChannel(ch, false)
		assert.Nil(t, first)
		assert.Len(t, queued, 1)
	})

	t.Run("empty channel", func(t *testing.T) {
		ch := make(chan ssh.NewChannel)
		close(ch)

		first, queued := waitForSessionChannel(ch, false)
		assert.Nil(t, first)
		assert.Empty(t, queued)
	})

	t.Run("reconnect timeout without session channel", func(t *testing.T) {
		ch := make(chan ssh.NewChannel) // never sends anything

		start := time.Now()
		first, queued := waitForSessionChannel(ch, true)
		elapsed := time.Since(start)
		assert.Nil(t, first)
		assert.Empty(t, queued)
		// Should return after ~100ms timeout, not block forever.
		// Use a generous upper bound to avoid flakes on slow CI.
		assert.Less(t, elapsed, 2*time.Second)
	})
}

// ---------------------------------------------------------------------------
// Manager creation and session registry
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	cfg := Config{
		MaxBlipsPerUser: 5,
		PodName:         "gw-0",
	}
	m := New(cfg)

	assert.NotNil(t, m)
	assert.Empty(t, m.sessions)
	assert.Equal(t, cfg.PodName, m.cfg.PodName)
	assert.Equal(t, cfg.MaxBlipsPerUser, m.cfg.MaxBlipsPerUser)
}

func TestRegisterUnregister(t *testing.T) {
	m := New(Config{})
	ep := sshPipe(t)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := proxy.NewSession(cancel, ep.serverConn)

	m.register("blip-0000000001", sess)
	assert.Len(t, m.sessions, 1)

	ep2 := sshPipe(t)
	_, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	sess2 := proxy.NewSession(cancel2, ep2.serverConn)
	m.register("blip-0000000002", sess2)
	assert.Len(t, m.sessions, 2)

	m.unregister("blip-0000000001")
	assert.Len(t, m.sessions, 1)
	_, exists := m.sessions["blip-0000000001"]
	assert.False(t, exists)

	// Unregister non-existent is a no-op
	m.unregister("blip-nonexistent")
	assert.Len(t, m.sessions, 1)

	m.unregister("blip-0000000002")
	assert.Empty(t, m.sessions)
}

func TestRegisterUnregister_ConcurrentSafety(t *testing.T) {
	m := New(Config{})
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			ep := sshPipe(t)
			_, cancel := context.WithCancel(context.Background())
			sess := proxy.NewSession(cancel, ep.serverConn)
			id := generateSessionID()

			m.register(id, sess)
			m.unregister(id)
			cancel()
		}(i)
	}
	wg.Wait()
	assert.Empty(t, m.sessions)
}

// ---------------------------------------------------------------------------
// NotifyShutdown
// ---------------------------------------------------------------------------

func TestNotifyShutdown(t *testing.T) {
	t.Run("sends banner to all sessions and closes them", func(t *testing.T) {
		m := New(Config{})

		type sessionFixture struct {
			clientCh ssh.Channel
			sess     *proxy.Session
			id       string
		}
		var fixtures []sessionFixture

		for range 3 {
			ep := sshPipe(t)
			clientCh, serverCh := openAndAcceptChannel(t, ep)

			_, cancel := context.WithCancel(context.Background())
			sess := proxy.NewSession(cancel, ep.serverConn)
			sess.SetBannerChannel(serverCh)

			id := generateSessionID()
			m.register(id, sess)

			fixtures = append(fixtures, sessionFixture{
				clientCh: clientCh,
				sess:     sess,
				id:       id,
			})
		}

		m.NotifyShutdown()

		for _, f := range fixtures {
			buf := make([]byte, 1024)
			n, _ := f.clientCh.Stderr().Read(buf)
			banner := string(buf[:n])
			assert.Contains(t, banner, "shutting down")
		}
	})

	t.Run("no sessions is a no-op", func(t *testing.T) {
		m := New(Config{})
		assert.NotPanics(t, func() { m.NotifyShutdown() })
	})
}

// ---------------------------------------------------------------------------
// logAndBannerAllocError
// ---------------------------------------------------------------------------

func TestLogAndBannerAllocError(t *testing.T) {
	tests := []struct {
		name         string
		reconnecting bool
		wantContains string
	}{
		{
			name:         "new session allocation failure",
			reconnecting: false,
			wantContains: "Blip allocation failed",
		},
		{
			name:         "reconnect failure",
			reconnecting: true,
			wantContains: "Reconnect failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(Config{})
			ep := sshPipe(t)
			clientCh, serverCh := openAndAcceptChannel(t, ep)

			m.logAndBannerAllocError(serverCh, "1.2.3.4:5678", "test-user", tt.reconnecting, "blip-0000000001", io.ErrUnexpectedEOF)

			buf := make([]byte, 1024)
			n, _ := clientCh.Stderr().Read(buf)
			banner := string(buf[:n])
			assert.Contains(t, banner, tt.wantContains)
			assert.Contains(t, banner, io.ErrUnexpectedEOF.Error())
		})
	}
}

// ---------------------------------------------------------------------------
// HandleConnection: early exit scenarios
// ---------------------------------------------------------------------------

func TestHandleConnection_NoSessionChannel(t *testing.T) {
	// When the client closes channels before sending a "session" channel,
	// HandleConnection should return gracefully without panicking.
	m := New(Config{
		GatewaySigner: generateSigner(t),
		PodName:       "test-gw",
	})

	ep := sshPipe(t)

	chans := make(chan ssh.NewChannel)
	close(chans)
	reqs := make(chan *ssh.Request)
	close(reqs)

	done := make(chan struct{})
	go func() {
		m.HandleConnection(context.Background(), ep.serverConn, chans, reqs)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleConnection did not return when channels were closed immediately")
	}
}

func TestHandleConnection_NonSessionChannelsThenClose(t *testing.T) {
	// Non-session channels arrive, then the stream closes before any
	// "session" channel. HandleConnection should return gracefully.
	m := New(Config{
		GatewaySigner: generateSigner(t),
		PodName:       "test-gw",
	})

	ep := sshPipe(t)

	chans := make(chan ssh.NewChannel, 2)
	chans <- &fakeNewChannel{chanType: "direct-tcpip"}
	chans <- &fakeNewChannel{chanType: "forwarded-tcpip"}
	close(chans)

	reqs := make(chan *ssh.Request)
	close(reqs)

	done := make(chan struct{})
	go func() {
		m.HandleConnection(context.Background(), ep.serverConn, chans, reqs)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleConnection did not return after non-session channels closed")
	}
}

// ---------------------------------------------------------------------------
// Reconnect detection via username
// ---------------------------------------------------------------------------

func TestHandleConnection_DetectsReconnectVsNewSession(t *testing.T) {
	tests := []struct {
		name       string
		user       string
		wantReconn bool
	}{
		{"normal user is new session", "runner", false},
		{"session ID is reconnect", "blip-a1b2c3d4e5", true},
		{"partial session ID is new session", "blip-short", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantReconn, isSessionID(tt.user))
		})
	}
}

// ---------------------------------------------------------------------------
// sessionTTL and isOIDCIdentity
// ---------------------------------------------------------------------------

func TestIsOIDCIdentity(t *testing.T) {
	tests := []struct {
		identity string
		want     bool
	}{
		{"oidc:repo:owner/repo:ref:refs/heads/main", true},
		{"oidc:anything", true},
		{"blip:SHA256:abc", false},
		{"blip-vm:blip-abc1234567", false},
		{"", false},
		{"runner", false},
	}
	for _, tt := range tests {
		t.Run(tt.identity, func(t *testing.T) {
			assert.Equal(t, tt.want, isOIDCIdentity(tt.identity))
		})
	}
}

func TestSessionTTL(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		wantSec  int
	}{
		{"CA cert identity gets 8 hour TTL", "blip:SHA256:abc", int(DefaultTTL.Seconds())},
		{"OIDC identity gets 30 minute TTL", "oidc:repo:owner/repo:ref:refs/heads/main", int(OIDCDefaultTTL.Seconds())},
		{"empty identity gets default TTL", "", int(DefaultTTL.Seconds())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantSec, sessionTTL(tt.identity))
		})
	}
}
