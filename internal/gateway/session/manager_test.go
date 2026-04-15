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

func TestNotifyShutdown(t *testing.T) {
	t.Run("sends banner to all sessions and closes them", func(t *testing.T) {
		m := New(Config{})

		type fixture struct {
			clientCh ssh.Channel
			id       string
		}
		var fixtures []fixture

		for range 3 {
			ep := sshPipe(t)
			clientCh, serverCh := openAndAcceptChannel(t, ep)

			_, cancel := context.WithCancel(context.Background())
			sess := proxy.NewSession(cancel, ep.serverConn)
			sess.SetBannerChannel(serverCh)

			id := generateSessionID()
			m.register(id, sess)

			fixtures = append(fixtures, fixture{
				clientCh: clientCh,
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

func TestHandleConnection_NoSessionChannelEarlyExit(t *testing.T) {
	tests := []struct {
		name    string
		prefill []string // channel types to enqueue before closing
		wantMsg string
	}{
		{
			name:    "no channels at all",
			prefill: nil,
			wantMsg: "HandleConnection did not return when channels were closed immediately",
		},
		{
			name:    "non-session channels then close",
			prefill: []string{"direct-tcpip", "forwarded-tcpip"},
			wantMsg: "HandleConnection did not return after non-session channels closed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(Config{
				GatewaySigner: generateSigner(t),
				PodName:       "test-gw",
			})
			ep := sshPipe(t)

			chans := make(chan ssh.NewChannel, len(tt.prefill))
			for _, ct := range tt.prefill {
				chans <- &fakeNewChannel{chanType: ct}
			}
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
				t.Fatal(tt.wantMsg)
			}
		})
	}
}

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

func TestSanitizeAuthorizedKeyComment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal string passes through", "oidc:alice@example.com", "oidc:alice@example.com"},
		{"newline replaced", "oidc:alice\ninjected-key ssh-ed25519 AAAA", "oidc:alice_injected-key ssh-ed25519 AAAA"},
		{"carriage return replaced", "oidc:alice\rinjected", "oidc:alice_injected"},
		{"CRLF replaced", "oidc:alice\r\ninjected", "oidc:alice__injected"},
		{"NUL replaced", "oidc:alice\x00injected", "oidc:alice_injected"},
		{"empty string", "", ""},
		{"multiple newlines", "a\nb\nc", "a_b_c"},
		{"unicode preserved", "oidc:ユーザー", "oidc:ユーザー"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeAuthorizedKeyComment(tt.input))
		})
	}
}

func TestContextWithConnClose(t *testing.T) {
	t.Run("context cancelled when connection is closed", func(t *testing.T) {
		ep := sshPipe(t)

		ctx, stop := contextWithConnClose(context.Background(), ep.serverConn)
		defer stop()

		// Context should not be cancelled yet.
		select {
		case <-ctx.Done():
			t.Fatal("context should not be cancelled before connection close")
		default:
		}

		// Close the client side of the connection — simulates Ctrl+C / disconnect.
		ep.client.Close()

		// Context should be cancelled promptly.
		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after connection close")
		}
	})

	t.Run("context cancelled when parent is cancelled", func(t *testing.T) {
		ep := sshPipe(t)

		parent, parentCancel := context.WithCancel(context.Background())
		ctx, stop := contextWithConnClose(parent, ep.serverConn)
		defer stop()

		parentCancel()

		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after parent cancel")
		}
	})

	t.Run("stop is safe to call multiple times", func(t *testing.T) {
		ep := sshPipe(t)

		_, stop := contextWithConnClose(context.Background(), ep.serverConn)
		assert.NotPanics(t, func() {
			stop()
			stop()
			stop()
		})
	})

	t.Run("does not interfere with channel data", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		_, stop := contextWithConnClose(context.Background(), ep.serverConn)
		defer stop()

		// Write data through the channel — the monitoring goroutine must
		// not consume any of it.
		testData := []byte("hello world")
		_, err := clientCh.Write(testData)
		require.NoError(t, err)

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(serverCh, buf)
		require.NoError(t, err)
		assert.Equal(t, testData, buf)
	})
}

func TestMonitorChannelInterrupt(t *testing.T) {
	t.Run("Ctrl+C byte cancels context", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Context should not be cancelled yet.
		select {
		case <-ctx.Done():
			t.Fatal("context should not be cancelled before Ctrl+C")
		default:
		}

		// Send Ctrl+C (0x03) from the client side.
		_, err := clientCh.Write([]byte{0x03})
		require.NoError(t, err)

		// Context should be cancelled promptly.
		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after Ctrl+C")
		}
	})

	t.Run("Ctrl+C byte embedded in data cancels context", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Send some data with Ctrl+C embedded.
		_, err := clientCh.Write([]byte("hello\x03world"))
		require.NoError(t, err)

		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after embedded Ctrl+C")
		}
	})

	t.Run("signal channel request cancels context", func(t *testing.T) {
		ep := sshPipe(t)
		_, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request, 1)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Send a signal request.
		reqs <- &ssh.Request{Type: "signal", WantReply: false}

		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after signal request")
		}
	})

	t.Run("pty-req does not cancel context", func(t *testing.T) {
		ep := sshPipe(t)
		_, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request, 2)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		reqs <- &ssh.Request{Type: "pty-req", WantReply: false}

		// Context should NOT be cancelled from a pty-req.
		select {
		case <-ctx.Done():
			t.Fatal("context should not be cancelled from pty-req")
		case <-time.After(100 * time.Millisecond):
			// expected — pty-req does not cancel
		}
	})

	t.Run("channel close cancels context", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Close the client channel.
		clientCh.Close()

		select {
		case <-ctx.Done():
			// expected — channel close causes Read to return EOF
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after channel close")
		}
	})

	t.Run("request channel close cancels context", func(t *testing.T) {
		ep := sshPipe(t)
		_, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request, 1)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Close the request channel (simulates client disconnect).
		close(reqs)

		select {
		case <-ctx.Done():
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("context was not cancelled after request channel close")
		}
	})

	t.Run("normal data without 0x03 does not cancel", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		reqs := make(chan *ssh.Request)
		go monitorChannelInterrupt(serverCh, reqs, cancel, done)

		// Send normal data (no Ctrl+C).
		_, err := clientCh.Write([]byte("hello world"))
		require.NoError(t, err)

		// Context should NOT be cancelled.
		select {
		case <-ctx.Done():
			t.Fatal("context should not be cancelled from normal data")
		case <-time.After(200 * time.Millisecond):
			// expected — normal data does not cancel
		}
	})

	t.Run("done channel stops monitor and releases channel", func(t *testing.T) {
		ep := sshPipe(t)
		_, serverCh := openAndAcceptChannel(t, ep)

		cancelled := false
		cancel := func() { cancelled = true }

		done := make(chan struct{})

		reqs := make(chan *ssh.Request, 1)
		monitorDone := make(chan struct{})
		go func() {
			monitorChannelInterrupt(serverCh, reqs, cancel, done)
			close(monitorDone)
		}()

		// Give the monitor time to start reading.
		time.Sleep(50 * time.Millisecond)

		// Close the done channel — simulates device flow completing.
		close(done)

		// The monitor should return promptly.
		select {
		case <-monitorDone:
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("monitor did not stop after done was closed")
		}

		// cancel should NOT have been called — device flow succeeded,
		// we don't want to cancel anything.
		assert.False(t, cancelled, "cancel should not be called when done is closed")

		// Note: the background reader goroutine inside
		// monitorChannelInterrupt may still be blocked on ch.Read.
		// Any data arriving after done is closed will be read and
		// discarded by that goroutine (it checks done before
		// forwarding). This is an inherent limitation of
		// ssh.Channel which does not support read cancellation or
		// deadlines. In practice this is not an issue because the
		// proxy bridge layer starts after the device flow
		// completes, and the client does not send unsolicited data
		// between flow completion and proxy setup.
	})

	t.Run("inner read goroutine respects done after read completes", func(t *testing.T) {
		ep := sshPipe(t)
		clientCh, serverCh := openAndAcceptChannel(t, ep)

		cancelled := false
		cancel := func() { cancelled = true }

		done := make(chan struct{})

		reqs := make(chan *ssh.Request)
		monitorDone := make(chan struct{})
		go func() {
			monitorChannelInterrupt(serverCh, reqs, cancel, done)
			close(monitorDone)
		}()

		// Give the monitor time to start reading.
		time.Sleep(50 * time.Millisecond)

		// Close done, then immediately send data. The inner goroutine
		// should see done is closed and discard the data rather than
		// calling cancel.
		close(done)

		<-monitorDone

		// Write data AFTER monitor has fully stopped. This data
		// should arrive at the inner read goroutine, but since done
		// is closed, it should be discarded (not treated as cancel).
		_, err := clientCh.Write([]byte{0x03})
		require.NoError(t, err)

		// Give the inner goroutine time to process the read.
		time.Sleep(100 * time.Millisecond)

		// cancel must NOT have been called — the 0x03 arrived after
		// done was closed, so the monitor should not treat it as an
		// interrupt.
		assert.False(t, cancelled, "cancel should not be called when data arrives after done")
	})

	t.Run("done channel stops request consumption", func(t *testing.T) {
		ep := sshPipe(t)
		_, serverCh := openAndAcceptChannel(t, ep)

		cancelled := false
		cancel := func() { cancelled = true }

		done := make(chan struct{})
		reqs := make(chan *ssh.Request, 4)

		monitorDone := make(chan struct{})
		go func() {
			monitorChannelInterrupt(serverCh, reqs, cancel, done)
			close(monitorDone)
		}()

		// Give the monitor time to start.
		time.Sleep(50 * time.Millisecond)

		// Close done — simulates device flow completing.
		close(done)

		select {
		case <-monitorDone:
			// expected
		case <-time.After(3 * time.Second):
			t.Fatal("monitor did not stop after done was closed")
		}

		// Send requests after monitor stopped — they should remain in
		// the channel for the proxy bridge to consume.
		reqs <- &ssh.Request{Type: "window-change"}
		reqs <- &ssh.Request{Type: "env"}

		// Both requests should be in the channel, unconsumed.
		assert.Len(t, reqs, 2, "requests sent after monitor stop should not be consumed")
		assert.False(t, cancelled, "cancel should not be called when done is closed")
	})
}
