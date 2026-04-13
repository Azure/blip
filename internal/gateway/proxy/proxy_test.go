package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Test helpers – generate keys and wire up SSH client/server over net.Pipe.
// ---------------------------------------------------------------------------

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// sshPipe creates a connected (client, server) SSH pair over a loopback
// TCP connection. The server accepts any auth (NoClientAuth). Returns the
// client *ssh.Client, the *ssh.ServerConn, and channels for new-channels /
// global-requests on the server side.
type sshEndpoints struct {
	client     *ssh.Client
	serverConn *ssh.ServerConn
	// Server-side streams (channels/requests arriving from the client).
	serverNewChans <-chan ssh.NewChannel
	serverReqs     <-chan *ssh.Request
}

func sshPipe(t *testing.T) sshEndpoints {
	t.Helper()

	signer := generateSigner(t)

	serverCfg := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	serverCfg.AddHostKey(signer)

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	// Server side – accept and handshake in background.
	var (
		sc     *ssh.ServerConn
		sCh    <-chan ssh.NewChannel
		sReqs  <-chan *ssh.Request
		sErr   error
		sReady = make(chan struct{})
	)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			sErr = err
			close(sReady)
			return
		}
		sc, sCh, sReqs, sErr = ssh.NewServerConn(conn, serverCfg)
		close(sReady)
	}()

	// Client side.
	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	cc, cCh, cReqs, err := ssh.NewClientConn(tcpConn, ln.Addr().String(), clientCfg)
	require.NoError(t, err)
	<-sReady
	require.NoError(t, sErr)

	client := ssh.NewClient(cc, cCh, cReqs)
	t.Cleanup(func() {
		client.Close()
		sc.Close()
	})

	return sshEndpoints{
		client:         client,
		serverConn:     sc,
		serverNewChans: sCh,
		serverReqs:     sReqs,
	}
}

// startEchoServer accepts channels from the server side and echoes data back.
func startEchoServer(t *testing.T, chans <-chan ssh.NewChannel) {
	t.Helper()
	go func() {
		for newCh := range chans {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func(ch ssh.Channel) {
				io.Copy(ch, ch)
				ch.CloseWrite()
			}(ch)
		}
	}()
}

// ---------------------------------------------------------------------------
// Session lifecycle tests
// ---------------------------------------------------------------------------

func TestSession_CloseIsIdempotent(t *testing.T) {
	ep := sshPipe(t)

	cancelCount := 0
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	wrappedCancel := func() { cancelCount++; cancel() }
	sess := NewSession(wrappedCancel, ep.serverConn)

	// Close multiple times – must not panic.
	sess.Close()
	sess.Close()
	sess.Close()

	assert.Equal(t, 1, cancelCount, "cancel should be called exactly once")
}

func TestSession_CloseWithAndWithoutUpstream(t *testing.T) {
	tests := []struct {
		name        string
		setUpstream bool
	}{
		{"without upstream", false},
		{"with upstream", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := sshPipe(t)
			_, cancel := context.WithCancel(context.Background())
			defer cancel()

			sess := NewSession(cancel, ep.serverConn)
			if tt.setUpstream {
				upstream := sshPipe(t)
				sess.SetUpstream(upstream.client)
			}

			// Should not panic regardless of upstream presence.
			assert.NotPanics(t, func() { sess.Close() })
		})
	}
}

func TestSendBannerAndClose(t *testing.T) {
	ep := sshPipe(t)

	// Accept the channel on the server side in a goroutine so that
	// OpenChannel on the client can complete.
	type accepted struct {
		ch  ssh.Channel
		err error
	}
	result := make(chan accepted, 1)
	go func() {
		newChan := <-ep.serverNewChans
		ch, _, err := newChan.Accept()
		result <- accepted{ch, err}
	}()

	clientCh, _, err := ep.client.OpenChannel("session", nil)
	require.NoError(t, err)

	a := <-result
	require.NoError(t, a.err)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(cancel, ep.serverConn)
	sess.SetBannerChannel(a.ch)

	const bannerText = "shutting down for maintenance\n"
	sess.SendBannerAndClose(bannerText)

	// Read the banner from the client's stderr stream.
	buf := make([]byte, 256)
	n, _ := clientCh.Stderr().Read(buf)
	assert.Equal(t, bannerText, string(buf[:n]))
}

func TestSendBannerAndClose_NoBannerChannel(t *testing.T) {
	ep := sshPipe(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(cancel, ep.serverConn)

	// No banner channel set – should not panic.
	assert.NotPanics(t, func() { sess.SendBannerAndClose("some banner") })
}

func TestSendBanner(t *testing.T) {
	ep := sshPipe(t)

	type accepted struct {
		ch  ssh.Channel
		err error
	}
	result := make(chan accepted, 1)
	go func() {
		newChan := <-ep.serverNewChans
		ch, _, err := newChan.Accept()
		result <- accepted{ch, err}
	}()

	clientCh, _, err := ep.client.OpenChannel("session", nil)
	require.NoError(t, err)

	a := <-result
	require.NoError(t, a.err)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(cancel, ep.serverConn)
	sess.SetBannerChannel(a.ch)

	const bannerText = "goodbye banner\n"
	sess.SendBanner(bannerText)

	buf := make([]byte, 256)
	n, _ := clientCh.Stderr().Read(buf)
	assert.Equal(t, bannerText, string(buf[:n]))
}

func TestSendBanner_NoBannerChannel(t *testing.T) {
	ep := sshPipe(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(cancel, ep.serverConn)

	// No banner channel set – should not panic.
	assert.NotPanics(t, func() { sess.SendBanner("some banner") })
}

// ---------------------------------------------------------------------------
// Channel forwarding end-to-end
// ---------------------------------------------------------------------------

func TestForward_BidirectionalDataThroughChannel(t *testing.T) {
	// Topology: testClient ↔ [serverConn / upstreamClient] ↔ upstreamServer
	clientSide := sshPipe(t)   // testClient ↔ gateway server side
	upstreamSide := sshPipe(t) // gateway client side ↔ upstream server

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start forwarding from client channels to upstream.
	go Forward(ctx, "test-session", clientSide.serverConn, upstreamSide.client,
		clientSide.serverNewChans, nil)

	// Upstream server: accept the forwarded channel and echo data back.
	startEchoServer(t, upstreamSide.serverNewChans)

	// Client opens a session channel.
	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	payload := []byte("hello through the proxy")
	_, err = clientCh.Write(payload)
	require.NoError(t, err)
	clientCh.CloseWrite()

	got, err := io.ReadAll(clientCh)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestForward_MultipleChannels(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Forward(ctx, "test-multi", clientSide.serverConn, upstreamSide.client,
		clientSide.serverNewChans, nil)

	// Upstream echoes.
	startEchoServer(t, upstreamSide.serverNewChans)

	const numChannels = 5
	var wg sync.WaitGroup
	wg.Add(numChannels)
	for i := range numChannels {
		go func(idx int) {
			defer wg.Done()
			ch, _, err := clientSide.client.OpenChannel("session", nil)
			if !assert.NoError(t, err) {
				return
			}
			msg := fmt.Sprintf("channel-%d", idx)
			_, _ = ch.Write([]byte(msg))
			ch.CloseWrite()
			got, _ := io.ReadAll(ch)
			assert.Equal(t, msg, string(got))
		}(i)
	}
	wg.Wait()
}

func TestForward_ContextCancellationStopsLoop(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		Forward(ctx, "test-cancel", clientSide.serverConn, upstreamSide.client,
			clientSide.serverNewChans, nil)
		close(done)
	}()

	cancel()
	<-done // If Forward doesn't return, the test framework's -timeout will catch it.
}

func TestForward_ClosedClientChansStopsLoop(t *testing.T) {
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a channel we control so we can close it.
	clientChans := make(chan ssh.NewChannel)
	close(clientChans)

	done := make(chan struct{})
	go func() {
		// serverConn is unused when clientChans is already closed,
		// but Forward still needs a non-nil value.
		Forward(ctx, "test-closed", nil, upstreamSide.client, clientChans, nil)
		close(done)
	}()

	<-done // If Forward doesn't return, the test framework's -timeout will catch it.
}

// ---------------------------------------------------------------------------
// Request forwarding
// ---------------------------------------------------------------------------

func TestForwardGlobalRequests_SupportsOnlyPortForwarding(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Drain upstream requests and reply true.
	go func() {
		for req := range upstreamSide.serverReqs {
			if req.WantReply {
				req.Reply(true, []byte("ok"))
			}
		}
	}()

	go ForwardGlobalRequests(ctx, "test-global", clientSide.serverReqs, upstreamSide.client)

	tests := []struct {
		reqType string
		wantOK  bool
	}{
		{"tcpip-forward", true},
		{"cancel-tcpip-forward", true},
		{"unknown-request", false},
		{"env", false},
	}
	for _, tt := range tests {
		t.Run(tt.reqType, func(t *testing.T) {
			ok, _, err := clientSide.client.SendRequest(tt.reqType, true, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestForwardGlobalRequests_ContextCancellation(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		ForwardGlobalRequests(ctx, "test-cancel-global", clientSide.serverReqs, upstreamSide.client)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardGlobalRequests did not return after context cancellation")
	}
}

// ---------------------------------------------------------------------------
// Per-channel request forwarding through bridge
// ---------------------------------------------------------------------------

func TestBridge_ForwardsChannelRequests(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Forward(ctx, "test-req", clientSide.serverConn, upstreamSide.client,
		clientSide.serverNewChans, nil)

	// Upstream: accept channel, reply true to "pty-req", then close.
	go func() {
		for newCh := range upstreamSide.serverNewChans {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
				for req := range reqs {
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
				ch.Close()
			}(ch, reqs)
		}
	}()

	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	ok, err := clientCh.SendRequest("pty-req", true, nil)
	require.NoError(t, err)
	assert.True(t, ok, "pty-req should be accepted by upstream")

	clientCh.Close()
}

// ---------------------------------------------------------------------------
// DialUpstream validation (no actual network — just argument checking)
// ---------------------------------------------------------------------------

func TestDialUpstream_Validation(t *testing.T) {
	signer := generateSigner(t)

	tests := []struct {
		name       string
		hostKey    string
		wantErrMsg string
	}{
		{
			name:       "empty host key",
			hostKey:    "",
			wantErrMsg: "no host key available",
		},
		{
			name:       "malformed host key",
			hostKey:    "not-a-real-key",
			wantErrMsg: "parse expected host key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialUpstream("192.0.2.1", signer, tt.hostKey)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// ---------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------

func TestRunKeepalive_StopsOnContextCancel(t *testing.T) {
	ep := sshPipe(t)
	ctx, cancel := context.WithCancel(context.Background())

	sess := NewSession(func() {}, ep.serverConn)

	// Drain requests on the client side so keepalives succeed.
	go ssh.DiscardRequests(ep.serverReqs)

	done := make(chan struct{})
	go func() {
		RunKeepalive(ctx, ep.serverConn, "test-ka", KeepaliveConfig{
			Interval: 50 * time.Millisecond,
			MaxMiss:  3,
		}, sess)
		close(done)
	}()

	// Let a couple of ticks pass, then cancel.
	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunKeepalive did not return after context cancellation")
	}
}

func TestRunKeepalive_ClosesSessionAfterMaxMisses(t *testing.T) {
	ep := sshPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	closed := make(chan struct{})
	sess := NewSession(func() { close(closed) }, ep.serverConn)

	// Do NOT drain requests on the client-side serverReqs.
	// Instead, close the client connection so SendRequest returns errors
	// immediately, simulating missed keepalives.
	ep.client.Close()

	done := make(chan struct{})
	go func() {
		RunKeepalive(ctx, ep.serverConn, "test-ka-miss", KeepaliveConfig{
			Interval: 20 * time.Millisecond,
			MaxMiss:  2,
		}, sess)
		close(done)
	}()

	select {
	case <-done:
		// RunKeepalive exited after max misses – good.
	case <-time.After(3 * time.Second):
		t.Fatal("RunKeepalive did not stop after max misses")
	}
}

// ---------------------------------------------------------------------------
// BridgeClientChannel (already-accepted channel)
// ---------------------------------------------------------------------------

func TestBridgeClientChannel_EndToEnd(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Upstream: echo server.
	startEchoServer(t, upstreamSide.serverNewChans)

	// Accept the channel on the gateway side in a goroutine so
	// OpenChannel on the client can complete.
	type acceptResult struct {
		newChan ssh.NewChannel
		ch      ssh.Channel
		reqs    <-chan *ssh.Request
		err     error
	}
	result := make(chan acceptResult, 1)
	go func() {
		nc := <-clientSide.serverNewChans
		ch, reqs, err := nc.Accept()
		result <- acceptResult{nc, ch, reqs, err}
	}()

	// Client opens a channel.
	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	ar := <-result
	require.NoError(t, ar.err)

	// Bridge the already-accepted channel to upstream.
	go BridgeClientChannel(ctx, "test-bridge", upstreamSide.client, ar.newChan, ar.ch, ar.reqs)

	payload := []byte("bridged-data")
	_, err = clientCh.Write(payload)
	require.NoError(t, err)
	clientCh.CloseWrite()

	got, err := io.ReadAll(clientCh)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// ---------------------------------------------------------------------------
// rejectChannel
// ---------------------------------------------------------------------------

func TestRejectChannel(t *testing.T) {
	tests := []struct {
		name          string
		closeUpstream bool // close upstream before forwarding?
		wantReason    ssh.RejectionReason
		wantMessage   string // if non-empty, assert the message too
	}{
		{
			name:          "OpenChannelError reason is preserved",
			closeUpstream: false,
			wantReason:    ssh.Prohibited,
			wantMessage:   "not allowed",
		},
		{
			name:          "generic error uses ConnectionFailed",
			closeUpstream: true,
			wantReason:    ssh.ConnectionFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSide := sshPipe(t)
			upstreamSide := sshPipe(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if tt.closeUpstream {
				// Close the upstream connection so OpenChannel fails with a generic error.
				upstreamSide.client.Close()
			} else {
				// Upstream: reject every channel with a specific error.
				go func() {
					for newCh := range upstreamSide.serverNewChans {
						newCh.Reject(ssh.Prohibited, "not allowed")
					}
				}()
			}

			go Forward(ctx, "test-reject", clientSide.serverConn, upstreamSide.client,
				clientSide.serverNewChans, nil)

			_, _, err := clientSide.client.OpenChannel("session", nil)
			require.Error(t, err)

			var openErr *ssh.OpenChannelError
			if assert.ErrorAs(t, err, &openErr) {
				assert.Equal(t, tt.wantReason, openErr.Reason)
				if tt.wantMessage != "" {
					assert.Equal(t, tt.wantMessage, openErr.Message)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reverse-forwarded channels (upstream → client)
// ---------------------------------------------------------------------------

func TestForward_UpstreamReverseForwardedChannel(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Register to receive forwarded-tcpip channels from upstream.
	upstreamForwarded := upstreamSide.client.HandleChannelOpen("forwarded-tcpip")

	// Handle reverse-forwarded channels arriving at the client.
	clientReverse := clientSide.client.HandleChannelOpen("forwarded-tcpip")

	go Forward(ctx, "test-reverse", clientSide.serverConn, upstreamSide.client,
		nil, upstreamForwarded)

	// Upstream server opens a reverse-forwarded channel in a goroutine,
	// because OpenChannel blocks until the far end (client) accepts,
	// and the client can only accept after Forward bridges it through.
	type openResult struct {
		ch  ssh.Channel
		err error
	}
	chResult := make(chan openResult, 1)
	go func() {
		ch, _, err := upstreamSide.serverConn.OpenChannel("forwarded-tcpip", []byte("extra"))
		chResult <- openResult{ch, err}
	}()

	// Client should receive the forwarded channel.
	var clientNewCh ssh.NewChannel
	select {
	case clientNewCh = <-clientReverse:
		require.NotNil(t, clientNewCh)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reverse-forwarded channel on client")
	}

	assert.Equal(t, "forwarded-tcpip", clientNewCh.ChannelType())
	assert.Equal(t, []byte("extra"), clientNewCh.ExtraData())

	clientCh, _, err := clientNewCh.Accept()
	require.NoError(t, err)

	// Now the upstream OpenChannel should complete.
	r := <-chResult
	require.NoError(t, r.err)

	// Write from upstream, read from client.
	msg := []byte("reverse-data")
	_, err = r.ch.Write(msg)
	require.NoError(t, err)
	r.ch.CloseWrite()

	got, err := io.ReadAll(clientCh)
	require.NoError(t, err)
	assert.Equal(t, msg, got)
}

// ---------------------------------------------------------------------------
// Full proxy scenario: data + requests through the complete pipeline
// ---------------------------------------------------------------------------

func TestFullProxyScenario(t *testing.T) {
	// End-to-end: client ↔ gateway ↔ upstream
	// Verifies: channel creation, bidirectional data, channel requests,
	// and session teardown.
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	sess := NewSession(cancel, clientSide.serverConn)
	sess.SetUpstream(upstreamSide.client)

	// Upstream: accept channels, handle "exec" request, write output, close.
	go func() {
		for newCh := range upstreamSide.serverNewChans {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
				for req := range reqs {
					switch req.Type {
					case "exec":
						if req.WantReply {
							req.Reply(true, nil)
						}
						ch.Write([]byte("command output"))
						ch.CloseWrite()
					default:
						if req.WantReply {
							req.Reply(false, nil)
						}
					}
				}
			}(ch, reqs)
		}
	}()

	// Start forwarding.
	go Forward(ctx, "full-test", clientSide.serverConn, upstreamSide.client,
		clientSide.serverNewChans, nil)
	go ForwardGlobalRequests(ctx, "full-test", clientSide.serverReqs, upstreamSide.client)

	// Client opens a session channel.
	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	// Send exec request.
	ok, err := clientCh.SendRequest("exec", true, []byte("ls"))
	require.NoError(t, err)
	assert.True(t, ok)

	// Read the output.
	var buf bytes.Buffer
	_, err = io.Copy(&buf, clientCh)
	require.NoError(t, err)
	assert.Equal(t, "command output", buf.String())

	// Teardown.
	sess.Close()
}

// ---------------------------------------------------------------------------
// BridgeNewClientChannel (thin wrapper coverage)
// ---------------------------------------------------------------------------

func TestBridgeNewClientChannel_EndToEnd(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Upstream: echo server.
	startEchoServer(t, upstreamSide.serverNewChans)

	// Bridge each client channel via BridgeNewClientChannel.
	go func() {
		for newCh := range clientSide.serverNewChans {
			go BridgeNewClientChannel(ctx, "test-new-bridge", upstreamSide.client, newCh)
		}
	}()

	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	payload := []byte("new-bridge-data")
	_, err = clientCh.Write(payload)
	require.NoError(t, err)
	clientCh.CloseWrite()

	got, err := io.ReadAll(clientCh)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// ---------------------------------------------------------------------------
// BridgeClientChannel when upstream is closed (error path)
// ---------------------------------------------------------------------------

func TestBridgeClientChannel_UpstreamClosed(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Close upstream so OpenChannel will fail.
	upstreamSide.client.Close()

	// Accept a channel from client, then try to bridge it to dead upstream.
	type acceptResult struct {
		newChan ssh.NewChannel
		ch      ssh.Channel
		reqs    <-chan *ssh.Request
	}
	result := make(chan acceptResult, 1)
	go func() {
		nc := <-clientSide.serverNewChans
		ch, reqs, _ := nc.Accept()
		result <- acceptResult{nc, ch, reqs}
	}()

	clientCh, _, err := clientSide.client.OpenChannel("session", nil)
	require.NoError(t, err)

	ar := <-result
	// BridgeClientChannel should close the client channel when upstream fails.
	BridgeClientChannel(ctx, "test-upstream-dead", upstreamSide.client, ar.newChan, ar.ch, ar.reqs)

	// Client channel should be closed (read returns EOF or error).
	buf := make([]byte, 1)
	_, err = clientCh.Read(buf)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ForwardGlobalRequests with payload round-trip
// ---------------------------------------------------------------------------

func TestForwardGlobalRequests_PayloadRoundTrip(t *testing.T) {
	clientSide := sshPipe(t)
	upstreamSide := sshPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Upstream: echo back the request payload.
	go func() {
		for req := range upstreamSide.serverReqs {
			if req.WantReply {
				req.Reply(true, req.Payload)
			}
		}
	}()

	go ForwardGlobalRequests(ctx, "test-payload", clientSide.serverReqs, upstreamSide.client)

	payload := []byte("forward-data")
	ok, resp, err := clientSide.client.SendRequest("tcpip-forward", true, payload)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, payload, resp)
}

func TestValidateShellSafe(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "hostname", input: "gateway.example.com", wantErr: false},
		{name: "ip address", input: "10.0.0.1", wantErr: false},
		{name: "ip with port-like", input: "10.0.0.1:22", wantErr: false},
		{name: "ssh pubkey", input: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI+base64data==", wantErr: false},
		{name: "empty string", input: "", wantErr: false},
		{name: "shell injection semicolon", input: "host; rm -rf /", wantErr: true},
		{name: "shell injection backtick", input: "host`id`", wantErr: true},
		{name: "shell injection dollar", input: "host$(id)", wantErr: true},
		{name: "shell injection newline", input: "host\nid", wantErr: true},
		{name: "shell injection pipe", input: "host|id", wantErr: true},
		{name: "shell injection ampersand", input: "host&&id", wantErr: true},
		{name: "shell injection single quote", input: "host'id", wantErr: true},
		{name: "shell injection double quote", input: `host"id`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateShellSafe(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
