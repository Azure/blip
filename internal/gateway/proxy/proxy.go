// Package proxy implements bidirectional SSH forwarding between a client and an upstream VM.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Session coordinates the lifecycle of a single proxied SSH connection.
type Session struct {
	cancel     context.CancelFunc
	serverConn *ssh.ServerConn
	upstream   *ssh.Client
	bannerCh   ssh.Channel
	once       sync.Once
}

// NewSession creates a Session for the given server connection.
func NewSession(cancel context.CancelFunc, serverConn *ssh.ServerConn) *Session {
	return &Session{cancel: cancel, serverConn: serverConn}
}

func (s *Session) SetUpstream(c *ssh.Client) { s.upstream = c }

func (s *Session) SetBannerChannel(ch ssh.Channel) { s.bannerCh = ch }

// Close tears down the session exactly once.
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		s.serverConn.Close()
		if s.upstream != nil {
			s.upstream.Close()
		}
	})
}

// SendBanner writes a banner to the session's stderr stream without closing.
func (s *Session) SendBanner(banner string) {
	if s.bannerCh != nil {
		if _, err := s.bannerCh.Stderr().Write([]byte(banner)); err != nil {
			slog.Debug("failed to write banner", "error", err)
		}
	}
}

// SendBannerAndClose writes a shutdown banner to stderr and tears down the session.
func (s *Session) SendBannerAndClose(banner string) {
	if s.bannerCh != nil {
		if _, err := s.bannerCh.Stderr().Write([]byte(banner)); err != nil {
			slog.Debug("failed to write shutdown banner", "error", err)
		}
	}
	s.Close()
}

type KeepaliveConfig struct {
	Interval time.Duration
	MaxMiss  int
}

// RunKeepalive sends periodic keepalive probes and closes the session on timeout.
func RunKeepalive(ctx context.Context, conn *ssh.ServerConn, sessionID string, cfg KeepaliveConfig, session *Session) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				misses++
				if misses >= cfg.MaxMiss {
					slog.Info("client keepalive timeout", "session_id", sessionID, "misses", misses)
					session.Close()
					return
				}
			} else {
				misses = 0
			}
		}
	}
}

// DialUpstream connects to the target blip via SSH with retry and exponential backoff.
func DialUpstream(vmIP string, signer ssh.Signer, expectedHostKey string) (*ssh.Client, error) {
	const (
		maxAttempts = 10
		dialTimeout = 3 * time.Second
		sshTimeout  = 7 * time.Second
		baseBackoff = 200 * time.Millisecond
		maxBackoff  = 2 * time.Second
	)

	if expectedHostKey == "" {
		return nil, fmt.Errorf("no host key available for blip %s; cannot verify identity", vmIP)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expectedHostKey))
	if err != nil {
		return nil, fmt.Errorf("parse expected host key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:              "runner",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: []string{hostKey.Type()},
		Timeout:           sshTimeout,
	}

	addr := net.JoinHostPort(vmIP, "22")

	var lastErr error
	for attempt := range maxAttempts {
		tcpConn, dialErr := net.DialTimeout("tcp", addr, dialTimeout)
		if dialErr != nil {
			lastErr = fmt.Errorf("tcp dial (attempt %d/%d): %w", attempt+1, maxAttempts, dialErr)
			slog.Debug("upstream TCP dial failed", "addr", addr, "attempt", attempt+1, "error", dialErr)
		} else {
			tcpConn.SetDeadline(time.Now().Add(sshTimeout))
			sshConn, chans, reqs, sshErr := ssh.NewClientConn(tcpConn, addr, cfg)
			if sshErr != nil {
				tcpConn.Close()
				lastErr = fmt.Errorf("ssh handshake (attempt %d/%d): %w", attempt+1, maxAttempts, sshErr)
				slog.Debug("upstream SSH handshake failed", "addr", addr, "attempt", attempt+1, "error", sshErr)
			} else {
				tcpConn.SetDeadline(time.Time{})
				return ssh.NewClient(sshConn, chans, reqs), nil
			}
		}

		if attempt < maxAttempts-1 {
			backoff := baseBackoff * time.Duration(1<<attempt)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			time.Sleep(backoff)
		}
	}
	return nil, fmt.Errorf("dial %s after %d attempts: %w", addr, maxAttempts, lastErr)
}

// Forward runs the main bidirectional channel forwarding loop until ctx is cancelled.
func Forward(ctx context.Context, sessionID string, serverConn *ssh.ServerConn, upstream *ssh.Client, clientChans <-chan ssh.NewChannel, upstreamForwardedChans <-chan ssh.NewChannel) {
	for {
		select {
		case <-ctx.Done():
			return
		case newChan, ok := <-clientChans:
			if !ok {
				return
			}
			go BridgeNewClientChannel(ctx, sessionID, upstream, newChan)
		case newChan, ok := <-upstreamForwardedChans:
			if !ok {
				upstreamForwardedChans = nil
				continue
			}
			go bridgeUpstreamChannel(ctx, sessionID, serverConn, newChan)
		}
	}
}

// ForwardGlobalRequests forwards supported global requests to upstream until ctx is cancelled.
func ForwardGlobalRequests(ctx context.Context, sessionID string, reqs <-chan *ssh.Request, upstream *ssh.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqs:
			if !ok {
				return
			}
			forwardGlobalRequest(req, sessionID, upstream)
		}
	}
}

// BridgeClientChannel bridges an already-accepted client channel with a new upstream channel.
func BridgeClientChannel(ctx context.Context, sessionID string, upstream *ssh.Client, newChan ssh.NewChannel, clientChan ssh.Channel, clientReqs <-chan *ssh.Request) {
	upstreamChan, upstreamReqs, err := upstream.OpenChannel(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		slog.Debug("failed to open upstream channel for accepted session",
			"session_id", sessionID,
			"error", err,
		)
		clientChan.Close()
		return
	}
	bridge(ctx, sessionID, clientChan, clientReqs, upstreamChan, upstreamReqs)
}

// BridgeNewClientChannel accepts a client channel, opens an upstream match, and bridges them.
func BridgeNewClientChannel(ctx context.Context, sessionID string, upstream *ssh.Client, newChan ssh.NewChannel) {
	slog.Debug("client channel open", "session_id", sessionID, "type", newChan.ChannelType())

	upstreamChan, upstreamReqs, err := upstream.OpenChannel(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		rejectChannel(newChan, err)
		return
	}

	clientChan, clientReqs, err := newChan.Accept()
	if err != nil {
		upstreamChan.Close()
		return
	}

	bridge(ctx, sessionID, clientChan, clientReqs, upstreamChan, upstreamReqs)
}

func bridgeUpstreamChannel(ctx context.Context, sessionID string, serverConn *ssh.ServerConn, newChan ssh.NewChannel) {
	slog.Debug("upstream channel open", "session_id", sessionID, "type", newChan.ChannelType())

	clientChan, clientReqs, err := serverConn.OpenChannel(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		rejectChannel(newChan, err)
		return
	}

	upstreamChan, upstreamReqs, err := newChan.Accept()
	if err != nil {
		clientChan.Close()
		return
	}

	bridge(ctx, sessionID, clientChan, clientReqs, upstreamChan, upstreamReqs)
}

// bridge performs bidirectional data copying and request forwarding between two channels.
func bridge(ctx context.Context, sessionID string, clientChan ssh.Channel, clientReqs <-chan *ssh.Request, upstreamChan ssh.Channel, upstreamReqs <-chan *ssh.Request) {
	clientToUpstreamDone := make(chan struct{})
	upstreamToClientDone := make(chan struct{})
	upstreamReqsDone := make(chan struct{})

	go func() {
		defer close(clientToUpstreamDone)
		if _, err := io.Copy(upstreamChan, clientChan); err != nil {
			slog.Debug("client->upstream copy ended", "session_id", sessionID, "error", err)
		}
		upstreamChan.CloseWrite()
	}()

	go func() {
		defer close(upstreamToClientDone)
		if _, err := io.Copy(clientChan, upstreamChan); err != nil {
			slog.Debug("upstream->client copy ended", "session_id", sessionID, "error", err)
		}
		clientChan.CloseWrite()
	}()

	go forwardRequests(ctx, clientReqs, upstreamChan)

	go func() {
		defer close(upstreamReqsDone)
		forwardRequests(ctx, upstreamReqs, clientChan)
	}()

	// When the upstream command finishes, the upstream->client copy
	// returns (EOF from upstream). We then wait briefly for trailing
	// channel requests (e.g. exit-status) to be relayed, and close
	// both channels. This unblocks the client->upstream copy if the
	// client has not sent EOF yet — which happens when a recursive SSH
	// session inherits stdin from a parent that keeps it open.
	<-upstreamToClientDone

	select {
	case <-upstreamReqsDone:
	case <-time.After(500 * time.Millisecond):
		slog.Debug("timed out waiting for upstream channel requests to drain", "session_id", sessionID)
	}

	// Close channels to tear down the bridge. This also unblocks the
	// client->upstream copy if it is still reading from clientChan.
	clientChan.Close()
	upstreamChan.Close()

	// Wait for the client->upstream copy to finish so we don't leak
	// the goroutine.
	<-clientToUpstreamDone
}

func forwardRequests(ctx context.Context, reqs <-chan *ssh.Request, dest ssh.Channel) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqs:
			if !ok {
				return
			}
			accepted, err := dest.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				return
			}
			if req.WantReply {
				req.Reply(accepted, nil)
			}
		}
	}
}

func forwardGlobalRequest(req *ssh.Request, sessionID string, upstream *ssh.Client) {
	if req.Type != "tcpip-forward" && req.Type != "cancel-tcpip-forward" {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	ok, payload, err := upstream.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		slog.Debug("global request forwarding failed",
			"session_id", sessionID,
			"type", req.Type,
			"error", err,
		)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	if req.WantReply {
		req.Reply(ok, payload)
	}
	slog.Debug("global request forwarded",
		"session_id", sessionID,
		"type", req.Type,
		"accepted", ok,
	)
}

func rejectChannel(ch ssh.NewChannel, err error) {
	if openErr, ok := err.(*ssh.OpenChannelError); ok {
		ch.Reject(openErr.Reason, openErr.Message)
	} else {
		ch.Reject(ssh.ConnectionFailed, err.Error())
	}
}

// InjectGatewayConfig writes a minimal SSH config into the VM so the user
// can SSH back to the gateway for recursive blip allocation. The VM uses
// its own client key (generated at boot) for authentication.
//
// reconnectHost is the hostname shown in `blip retain` output. For VMs
// allocated from inside another blip this is the in-cluster alias "blip";
// for external users it is the public gateway hostname. When empty the
// reconnect-host file is not written and the blip script falls back to
// a <gateway-host> placeholder.
func InjectGatewayConfig(upstream *ssh.Client, gatewayHost, reconnectHost string) error {
	if err := validateShellSafe(gatewayHost); err != nil {
		return fmt.Errorf("invalid gateway host: %w", err)
	}
	if err := validateShellSafe(reconnectHost); err != nil {
		return fmt.Errorf("invalid reconnect host: %w", err)
	}

	session, err := upstream.NewSession()
	if err != nil {
		return fmt.Errorf("open session for gateway config injection: %w", err)
	}
	defer session.Close()

	script := fmt.Sprintf(`#!/bin/sh
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh

cat > ~/.ssh/config << 'BLIP_CONFIG_EOF'
Host blip blip-gateway
    HostName %s
    Port 22
    User runner
    IdentityFile /etc/ssh/ssh_client_ed25519_key
    StrictHostKeyChecking yes
BLIP_CONFIG_EOF
chmod 644 ~/.ssh/config
`, gatewayHost)

	// Write the reconnect host so the `blip retain` command can show
	// a correct reconnect instruction.
	if reconnectHost != "" {
		script += fmt.Sprintf(`
mkdir -p ~/.blip
printf '%%s' '%s' > ~/.blip/reconnect-host
`, reconnectHost)
	}

	if err := session.Run(script); err != nil {
		return fmt.Errorf("inject gateway config script: %w", err)
	}
	return nil
}

// validateShellSafe rejects strings with characters that could break shell heredocs.
func validateShellSafe(s string) error {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == ' ', c == '+', c == '/', c == '=',
			c == '.', c == '-', c == '_', c == ':',
			c == '@':
			// allowed
		default:
			return fmt.Errorf("disallowed character %q", c)
		}
	}
	return nil
}
