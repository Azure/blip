// Package session manages the lifecycle of SSH sessions proxied through the gateway.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/proxy"
	"github.com/project-unbounded/blip/internal/gateway/vm"
)

func isOIDCIdentity(identity string) bool {
	return strings.HasPrefix(identity, "oidc:")
}

func sessionTTL(authIdentity string) int {
	if isOIDCIdentity(authIdentity) {
		return int(OIDCDefaultTTL.Seconds())
	}
	return int(DefaultTTL.Seconds())
}

const (
	DefaultTTL     = 8 * time.Hour
	OIDCDefaultTTL = 30 * time.Minute
)

// Config holds the dependencies and tunables for the session Manager.
type Config struct {
	GatewaySigner      ssh.Signer
	GatewayHost        string
	ExternalHost       string
	VMClient           *vm.Client
	VMPoolName         string
	PodName            string
	MaxBlipsPerUser    int
	MaxSessionDuration time.Duration
	KeepAliveInterval  time.Duration
	KeepAliveMax       int

	// AuthWatcher provides dynamic auth configuration; used for device
	// flow execution and public key binding. May be nil when device flow
	// is not configured.
	AuthWatcher *auth.AuthWatcher

	// IdentityStore provides OIDC identity storage backed by Kubernetes
	// Secrets. Used to store refresh tokens from device flow and to verify
	// OIDC identity when reconnecting via linked SSH pubkeys.
	IdentityStore *auth.IdentityStore
}

// Manager tracks active sessions and handles incoming SSH connections.
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*proxy.Session
}

// New creates a Manager ready to accept connections.
func New(cfg Config) *Manager {
	return &Manager{
		cfg:      cfg,
		sessions: make(map[string]*proxy.Session),
	}
}

// HandleConnection owns an SSH connection post-handshake: allocates a VM, dials upstream, and bridges channels.
func (m *Manager) HandleConnection(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	remoteAddr := serverConn.RemoteAddr().String()

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	sess := proxy.NewSession(sessionCancel, serverConn)
	defer sess.Close()

	// Buffer global requests so the SSH mux doesn't block during setup.
	bufferedReqs := make(chan *ssh.Request, 64)
	go func() {
		for req := range reqs {
			bufferedReqs <- req
		}
		close(bufferedReqs)
	}()

	authFingerprint, authIdentity, _ := extractAuthExtensions(serverConn)
	deviceFlowPending := isDeviceFlowPending(serverConn)
	offeredPubkey := extractOfferedPubkey(serverConn)
	identityLinked := isIdentityLinked(serverConn)

	slog.Info("client authenticated",
		"user", serverConn.User(),
		"remote", remoteAddr,
		"client_version", string(serverConn.ClientVersion()),
		"device_flow_pending", deviceFlowPending,
		"identity_linked", identityLinked,
	)

	reconnecting := isSessionID(serverConn.User())

	firstSession, queued := waitForSessionChannel(chans, reconnecting)

	if firstSession == nil && !reconnecting {
		slog.Debug("client closed channels before opening a session", "remote", remoteAddr)
		return
	}

	var firstClientChan ssh.Channel
	var firstClientReqs <-chan *ssh.Request
	if firstSession != nil {
		var err error
		firstClientChan, firstClientReqs, err = firstSession.Accept()
		if err != nil {
			slog.Debug("failed to accept first session channel", "remote", remoteAddr, "error", err)
			return
		}
	}

	// Monitor the SSH connection so that a full client disconnect
	// during blocking pre-proxy phases — device flow, VM allocation,
	// host key retrieval, upstream dial — cancels the operation
	// immediately. serverConn.Wait() returns when the transport closes
	// (e.g. client closes terminal window, network drop), so this
	// catches connection-level failures. Note: Ctrl+C does NOT close
	// the TCP connection — it sends data/signals through the SSH
	// channel. Channel-level interrupt detection for device flow is
	// handled separately in monitorChannelInterrupt.
	setupCtx, stopSetupMonitor := contextWithConnClose(ctx, serverConn)

	// If this connection requires device flow, run it now using the SSH
	// channel for user interaction. This must happen before VM allocation.
	if deviceFlowPending && firstClientChan != nil {
		var refreshToken, issuer string
		var err error
		authIdentity, authFingerprint, refreshToken, issuer, err = m.runDeviceFlow(setupCtx, serverConn, firstClientChan, firstClientReqs)
		if err != nil {
			slog.Warn("device flow failed",
				"remote", remoteAddr,
				"error", err,
			)
			stopSetupMonitor()
			writeBanner(firstClientChan, deviceFlowErrorBanner(err))
			firstClientChan.Close()
			return
		}

		// Attempt to bind the client's SSH public key to their OIDC identity.
		if offeredPubkey != "" {
			m.bindPubkeyAsync(ctx, serverConn, offeredPubkey, authIdentity)
		}

		// Store the refresh token and link the pubkey in the identity store.
		if refreshToken != "" && m.cfg.IdentityStore != nil {
			m.storeIdentityAsync(ctx, serverConn, authIdentity, issuer, refreshToken, offeredPubkey)
		}
	}

	// If this connection was authenticated via an identity-linked pubkey,
	// verify the OIDC identity is still valid by using the stored refresh
	// token. This maintains a strong OIDC binding — the user's pubkey is
	// only accepted if their OIDC identity can be confirmed.
	if identityLinked && m.cfg.IdentityStore != nil && m.cfg.AuthWatcher != nil {
		pubkeyFingerprint := authFingerprint // save SSH pubkey fingerprint before overwrite
		verifiedIdentity, newFingerprint, err := m.verifyIdentityLink(setupCtx, pubkeyFingerprint, authIdentity)
		if err != nil {
			slog.Warn("identity-linked pubkey verification failed, rejecting",
				"remote", remoteAddr,
				"fingerprint", pubkeyFingerprint,
				"identity", authIdentity,
				"error", err,
			)
			stopSetupMonitor()
			if firstClientChan != nil {
				writeBanner(firstClientChan, identityVerificationErrorBanner(err))
				firstClientChan.Close()
			}
			return
		}
		// Update identity and fingerprint with the refresh-verified values.
		authIdentity = verifiedIdentity
		if newFingerprint != "" {
			authFingerprint = newFingerprint
		}

		// Touch the pubkey link to keep it alive (use the SSH pubkey
		// fingerprint, not the OIDC token fingerprint).
		go func() {
			touchCtx, touchCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer touchCancel()
			if err := m.cfg.IdentityStore.TouchPubkey(touchCtx, pubkeyFingerprint); err != nil {
				slog.Warn("failed to touch pubkey link", "fingerprint", pubkeyFingerprint, "error", err)
			}
		}()
	}

	start := time.Now()
	ttlSec := sessionTTL(authIdentity)
	sessionTimeout := time.Duration(ttlSec) * time.Second

	sessionID, alloc, err := m.allocateOrReconnect(setupCtx, serverConn.User(), authFingerprint, authIdentity, reconnecting, ttlSec)
	if err != nil {
		stopSetupMonitor()
		if firstClientChan != nil {
			m.logAndBannerAllocError(firstClientChan, remoteAddr, serverConn.User(), reconnecting, sessionID, err)
			firstClientChan.Close()
		} else {
			slog.Warn("allocation failed (no session channel for banner)",
				"remote", remoteAddr, "user", serverConn.User(), "error", err)
		}
		return
	}

	if !reconnecting && authFingerprint != "" {
		if err := m.cfg.VMClient.StoreAuthFingerprint(ctx, sessionID, authFingerprint); err != nil {
			slog.Warn("failed to store auth fingerprint", "session_id", sessionID, "error", err)
		}
	}

	site := m.cfg.VMClient.GetNodeLabel(ctx, alloc.NodeName, "unbounded.aks.azure.com/site")

	if reconnecting {
		slog.Info("blip reconnected",
			"session_id", sessionID,
			"vm_name", alloc.Name,
			"vm_ip", alloc.PodIP,
			"remote", remoteAddr,
		)
	} else {
		slog.Info("blip claimed",
			"session_id", sessionID,
			"vm_name", alloc.Name,
			"vm_ip", alloc.PodIP,
			"site", site,
			"claim_duration", time.Since(start).String(),
		)
	}

	if firstClientChan != nil {
		writeBanner(firstClientChan, welcomeBanner(reconnecting)+vmInfoBanner(sessionID, alloc.Name, site, reconnecting, sessionTimeout))
	}

	hostKey, err := m.cfg.VMClient.GetHostKey(setupCtx, alloc.Name)
	if err != nil {
		slog.Error("failed to read host key for blip",
			"vm_name", alloc.Name,
			"error", err,
		)
		stopSetupMonitor()
		if firstClientChan != nil {
			writeBanner(firstClientChan, hostKeyErrorBanner())
			firstClientChan.Close()
		}
		return
	}

	upstreamConn, err := proxy.DialUpstream(setupCtx, alloc.PodIP, m.cfg.GatewaySigner, hostKey)
	if err != nil {
		slog.Error("failed to connect to blip",
			"vm_name", alloc.Name,
			"vm_ip", alloc.PodIP,
			"error", err,
		)
		stopSetupMonitor()
		if firstClientChan != nil {
			firstClientChan.Close()
		}
		return
	}

	// Setup is complete — stop monitoring the connection for early
	// disconnection. From here on the proxy layer owns the channels
	// and the session context tracks liveness.
	stopSetupMonitor()

	sess.SetUpstream(upstreamConn)
	if firstClientChan != nil {
		sess.SetBannerChannel(firstClientChan)
	}

	// Inject SSH config and blip CLI shim for recursive blip connections.
	if !reconnecting && m.cfg.GatewayHost != "" {
		go func() {
			if err := proxy.InjectGatewayConfig(
				upstreamConn,
				m.cfg.GatewayHost,
			); err != nil {
				slog.Warn("failed to inject gateway config",
					"session_id", sessionID,
					"error", err,
				)
			} else {
				slog.Info("gateway config injected",
					"session_id", sessionID,
				)
			}
		}()
	}

	m.register(sessionID, sess)
	defer m.unregister(sessionID)

	slog.Info("connected to blip",
		"session_id", sessionID,
		"vm_name", alloc.Name,
		"vm_ip", alloc.PodIP,
	)

	upstreamForwardedChans := upstreamConn.HandleChannelOpen("forwarded-tcpip")

	go proxy.ForwardGlobalRequests(sessionCtx, sessionID, bufferedReqs, upstreamConn)

	timer := time.AfterFunc(sessionTimeout, func() {
		slog.Info("session timeout", "session_id", sessionID, "duration", sessionTimeout.String())
		sess.Close()
	})
	defer timer.Stop()

	go proxy.RunKeepalive(sessionCtx, serverConn, sessionID, proxy.KeepaliveConfig{
		Interval: m.cfg.KeepAliveInterval,
		MaxMiss:  m.cfg.KeepAliveMax,
	}, sess)

	if firstSession != nil {
		go proxy.BridgeClientChannel(sessionCtx, sessionID, upstreamConn, firstSession, firstClientChan, firstClientReqs)
	}

	for _, queuedChan := range queued {
		go proxy.BridgeNewClientChannel(sessionCtx, sessionID, upstreamConn, queuedChan)
	}

	proxy.Forward(sessionCtx, sessionID, serverConn, upstreamConn, chans, upstreamForwardedChans)

	// Show a goodbye banner before tearing down.
	// Use a fresh context because the session context is already cancelled.
	goodbyeCtx, goodbyeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer goodbyeCancel()
	m.sendGoodbyeBanner(goodbyeCtx, sess, sessionID)

	// Release ephemeral VMs after session ends. Use a fresh context
	// because the session context is already cancelled.
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer releaseCancel()
	m.releaseIfEphemeral(releaseCtx, sessionID)

	slog.Info("session ended",
		"session_id", sessionID,
		"vm_name", alloc.Name,
		"duration", time.Since(start).String(),
	)
}

// NotifyShutdown sends a shutdown banner to every active session and closes them.
func (m *Manager) NotifyShutdown() {
	m.mu.Lock()
	snapshot := make(map[string]*proxy.Session, len(m.sessions))
	for id, s := range m.sessions {
		snapshot[id] = s
	}
	m.mu.Unlock()

	banner := shutdownBanner()
	for id, s := range snapshot {
		slog.Info("sending shutdown banner", "session_id", id)
		s.SendBannerAndClose(banner)
	}
}

func (m *Manager) register(sessionID string, s *proxy.Session) {
	m.mu.Lock()
	m.sessions[sessionID] = s
	m.mu.Unlock()
}

func (m *Manager) unregister(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

func (m *Manager) allocateOrReconnect(ctx context.Context, user, authFingerprint, authIdentity string, reconnecting bool, maxDurSec int) (string, *vm.ClaimResult, error) {
	if reconnecting {
		sessionID := user
		alloc, err := m.cfg.VMClient.Reconnect(ctx, sessionID, authFingerprint, m.cfg.PodName, maxDurSec)
		return sessionID, alloc, err
	}
	sessionID := generateSessionID()
	alloc, err := m.cfg.VMClient.Claim(ctx, m.cfg.VMPoolName, sessionID, m.cfg.PodName, maxDurSec, authIdentity, m.cfg.MaxBlipsPerUser)
	return sessionID, alloc, err
}

func (m *Manager) logAndBannerAllocError(ch ssh.Channel, remoteAddr, user string, reconnecting bool, sessionID string, err error) {
	if reconnecting {
		slog.Warn("reconnect failed", "session_id", user, "remote", remoteAddr, "error", err)
	} else {
		slog.Error("no blips available", "error", err, "session_id", sessionID)
	}
	writeBanner(ch, allocErrorBanner(reconnecting, err))
}

// releaseIfEphemeral checks if the VM for the given session is still
// ephemeral and, if so, marks it for release so the deallocation
// controller will reclaim it.
func (m *Manager) releaseIfEphemeral(ctx context.Context, sessionID string) {
	ephemeral, err := m.cfg.VMClient.IsEphemeral(ctx, sessionID)
	if err != nil {
		slog.Warn("failed to check ephemeral status", "session_id", sessionID, "error", err)
		return
	}
	if !ephemeral {
		slog.Info("blip retained, skipping release", "session_id", sessionID)
		return
	}
	if err := m.cfg.VMClient.ReleaseVM(ctx, sessionID); err != nil {
		slog.Error("failed to release ephemeral blip", "session_id", sessionID, "error", err)
		return
	}
	slog.Info("ephemeral blip released", "session_id", sessionID)
}

// sendGoodbyeBanner queries the VM status and writes a goodbye banner
// to the session's banner channel.
func (m *Manager) sendGoodbyeBanner(ctx context.Context, sess *proxy.Session, sessionID string) {
	status, err := m.cfg.VMClient.GetSessionStatus(ctx, sessionID)
	if err != nil {
		slog.Debug("failed to get session status for goodbye banner", "session_id", sessionID, "error", err)
		return
	}
	sess.SendBanner(goodbyeBanner(sessionID, status.Ephemeral, status.RemainingTTL, m.cfg.ExternalHost))
}

func extractAuthExtensions(conn *ssh.ServerConn) (fingerprint, identity string, isVMClient bool) {
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		fingerprint = conn.Permissions.Extensions[auth.ExtFingerprint]
		identity = conn.Permissions.Extensions[auth.ExtIdentity]
		isVMClient = conn.Permissions.Extensions[auth.ExtIsVMClient] == "true"
	}
	return
}

// isDeviceFlowPending reports whether the connection was authenticated via
// keyboard-interactive and is pending device flow completion.
func isDeviceFlowPending(conn *ssh.ServerConn) bool {
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		return conn.Permissions.Extensions[auth.ExtDeviceFlowPending] == "true"
	}
	return false
}

// extractOfferedPubkey returns the SSH public key the client offered during
// a prior failed pubkey auth attempt (in authorized_keys format), or "".
func extractOfferedPubkey(conn *ssh.ServerConn) string {
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		return conn.Permissions.Extensions[auth.ExtOfferedPubkey]
	}
	return ""
}

// isIdentityLinked reports whether the connection was authenticated via
// a pubkey that is linked to an OIDC identity in the identity store.
func isIdentityLinked(conn *ssh.ServerConn) bool {
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		return conn.Permissions.Extensions[auth.ExtIdentityLinked] == "true"
	}
	return false
}

// runDeviceFlow executes the OAuth2 device authorization flow for the
// connection, displaying prompts via the SSH channel. Returns the verified
// OIDC identity, a fingerprint derived from the access token, the refresh
// token (if issued), and the OIDC issuer URL.
//
// channelReqs receives per-channel requests (e.g. pty-req, shell, signal)
// from the client. During device flow we drain these requests and watch
// for interrupt signals so that Ctrl+C cancels the flow immediately.
func (m *Manager) runDeviceFlow(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, channelReqs <-chan *ssh.Request) (identity, fingerprint, refreshToken, issuer string, err error) {
	if m.cfg.AuthWatcher == nil {
		return "", "", "", "", fmt.Errorf("device flow not available: no auth watcher")
	}

	providers := m.cfg.AuthWatcher.DeviceFlowProviders()
	if len(providers) == 0 {
		return "", "", "", "", fmt.Errorf("device flow not available: no device-flow providers configured")
	}

	// Use a generous timeout for the device flow (matches typical code expiry).
	flowCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	// Monitor the SSH channel for Ctrl+C (0x03 in the data stream) and
	// channel-level "signal" requests. During device flow the user is
	// waiting for browser authentication — any input is an interrupt
	// attempt. Without this, Ctrl+C is silently ignored because:
	//   - The SSH client sends Ctrl+C as channel data (byte 0x03) or a
	//     "signal" channel request, neither of which closes the TCP
	//     connection.
	//   - contextWithConnClose only detects TCP-level disconnection via
	//     serverConn.Wait(), so it never fires on Ctrl+C.
	//   - Nobody reads from the channel during device flow, so the
	//     interrupt is buffered indefinitely.
	//
	// stopMonitor is closed when runDeviceFlow returns (success or
	// failure) to stop the monitor goroutines and prevent them from
	// consuming channel data or requests after the channel is handed
	// to the proxy bridge layer.
	stopMonitor := make(chan struct{})
	defer close(stopMonitor)
	go monitorChannelInterrupt(ch, channelReqs, cancel, stopMonitor)

	// Send messages to the user via the SSH channel's stderr stream.
	sendMessage := func(msg string) {
		if _, err := ch.Stderr().Write([]byte(msg)); err != nil {
			slog.Debug("device flow: failed to write to client", "error", err)
		}
	}

	// Try each device-flow provider in order.
	var lastErr error
	for _, provider := range providers {
		identity, fp, rt, iss, err := auth.RunDeviceFlow(flowCtx, provider, sendMessage)
		if err != nil {
			lastErr = err
			slog.Debug("device flow failed for provider",
				"issuer", provider.Issuer,
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
			continue
		}

		sendMessage("\r\n  Authentication successful!\r\n\r\n")

		return identity, fp, rt, iss, nil
	}

	if len(providers) == 1 {
		return "", "", "", "", fmt.Errorf("device flow authentication failed: %w", lastErr)
	}
	return "", "", "", "", fmt.Errorf("device flow not accepted by any provider (%d tried)", len(providers))
}

// monitorChannelInterrupt reads from the SSH channel's data stream and
// channel request stream, cancelling cancel when an interrupt is detected.
// An interrupt is:
//   - Byte 0x03 (ETX / Ctrl+C) in the channel data stream.
//   - An SSH "signal" channel request (RFC 4254 §6.9).
//   - The channel being closed by the client (Read returns EOF).
//
// The done channel must be closed by the caller when monitoring should
// stop (e.g. device flow completed). This prevents the monitor from
// consuming channel data or requests after the channel is handed to the
// proxy bridge layer.
//
// Design note: ssh.Channel.Read is a blocking call that cannot be
// interrupted by a context or channel. A background goroutine performs
// the blocking reads and forwards results. When done is closed, this
// goroutine may still be blocked on one final ch.Read — it will exit
// when the session eventually ends and the channel is closed. Crucially,
// after done is closed, the goroutine will NOT call cancel or send any
// further results, preventing it from interfering with the proxy layer.
//
// This function is intended to run as a goroutine during device flow.
func monitorChannelInterrupt(ch ssh.Channel, reqs <-chan *ssh.Request, cancel context.CancelFunc, done <-chan struct{}) {
	// readResult is sent from the blocking ch.Read goroutine.
	type readResult struct {
		data []byte
		err  error
	}
	reads := make(chan readResult, 1)

	// Spawn a goroutine that performs blocking reads from the channel
	// and forwards results. This goroutine may outlive
	// monitorChannelInterrupt if it is blocked on ch.Read when done is
	// closed — it will exit when the channel is eventually closed at
	// session end. After done is closed, it will not send to reads
	// (the select below ensures this), preventing any interference
	// with the proxy bridge layer that later reads from the same
	// channel.
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				// Stop if done was closed while we were reading.
				select {
				case <-done:
					return
				case reads <- readResult{data: data}:
				}
			}
			if err != nil {
				select {
				case <-done:
					return
				case reads <- readResult{err: err}:
				}
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case r := <-reads:
			if r.err != nil {
				// Channel closed or error — cancel the flow.
				cancel()
				return
			}
			for _, b := range r.data {
				if b == 0x03 { // ETX — Ctrl+C
					slog.Debug("device flow: Ctrl+C received on channel data")
					cancel()
					return
				}
			}
		case req, ok := <-reqs:
			if !ok {
				// Channel requests closed — the client disconnected.
				cancel()
				return
			}
			// Reply to requests that expect a response so the SSH
			// client doesn't block waiting. Accept pty-req so the
			// client allocates a PTY (needed for Ctrl+C to be sent
			// as data rather than being handled locally by the
			// client's terminal driver).
			if req.WantReply {
				req.Reply(req.Type == "pty-req", nil)
			}
			if req.Type == "signal" {
				slog.Debug("device flow: signal request received on channel", "payload_len", len(req.Payload))
				cancel()
				return
			}
		}
	}
}

// storeIdentityAsync asynchronously stores the refresh token and links the
// SSH pubkey to the OIDC identity in the identity store.
func (m *Manager) storeIdentityAsync(ctx context.Context, conn *ssh.ServerConn, identity, issuer, refreshToken, offeredPubkey string) {
	var pubkeyFingerprint, authorizedKeyLine string
	if offeredPubkey != "" {
		keyLine := strings.TrimSpace(offeredPubkey)
		if keyLine != "" {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
			if err == nil {
				pubkeyFingerprint = ssh.FingerprintSHA256(pub)
				sanitizedIdentity := sanitizeAuthorizedKeyComment(identity)
				authorizedKeyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + sanitizedIdentity
			}
		}
	}

	go func() {
		storeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.cfg.IdentityStore.StoreIdentity(storeCtx, identity, issuer, refreshToken, pubkeyFingerprint, authorizedKeyLine); err != nil {
			slog.Error("failed to store identity in identity store",
				"remote", conn.RemoteAddr().String(),
				"identity", identity,
				"pubkey_fingerprint", pubkeyFingerprint,
				"error", err,
			)
		} else {
			slog.Info("identity stored in identity store",
				"remote", conn.RemoteAddr().String(),
				"identity", identity,
				"pubkey_linked", pubkeyFingerprint != "",
				"has_refresh_token", true,
			)
		}
	}()
}

// verifyIdentityLink verifies that an identity-linked pubkey's OIDC identity
// is still valid by exchanging the stored refresh token. Returns the verified
// identity and a new auth fingerprint derived from the refreshed access token.
func (m *Manager) verifyIdentityLink(ctx context.Context, pubkeyFingerprint, storedIdentity string) (identity, newFingerprint string, err error) {
	result, err := m.cfg.IdentityStore.LookupByPubkey(ctx, pubkeyFingerprint)
	if err != nil {
		return "", "", fmt.Errorf("identity store lookup: %w", err)
	}
	if result == nil {
		return "", "", fmt.Errorf("pubkey %s not linked to any OIDC identity", pubkeyFingerprint)
	}

	providers := m.cfg.AuthWatcher.OIDCProviders()
	verifiedIdentity, newRefreshToken, fp, err := auth.RefreshOIDCToken(ctx, result.Issuer, result.RefreshToken, providers)
	if err != nil {
		return "", "", fmt.Errorf("refresh token verification for %s: %w", result.OIDCIdentity, err)
	}

	// Update the refresh token if it was rotated.
	if newRefreshToken != result.RefreshToken {
		go func() {
			updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := m.cfg.IdentityStore.UpdateRefreshToken(updateCtx, result.OIDCIdentity, newRefreshToken); err != nil {
				slog.Warn("failed to update rotated refresh token",
					"identity", result.OIDCIdentity,
					"error", err,
				)
			}
		}()
	}

	slog.Info("identity-linked pubkey verification succeeded",
		"pubkey_fingerprint", pubkeyFingerprint,
		"verified_identity", verifiedIdentity,
		"stored_identity", result.OIDCIdentity,
	)

	return verifiedIdentity, fp, nil
}

// bindPubkeyAsync asynchronously binds the client's offered SSH public key
// to their OIDC identity by creating a BlipOwner CR.
func (m *Manager) bindPubkeyAsync(ctx context.Context, conn *ssh.ServerConn, authorizedKeyLine string, identity string) {
	if m.cfg.AuthWatcher == nil {
		return
	}

	// Parse the key to get the fingerprint and validate it.
	keyLine := strings.TrimSpace(authorizedKeyLine)
	if keyLine == "" {
		return
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		slog.Warn("device flow: failed to parse offered pubkey for binding",
			"remote", conn.RemoteAddr().String(),
			"error", err,
		)
		return
	}

	// Replace the comment with the OIDC identity for traceability.
	// Sanitize the identity to prevent newline injection in authorized_keys format.
	sanitizedIdentity := sanitizeAuthorizedKeyComment(identity)
	keyLineWithIdentity := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + sanitizedIdentity
	fingerprint := ssh.FingerprintSHA256(pub)

	go func() {
		bindCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.cfg.AuthWatcher.BindPubkey(bindCtx, fingerprint, keyLineWithIdentity); err != nil {
			slog.Error("device flow: failed to bind pubkey",
				"remote", conn.RemoteAddr().String(),
				"fingerprint", fingerprint,
				"identity", identity,
				"error", err,
			)
		} else {
			slog.Info("device flow: pubkey bound to identity",
				"remote", conn.RemoteAddr().String(),
				"fingerprint", fingerprint,
				"identity", identity,
			)
		}
	}()
}

// waitForSessionChannel reads from chans until a "session" channel arrives.
// Non-session channels are returned as queued for later forwarding.
//
// For reconnecting clients the timeout is kept short (100ms) so that
// session-less connections (e.g. port-forward with -N) proceed quickly.
// A 3-second wait would delay the start of the Forward loop, preventing
// direct-tcpip channels from being processed in time.
func waitForSessionChannel(chans <-chan ssh.NewChannel, reconnecting bool) (ssh.NewChannel, []ssh.NewChannel) {
	var queued []ssh.NewChannel

	var timeout <-chan time.Time
	if reconnecting {
		timeout = time.After(100 * time.Millisecond)
	}

	for {
		select {
		case newChan, ok := <-chans:
			if !ok {
				return nil, queued
			}
			if newChan.ChannelType() == "session" {
				return newChan, queued
			}
			queued = append(queued, newChan)
		case <-timeout:
			return nil, queued
		}
	}
}

const sessionIDPrefix = "blip-"

// generateSessionID returns a new random session ID (e.g. "blip-a3f29c04b1").
func generateSessionID() string {
	var buf [5]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return sessionIDPrefix + hex.EncodeToString(buf[:])
}

// isSessionID reports whether user matches the blip session ID format.
func isSessionID(user string) bool {
	suffix, ok := strings.CutPrefix(user, sessionIDPrefix)
	if !ok || len(suffix) != 10 {
		return false
	}
	// Only lowercase hex is valid (generateSessionID produces lowercase).
	_, err := hex.DecodeString(suffix)
	return err == nil && suffix == strings.ToLower(suffix)
}

// sanitizeAuthorizedKeyComment removes characters that could inject extra
// lines or break the authorized_keys format. Newlines, carriage returns,
// and NUL bytes are replaced with underscores.
func sanitizeAuthorizedKeyComment(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', 0:
			return '_'
		default:
			return r
		}
	}, s)
}

// contextWithConnClose derives a context that is cancelled when the SSH
// connection's underlying transport is closed (e.g. client closes the
// terminal window, network drop). This allows blocking pre-proxy
// operations — VM allocation, upstream dial — to be interrupted when the
// client fully disconnects.
//
// Note: Ctrl+C does NOT close the TCP connection — it sends data or
// signal requests through the SSH channel. Channel-level interrupt
// detection during device flow is handled by monitorChannelInterrupt.
//
// The monitoring goroutine observes connection closure via
// serverConn.Wait(), which returns when the underlying transport is
// closed. This avoids reading from any SSH channel, so it has no
// interaction with the proxy layer that later owns the channels.
//
// The returned stop function cancels the derived context and should be
// called when monitoring is no longer needed. Calling stop is safe after
// the context is already cancelled and may be called multiple times.
func contextWithConnClose(parent context.Context, conn *ssh.ServerConn) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)

	go func() {
		// Wait returns when the connection is closed. This covers
		// full client disconnects (terminal closed, network failure)
		// but NOT in-band signals like Ctrl+C.
		conn.Wait()
		cancel()
	}()

	// cancel is safe to call multiple times.
	return ctx, cancel
}
