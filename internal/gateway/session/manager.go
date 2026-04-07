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
	VMClient           *vm.Client
	VMPoolName         string
	PodName            string
	MaxBlipsPerUser    int
	MaxSessionDuration time.Duration
	KeepAliveInterval  time.Duration
	KeepAliveMax       int
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

	authFingerprint, authIdentity := extractAuthExtensions(serverConn)

	slog.Info("client authenticated",
		"user", serverConn.User(),
		"remote", remoteAddr,
		"client_version", string(serverConn.ClientVersion()),
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

	start := time.Now()
	ttlSec := sessionTTL(authIdentity)
	sessionTimeout := time.Duration(ttlSec) * time.Second

	sessionID, alloc, err := m.allocateOrReconnect(ctx, serverConn.User(), authFingerprint, authIdentity, reconnecting, ttlSec)
	if err != nil {
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
		slog.Info("VM reconnected",
			"session_id", sessionID,
			"vm_name", alloc.Name,
			"vm_ip", alloc.PodIP,
			"remote", remoteAddr,
		)
	} else {
		slog.Info("VM claimed",
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

	hostKey, err := m.cfg.VMClient.GetHostKey(ctx, alloc.Name)
	if err != nil {
		slog.Error("failed to read host key for VM",
			"vm_name", alloc.Name,
			"error", err,
		)
		if firstClientChan != nil {
			writeBanner(firstClientChan, crlf("\n  >>> Failed to verify VM identity\n\n"))
			firstClientChan.Close()
		}
		return
	}

	upstreamConn, err := proxy.DialUpstream(alloc.PodIP, m.cfg.GatewaySigner, hostKey)
	if err != nil {
		slog.Error("failed to connect to VM",
			"vm_name", alloc.Name,
			"vm_ip", alloc.PodIP,
			"error", err,
		)
		if firstClientChan != nil {
			firstClientChan.Close()
		}
		return
	}
	sess.SetUpstream(upstreamConn)
	if firstClientChan != nil {
		sess.SetBannerChannel(firstClientChan)
	}

	// Inject SSH config for recursive blip connections (gateway host + key).
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

	slog.Info("connected to VM",
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

		go func() {
			time.Sleep(500 * time.Millisecond)
			select {
			case <-sessionCtx.Done():
				return
			default:
			}
			writeBanner(firstClientChan, sessionIDBanner(sessionID))
		}()
	}

	for _, queuedChan := range queued {
		go proxy.BridgeNewClientChannel(sessionCtx, sessionID, upstreamConn, queuedChan)
	}

	proxy.Forward(sessionCtx, sessionID, serverConn, upstreamConn, chans, upstreamForwardedChans)

	// Release ephemeral VMs after session ends. Use a fresh context
	// because the session context is already cancelled.
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	m.releaseIfEphemeral(releaseCtx, sessionID)
	releaseCancel()

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
		writeBanner(ch, crlf("\n  >>> Reconnect failed: "+err.Error()+"\n\n"))
	} else {
		slog.Error("no VMs available", "error", err, "session_id", sessionID)
		writeBanner(ch, crlf("\n  >>> VM allocation failed: "+err.Error()+"\n\n"))
	}
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

func extractAuthExtensions(conn *ssh.ServerConn) (fingerprint, identity string) {
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		fingerprint = conn.Permissions.Extensions[auth.ExtFingerprint]
		identity = conn.Permissions.Extensions[auth.ExtIdentity]
	}
	return
}

// waitForSessionChannel reads from chans until a "session" channel arrives.
// Non-session channels are returned as queued for later forwarding.
func waitForSessionChannel(chans <-chan ssh.NewChannel, reconnecting bool) (ssh.NewChannel, []ssh.NewChannel) {
	var queued []ssh.NewChannel

	var timeout <-chan time.Time
	if reconnecting {
		timeout = time.After(3 * time.Second)
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

func writeBanner(ch ssh.Channel, banner string) {
	if _, err := ch.Stderr().Write([]byte(banner)); err != nil {
		slog.Debug("failed to write banner", "error", err)
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
	if !strings.HasPrefix(user, sessionIDPrefix) {
		return false
	}
	suffix := user[len(sessionIDPrefix):]
	if len(suffix) != 10 {
		return false
	}
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

const bannerSpacer = "\n\n\n-----------------------------------\n\n\n"

func crlf(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func welcomeBanner(reconnecting bool) string {
	status := ">>> Allocating VM..."
	if reconnecting {
		status = ">>> Reconnecting..."
	}
	banner := fmt.Sprintf(`
  ____  _ _
 | __ )| (_)_ __
 |  _ \| | | '_ \
 | |_) | | | |_) |
 |____/|_|_| .__/
            |_|

  %s
`, status)
	return crlf(banner)
}

func vmInfoBanner(sessionID, vmName, site string, reconnecting bool, ttl time.Duration) string {
	connMsg := ">>> Connected to gateway"
	if reconnecting {
		connMsg = ">>> Reconnected to gateway"
	}
	banner := fmt.Sprintf(`  %s
  Session : %s
  VM      : %s
  Lease   : ephemeral (%s TTL)`, connMsg, sessionID, vmName, formatDuration(ttl))
	if site != "" {
		banner += fmt.Sprintf("\n  Site    : %s", site)
	}
	banner += fmt.Sprintf(`

  This blip is ephemeral and will be destroyed when you
  disconnect. Run 'blip retain' to preserve it.`)
	banner += bannerSpacer
	return crlf(banner)
}

// formatDuration produces a human-friendly duration string like "8h" or "2h30m".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 && m > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", m)
}

func shutdownBanner() string {
	banner := `

-----------------------------------

  >>> Gateway is shutting down.
  >>> Your VM is still running.
  >>> Reconnect with your session ID.

-----------------------------------

`
	return crlf(banner)
}

func sessionIDBanner(sessionID string) string {
	return crlf(fmt.Sprintf("  [session: %s]\n", sessionID))
}
