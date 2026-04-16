// Package session manages the lifecycle of SSH sessions proxied through the gateway.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/proxy"
	"github.com/project-unbounded/blip/internal/gateway/vm"
)

const (
	DefaultTTL = 8 * time.Hour
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

	// TokenReviewer validates Kubernetes ServiceAccount tokens for
	// post-connect validation of _register exec commands. May be nil.
	TokenReviewer auth.TokenReviewer
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

	// Monitor the SSH connection so that a full client disconnect
	// during blocking pre-proxy phases — VM allocation, host key
	// retrieval, upstream dial — cancels the operation immediately.
	setupCtx, stopSetupMonitor := contextWithConnClose(ctx, serverConn)

	start := time.Now()
	ttlSec := int(DefaultTTL.Seconds())
	sessionTimeout := DefaultTTL

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
		injectCtx, injectCancel := context.WithTimeout(ctx, 10*time.Second)
		if err := proxy.InjectGatewayConfig(
			injectCtx,
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
		injectCancel()
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
	goodbyeCtx, goodbyeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer goodbyeCancel()
	m.sendGoodbyeBanner(goodbyeCtx, sess, sessionID)

	// Release ephemeral VMs after session ends.
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

// waitForSessionChannel reads from chans until a "session" channel arrives.
// Non-session channels are returned as queued for later forwarding.
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
	_, err := hex.DecodeString(suffix)
	return err == nil && suffix == strings.ToLower(suffix)
}

// contextWithConnClose derives a context that is cancelled when the SSH
// connection's underlying transport is closed.
func contextWithConnClose(parent context.Context, conn *ssh.ServerConn) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)

	go func() {
		conn.Wait()
		cancel()
	}()

	return ctx, cancel
}
