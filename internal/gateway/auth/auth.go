// Package auth implements SSH server authentication for the gateway,
// supporting explicit pubkey auth and OIDC token auth from any
// standards-compliant provider (GitHub Actions, Azure Entra / AAD, etc.).
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

// Permission extension keys stored in ssh.Permissions.Extensions.
const (
	// ExtFingerprint is a SHA256 fingerprint of the client's key material.
	ExtFingerprint = "auth-fingerprint"

	// ExtIdentity is a stable user identity string derived from the auth method.
	ExtIdentity = "auth-identity"

	// ExtIsVMClient is set to "true" when the connection was authenticated
	// using a VM client key (recursive blip). Used to determine whether the
	// reconnect host should be the internal cluster alias ("blip") rather
	// than the external gateway hostname.
	ExtIsVMClient = "auth-is-vm-client"
)

// Config holds authentication parameters for building an ssh.ServerConfig.
type Config struct {
	HostSigner   ssh.Signer
	MaxAuthTries int

	// AuthWatcher provides the dynamic OIDC providers, allowed-subjects,
	// and allowed-pubkeys from a ConfigMap.
	AuthWatcher *AuthWatcher

	// VMKeyResolver resolves a VM client key fingerprint to the root user
	// identity of the session that owns the VM. This is used for recursive
	// blip connections where VMs SSH back to the gateway.
	VMKeyResolver VMKeyResolver

	// IdentityStore provides OIDC identity lookup for SSH pubkeys that
	// have been linked to an OIDC identity via device flow. When set,
	// pubkeys found in the identity store are accepted with the stored
	// OIDC identity, subject to post-handshake refresh token verification.
	IdentityStore *IdentityStore
}

// VMKeyResolver resolves a VM SSH client key fingerprint to the original
// user identity and auth fingerprint of the session that owns the VM.
type VMKeyResolver interface {
	ResolveRootIdentity(fingerprint string) (identity string, authFingerprint string, err error)
}

// Permission extension keys for device flow state.
const (
	// ExtDeviceFlowPending is set to "true" when the connection was
	// authenticated via keyboard-interactive and requires device flow
	// completion post-handshake (in the session handler).
	ExtDeviceFlowPending = "auth-device-flow-pending"

	// ExtOfferedPubkey holds the SSH public key the client offered during
	// the handshake (in authorized_keys format). Set when the client
	// tried pubkey auth before falling back to keyboard-interactive.
	// Used to bind the key after successful device flow authentication.
	ExtOfferedPubkey = "auth-offered-pubkey"

	// ExtIdentityLinked is set to "true" when the connection was
	// authenticated via a pubkey that is linked to an OIDC identity in
	// the identity store. The OIDC identity is set in ExtIdentity, but
	// a post-handshake refresh token verification is required to confirm
	// the identity is still valid.
	ExtIdentityLinked = "auth-identity-linked"
)

// pendingPubkeys tracks public keys offered by clients during failed pubkey
// auth attempts. Keyed by SSH session ID (unique per connection). This allows
// us to capture the client's public key for binding after successful device
// flow auth, even though pubkey auth itself was rejected.
//
// Entries are evicted after pendingKeyTTL to prevent memory leaks from clients
// that disconnect before completing keyboard-interactive auth.
type pendingPubkeys struct {
	mu   sync.Mutex
	keys map[string]pendingEntry // sessionID -> entry
}

type pendingEntry struct {
	key       ssh.PublicKey
	createdAt time.Time
}

const pendingKeyTTL = 60 * time.Second

func newPendingPubkeys(ctx context.Context) *pendingPubkeys {
	p := &pendingPubkeys{keys: make(map[string]pendingEntry)}
	go p.evictionLoop(ctx)
	return p
}

func (p *pendingPubkeys) Store(sessionID string, key ssh.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[sessionID] = pendingEntry{key: key, createdAt: time.Now()}
}

func (p *pendingPubkeys) LoadAndDelete(sessionID string) (ssh.PublicKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.keys[sessionID]
	if ok {
		delete(p.keys, sessionID)
	}
	return entry.key, ok
}

// evictionLoop removes stale entries every 30 seconds.
func (p *pendingPubkeys) evictionLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.evictStale()
		}
	}
}

func (p *pendingPubkeys) evictStale() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for id, entry := range p.keys {
		if now.Sub(entry.createdAt) > pendingKeyTTL {
			delete(p.keys, id)
		}
	}
}

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
// The context is used for background goroutines (e.g. pending pubkey eviction).
func NewServerConfig(ctx context.Context, cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	// Track public keys offered during failed pubkey auth for later binding.
	pending := newPendingPubkeys(ctx)

	if cfg.AuthWatcher != nil || cfg.VMKeyResolver != nil || cfg.IdentityStore != nil {
		sshCfg.PublicKeyCallback = pubkeyCallback(cfg.AuthWatcher, cfg.VMKeyResolver, cfg.IdentityStore, pending)
	}

	if cfg.AuthWatcher != nil {
		sshCfg.PasswordCallback = oidcCallback(cfg.AuthWatcher)

		// Enable keyboard-interactive auth for device flow when any
		// OIDC provider has device-flow enabled.
		sshCfg.KeyboardInteractiveCallback = deviceFlowKeyboardInteractive(cfg.AuthWatcher, pending)
	}

	if cfg.AuthWatcher == nil && cfg.VMKeyResolver == nil {
		slog.Warn("no auth watcher configured, all authentication is disabled")
	}

	return sshCfg
}

// pubkeyCallback returns a PublicKeyCallback that checks keys in order:
// 1. Explicit allowed pubkeys from the AuthWatcher's ConfigMap.
// 2. OIDC-linked pubkeys from the IdentityStore (refresh token-backed).
// 3. VM client keys for recursive blip connections.
// When all fail, the key is stored in pendingKeys for post-device-flow binding.
func pubkeyCallback(watcher *AuthWatcher, vmResolver VMKeyResolver, identityStore *IdentityStore, pendingKeys *pendingPubkeys) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// First, try explicit pubkey auth (user keys in ConfigMap).
		if watcher != nil {
			perm, err := verifyExplicitPubkey(conn, key, watcher)
			if err == nil {
				return perm, nil
			}
		}

		// Second, try identity-linked pubkey auth (OIDC identity from store).
		if identityStore != nil {
			perm, err := verifyIdentityLinkedPubkey(conn, key, identityStore)
			if err == nil {
				return perm, nil
			}
		}

		// Third, try VM client key auth (for recursive blip connections).
		if vmResolver != nil {
			perm, err := verifyVMClientKey(conn, key, vmResolver)
			if err == nil {
				return perm, nil
			}
		}

		// Store the offered key for potential binding after device flow.
		if pendingKeys != nil {
			pendingKeys.Store(string(conn.SessionID()), key)
		}

		return nil, fmt.Errorf("public key %s is not authorized", ssh.FingerprintSHA256(key))
	}
}

// verifyExplicitPubkey checks whether a raw public key's fingerprint is in the
// allowed set, and uses the pubkey's comment (username) as the stable identity.
func verifyExplicitPubkey(conn ssh.ConnMetadata, key ssh.PublicKey, watcher *AuthWatcher) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	if !watcher.IsPubkeyAllowed(fingerprint) {
		return nil, fmt.Errorf("public key %s is not in the allowed list", fingerprint)
	}

	username := watcher.PubkeyUsername(fingerprint)
	if username == "" {
		return nil, fmt.Errorf("public key %s has no comment (username) in authorized_keys entry", fingerprint)
	}

	slog.Info("explicit pubkey auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
		"pubkey_username", username,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    fmt.Sprintf("pubkey:%s", username),
		},
	}, nil
}

// verifyIdentityLinkedPubkey checks whether the key is linked to an OIDC
// identity in the identity store. If found (and the link hasn't expired),
// the connection is accepted with the stored OIDC identity and marked for
// post-handshake refresh token verification.
//
// This enables "strong" OIDC identity for SSH pubkey auth: after a user
// completes device flow once, their SSH pubkey is linked to their OIDC
// identity. Subsequent connections use the pubkey but retain the OIDC
// identity, verified via refresh token exchange.
func verifyIdentityLinkedPubkey(conn ssh.ConnMetadata, key ssh.PublicKey, store *IdentityStore) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)

	// Use a short timeout for the lookup since this is in the SSH handshake path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := store.LookupByPubkey(ctx, fingerprint)
	if err != nil {
		slog.Warn("identity store lookup failed during pubkey auth",
			"fingerprint", fingerprint,
			"error", err,
		)
		return nil, fmt.Errorf("identity store lookup failed: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("public key %s not linked to any OIDC identity", fingerprint)
	}

	slog.Info("identity-linked pubkey auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
		"oidc_identity", result.OIDCIdentity,
		"issuer", result.Issuer,
	)

	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint:    fingerprint,
			ExtIdentity:       result.OIDCIdentity,
			ExtIdentityLinked: "true",
		},
	}, nil
}

// verifyVMClientKey checks whether the key belongs to a VM by looking up its
// fingerprint in the VM annotations. If found, it resolves the root user
// identity and auth fingerprint for the session that owns the VM. This enables
// identity propagation for recursive blip connections so that nested blips are
// owned by the original connecting user.
func verifyVMClientKey(conn ssh.ConnMetadata, key ssh.PublicKey, resolver VMKeyResolver) (*ssh.Permissions, error) {
	vmFingerprint := ssh.FingerprintSHA256(key)
	identity, rootAuthFingerprint, err := resolver.ResolveRootIdentity(vmFingerprint)
	if err != nil {
		return nil, fmt.Errorf("VM client key lookup failed for %s: %w", vmFingerprint, err)
	}

	// Use the root user's auth fingerprint when available so that the
	// nested blip can be retained and reconnected to directly by the
	// original user. Fall back to the VM client key fingerprint when the
	// parent VM has no auth-fingerprint stored (should not happen in
	// practice, but keeps the system robust).
	fingerprint := rootAuthFingerprint
	if fingerprint == "" {
		slog.Warn("VM client key auth: parent VM has no auth-fingerprint, "+
			"falling back to VM client key fingerprint — reconnect to nested blip may fail",
			"vm_client_key_fingerprint", vmFingerprint,
			"resolved_identity", identity,
		)
		fingerprint = vmFingerprint
	}

	slog.Info("blip client key auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", vmFingerprint,
		"resolved_identity", identity,
		"resolved_auth_fingerprint", fingerprint,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    identity,
			ExtIsVMClient:  "true",
		},
	}, nil
}

// oidcCallback returns a PasswordCallback that validates OIDC tokens against
// all configured providers. The watcher is consulted on every auth attempt,
// so ConfigMap changes take effect without restarting the gateway.
func oidcCallback(watcher *AuthWatcher) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		token := string(password)
		providers := watcher.OIDCProviders()

		if len(providers) == 0 {
			return nil, fmt.Errorf("OIDC authentication failed: no providers configured")
		}

		identity, err := verifyOIDCToken(token, providers)
		if err != nil {
			slog.Warn("OIDC auth failed",
				"user", conn.User(),
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
			return nil, fmt.Errorf("OIDC authentication failed")
		}

		slog.Info("OIDC auth succeeded",
			"user", conn.User(),
			"remote", conn.RemoteAddr().String(),
			"identity", identity,
		)

		h := TokenFingerprint(token)
		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtFingerprint: h,
				ExtIdentity:    identity,
			},
		}, nil
	}
}

// deviceFlowLimiter limits the rate of device flow initiations to prevent
// abuse. Allows 10 per second with a burst of 20.
var deviceFlowLimiter = rate.NewLimiter(10, 20)

// deviceFlowKeyboardInteractive returns a KeyboardInteractiveCallback that
// accepts keyboard-interactive auth when device flow providers are configured.
// It does NOT run the full device flow during the SSH handshake — that would
// block too long. Instead, it marks the connection as needing device flow
// completion in the session handler (post-handshake).
//
// The actual device flow (showing URLs, polling) happens in the session manager
// after the SSH connection is established, giving us access to the SSH channel
// for rich user interaction without handshake timeout constraints.
func deviceFlowKeyboardInteractive(watcher *AuthWatcher, pendingKeys *pendingPubkeys) func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		if !watcher.HasDeviceFlowProviders() {
			return nil, fmt.Errorf("keyboard-interactive auth not available: no device-flow providers configured")
		}

		// Rate-limit device flow initiations to prevent DoS.
		if !deviceFlowLimiter.Allow() {
			slog.Warn("device flow rate limited",
				"remote", conn.RemoteAddr().String(),
			)
			return nil, fmt.Errorf("too many device flow requests, please try again later")
		}

		slog.Info("device flow: keyboard-interactive auth accepted, deferring flow to session",
			"user", conn.User(),
			"remote", conn.RemoteAddr().String(),
		)

		// Send a notice to the user via keyboard-interactive instruction.
		// The challenge function allows us to send instructions without
		// requiring a response (zero questions).
		_, err := client(
			"", // user (empty = use connection user)
			"Authenticating via device flow — please wait...",
			nil, // no questions
			nil, // no echo settings
		)
		if err != nil {
			slog.Debug("device flow: failed to send keyboard-interactive instruction",
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
		}

		// Build permissions with the device-flow-pending marker.
		extensions := map[string]string{
			ExtDeviceFlowPending: "true",
		}

		// If the client offered a public key during an earlier failed attempt,
		// capture it so the session handler can bind it after successful auth.
		if pendingKeys != nil {
			if offeredKey, ok := pendingKeys.LoadAndDelete(string(conn.SessionID())); ok {
				extensions[ExtOfferedPubkey] = string(ssh.MarshalAuthorizedKey(offeredKey))
				slog.Debug("device flow: captured offered pubkey for binding",
					"remote", conn.RemoteAddr().String(),
					"fingerprint", ssh.FingerprintSHA256(offeredKey),
				)
			}
		}

		return &ssh.Permissions{
			Extensions: extensions,
		}, nil
	}
}

// OIDCProviderConfig describes a single OIDC provider for token verification.
type OIDCProviderConfig struct {
	// Issuer is the OIDC issuer URL (e.g. "https://token.actions.githubusercontent.com"
	// or "https://login.microsoftonline.com/{tenant}/v2.0").
	Issuer string `yaml:"issuer"`

	// Audience is the expected "aud" claim (e.g. "blip" or "api://blip").
	Audience string `yaml:"audience"`

	// IdentityClaim is the JWT claim used as the user identity.
	// Defaults to "sub" if empty. Common values: "sub", "oid", "email".
	IdentityClaim string `yaml:"identity-claim"`

	// AllowedSubjects is a list of allowed subject patterns. If non-empty,
	// the token's subject claim must match at least one entry. Supports
	// glob patterns (e.g. "repo:my-org/*:*").
	// When empty, any valid token from this issuer is accepted.
	AllowedSubjects []string `yaml:"allowed-subjects"`

	// DeviceFlow enables the OAuth2 Device Authorization Grant (RFC 8628)
	// for this provider. When true, users can connect without a token —
	// the gateway presents a login URL in the SSH prompt and polls for
	// completion. Requires ClientID and DeviceAuthURL.
	DeviceFlow bool `yaml:"device-flow"`

	// ClientID is the OAuth2 client ID for the device flow. Required when
	// DeviceFlow is true. This is typically a public client (no secret).
	ClientID string `yaml:"client-id"`

	// DeviceAuthURL is the OAuth2 device authorization endpoint.
	// Required when DeviceFlow is true.
	// GitHub: "https://github.com/login/device/code"
	// Azure:  "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
	DeviceAuthURL string `yaml:"device-auth-url"`

	// TokenURL is the OAuth2 token endpoint for polling device flow completion.
	// Required when DeviceFlow is true.
	// GitHub: "https://github.com/login/oauth/access_token"
	// Azure:  "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
	TokenURL string `yaml:"token-url"`

	// Scopes is the list of OAuth2 scopes to request during device flow.
	// GitHub: ["read:user"] or ["openid"]
	// Azure:  ["api://blip/.default"] or ["openid", "profile"]
	Scopes []string `yaml:"scopes"`
}

// oidcProviderCache holds lazily-initialized OIDC providers keyed by issuer URL.
// Entries are evicted when they are no longer referenced by the active
// AuthWatcher configuration (see pruneProviderCache).
type oidcProviderCache struct {
	mu        sync.Mutex
	providers map[string]*oidc.Provider
}

var providerCache = oidcProviderCache{
	providers: make(map[string]*oidc.Provider),
}

// getOIDCProvider returns a cached (or newly fetched) OIDC provider for the
// given issuer URL. The go-oidc library handles JWKS key rotation internally
// by re-fetching when it encounters an unknown kid.
func getOIDCProvider(issuer string) (*oidc.Provider, error) {
	providerCache.mu.Lock()
	defer providerCache.mu.Unlock()

	if p, ok := providerCache.providers[issuer]; ok {
		return p, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider %s: %w", issuer, err)
	}
	providerCache.providers[issuer] = p
	return p, nil
}

// pruneProviderCache removes cached OIDC providers whose issuer URL is not in
// the given set of active issuers. Called from AuthWatcher.reload to prevent
// stale entries from accumulating when operators change providers.
func pruneProviderCache(activeIssuers map[string]bool) {
	providerCache.mu.Lock()
	defer providerCache.mu.Unlock()

	for issuer := range providerCache.providers {
		if !activeIssuers[issuer] {
			delete(providerCache.providers, issuer)
			slog.Info("pruned stale OIDC provider from cache", "issuer", issuer)
		}
	}
}

// verifyOIDCToken validates a token against each configured provider in order
// and returns the identity string from the first provider that accepts it.
func verifyOIDCToken(token string, providers []OIDCProviderConfig) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}

	var lastErr error
	for _, pCfg := range providers {
		identity, err := verifyTokenAgainstProvider(token, pCfg)
		if err == nil {
			return identity, nil
		}
		lastErr = err
	}

	if len(providers) == 1 {
		return "", fmt.Errorf("token validation: %w", lastErr)
	}
	return "", fmt.Errorf("token not accepted by any configured OIDC provider (%d tried)", len(providers))
}

// verifyTokenAgainstProvider validates a token against a single OIDC provider
// configuration, checking audience, signature, and subject allowlist.
func verifyTokenAgainstProvider(token string, cfg OIDCProviderConfig) (string, error) {
	provider, err := getOIDCProvider(cfg.Issuer)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.Audience,
	})

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return "", fmt.Errorf("token validation against %s: %w", cfg.Issuer, err)
	}

	// Extract the identity claim.
	identityClaim := cfg.IdentityClaim
	if identityClaim == "" {
		identityClaim = "sub"
	}

	var identity string
	if identityClaim == "sub" {
		// Subject is a first-class field on the token, no need to parse claims.
		identity = idToken.Subject
	} else {
		// For other claims, parse the full claim set.
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			return "", fmt.Errorf("extract claims from %s: %w", cfg.Issuer, err)
		}
		val, ok := claims[identityClaim]
		if !ok {
			return "", fmt.Errorf("token from %s missing %q claim", cfg.Issuer, identityClaim)
		}
		identity, ok = val.(string)
		if !ok {
			return "", fmt.Errorf("token from %s: claim %q is not a string", cfg.Issuer, identityClaim)
		}
	}

	if identity == "" {
		return "", fmt.Errorf("token from %s has empty identity claim %q", cfg.Issuer, identityClaim)
	}

	// Check identity against allowlist. The allowlist is matched against the
	// resolved identity value (selected by identity-claim), not always the
	// raw sub claim. This ensures that an Azure Entra config with
	// identity-claim=oid and allowed-subjects listing OIDs works correctly.
	if err := checkSubjectAllowed(identity, cfg.AllowedSubjects); err != nil {
		return "", fmt.Errorf("issuer %s: %w", cfg.Issuer, err)
	}

	return fmt.Sprintf("oidc:%s", identity), nil
}

// checkSubjectAllowed verifies that subject matches at least one entry in
// allowedSubjects. Entries support simple glob patterns where "*" matches any
// sequence of characters (including "/" and ":"). An empty allowlist permits
// any subject.
func checkSubjectAllowed(subject string, allowedSubjects []string) error {
	if len(allowedSubjects) == 0 {
		return nil
	}
	for _, pattern := range allowedSubjects {
		// Try exact case-insensitive match first.
		if strings.EqualFold(subject, pattern) {
			return nil
		}
		// Try glob match (case-insensitive).
		if globMatch(strings.ToLower(pattern), strings.ToLower(subject)) {
			return nil
		}
	}
	return fmt.Errorf("subject %q is not in the allowed list", subject)
}

// globMatch performs a simple glob match where "*" matches any sequence of
// characters (including none). Unlike filepath.Match, "*" matches "/" and ":"
// which commonly appear in OIDC subject claims.
//
// Uses an iterative two-pointer algorithm with O(n*m) worst-case complexity
// (no recursive backtracking).
func globMatch(pattern, str string) bool {
	px, sx := 0, 0
	// nextPx/nextSx track the backtrack point for the most recent "*".
	nextPx, nextSx := -1, 0

	for sx < len(str) {
		if px < len(pattern) && pattern[px] == '*' {
			// Record backtrack point and skip the star.
			nextPx = px
			nextSx = sx
			px++
		} else if px < len(pattern) && pattern[px] == str[sx] {
			// Literal match — advance both pointers.
			px++
			sx++
		} else if nextPx >= 0 {
			// Mismatch — backtrack: let the last star consume one more character.
			nextSx++
			sx = nextSx
			px = nextPx + 1
		} else {
			// Mismatch with no star to backtrack to.
			return false
		}
	}
	// Consume any trailing stars in the pattern.
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
