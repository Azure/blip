// Package auth implements SSH server authentication for the gateway,
// supporting static pubkey auth from ConfigMaps, OIDC token password auth,
// and VM registration via Kubernetes ServiceAccount tokens.
package auth

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

	// ExtVMName is set on _register connections after the SA token is
	// validated. Contains the VM name derived from the virt-launcher pod
	// name in the token's bound pod claim.
	ExtVMName = "auth-vm-name"
)

// Config holds authentication parameters for building an ssh.ServerConfig.
type Config struct {
	HostSigner   ssh.Signer
	MaxAuthTries int

	// AuthWatcher provides the dynamic SSH public keys from ConfigMaps
	// with the blip.azure.com/user label.
	AuthWatcher *AuthWatcher

	// VMKeyResolver resolves a VM client key fingerprint to the root user
	// identity of the session that owns the VM. This is used for recursive
	// blip connections where VMs SSH back to the gateway.
	VMKeyResolver VMKeyResolver

	// TokenReviewer validates Kubernetes ServiceAccount tokens for
	// _register connections. When set, VMs must present a valid SA token
	// as their SSH password to register keys. When nil, _register
	// connections are rejected.
	TokenReviewer TokenReviewer

	// OIDCTokenVerifier validates OIDC tokens supplied as SSH passwords.
	// This supports non-interactive environments that can obtain an OIDC
	// token directly, such as GitHub Actions.
	OIDCTokenVerifier OIDCTokenVerifier

	// AuthenticatorURL is the URL of the web authenticator for the
	// device-flow. When set (along with AuthWatcher and JWTSigner),
	// users with unrecognized pubkeys are prompted to authenticate via
	// their browser.
	AuthenticatorURL string

	// JWTSigner is the private key used to sign device-flow JWTs.
	JWTSigner SigningKeyProvider

	// DeviceFlow provides dynamic device-flow configuration (authenticator
	// URL and signing key). When non-nil, the keyboard-interactive callback
	// reads the authenticator URL at runtime, allowing it to be changed via
	// ConfigMap without restarting the gateway. Takes precedence over the
	// static AuthenticatorURL and JWTSigner fields.
	DeviceFlow DeviceFlowProvider

	// JWTIssuer is the issuer claim for device-flow JWTs (typically the
	// gateway's external hostname).
	JWTIssuer string

	// PendingFingerprints tracks pubkey fingerprints from failed auth
	// attempts, bridging pubkeyCallback and keyboard-interactive.
	PendingFingerprints *PendingFingerprints
}

// VMKeyResolver resolves a VM SSH client key fingerprint to the original
// user identity and auth fingerprint of the session that owns the VM.
type VMKeyResolver interface {
	ResolveRootIdentity(fingerprint string) (identity string, authFingerprint string, err error)
}

// OIDCTokenIdentity is the authenticated identity extracted from an OIDC token.
type OIDCTokenIdentity struct {
	Subject string
	Expiry  time.Time
}

// OIDCTokenVerifier validates an OIDC token and returns its subject.
type OIDCTokenVerifier interface {
	VerifyOIDCToken(ctx context.Context, token string) (*OIDCTokenIdentity, error)
}

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
func NewServerConfig(ctx context.Context, cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	if cfg.AuthWatcher != nil || cfg.VMKeyResolver != nil {
		sshCfg.PublicKeyCallback = pubkeyCallback(cfg.AuthWatcher, cfg.VMKeyResolver, cfg.PendingFingerprints)
	}

	// Enable keyboard-interactive for device-flow auth when configured.
	// When DeviceFlow is set, the callback reads the authenticator URL at
	// runtime so the keyboard-interactive path activates/deactivates
	// dynamically as the OIDC ConfigMap changes.
	if cfg.DeviceFlow != nil && cfg.AuthWatcher != nil && cfg.PendingFingerprints != nil {
		sshCfg.KeyboardInteractiveCallback = deviceFlowKeyboardInteractive(
			cfg.DeviceFlow,
			cfg.JWTIssuer,
			cfg.PendingFingerprints,
		)
	} else if cfg.AuthenticatorURL != "" && cfg.AuthWatcher != nil && cfg.JWTSigner != nil && cfg.PendingFingerprints != nil {
		sshCfg.KeyboardInteractiveCallback = deviceFlowKeyboardInteractive(
			&staticDeviceFlow{url: cfg.AuthenticatorURL, signer: cfg.JWTSigner},
			cfg.JWTIssuer,
			cfg.PendingFingerprints,
		)
	}

	// Authenticate _register connections using a Kubernetes ServiceAccount
	// token as the SSH password. VMs mount a SA token via virtiofs and
	// present it during registration. The gateway validates the token via
	// the TokenReview API, verifying it belongs to the expected SA and
	// extracting the bound pod name to derive the VM name.
	//
	// Because OpenSSH clients truncate passwords to 1023 bytes and
	// pod-bound SA tokens are ~1192 bytes, we also accept none-auth for
	// _register connections. In that case, the VM must pass the token via
	// the exec command's --token flag, and the session handler validates
	// it post-connect.
	if cfg.TokenReviewer != nil || cfg.OIDCTokenVerifier != nil {
		registerLimiter := rate.NewLimiter(20, 40) // 20/s with burst of 40
		oidcLimiter := rate.NewLimiter(20, 40)     // 20/s with burst of 40
		sshCfg.PasswordCallback = passwordCallback(cfg.TokenReviewer, cfg.OIDCTokenVerifier, registerLimiter, oidcLimiter)
	}

	if cfg.TokenReviewer != nil {
		// Allow none-auth for _register so VMs can pass full-length
		// tokens via the exec command instead of truncated passwords.
		// NoClientAuth must be true for NoClientAuthCallback to fire;
		// the callback rejects non-_register connections.
		sshCfg.NoClientAuth = true
		sshCfg.NoClientAuthCallback = registerNoneAuthCallback()
	}

	if cfg.AuthWatcher == nil && cfg.VMKeyResolver == nil {
		slog.Warn("no auth watcher configured, all authentication is disabled")
	}

	return sshCfg
}

func passwordCallback(reviewer TokenReviewer, oidcVerifier OIDCTokenVerifier, registerLimiter, oidcLimiter *rate.Limiter) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if conn.User() == "_register" {
			if reviewer == nil {
				return nil, fmt.Errorf("_register password auth is not configured")
			}
			return registerPasswordCallback(reviewer, registerLimiter)(conn, password)
		}

		if oidcVerifier == nil {
			return nil, fmt.Errorf("password auth not supported for user %q", conn.User())
		}
		return oidcPasswordCallback(oidcVerifier, oidcLimiter)(conn, password)
	}
}

// staticDeviceFlow is a DeviceFlowProvider backed by static values.
type staticDeviceFlow struct {
	url    string
	signer SigningKeyProvider
}

func (s *staticDeviceFlow) AuthenticatorURL() string     { return s.url }
func (s *staticDeviceFlow) GetSigningKey() crypto.Signer { return s.signer.GetSigningKey() }

// pubkeyCallback returns a PublicKeyCallback that checks keys in order:
//  1. Allowed pubkeys from ConfigMaps with blip.azure.com/user label. These
//     include static test keys and dynamic OIDC/device-flow registrations.
//  2. VM client keys for recursive blip connections.
//
// When all checks fail and pending is non-nil, the fingerprint is recorded
// for use by the keyboard-interactive device flow callback.
func pubkeyCallback(watcher *AuthWatcher, vmResolver VMKeyResolver, pending *PendingFingerprints) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fingerprint := ssh.FingerprintSHA256(key)

		// First, try ConfigMap-backed pubkey auth (static and OIDC/device-flow).
		if watcher != nil {
			perm, err := verifyExplicitPubkey(conn, key, watcher)
			if err == nil {
				return perm, nil
			}
		}

		// Second, try VM client key auth (for recursive blip connections).
		if vmResolver != nil {
			perm, err := verifyVMClientKey(conn, key, vmResolver)
			if err == nil {
				return perm, nil
			}
		}

		// Record the fingerprint and pubkey for use by keyboard-interactive fallback.
		if pending != nil {
			pubkeyStr := string(ssh.MarshalAuthorizedKey(key))
			pending.Add(conn.RemoteAddr().String(), fingerprint, strings.TrimSpace(pubkeyStr))
		}

		return nil, fmt.Errorf("public key %s is not authorized", fingerprint)
	}
}

// deviceFlowKeyboardInteractive returns a KeyboardInteractiveCallback that
// presents a device-flow authentication URL to the user. It reads the
// authenticator URL and signing key from the DeviceFlowProvider at runtime,
// so the callback activates/deactivates as configuration changes.
func deviceFlowKeyboardInteractive(
	deviceFlow DeviceFlowProvider,
	issuer string,
	pending *PendingFingerprints,
) func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		authenticatorURL := deviceFlow.AuthenticatorURL()
		if authenticatorURL == "" {
			return nil, fmt.Errorf("device flow auth not configured")
		}

		pendingKeys := pending.Take(conn.RemoteAddr().String())
		if len(pendingKeys) == 0 {
			return nil, fmt.Errorf("no pubkey was offered before keyboard-interactive")
		}

		// Use the last key offered (most likely the intended key).
		lastKey := pendingKeys[len(pendingKeys)-1]

		signer := deviceFlow.GetSigningKey()
		if signer == nil {
			return nil, fmt.Errorf("device flow auth not available: no signing key")
		}

		authURL, err := GenerateAuthURL(authenticatorURL, lastKey.fingerprint, lastKey.pubkey, signer, issuer)
		if err != nil {
			slog.Error("failed to generate device flow auth URL",
				"error", err,
				"fingerprint", lastKey.fingerprint,
			)
			return nil, fmt.Errorf("internal error generating auth URL")
		}

		banner := FormatDeviceFlowBanner(authURL)

		// Send the URL to the user via keyboard-interactive. We use a
		// single prompt with no echo so the user sees the banner and
		// presses Enter. We don't actually need their response.
		_, err = client(
			conn.User(),
			banner,
			[]string{"Press Enter after authenticating in your browser: "},
			[]bool{true},
		)
		if err != nil {
			return nil, fmt.Errorf("keyboard-interactive challenge failed: %w", err)
		}

		slog.Info("device flow auth initiated",
			"user", conn.User(),
			"remote", conn.RemoteAddr().String(),
			"fingerprint", lastKey.fingerprint,
		)

		// Return success immediately with a pending flag. The connection
		// handler will call WaitForAuth to block until the browser auth
		// completes.
		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtFingerprint:           lastKey.fingerprint,
				ExtPendingDeviceAuth:     "true",
				ExtDeviceFlowFingerprint: lastKey.fingerprint,
			},
		}, nil
	}
}

// verifyExplicitPubkey checks whether a raw public key's fingerprint is in the
// allowed set, and uses the ConfigMap's blip.azure.com/user label value as the
// stable identity.
func verifyExplicitPubkey(conn ssh.ConnMetadata, key ssh.PublicKey, watcher *AuthWatcher) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	entry, found := watcher.Lookup(fingerprint)
	if !found {
		return nil, fmt.Errorf("public key %s is not in the allowed list", fingerprint)
	}
	if entry.UserIdentity == "" {
		return nil, fmt.Errorf("public key %s has no user identity (empty blip.azure.com/user label)", fingerprint)
	}

	identity := fmt.Sprintf("pubkey:%s", entry.UserIdentity)
	if entry.Subject != "" {
		identity = fmt.Sprintf("oidc:%s", entry.Subject)
	}

	slog.Info("explicit pubkey auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
		"user_identity", entry.UserIdentity,
		"subject", entry.Subject,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    identity,
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

// registerPasswordCallback returns a PasswordCallback that handles
// _register connections authenticated via Kubernetes ServiceAccount tokens.
//
// When the user is "_register", the password is treated as a SA token and
// validated via the TokenReview API. The token must belong to the expected
// SA, and the bound pod name is used to derive the VM name. The VM name is
// stored in ExtVMName so the session handler can use it directly without
// IP-based resolution.
//
// For all other users, password auth is rejected.
func registerPasswordCallback(reviewer TokenReviewer, limiter *rate.Limiter) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if conn.User() != "_register" {
			return nil, fmt.Errorf("password auth not supported for user %q", conn.User())
		}

		// Rate-limit _register connections to prevent abuse.
		if limiter != nil && !limiter.Allow() {
			return nil, fmt.Errorf("too many registration attempts, please try again later")
		}

		token := string(password)
		if token == "" {
			return nil, fmt.Errorf("_register requires a ServiceAccount token as password")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := reviewer.Review(ctx, token)
		if err != nil {
			slog.Warn("VM registration auth: token review failed",
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
			return nil, fmt.Errorf("ServiceAccount token validation failed")
		}

		extensions := map[string]string{
			ExtIdentity: "vm-register",
		}

		// Derive VM name from the token's bound pod name when available.
		if result.PodName != "" {
			vmName, err := VMNameFromPodName(result.PodName)
			if err != nil {
				slog.Warn("VM registration auth: cannot derive VM name from pod",
					"remote", conn.RemoteAddr().String(),
					"pod_name", result.PodName,
					"error", err,
				)
			} else {
				extensions[ExtVMName] = vmName
			}
		}

		slog.Info("VM registration auth: SA token validated",
			"remote", conn.RemoteAddr().String(),
			"service_account", result.ServiceAccountName,
			"pod_name", result.PodName,
			"vm_name", extensions[ExtVMName],
		)

		return &ssh.Permissions{
			Extensions: extensions,
		}, nil
	}
}

// oidcPasswordCallback authenticates regular SSH users with an OIDC token
// supplied as the SSH password. The token subject becomes both the stable
// identity for quota tracking and the reconnect verifier for retained blips.
func oidcPasswordCallback(verifier OIDCTokenVerifier, limiter *rate.Limiter) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if limiter != nil && !limiter.Allow() {
			return nil, fmt.Errorf("too many OIDC password auth attempts, please try again later")
		}

		token := string(password)
		if token == "" {
			return nil, fmt.Errorf("OIDC password auth requires a token")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		identity, err := verifier.VerifyOIDCToken(ctx, token)
		if err != nil {
			slog.Warn("OIDC password auth: token verification failed",
				"user", conn.User(),
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
			return nil, fmt.Errorf("OIDC token validation failed")
		}
		if identity == nil || identity.Subject == "" {
			return nil, fmt.Errorf("OIDC token has empty subject claim")
		}

		authIdentity := fmt.Sprintf("oidc:%s", identity.Subject)
		slog.Info("OIDC password auth succeeded",
			"user", conn.User(),
			"remote", conn.RemoteAddr().String(),
			"subject", identity.Subject,
			"expiry", identity.Expiry.UTC().Format(time.RFC3339),
		)

		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtFingerprint: authIdentity,
				ExtIdentity:    authIdentity,
			},
		}, nil
	}
}

// registerNoneAuthCallback returns a NoClientAuthCallback that accepts
// none-auth only for _register connections. This allows VMs to connect
// without password auth and pass their SA token via the exec command's
// --token flag, bypassing OpenSSH's 1023-byte password truncation limit.
//
// The token is validated post-connect in the vmcmd handler before any
// keys are registered, so no unauthenticated state changes occur.
func registerNoneAuthCallback() func(ssh.ConnMetadata) (*ssh.Permissions, error) {
	limiter := rate.NewLimiter(20, 40) // 20/s with burst of 40
	return func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
		if conn.User() != "_register" {
			return nil, fmt.Errorf("none auth not supported for user %q", conn.User())
		}
		if !limiter.Allow() {
			return nil, fmt.Errorf("too many registration attempts")
		}
		slog.Debug("none-auth accepted for _register, token will be validated post-connect",
			"remote", conn.RemoteAddr().String(),
		)
		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtIdentity: "vm-register",
			},
		}, nil
	}
}
