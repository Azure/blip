// Package auth implements SSH server authentication for the gateway,
// supporting static pubkey auth from ConfigMaps and VM registration
// via Kubernetes ServiceAccount tokens.
package auth

import (
	"context"
	"fmt"
	"log/slog"
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

	// AuthSessionWatcher watches Kubernetes Secrets for device-flow auth
	// sessions. When set, pubkey auth also checks auth session secrets.
	AuthSessionWatcher *AuthSessionWatcher

	// AuthenticatorURL is the URL of the web authenticator for the
	// device-flow. When set (along with AuthSessionWatcher and JWTSigner),
	// users with unrecognized pubkeys are prompted to authenticate via
	// their browser.
	AuthenticatorURL string

	// JWTSigner is the private key used to sign device-flow JWTs.
	JWTSigner SigningKeyProvider

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

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
func NewServerConfig(ctx context.Context, cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	if cfg.AuthWatcher != nil || cfg.VMKeyResolver != nil || cfg.AuthSessionWatcher != nil {
		sshCfg.PublicKeyCallback = pubkeyCallback(cfg.AuthWatcher, cfg.VMKeyResolver, cfg.AuthSessionWatcher, cfg.PendingFingerprints)
	}

	// Enable keyboard-interactive for device-flow auth when configured.
	if cfg.AuthenticatorURL != "" && cfg.AuthSessionWatcher != nil && cfg.JWTSigner != nil && cfg.PendingFingerprints != nil {
		sshCfg.KeyboardInteractiveCallback = deviceFlowKeyboardInteractive(
			cfg.AuthenticatorURL,
			cfg.JWTSigner,
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
	if cfg.TokenReviewer != nil {
		registerLimiter := rate.NewLimiter(20, 40) // 20/s with burst of 40
		sshCfg.PasswordCallback = registerPasswordCallback(cfg.TokenReviewer, registerLimiter)

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

// pubkeyCallback returns a PublicKeyCallback that checks keys in order:
// 1. Explicit allowed pubkeys from ConfigMaps with blip.azure.com/user label.
// 2. Auth session secrets from the device-flow login workflow.
// 3. VM client keys for recursive blip connections.
// When all checks fail and pending is non-nil, the fingerprint is recorded
// for use by the keyboard-interactive device flow callback.
func pubkeyCallback(watcher *AuthWatcher, vmResolver VMKeyResolver, sessionWatcher *AuthSessionWatcher, pending *PendingFingerprints) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fingerprint := ssh.FingerprintSHA256(key)

		// First, try explicit pubkey auth (user keys from ConfigMaps).
		if watcher != nil {
			perm, err := verifyExplicitPubkey(conn, key, watcher)
			if err == nil {
				return perm, nil
			}
		}

		// Second, try auth session secrets (device-flow completed sessions).
		if sessionWatcher != nil {
			if subject, found := sessionWatcher.LookupByFingerprint(context.Background(), fingerprint); found {
				slog.Info("auth session secret auth succeeded",
					"user", conn.User(),
					"remote", conn.RemoteAddr().String(),
					"key_fingerprint", fingerprint,
					"subject", subject,
				)
				return &ssh.Permissions{
					Extensions: map[string]string{
						ExtFingerprint: fingerprint,
						ExtIdentity:    fmt.Sprintf("device:%s", subject),
					},
				}, nil
			}
		}

		// Third, try VM client key auth (for recursive blip connections).
		if vmResolver != nil {
			perm, err := verifyVMClientKey(conn, key, vmResolver)
			if err == nil {
				return perm, nil
			}
		}

		// Record the fingerprint for use by keyboard-interactive fallback.
		if pending != nil {
			pending.Add(conn.RemoteAddr().String(), fingerprint)
		}

		return nil, fmt.Errorf("public key %s is not authorized", fingerprint)
	}
}

// deviceFlowKeyboardInteractive returns a KeyboardInteractiveCallback that
// presents a device-flow authentication URL to the user. It succeeds
// immediately after showing the URL, setting ExtPendingDeviceAuth so the
// connection handler knows to call WaitForAuth before proxying.
func deviceFlowKeyboardInteractive(
	authenticatorURL string,
	signingKeyProvider SigningKeyProvider,
	issuer string,
	pending *PendingFingerprints,
) func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		fingerprints := pending.Take(conn.RemoteAddr().String())
		if len(fingerprints) == 0 {
			return nil, fmt.Errorf("no pubkey was offered before keyboard-interactive")
		}

		// Use the last fingerprint offered (most likely the intended key).
		fingerprint := fingerprints[len(fingerprints)-1]

		signer := signingKeyProvider.GetSigningKey()
		if signer == nil {
			return nil, fmt.Errorf("device flow auth not available: no signing key")
		}

		authURL, err := GenerateAuthURL(authenticatorURL, fingerprint, signer, issuer)
		if err != nil {
			slog.Error("failed to generate device flow auth URL",
				"error", err,
				"fingerprint", fingerprint,
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
			"fingerprint", fingerprint,
		)

		// Return success immediately with a pending flag. The connection
		// handler will call WaitForAuth to block until the browser auth
		// completes.
		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtFingerprint:           fingerprint,
				ExtPendingDeviceAuth:     "true",
				ExtDeviceFlowFingerprint: fingerprint,
			},
		}, nil
	}
}

// verifyExplicitPubkey checks whether a raw public key's fingerprint is in the
// allowed set, and uses the ConfigMap's blip.azure.com/user label value as the
// stable identity.
func verifyExplicitPubkey(conn ssh.ConnMetadata, key ssh.PublicKey, watcher *AuthWatcher) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	if !watcher.IsPubkeyAllowed(fingerprint) {
		return nil, fmt.Errorf("public key %s is not in the allowed list", fingerprint)
	}

	userIdentity := watcher.PubkeyUserIdentity(fingerprint)
	if userIdentity == "" {
		return nil, fmt.Errorf("public key %s has no user identity (empty blip.azure.com/user label)", fingerprint)
	}

	slog.Info("explicit pubkey auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
		"user_identity", userIdentity,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    fmt.Sprintf("pubkey:%s", userIdentity),
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
		if !limiter.Allow() {
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
