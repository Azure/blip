// Package auth implements SSH server authentication for the gateway,
// supporting explicit pubkey auth and GitHub Actions OIDC auth.
package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/ssh"
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

	// AuthWatcher provides the dynamic allowed-repos and allowed-pubkeys
	// lists from a ConfigMap.
	AuthWatcher *AuthWatcher

	// VMKeyResolver resolves a VM client key fingerprint to the root user
	// identity of the session that owns the VM. This is used for recursive
	// blip connections where VMs SSH back to the gateway.
	VMKeyResolver VMKeyResolver
}

// VMKeyResolver resolves a VM SSH client key fingerprint to the original
// user identity of the session that owns the VM.
type VMKeyResolver interface {
	ResolveRootIdentity(fingerprint string) (identity string, err error)
}

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
func NewServerConfig(cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	if cfg.AuthWatcher != nil || cfg.VMKeyResolver != nil {
		sshCfg.PublicKeyCallback = pubkeyCallback(cfg.AuthWatcher, cfg.VMKeyResolver)
	}

	if cfg.AuthWatcher != nil {
		sshCfg.PasswordCallback = oidcCallback(cfg.AuthWatcher)
	}

	if cfg.AuthWatcher == nil && cfg.VMKeyResolver == nil {
		slog.Warn("no auth watcher configured, all authentication is disabled")
	}

	return sshCfg
}

// pubkeyCallback returns a PublicKeyCallback that first checks against the
// AuthWatcher's explicit allowed set, and then falls back to checking if the
// key belongs to a VM for recursive blip connections.
func pubkeyCallback(watcher *AuthWatcher, vmResolver VMKeyResolver) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// First, try explicit pubkey auth (user keys in ConfigMap).
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

		return nil, fmt.Errorf("public key %s is not authorized", ssh.FingerprintSHA256(key))
	}
}

// verifyExplicitPubkey checks whether a raw public key's fingerprint is in the
// allowed set.
func verifyExplicitPubkey(conn ssh.ConnMetadata, key ssh.PublicKey, watcher *AuthWatcher) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	if !watcher.IsPubkeyAllowed(fingerprint) {
		return nil, fmt.Errorf("public key %s is not in the allowed list", fingerprint)
	}

	slog.Info("explicit pubkey auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    fmt.Sprintf("pubkey:%s", fingerprint),
		},
	}, nil
}

// verifyVMClientKey checks whether the key belongs to a VM by looking up its
// fingerprint in the VM annotations. If found, it resolves the root user
// identity for the session that owns the VM. This enables identity propagation
// for recursive blip connections.
func verifyVMClientKey(conn ssh.ConnMetadata, key ssh.PublicKey, resolver VMKeyResolver) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	identity, err := resolver.ResolveRootIdentity(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("VM client key lookup failed for %s: %w", fingerprint, err)
	}

	slog.Info("blip client key auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_fingerprint", fingerprint,
		"resolved_identity", identity,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtFingerprint: fingerprint,
			ExtIdentity:    identity,
			ExtIsVMClient:  "true",
		},
	}, nil
}

// oidcCallback returns a PasswordCallback that validates GitHub Actions OIDC tokens.
// The watcher is consulted on every auth attempt, so ConfigMap changes take
// effect without restarting the gateway.
func oidcCallback(watcher *AuthWatcher) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		token := string(password)
		allowedRepos := watcher.AllowedRepos()
		identity, err := verifyGitHubActionsToken(token, allowedRepos)
		if err != nil {
			slog.Warn("GitHub Actions OIDC auth failed",
				"user", conn.User(),
				"remote", conn.RemoteAddr().String(),
				"error", err,
			)
			return nil, fmt.Errorf("GitHub Actions authentication failed")
		}

		slog.Info("GitHub Actions OIDC auth succeeded",
			"user", conn.User(),
			"remote", conn.RemoteAddr().String(),
			"identity", identity,
		)

		h := sha256.Sum256([]byte(token))
		fingerprint := fmt.Sprintf("SHA256:%x", h)
		return &ssh.Permissions{
			Extensions: map[string]string{
				ExtFingerprint: fingerprint,
				ExtIdentity:    identity,
			},
		}, nil
	}
}

const (
	ghActionsIssuer   = "https://token.actions.githubusercontent.com"
	ghActionsAudience = "blip"
)

var (
	cachedProvider     *oidc.Provider
	cachedProviderOnce sync.Once
)

func getOIDCProvider() (*oidc.Provider, error) {
	var initErr error
	cachedProviderOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cachedProvider, initErr = oidc.NewProvider(ctx, ghActionsIssuer)
	})
	if initErr != nil {
		return nil, fmt.Errorf("GitHub Actions OIDC provider: %w", initErr)
	}
	return cachedProvider, nil
}

// verifyGitHubActionsToken validates a GitHub Actions OIDC token against the allowed repos.
func verifyGitHubActionsToken(token string, allowedRepos []string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}

	provider, err := getOIDCProvider()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	verifier := provider.Verifier(&oidc.Config{
		ClientID: ghActionsAudience,
	})

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return "", fmt.Errorf("token validation: %w", err)
	}

	var claims struct {
		Repository string `json:"repository"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("extract claims: %w", err)
	}

	if claims.Repository == "" {
		return "", fmt.Errorf("token missing repository claim")
	}

	if err := checkRepoAllowed(claims.Repository, allowedRepos); err != nil {
		return "", err
	}

	return fmt.Sprintf("oidc:%s", idToken.Subject), nil
}

// checkRepoAllowed verifies that repo is in the allowedRepos list.
func checkRepoAllowed(repo string, allowedRepos []string) error {
	if len(allowedRepos) == 0 {
		return nil
	}
	for _, allowed := range allowedRepos {
		if strings.EqualFold(repo, allowed) {
			return nil
		}
	}
	return fmt.Errorf("repository %q is not in the allowed list", repo)
}
