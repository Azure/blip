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
)

// Config holds authentication parameters for building an ssh.ServerConfig.
type Config struct {
	HostSigner   ssh.Signer
	MaxAuthTries int

	// AuthWatcher provides the dynamic allowed-repos and allowed-pubkeys
	// lists from a ConfigMap.
	AuthWatcher *AuthWatcher
}

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
func NewServerConfig(cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	if cfg.AuthWatcher != nil {
		sshCfg.PublicKeyCallback = pubkeyCallback(cfg.AuthWatcher)
		sshCfg.PasswordCallback = oidcCallback(cfg.AuthWatcher)
	} else {
		slog.Warn("no auth watcher configured, all authentication is disabled")
	}

	return sshCfg
}

// pubkeyCallback returns a PublicKeyCallback that accepts raw public keys
// whose fingerprint is in the AuthWatcher's allowed set.
func pubkeyCallback(watcher *AuthWatcher) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return verifyExplicitPubkey(conn, key, watcher)
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

// looksLikeSessionID reports whether user matches the blip session ID format.
func looksLikeSessionID(user string) bool {
	const prefix = "blip-"
	if !strings.HasPrefix(user, prefix) {
		return false
	}
	suffix := user[len(prefix):]
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
