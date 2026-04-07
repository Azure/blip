// Package auth implements SSH server authentication for the gateway,
// supporting CA certificate auth, explicit pubkey auth, and GitHub Actions OIDC auth.
package auth

import (
	"bytes"
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

	// ExtBlipVM is "true" when the certificate was issued to a blip VM.
	ExtBlipVM = "auth-blip-vm"
)

// Config holds authentication parameters for building an ssh.ServerConfig.
type Config struct {
	CAPublicKey  ssh.PublicKey
	HostSigner   ssh.Signer
	MaxAuthTries int

	// AuthWatcher provides the dynamic allowed-repos and allowed-pubkeys
	// lists from a ConfigMap. When nil, OIDC and explicit pubkey auth are
	// disabled entirely.
	AuthWatcher *AuthWatcher
}

// NewServerConfig builds an ssh.ServerConfig with auth callbacks from cfg.
func NewServerConfig(cfg Config) *ssh.ServerConfig {
	sshCfg := &ssh.ServerConfig{MaxAuthTries: cfg.MaxAuthTries}
	sshCfg.AddHostKey(cfg.HostSigner)

	sshCfg.PublicKeyCallback = pubkeyCallback(cfg.CAPublicKey, cfg.AuthWatcher)

	if cfg.AuthWatcher != nil {
		sshCfg.PasswordCallback = oidcCallback(cfg.AuthWatcher)
	} else {
		slog.Info("no auth watcher configured, only CA certificate auth is enabled")
	}

	return sshCfg
}

// BlipVMKeyIDPrefix is the certificate KeyId prefix for blip VM identities.
const BlipVMKeyIDPrefix = "blip-vm:"

// IsBlipVMIdentity reports whether the identity belongs to a blip VM.
func IsBlipVMIdentity(identity string) bool {
	return strings.HasPrefix(identity, BlipVMKeyIDPrefix)
}

// pubkeyCallback returns a PublicKeyCallback that accepts:
//  1. Certificates signed by caPublicKey (SSH CA auth).
//  2. Raw public keys whose fingerprint is in the AuthWatcher's allowed set.
func pubkeyCallback(caPublicKey ssh.PublicKey, watcher *AuthWatcher) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	caBytes := caPublicKey.Marshal()
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Try certificate auth first.
		if cert, ok := key.(*ssh.Certificate); ok {
			return verifyCert(conn, cert, caBytes)
		}

		// Fall back to explicit pubkey auth if a watcher is configured.
		if watcher == nil {
			return nil, fmt.Errorf("only certificate authentication is supported")
		}
		return verifyExplicitPubkey(conn, key, watcher)
	}
}

// verifyCert validates an SSH certificate against the CA.
func verifyCert(conn ssh.ConnMetadata, cert *ssh.Certificate, caBytes []byte) (*ssh.Permissions, error) {
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caBytes)
		},
	}

	// Reconnections use a session ID as the SSH user; verify
	// the cert against its first principal instead.
	principal := conn.User()
	if looksLikeSessionID(principal) && len(cert.ValidPrincipals) > 0 {
		principal = cert.ValidPrincipals[0]
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, fmt.Errorf("certificate verification failed: %w", err)
	}
	if !checker.IsUserAuthority(cert.SignatureKey) {
		return nil, fmt.Errorf("certificate verification failed: signed by unrecognized authority")
	}

	fingerprint := ssh.FingerprintSHA256(cert.Key)
	slog.Info("CA certificate auth succeeded",
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"key_id", cert.KeyId,
		"key_fingerprint", fingerprint,
	)
	extensions := map[string]string{
		ExtFingerprint: fingerprint,
		ExtIdentity:    cert.KeyId,
	}
	if IsBlipVMIdentity(cert.KeyId) {
		extensions[ExtBlipVM] = "true"
		slog.Info("blip-vm certificate detected, will resolve root identity",
			"key_id", cert.KeyId,
			"fingerprint", fingerprint,
		)
	}
	return &ssh.Permissions{
		Extensions: extensions,
	}, nil
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
