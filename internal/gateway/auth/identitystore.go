// Package auth — identitystore.go implements a Kubernetes Secret-backed store
// that links SSH public key fingerprints to OIDC identities via stored refresh
// tokens. This enables "strong" OIDC identity for SSH pubkey authentication:
// when a user authenticates via device flow, their refresh token and SSH public
// key are stored together. On subsequent connections the gateway uses the
// refresh token to verify the OIDC identity is still valid, then grants the
// connection the OIDC identity rather than a weaker pubkey-only identity.
//
// Each OIDC identity gets one Secret named "blip-identity-<hash>" containing:
//   - The refresh token (encrypted at rest by K8s if configured)
//   - A set of linked SSH pubkey fingerprints with last-used timestamps
//   - The OIDC user ID and issuer for traceability
//
// Pubkey links that have not been used within the configurable TTL (default 24h)
// are automatically removed by a background sweep.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// identitySecretPrefix is the name prefix for identity secrets.
	identitySecretPrefix = "blip-identity-"

	// identitySecretLabel marks secrets managed by the identity store.
	identitySecretLabel = "blip.io/identity-secret"

	// DefaultPubkeyLinkTTL is the default time-to-live for a pubkey-to-identity
	// link. If a pubkey has not been used to connect within this duration, the
	// link is automatically removed.
	DefaultPubkeyLinkTTL = 24 * time.Hour

	// sweepInterval controls how often the background goroutine scans for
	// expired pubkey links.
	sweepInterval = 10 * time.Minute
)

// LinkedPubkey records a pubkey linked to an OIDC identity.
type LinkedPubkey struct {
	// Fingerprint is the SSH SHA256 fingerprint (e.g. "SHA256:...").
	Fingerprint string `json:"fingerprint"`

	// AuthorizedKey is the full authorized_keys line for this key.
	AuthorizedKey string `json:"authorized_key"`

	// LastUsed is the last time this pubkey was used to authenticate.
	LastUsed time.Time `json:"last_used"`
}

// IdentityRecord is the JSON structure stored in the Secret's data.
type IdentityRecord struct {
	// OIDCIdentity is the full identity string (e.g. "oidc:alice").
	OIDCIdentity string `json:"oidc_identity"`

	// Issuer is the OIDC issuer URL for traceability.
	Issuer string `json:"issuer"`

	// RefreshToken is the OAuth2 refresh token for re-verifying identity.
	RefreshToken string `json:"refresh_token"`

	// LinkedPubkeys is the set of SSH pubkeys linked to this identity.
	LinkedPubkeys []LinkedPubkey `json:"linked_pubkeys"`

	// CreatedAt is when this identity record was first created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this record was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityLookupResult is returned when a pubkey fingerprint is found in the
// identity store.
type IdentityLookupResult struct {
	// OIDCIdentity is the OIDC identity string (e.g. "oidc:alice").
	OIDCIdentity string

	// Issuer is the OIDC issuer URL.
	Issuer string

	// RefreshToken is the stored OAuth2 refresh token.
	RefreshToken string
}

// IdentityStore manages OIDC identity records in Kubernetes Secrets.
type IdentityStore struct {
	client    kubernetes.Interface
	namespace string
	linkTTL   time.Duration

	// mu protects the in-memory cache.
	mu sync.RWMutex
	// cache maps pubkey fingerprint -> secret name for fast lookup.
	cache map[string]string
}

// NewIdentityStore creates a new IdentityStore backed by Kubernetes Secrets.
// It starts a background goroutine to sweep expired pubkey links. The context
// controls the lifetime of that goroutine.
func NewIdentityStore(ctx context.Context, namespace string, linkTTL time.Duration) (*IdentityStore, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}

	return NewIdentityStoreWithClient(ctx, clientset, namespace, linkTTL)
}

// NewIdentityStoreWithClient creates an IdentityStore with the given K8s
// clientset. Useful for testing with fake clients.
func NewIdentityStoreWithClient(ctx context.Context, client kubernetes.Interface, namespace string, linkTTL time.Duration) (*IdentityStore, error) {
	if linkTTL <= 0 {
		linkTTL = DefaultPubkeyLinkTTL
	}

	s := &IdentityStore{
		client:    client,
		namespace: namespace,
		linkTTL:   linkTTL,
		cache:     make(map[string]string),
	}

	// Build the initial cache from existing secrets.
	if err := s.rebuildCache(ctx); err != nil {
		slog.Warn("identity store: failed to build initial cache, starting empty",
			"error", err,
		)
	}

	// Start the background sweep for expired links.
	go s.sweepLoop(ctx)

	slog.Info("identity store started",
		"namespace", namespace,
		"link_ttl", linkTTL.String(),
		"cached_pubkeys", len(s.cache),
	)

	return s, nil
}

// StoreIdentity creates or updates the identity secret for the given OIDC
// identity, storing the refresh token and optionally linking an SSH pubkey.
func (s *IdentityStore) StoreIdentity(ctx context.Context, identity, issuer, refreshToken, pubkeyFingerprint, authorizedKeyLine string) error {
	secretName := identitySecretName(identity)

	// Try to get existing secret.
	existing, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("get identity secret %s: %w", secretName, err)
	}

	now := time.Now()

	if k8serrors.IsNotFound(err) {
		// Create new secret.
		record := IdentityRecord{
			OIDCIdentity: identity,
			Issuer:       issuer,
			RefreshToken: refreshToken,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		if pubkeyFingerprint != "" {
			record.LinkedPubkeys = []LinkedPubkey{{
				Fingerprint:   pubkeyFingerprint,
				AuthorizedKey: authorizedKeyLine,
				LastUsed:      now,
			}}
		}

		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal identity record: %w", err)
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: s.namespace,
				Labels: map[string]string{
					identitySecretLabel: "true",
				},
			},
			Data: map[string][]byte{
				"identity": data,
			},
		}

		if _, err := s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create identity secret %s: %w", secretName, err)
		}

		// Update cache.
		if pubkeyFingerprint != "" {
			s.mu.Lock()
			s.cache[pubkeyFingerprint] = secretName
			s.mu.Unlock()
		}

		slog.Info("identity stored",
			"secret", secretName,
			"identity", identity,
			"pubkey_linked", pubkeyFingerprint != "",
		)
		return nil
	}

	// Update existing secret.
	record, err := parseIdentityRecord(existing)
	if err != nil {
		return fmt.Errorf("parse existing identity record: %w", err)
	}

	// Always update the refresh token (it may have been rotated).
	record.RefreshToken = refreshToken
	record.Issuer = issuer
	record.UpdatedAt = now

	// Link the pubkey if provided and not already linked.
	if pubkeyFingerprint != "" {
		found := false
		for i, lp := range record.LinkedPubkeys {
			if lp.Fingerprint == pubkeyFingerprint {
				record.LinkedPubkeys[i].LastUsed = now
				record.LinkedPubkeys[i].AuthorizedKey = authorizedKeyLine
				found = true
				break
			}
		}
		if !found {
			record.LinkedPubkeys = append(record.LinkedPubkeys, LinkedPubkey{
				Fingerprint:   pubkeyFingerprint,
				AuthorizedKey: authorizedKeyLine,
				LastUsed:      now,
			})
		}
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal identity record: %w", err)
	}

	existing.Data["identity"] = data
	if _, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update identity secret %s: %w", secretName, err)
	}

	// Update cache.
	if pubkeyFingerprint != "" {
		s.mu.Lock()
		s.cache[pubkeyFingerprint] = secretName
		s.mu.Unlock()
	}

	slog.Info("identity updated",
		"secret", secretName,
		"identity", identity,
		"pubkey_linked", pubkeyFingerprint != "",
		"total_linked_pubkeys", len(record.LinkedPubkeys),
	)
	return nil
}

// LookupByPubkey looks up an OIDC identity linked to the given SSH pubkey
// fingerprint. Returns nil if the fingerprint is not linked to any identity.
func (s *IdentityStore) LookupByPubkey(ctx context.Context, fingerprint string) (*IdentityLookupResult, error) {
	s.mu.RLock()
	secretName, ok := s.cache[fingerprint]
	s.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Secret was deleted — evict from cache.
			s.mu.Lock()
			delete(s.cache, fingerprint)
			s.mu.Unlock()
			return nil, nil
		}
		return nil, fmt.Errorf("get identity secret %s: %w", secretName, err)
	}

	record, err := parseIdentityRecord(secret)
	if err != nil {
		return nil, fmt.Errorf("parse identity record from %s: %w", secretName, err)
	}

	// Verify the fingerprint is still linked and not expired.
	for _, lp := range record.LinkedPubkeys {
		if lp.Fingerprint == fingerprint {
			if time.Since(lp.LastUsed) > s.linkTTL {
				// Link expired — don't use it.
				slog.Info("identity store: pubkey link expired",
					"fingerprint", fingerprint,
					"identity", record.OIDCIdentity,
					"last_used", lp.LastUsed.Format(time.RFC3339),
					"ttl", s.linkTTL.String(),
				)
				return nil, nil
			}

			return &IdentityLookupResult{
				OIDCIdentity: record.OIDCIdentity,
				Issuer:       record.Issuer,
				RefreshToken: record.RefreshToken,
			}, nil
		}
	}

	// Fingerprint not found in record — evict from cache.
	s.mu.Lock()
	delete(s.cache, fingerprint)
	s.mu.Unlock()
	return nil, nil
}

// TouchPubkey updates the last-used timestamp for a pubkey link. Called on
// successful authentication to keep the link alive.
func (s *IdentityStore) TouchPubkey(ctx context.Context, fingerprint string) error {
	s.mu.RLock()
	secretName, ok := s.cache[fingerprint]
	s.mu.RUnlock()

	if !ok {
		return nil
	}

	// Retry on conflict.
	for attempt := 0; attempt < 3; attempt++ {
		secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("get identity secret %s: %w", secretName, err)
		}

		record, err := parseIdentityRecord(secret)
		if err != nil {
			return fmt.Errorf("parse identity record: %w", err)
		}

		found := false
		for i, lp := range record.LinkedPubkeys {
			if lp.Fingerprint == fingerprint {
				record.LinkedPubkeys[i].LastUsed = time.Now()
				found = true
				break
			}
		}
		if !found {
			return nil
		}

		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal identity record: %w", err)
		}
		secret.Data["identity"] = data

		_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if !k8serrors.IsConflict(err) {
			return fmt.Errorf("update identity secret %s: %w", secretName, err)
		}
		slog.Debug("identity store: conflict updating last-used, retrying",
			"attempt", attempt+1,
			"secret", secretName,
		)
	}

	return fmt.Errorf("failed to update last-used after 3 retries")
}

// UpdateRefreshToken replaces the stored refresh token for an identity.
// Called when a refresh token is rotated during a token refresh.
func (s *IdentityStore) UpdateRefreshToken(ctx context.Context, identity, newRefreshToken string) error {
	secretName := identitySecretName(identity)

	for attempt := 0; attempt < 3; attempt++ {
		secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return nil // Secret was already deleted, nothing to update.
			}
			return fmt.Errorf("get identity secret %s: %w", secretName, err)
		}

		record, err := parseIdentityRecord(secret)
		if err != nil {
			return fmt.Errorf("parse identity record: %w", err)
		}

		record.RefreshToken = newRefreshToken
		record.UpdatedAt = time.Now()

		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal identity record: %w", err)
		}
		secret.Data["identity"] = data

		_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if !k8serrors.IsConflict(err) {
			return fmt.Errorf("update identity secret %s: %w", secretName, err)
		}
	}

	return fmt.Errorf("failed to update refresh token after 3 retries")
}

// sweepLoop periodically removes expired pubkey links and empty identity secrets.
func (s *IdentityStore) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.sweepExpiredLinks(ctx); err != nil {
				slog.Warn("identity store: sweep failed", "error", err)
			}
		}
	}
}

// sweepExpiredLinks scans all identity secrets and removes pubkey links
// that haven't been used within the TTL. Secrets with no remaining links
// are deleted.
func (s *IdentityStore) sweepExpiredLinks(ctx context.Context) error {
	secrets, err := s.client.CoreV1().Secrets(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: identitySecretLabel + "=true",
	})
	if err != nil {
		return fmt.Errorf("list identity secrets: %w", err)
	}

	now := time.Now()
	var removedLinks, deletedSecrets int

	for i := range secrets.Items {
		secret := &secrets.Items[i]
		record, err := parseIdentityRecord(secret)
		if err != nil {
			slog.Warn("identity store: sweep: failed to parse secret, skipping",
				"secret", secret.Name,
				"error", err,
			)
			continue
		}

		// Filter out expired links.
		var active []LinkedPubkey
		for _, lp := range record.LinkedPubkeys {
			if now.Sub(lp.LastUsed) > s.linkTTL {
				slog.Info("identity store: de-linking expired pubkey",
					"fingerprint", lp.Fingerprint,
					"identity", record.OIDCIdentity,
					"last_used", lp.LastUsed.Format(time.RFC3339),
				)
				// Evict from cache.
				s.mu.Lock()
				delete(s.cache, lp.Fingerprint)
				s.mu.Unlock()
				removedLinks++
			} else {
				active = append(active, lp)
			}
		}

		if len(active) == len(record.LinkedPubkeys) {
			// No changes needed.
			continue
		}

		if len(active) == 0 {
			// No linked pubkeys remain — delete the secret entirely.
			// The refresh token is no longer useful without any linked keys.
			if err := s.client.CoreV1().Secrets(s.namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
				slog.Warn("identity store: sweep: failed to delete empty secret",
					"secret", secret.Name,
					"error", err,
				)
			} else {
				slog.Info("identity store: deleted secret with no linked pubkeys",
					"secret", secret.Name,
					"identity", record.OIDCIdentity,
				)
				deletedSecrets++
			}
			continue
		}

		// Update the secret with remaining links.
		record.LinkedPubkeys = active
		record.UpdatedAt = now
		data, err := json.Marshal(record)
		if err != nil {
			slog.Warn("identity store: sweep: failed to marshal record",
				"secret", secret.Name,
				"error", err,
			)
			continue
		}
		secret.Data["identity"] = data
		if _, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			slog.Warn("identity store: sweep: failed to update secret",
				"secret", secret.Name,
				"error", err,
			)
		}
	}

	if removedLinks > 0 || deletedSecrets > 0 {
		slog.Info("identity store: sweep completed",
			"removed_links", removedLinks,
			"deleted_secrets", deletedSecrets,
		)
	}

	return nil
}

// rebuildCache scans all identity secrets and rebuilds the in-memory
// fingerprint -> secret name cache.
func (s *IdentityStore) rebuildCache(ctx context.Context) error {
	secrets, err := s.client.CoreV1().Secrets(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: identitySecretLabel + "=true",
	})
	if err != nil {
		return fmt.Errorf("list identity secrets: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache = make(map[string]string)
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		record, err := parseIdentityRecord(secret)
		if err != nil {
			slog.Warn("identity store: rebuild cache: failed to parse secret",
				"secret", secret.Name,
				"error", err,
			)
			continue
		}
		for _, lp := range record.LinkedPubkeys {
			if time.Since(lp.LastUsed) <= s.linkTTL {
				s.cache[lp.Fingerprint] = secret.Name
			}
		}
	}

	return nil
}

// RefreshOIDCToken uses the stored refresh token to obtain a new access token
// from the OIDC provider's token endpoint. This verifies the OIDC identity is
// still valid. Returns the new identity, new refresh token (if rotated), and
// a fingerprint of the new access token.
//
// The providerConfigs are consulted to find the matching issuer for the token
// endpoint URL and client ID.
func RefreshOIDCToken(ctx context.Context, issuer, refreshToken string, providers []OIDCProviderConfig) (identity, newRefreshToken, tokenFingerprint string, err error) {
	// Find the matching provider config for this issuer.
	var cfg *OIDCProviderConfig
	for i, p := range providers {
		if p.Issuer == issuer && p.DeviceFlow {
			cfg = &providers[i]
			break
		}
	}
	if cfg == nil {
		return "", "", "", fmt.Errorf("no device-flow provider configured for issuer %s", issuer)
	}

	// Use the token endpoint to exchange the refresh token.
	tokenResp, newRT, err := exchangeRefreshToken(ctx, *cfg, refreshToken)
	if err != nil {
		return "", "", "", fmt.Errorf("refresh token exchange: %w", err)
	}

	fp := TokenFingerprint(tokenResp.AccessToken)

	// Resolve the user identity from the refreshed token.
	if isGitHubDeviceFlow(*cfg) {
		identity, err = resolveGitHubIdentity(ctx, tokenResp.AccessToken)
		if err != nil {
			return "", "", "", fmt.Errorf("resolve GitHub identity from refreshed token: %w", err)
		}
		// Check allowlist.
		rawIdentity := strings.TrimPrefix(identity, "oidc:")
		if err := checkSubjectAllowed(rawIdentity, cfg.AllowedSubjects); err != nil {
			return "", "", "", fmt.Errorf("GitHub identity check: %w", err)
		}
	} else {
		tokenToVerify := tokenResp.IDToken
		if tokenToVerify == "" {
			tokenToVerify = tokenResp.AccessToken
		}
		identity, err = verifyTokenAgainstProvider(tokenToVerify, *cfg)
		if err != nil {
			return "", "", "", fmt.Errorf("verify refreshed token: %w", err)
		}
	}

	// Use the new refresh token if one was issued (token rotation),
	// otherwise keep the existing one.
	if newRT == "" {
		newRT = refreshToken
	}

	return identity, newRT, fp, nil
}

// exchangeRefreshToken performs the OAuth2 refresh token grant.
func exchangeRefreshToken(ctx context.Context, cfg OIDCProviderConfig, refreshToken string) (*DeviceTokenResponse, string, error) {
	form := url.Values{
		"client_id":     {cfg.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := deviceFlowHTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("refresh token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, "", fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("refresh token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the token response. The refresh token response uses the same
	// format as the device flow token response.
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		IDToken      string `json:"id_token"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, "", fmt.Errorf("parse refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, "", fmt.Errorf("refresh response missing access_token")
	}

	return &DeviceTokenResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		IDToken:     tokenResp.IDToken,
		Scope:       tokenResp.Scope,
	}, tokenResp.RefreshToken, nil
}

// identitySecretName computes a deterministic secret name from an OIDC identity.
func identitySecretName(identity string) string {
	h := sha256.Sum256([]byte(identity))
	return identitySecretPrefix + hex.EncodeToString(h[:12])
}

// parseIdentityRecord extracts and parses the IdentityRecord from a Secret.
func parseIdentityRecord(secret *corev1.Secret) (*IdentityRecord, error) {
	data, ok := secret.Data["identity"]
	if !ok {
		return nil, fmt.Errorf("secret %s missing 'identity' key", secret.Name)
	}
	var record IdentityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("unmarshal identity record from %s: %w", secret.Name, err)
	}
	return &record, nil
}
