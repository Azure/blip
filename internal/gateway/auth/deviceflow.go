package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// AuthSessionLabel marks a Secret as a device-flow auth session.
	AuthSessionLabel = "blip.azure.com/auth-session"

	// AuthSessionFingerprintAnnotation stores the SSH pubkey fingerprint
	// (e.g. "SHA256:...") on an auth session Secret.
	AuthSessionFingerprintAnnotation = "blip.azure.com/fingerprint"

	// AuthSessionSubjectAnnotation stores the authenticated user identity
	// on an auth session Secret, set by the login workflow.
	AuthSessionSubjectAnnotation = "blip.azure.com/subject"

	// AuthSessionPubkeyKey is the data key in the auth session Secret
	// containing the SSH public key in authorized_keys format.
	AuthSessionPubkeyKey = "pubkey"

	// fingerprintIndexKey is the cache index field name for fingerprint lookups.
	fingerprintIndexKey = ".metadata.annotations.blip.azure.com/fingerprint"

	// ExtPendingDeviceAuth is set to "true" in ssh.Permissions when the
	// user authenticated via keyboard-interactive device flow and still
	// needs to complete browser auth. The connection handler must call
	// WaitForAuth before proxying.
	ExtPendingDeviceAuth = "auth-pending-device-auth"

	// ExtDeviceFlowFingerprint stores the pubkey fingerprint for a pending
	// device flow auth, used by the connection handler to call WaitForAuth.
	ExtDeviceFlowFingerprint = "auth-device-flow-fingerprint"
)

// SigningKeyProvider provides the private key used for signing device-flow JWTs.
type SigningKeyProvider interface {
	GetSigningKey() crypto.Signer
}

// AuthSessionWatcher watches Kubernetes Secrets with the auth-session label
// for device-flow authentication sessions. It indexes secrets by pubkey
// fingerprint for O(1) lookups.
type AuthSessionWatcher struct {
	cache     crcache.Cache
	namespace string
}

// NewAuthSessionWatcher creates a watcher for auth session Secrets. It
// registers a field index on the fingerprint annotation for fast lookups.
// The informerCache must already be started and synced.
func NewAuthSessionWatcher(ctx context.Context, informerCache crcache.Cache, namespace string) (*AuthSessionWatcher, error) {
	// Register a field index on the fingerprint annotation so we can do
	// indexed lookups by fingerprint via the cache.
	if err := informerCache.IndexField(ctx, &corev1.Secret{}, fingerprintIndexKey, func(obj client.Object) []string {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}
		// Only index secrets with the auth-session label.
		if secret.Labels[AuthSessionLabel] != "true" {
			return nil
		}
		fp := secret.Annotations[AuthSessionFingerprintAnnotation]
		if fp == "" {
			return nil
		}
		return []string{fp}
	}); err != nil {
		return nil, fmt.Errorf("register auth session fingerprint index: %w", err)
	}

	w := &AuthSessionWatcher{
		cache:     informerCache,
		namespace: namespace,
	}

	slog.Info("auth session watcher started", "namespace", namespace)
	return w, nil
}

// LookupByFingerprint checks if an auth session Secret exists for the given
// pubkey fingerprint. Returns the user subject and true if found.
func (w *AuthSessionWatcher) LookupByFingerprint(ctx context.Context, fingerprint string) (subject string, found bool) {
	var secrets corev1.SecretList
	if err := w.cache.List(ctx, &secrets,
		client.InNamespace(w.namespace),
		client.MatchingFields{fingerprintIndexKey: fingerprint},
	); err != nil {
		slog.Error("auth session watcher: failed to lookup by fingerprint",
			"fingerprint", fingerprint,
			"error", err,
		)
		return "", false
	}
	if len(secrets.Items) == 0 {
		return "", false
	}
	subject = secrets.Items[0].Annotations[AuthSessionSubjectAnnotation]
	return subject, true
}

// WaitForAuth blocks until an auth session Secret matching the given
// fingerprint is created, or until the context is cancelled / timeout expires.
// Returns the user subject from the Secret.
func (w *AuthSessionWatcher) WaitForAuth(ctx context.Context, fingerprint string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Set up notification channel before checking, to avoid the race where
	// a Secret is created between the check and the watch registration.
	notifyCh := make(chan string, 1)

	secretInformer, err := w.cache.GetInformer(ctx, &corev1.Secret{})
	if err != nil {
		return "", fmt.Errorf("get secret informer: %w", err)
	}

	reg, err := secretInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			if secret.Labels[AuthSessionLabel] != "true" {
				return
			}
			if secret.Annotations[AuthSessionFingerprintAnnotation] != fingerprint {
				return
			}
			subject := secret.Annotations[AuthSessionSubjectAnnotation]
			select {
			case notifyCh <- subject:
			default:
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			secret, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			if secret.Labels[AuthSessionLabel] != "true" {
				return
			}
			if secret.Annotations[AuthSessionFingerprintAnnotation] != fingerprint {
				return
			}
			subject := secret.Annotations[AuthSessionSubjectAnnotation]
			select {
			case notifyCh <- subject:
			default:
			}
		},
	})
	if err != nil {
		return "", fmt.Errorf("add auth session event handler: %w", err)
	}
	defer func() {
		if err := secretInformer.RemoveEventHandler(reg); err != nil {
			slog.Warn("failed to remove auth session event handler", "error", err)
		}
	}()

	// Check if a matching secret already exists (after handler registration).
	if subject, found := w.LookupByFingerprint(ctx, fingerprint); found {
		return subject, nil
	}

	// Block until the secret appears or context expires.
	select {
	case subject := <-notifyCh:
		return subject, nil
	case <-ctx.Done():
		return "", fmt.Errorf("device flow auth timed out waiting for browser authentication")
	}
}

// pendingFingerprintEntry holds fingerprint(s) attempted by a connection,
// with a timestamp for TTL-based eviction.
type pendingFingerprintEntry struct {
	fingerprints []string
	createdAt    time.Time
}

// PendingFingerprints tracks pubkey fingerprints from failed auth attempts
// per connection, keyed by RemoteAddr. Used to bridge pubkeyCallback and
// keyboard-interactive callback.
type PendingFingerprints struct {
	mu      sync.Mutex
	entries map[string]*pendingFingerprintEntry
}

// NewPendingFingerprints creates a new tracker with background eviction.
func NewPendingFingerprints(ctx context.Context) *PendingFingerprints {
	pf := &PendingFingerprints{
		entries: make(map[string]*pendingFingerprintEntry),
	}
	go pf.evictLoop(ctx)
	return pf
}

// Add records a fingerprint for the given remote address.
func (pf *PendingFingerprints) Add(remoteAddr, fingerprint string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	entry, ok := pf.entries[remoteAddr]
	if !ok {
		entry = &pendingFingerprintEntry{createdAt: time.Now()}
		pf.entries[remoteAddr] = entry
	}
	// Avoid duplicates (pubkeyCallback fires twice per key: probe + verify).
	for _, fp := range entry.fingerprints {
		if fp == fingerprint {
			return
		}
	}
	entry.fingerprints = append(entry.fingerprints, fingerprint)
}

// Take returns and removes all fingerprints for the given remote address.
func (pf *PendingFingerprints) Take(remoteAddr string) []string {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	entry, ok := pf.entries[remoteAddr]
	if !ok {
		return nil
	}
	delete(pf.entries, remoteAddr)
	return entry.fingerprints
}

// evictLoop periodically removes stale entries (older than 2 minutes).
func (pf *PendingFingerprints) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pf.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Minute)
			for addr, entry := range pf.entries {
				if entry.createdAt.Before(cutoff) {
					delete(pf.entries, addr)
				}
			}
			pf.mu.Unlock()
		}
	}
}

// ecdsaSignature is used by encoding/asn1 to unmarshal DER-encoded ECDSA signatures.
type ecdsaSignature struct {
	R, S *big.Int
}

// jwtHeader is the fixed JWT header for ES256.
var jwtHeader = base64URLEncode([]byte(`{"alg":"ES256","typ":"JWT"}`))

// GenerateAuthURL creates a device-flow authentication URL containing a JWT
// signed with the given EC P-256 private key. The JWT contains the user's
// pubkey fingerprint, issuer, audience, and a 5-minute expiry.
func GenerateAuthURL(authenticatorURL, fingerprint string, signer crypto.Signer, issuer string) (string, error) {
	// Validate the signing key is ECDSA P-256.
	ecKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return "", fmt.Errorf("signing key must be ECDSA P-256, got %T", signer.Public())
	}

	now := time.Now()
	claims := map[string]interface{}{
		"fingerprint": fingerprint,
		"iss":         issuer,
		"aud":         authenticatorURL,
		"iat":         now.Unix(),
		"exp":         now.Add(5 * time.Minute).Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	signingInput := jwtHeader + "." + base64URLEncode(payload)

	// Sign with ES256 (ECDSA P-256 + SHA-256).
	hash := crypto.SHA256.New()
	hash.Write([]byte(signingInput))
	digest := hash.Sum(nil)

	sigBytes, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	// ECDSA signature from crypto.Signer is ASN.1 DER encoded.
	// JWT ES256 requires the raw R||S format (32 bytes each for P-256).
	var parsed ecdsaSignature
	if _, err := asn1.Unmarshal(sigBytes, &parsed); err != nil {
		return "", fmt.Errorf("unmarshal ECDSA signature: %w", err)
	}

	// Pad R and S to 32 bytes each for P-256.
	keyBytes := 32
	rBytes := parsed.R.Bytes()
	sBytes := parsed.S.Bytes()
	rawSig := make([]byte, 2*keyBytes)
	copy(rawSig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(rawSig[2*keyBytes-len(sBytes):], sBytes)

	token := signingInput + "." + base64URLEncode(rawSig)

	u, err := url.Parse(authenticatorURL)
	if err != nil {
		return "", fmt.Errorf("parse authenticator url: %w", err)
	}
	q := u.Query()
	q.Set("u", token)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// base64URLEncode encodes data using base64url without padding.
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// FormatDeviceFlowBanner creates the user-facing banner shown during
// keyboard-interactive auth with the device flow URL.
func FormatDeviceFlowBanner(authURL string) string {
	return fmt.Sprintf("\r\n"+
		"  Authenticate by visiting:\r\n"+
		"\r\n"+
		"    %s\r\n"+
		"\r\n"+
		"  Waiting for browser authentication...\r\n"+
		"\r\n", authURL)
}

// VerifyES256 verifies a JWT token string using the given ECDSA P-256 public key.
// Exported for use by the authenticator to verify incoming tokens.
func VerifyES256(tokenString string, pubKey *ecdsa.PublicKey) (map[string]interface{}, error) {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	sigRaw, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}

	// ES256 signature: 32 bytes R + 32 bytes S for P-256.
	keySize := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(sigRaw) != 2*keySize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sigRaw), 2*keySize)
	}
	r := new(big.Int).SetBytes(sigRaw[:keySize])
	s := new(big.Int).SetBytes(sigRaw[keySize:])

	hash := crypto.SHA256.New()
	hash.Write([]byte(signingInput))
	digest := hash.Sum(nil)

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return nil, fmt.Errorf("JWT signature verification failed")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	// Check expiry (required).
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("JWT missing exp claim")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("JWT expired")
	}

	return claims, nil
}

// base64URLDecode decodes base64url data (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
