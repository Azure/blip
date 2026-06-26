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
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
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

// DeviceFlowProvider supplies the runtime configuration for device-flow
// authentication. Implementations must be safe for concurrent use. The
// OIDCConfigWatcher in the gateway package satisfies this interface.
type DeviceFlowProvider interface {
	SigningKeyProvider
	// AuthenticatorURL returns the current web authenticator URL. An empty
	// string means device-flow auth is currently disabled.
	AuthenticatorURL() string
}

// pendingKey holds a fingerprint and the corresponding authorized_keys-format
// public key string from a failed auth attempt.
type pendingKey struct {
	fingerprint string
	pubkey      string // authorized_keys format (e.g. "ssh-ed25519 AAAA...")
}

// pendingFingerprintEntry holds fingerprint(s) attempted by a connection,
// with a timestamp for TTL-based eviction.
type pendingFingerprintEntry struct {
	keys      []pendingKey
	createdAt time.Time
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

// Add records a fingerprint and its corresponding authorized_keys-format
// public key for the given remote address.
func (pf *PendingFingerprints) Add(remoteAddr, fingerprint, pubkey string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	entry, ok := pf.entries[remoteAddr]
	if !ok {
		entry = &pendingFingerprintEntry{createdAt: time.Now()}
		pf.entries[remoteAddr] = entry
	}
	// Avoid duplicates (pubkeyCallback fires twice per key: probe + verify).
	for _, k := range entry.keys {
		if k.fingerprint == fingerprint {
			return
		}
	}
	entry.keys = append(entry.keys, pendingKey{fingerprint: fingerprint, pubkey: pubkey})
}

// Take returns and removes all pending keys for the given remote address.
func (pf *PendingFingerprints) Take(remoteAddr string) []pendingKey {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	entry, ok := pf.entries[remoteAddr]
	if !ok {
		return nil
	}
	delete(pf.entries, remoteAddr)
	return entry.keys
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
// pubkey fingerprint, the full SSH public key in authorized_keys format,
// issuer, audience, and a 5-minute expiry.
func GenerateAuthURL(authenticatorURL, fingerprint, pubkey string, signer crypto.Signer, issuer string) (string, error) {
	// Validate the signing key is ECDSA P-256.
	ecKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return "", fmt.Errorf("signing key must be ECDSA P-256, got %T", signer.Public())
	}

	now := time.Now()
	claims := map[string]interface{}{
		"fingerprint": fingerprint,
		"pubkey":      pubkey,
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

	// Validate the JWT header specifies ES256.
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal JWT header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
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

	// Check expiry (required). Allow 30 seconds of clock skew.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("JWT missing exp claim")
	}
	const clockSkewSeconds = 30
	if time.Now().Unix() > int64(exp)+clockSkewSeconds {
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
