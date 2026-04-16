package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayauth "github.com/project-unbounded/blip/internal/gateway/auth"

	"github.com/project-unbounded/blip/internal/controllers/sshpubkey"
)

// HTTPSConfig holds the configuration for the HTTPS API server.
type HTTPSConfig struct {
	// Addr is the listen address for the HTTPS server (e.g. ":8443").
	Addr string

	// JWTIssuer is the expected "iss" claim in device-flow pubkey JWTs
	// (typically the gateway's own hostname or URL).
	JWTIssuer string

	// OIDCConfig provides dynamic OIDC configuration from a watched ConfigMap.
	// The verifier, authenticator URL, and TLS certificate are all read from
	// this watcher at request time, allowing runtime reconfiguration.
	OIDCConfig *OIDCConfigWatcher
}

// NewHTTPSServer creates an HTTPS server with:
//   - TLS certificate dynamically provided by the OIDCConfigWatcher
//   - POST /auth/user — OIDC bearer token authentication with dynamic verifier
//
// The OIDC verifier and TLS certificate are read from the OIDCConfigWatcher at
// request time, so configuration changes in the watched ConfigMap take effect
// immediately without a restart.
func NewHTTPSServer(ctx context.Context, cfg HTTPSConfig, kubeWriter client.Client, namespace string) (*http.Server, error) {
	oidcCfg := cfg.OIDCConfig

	mux := http.NewServeMux()
	mux.Handle("POST /auth/user", dynamicAuthHandler(oidcCfg, kubeWriter, namespace, cfg.JWTIssuer))

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: oidcCfg.GetCertificate,
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}

	return srv, nil
}

// dynamicAuthHandler returns a handler for POST /auth/user that reads the
// OIDC verifier, signing key, and authenticator URL from the OIDCConfigWatcher
// at request time. This allows runtime reconfiguration via ConfigMap changes.
//
// The handler:
//  1. Checks that OIDC is configured (returns 503 if not).
//  2. Verifies an OIDC bearer token from the Authorization header.
//  3. Extracts the user ID (subject) and TTL (token expiry) from the token.
//  4. Reads the "pubkey" form value — a JWT issued by the SSH gateway during
//     device-flow auth — verifies it against the TLS signing key, and extracts
//     the SSH public key.
//  5. Creates a session ConfigMap with the public key for the AuthWatcher.
func dynamicAuthHandler(oidcCfg *OIDCConfigWatcher, kubeWriter client.Client, namespace string, jwtIssuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that OIDC auth is configured.
		verifier := oidcCfg.Verifier()
		if verifier == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "OIDC auth not configured")
			return
		}

		idToken, ok := verifyBearerToken(w, r, verifier)
		if !ok {
			return
		}

		// Limit request body to 64 KiB to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		pubkeyJWT := r.FormValue("pubkey")
		if pubkeyJWT == "" {
			writeJSONError(w, http.StatusBadRequest, "missing required form value: pubkey")
			return
		}

		// The pubkey form value is a JWT issued by this gateway during the
		// device-flow auth. Verify its signature against our signing key
		// and check expiration, then extract the SSH public key from claims.
		signer := oidcCfg.GetSigningKey()
		if signer == nil {
			slog.Error("no signing key available to verify pubkey JWT")
			writeJSONError(w, http.StatusInternalServerError, "server signing key unavailable")
			return
		}
		ecPub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			slog.Error("signing key is not ECDSA", "type", fmt.Sprintf("%T", signer.Public()))
			writeJSONError(w, http.StatusInternalServerError, "server signing key has unexpected type")
			return
		}

		claims, err := gatewayauth.VerifyES256(pubkeyJWT, ecPub)
		if err != nil {
			slog.Debug("pubkey JWT verification failed", "error", err)
			writeJSONError(w, http.StatusBadRequest, "invalid pubkey token")
			return
		}

		// Validate issuer and audience claims to prevent token confusion.
		if iss, _ := claims["iss"].(string); iss != jwtIssuer {
			writeJSONError(w, http.StatusBadRequest, "invalid pubkey token issuer")
			return
		}
		// The audience is the authenticator URL, read dynamically.
		jwtAudience := oidcCfg.AuthenticatorURL()
		if aud, _ := claims["aud"].(string); aud != jwtAudience {
			writeJSONError(w, http.StatusBadRequest, "invalid pubkey token audience")
			return
		}

		pubkey, _ := claims["pubkey"].(string)
		if pubkey == "" {
			writeJSONError(w, http.StatusBadRequest, "pubkey token missing pubkey claim")
			return
		}

		// Validate the pubkey is a well-formed SSH public key and cross-check
		// the fingerprint claim against the actual key.
		fingerprint, err := parsePubkeyString(pubkey)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid SSH public key in token: %v", err))
			return
		}
		if fpClaim, _ := claims["fingerprint"].(string); fpClaim != "" && fpClaim != fingerprint {
			writeJSONError(w, http.StatusBadRequest, "pubkey/fingerprint mismatch in token")
			return
		}

		subject := idToken.Subject
		if subject == "" {
			writeJSONError(w, http.StatusUnauthorized, "token has empty subject claim")
			return
		}

		// Use the token's expiry as the session TTL. If the token has no
		// expiry (zero value), reject the request since we need a finite TTL.
		if idToken.Expiry.IsZero() {
			writeJSONError(w, http.StatusBadRequest, "token has no expiry claim")
			return
		}
		expiration := idToken.Expiry

		// Compute ConfigMap name: use generateName for uniqueness.
		// The session controller deduplicates if multiple ConfigMaps
		// exist for the same user.

		// Sanitize subject for use as a Kubernetes label value (max 63 chars,
		// must match [a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?).
		labelValue := sanitizeLabelValue(subject)
		if labelValue == "" {
			slog.Error("OIDC subject produced empty label value", "subject", subject)
			writeJSONError(w, http.StatusBadRequest, "token subject cannot be used as a user identity")
			return
		}

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "session-",
				Namespace:    namespace,
				Labels: map[string]string{
					sshpubkey.LabelUser: labelValue,
				},
				Annotations: map[string]string{
					sshpubkey.AnnotationExpiration: expiration.UTC().Format(time.RFC3339),
					sshpubkey.AnnotationSubject:    subject,
				},
			},
			Data: map[string]string{
				"pubkey": pubkey,
			},
		}

		if err := kubeWriter.Create(r.Context(), cm); err != nil {
			slog.Error("failed to create session configmap", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
			return
		}

		slog.Info("session configmap created",
			"subject", subject,
			"configmap", cm.Name,
			"expiration", expiration.UTC().Format(time.RFC3339),
		)
		writeJSON(w, http.StatusOK, map[string]string{
			"subject":    subject,
			"configmap":  cm.Name,
			"expiration": expiration.UTC().Format(time.RFC3339),
		})
	})
}

// verifyBearerToken extracts and verifies a bearer token from the request.
// On success it returns the verified IDToken. On failure it writes an
// appropriate error response and returns ok=false.
func verifyBearerToken(w http.ResponseWriter, r *http.Request, verifier *oidc.IDTokenVerifier) (idToken *oidc.IDToken, ok bool) {
	token, found := parseBearerToken(r)
	if !found {
		writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return nil, false
	}

	idToken, err := verifier.Verify(r.Context(), token)
	if err != nil {
		slog.Debug("oidc token verification failed", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "invalid token")
		return nil, false
	}

	return idToken, true
}

// parsePubkeyString validates that s is a well-formed SSH public key in
// authorized_keys format. It returns the parsed fingerprint or an error.
func parsePubkeyString(s string) (string, error) {
	line := strings.TrimSpace(s)
	if line == "" {
		return "", fmt.Errorf("empty key")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", fmt.Errorf("parse SSH public key: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}

// sanitizeLabelValue sanitizes a string for use as a Kubernetes label value.
// Label values must be at most 63 characters and match the regex
// [a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])? (or be empty).
func sanitizeLabelValue(s string) string {
	// Replace characters not in [a-zA-Z0-9._-] with underscores.
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	result := b.String()

	// Truncate to 63 characters.
	if len(result) > 63 {
		result = result[:63]
	}

	// Trim leading/trailing non-alphanumeric characters.
	result = strings.TrimLeft(result, "._-")
	result = strings.TrimRight(result, "._-")

	return result
}

// parseBearerToken extracts the token from an "Authorization: Bearer <token>"
// header. The scheme comparison is case-insensitive per RFC 6750.
func parseBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(auth[7:])
	if token == "" {
		return "", false
	}
	return token, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode json response", "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// StartHTTPSServer starts the HTTPS server in the background and returns
// a channel that receives any startup or runtime error.
func StartHTTPSServer(srv *http.Server) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		// Empty cert/key paths: TLSConfig.GetCertificate provides certs.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	return errCh
}

// ShutdownHTTPSServer gracefully shuts down the HTTPS server.
func ShutdownHTTPSServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("https server shutdown error", "error", err)
	}
}

// tlsCertWatcher watches a Kubernetes Secret for TLS certificate updates
// using a controller-runtime cache informer. It caches the parsed
// tls.Certificate for use in tls.Config.GetCertificate.
type tlsCertWatcher struct {
	namespace string
	name      string

	mu   sync.RWMutex
	cert *tls.Certificate // cached parsed certificate; nil until first load
}

// newTLSCertWatcher sets up a watcher on the named Secret using the provided
// controller-runtime cache. It performs an initial load, then registers an
// event handler so that certificate rotations are picked up immediately.
func newTLSCertWatcher(ctx context.Context, informerCache crcache.Cache, namespace, secretName string) (*tlsCertWatcher, error) {
	w := &tlsCertWatcher{
		namespace: namespace,
		name:      secretName,
	}

	// Ensure the cache has an informer for Secrets and wait for it to sync.
	secretInformer, err := informerCache.GetInformer(ctx, &corev1.Secret{})
	if err != nil {
		return nil, fmt.Errorf("get secret informer: %w", err)
	}

	// Try initial load from the cache. The secret may not exist yet when
	// configuration is applied before the TLS secret is created.
	var secret corev1.Secret
	if err := informerCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &secret); err == nil {
		if err := w.parseAndCache(&secret); err != nil {
			slog.Warn("failed to parse tls secret, will retry on update",
				"namespace", namespace, "secret", secretName, "error", err)
		} else {
			slog.Info("tls certificate loaded from secret", "namespace", namespace, "secret", secretName)
		}
	} else {
		slog.Info("tls secret not found, will load when created",
			"namespace", namespace, "secret", secretName)
	}

	// Register an event handler to update the cached cert on changes.
	if _, err := secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handleEvent(obj) },
		UpdateFunc: func(_, newObj interface{}) { w.handleEvent(newObj) },
		DeleteFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok || secret.Name != w.name || secret.Namespace != w.namespace {
				return
			}
			slog.Warn("tls secret deleted, serving stale certificate", "namespace", w.namespace, "secret", w.name)
		},
	}); err != nil {
		return nil, fmt.Errorf("add tls secret event handler: %w", err)
	}

	slog.Info("tls cert watcher started",
		"namespace", namespace,
		"secret", secretName,
	)
	return w, nil
}

// GetCertificate returns the cached TLS certificate for use in tls.Config.
func (w *tlsCertWatcher) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cert == nil {
		return nil, fmt.Errorf("no tls certificate available yet")
	}
	return w.cert, nil
}

// GetSigningKey returns the private key from the cached TLS certificate
// as a crypto.Signer, suitable for signing JWTs.
func (w *tlsCertWatcher) GetSigningKey() crypto.Signer {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cert == nil || w.cert.PrivateKey == nil {
		return nil
	}
	signer, ok := w.cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}
	return signer
}

func (w *tlsCertWatcher) handleEvent(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	if secret.Name != w.name || secret.Namespace != w.namespace {
		return
	}
	if err := w.parseAndCache(secret); err != nil {
		slog.Error("failed to parse updated tls secret", "error", err)
	} else {
		slog.Info("tls certificate updated from secret",
			"namespace", w.namespace,
			"secret", w.name,
		)
	}
}

func (w *tlsCertWatcher) parseAndCache(secret *corev1.Secret) error {
	certPEM, ok := secret.Data["tls.crt"]
	if !ok || len(certPEM) == 0 {
		return fmt.Errorf("secret %s/%s missing tls.crt key", w.namespace, w.name)
	}
	keyPEM, ok := secret.Data["tls.key"]
	if !ok || len(keyPEM) == 0 {
		return fmt.Errorf("secret %s/%s missing tls.key key", w.namespace, w.name)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse tls keypair: %w", err)
	}

	w.mu.Lock()
	w.cert = &cert
	w.mu.Unlock()
	return nil
}
