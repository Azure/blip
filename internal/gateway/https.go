package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayauth "github.com/project-unbounded/blip/internal/gateway/auth"
)

// HTTPSConfig holds the configuration for the HTTPS API server.
type HTTPSConfig struct {
	// Addr is the listen address for the HTTPS server (e.g. ":8443").
	Addr string

	// TLSSecretName is the Kubernetes Secret containing the TLS certificate
	// (key "tls.crt") and private key (key "tls.key"). The secret is watched
	// via the controller-runtime cache so rotations are picked up immediately.
	TLSSecretName string

	// TLSSecretNamespace is the namespace of the TLS secret.
	TLSSecretNamespace string

	// OIDCIssuerURL is the trusted OIDC issuer URL (e.g. "https://accounts.google.com").
	// Only tokens from this issuer are accepted.
	OIDCIssuerURL string

	// OIDCAudience is the expected "aud" claim in the OIDC token.
	OIDCAudience string

	// GitHubAllowedOrgs is a list of GitHub organizations whose repos are
	// allowed to authenticate via the /auth/github endpoint. The org is
	// extracted from the "repository" claim (owner/repo) of the GitHub
	// Actions OIDC token.
	GitHubAllowedOrgs []string

	// JWTIssuer is the expected "iss" claim in device-flow pubkey JWTs
	// (typically the gateway's own hostname or URL).
	JWTIssuer string

	// AuthenticatorURL is the expected "aud" claim in device-flow pubkey
	// JWTs (the URL of the web authenticator).
	AuthenticatorURL string
}

// githubActionsIssuer is the OIDC issuer URL for GitHub Actions tokens.
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// githubActionsAudience is the expected audience for GitHub Actions tokens
// when authenticating to Blip.
const githubActionsAudience = "blip"

// NewHTTPSServer creates an HTTPS server with:
//   - TLS certificate watched from a Kubernetes Secret via controller-runtime cache
//   - POST /auth/user — OIDC bearer token authentication against the configured issuer
//   - POST /auth/github — OIDC bearer token authentication for GitHub Actions tokens
//
// The informerCache must already be started and synced.
func NewHTTPSServer(ctx context.Context, cfg HTTPSConfig, informerCache crcache.Cache, kubeWriter client.Client, namespace string) (*http.Server, *tlsCertWatcher, error) {
	// Start the TLS cert watcher using the shared cache.
	certWatcher, err := newTLSCertWatcher(ctx, informerCache, cfg.TLSSecretNamespace, cfg.TLSSecretName)
	if err != nil {
		return nil, nil, fmt.Errorf("create tls cert watcher: %w", err)
	}

	// Set up the user OIDC provider and verifier.
	userProvider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("create oidc provider for %s: %w", cfg.OIDCIssuerURL, err)
	}
	userVerifier := userProvider.Verifier(&oidc.Config{
		ClientID: cfg.OIDCAudience,
	})

	// Set up the GitHub Actions OIDC provider and verifier.
	ghProvider, err := oidc.NewProvider(ctx, githubActionsIssuer)
	if err != nil {
		return nil, nil, fmt.Errorf("create oidc provider for %s: %w", githubActionsIssuer, err)
	}
	ghVerifier := ghProvider.Verifier(&oidc.Config{
		ClientID: githubActionsAudience,
	})

	mux := http.NewServeMux()
	mux.Handle("POST /auth/user", authHandler(userVerifier, kubeWriter, namespace, certWatcher, cfg.JWTIssuer, cfg.AuthenticatorURL))
	mux.Handle("POST /auth/github", githubAuthHandler(ghVerifier, cfg.GitHubAllowedOrgs, kubeWriter, namespace))

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certWatcher.GetCertificate,
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

	return srv, certWatcher, nil
}

// authHandler returns a handler for POST /auth/user that:
//  1. Verifies an OIDC bearer token from the Authorization header.
//  2. Extracts the user ID (subject) and TTL (token expiry) from the token.
//  3. Reads the "pubkey" form value, which is a JWT originally issued by the
//     SSH gateway during device-flow auth (via GenerateAuthURL). The JWT is
//     verified against the gateway's TLS signing key and checked for expiry.
//     The SSH public key is extracted from the JWT's "pubkey" claim.
//  4. Creates or updates a ConfigMap named "user-<hash>" (8-char truncated
//     SHA-256 of the subject) in the given namespace, storing the public key
//     and labelled with the user identity. The ConfigMap is annotated with an
//     expiration timestamp derived from the token's expiry, so the sshpubkey
//     controller will garbage-collect it after the token expires.
//
// This integrates with the AuthWatcher (which watches ConfigMaps with the
// blip.azure.com/user label) to dynamically authorize SSH connections for
// OIDC-authenticated users.
func authHandler(verifier *oidc.IDTokenVerifier, kubeWriter client.Client, namespace string, signingKeyProvider *tlsCertWatcher, jwtIssuer, jwtAudience string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		signer := signingKeyProvider.GetSigningKey()
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

		// Compute ConfigMap name: user-<first 8 chars of SHA-256 of subject>.
		subjectHash := sha256.Sum256([]byte(subject))
		cmName := "user-" + hex.EncodeToString(subjectHash[:])[:8]

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
				Name:      cmName,
				Namespace: namespace,
				Labels: map[string]string{
					"blip.azure.com/user": labelValue,
				},
				Annotations: map[string]string{
					"blip.azure.com/expiration": expiration.UTC().Format(time.RFC3339),
					"blip.azure.com/subject":    subject,
				},
			},
			Data: map[string]string{
				"pubkey": pubkey,
			},
		}

		// Create or update the ConfigMap. Handle the race where a concurrent
		// request creates the ConfigMap between our Get and Create by falling
		// back to an update on AlreadyExists.
		existing := &corev1.ConfigMap{}
		err = kubeWriter.Get(r.Context(), client.ObjectKey{Namespace: namespace, Name: cmName}, existing)
		if k8serrors.IsNotFound(err) {
			if createErr := kubeWriter.Create(r.Context(), cm); createErr != nil {
				if !k8serrors.IsAlreadyExists(createErr) {
					slog.Error("failed to create user pubkey configmap", "error", createErr, "configmap", cmName)
					writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
					return
				}
				// Lost the race — re-fetch and update.
				if err := kubeWriter.Get(r.Context(), client.ObjectKey{Namespace: namespace, Name: cmName}, existing); err != nil {
					slog.Error("failed to re-fetch user pubkey configmap after conflict", "error", err, "configmap", cmName)
					writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
					return
				}
				existing.Labels = cm.Labels
				existing.Annotations = cm.Annotations
				existing.Data = cm.Data
				if err := kubeWriter.Update(r.Context(), existing); err != nil {
					slog.Error("failed to update user pubkey configmap after conflict", "error", err, "configmap", cmName)
					writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
					return
				}
			}
		} else if err != nil {
			slog.Error("failed to get user pubkey configmap", "error", err, "configmap", cmName)
			writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
			return
		} else {
			existing.Labels = cm.Labels
			existing.Annotations = cm.Annotations
			existing.Data = cm.Data
			if err := kubeWriter.Update(r.Context(), existing); err != nil {
				slog.Error("failed to update user pubkey configmap", "error", err, "configmap", cmName)
				writeJSONError(w, http.StatusInternalServerError, "failed to store public key")
				return
			}
		}

		slog.Info("user pubkey stored",
			"subject", subject,
			"configmap", cmName,
			"expiration", expiration.UTC().Format(time.RFC3339),
		)
		writeJSON(w, http.StatusOK, map[string]string{
			"subject":    subject,
			"configmap":  cmName,
			"expiration": expiration.UTC().Format(time.RFC3339),
		})
	})
}

// githubActionsClaims represents the custom claims in a GitHub Actions OIDC token.
type githubActionsClaims struct {
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
}

// githubAuthHandler returns a handler for POST /auth/github that:
//  1. Reads a "token" form value from the POST body.
//  2. Verifies it as a GitHub Actions OIDC token.
//  3. Checks the repository owner against the allowed orgs list.
//  4. Creates a Kubernetes Secret named "gh-<hash>" (8-char truncated SHA-256
//     of the repository name) in the given namespace, storing the raw token
//     and labelled with the full repository name.
func githubAuthHandler(verifier *oidc.IDTokenVerifier, allowedOrgs []string, kubeWriter client.Client, namespace string) http.Handler {
	// Build a set for fast org lookup.
	orgSet := make(map[string]struct{}, len(allowedOrgs))
	for _, org := range allowedOrgs {
		orgSet[strings.ToLower(strings.TrimSpace(org))] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token == "" {
			writeJSONError(w, http.StatusBadRequest, "missing required form value: token")
			return
		}

		idToken, err := verifier.Verify(r.Context(), token)
		if err != nil {
			slog.Debug("github oidc token verification failed", "error", err)
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		var claims githubActionsClaims
		if err := idToken.Claims(&claims); err != nil {
			slog.Error("failed to extract github token claims", "error", err)
			writeJSONError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		if claims.Repository == "" || claims.RepositoryOwner == "" {
			writeJSONError(w, http.StatusUnauthorized, "token missing repository claims")
			return
		}

		// Authorize against allowed orgs.
		if len(orgSet) > 0 {
			if _, ok := orgSet[strings.ToLower(claims.RepositoryOwner)]; !ok {
				slog.Debug("github auth rejected: org not allowed",
					"owner", claims.RepositoryOwner,
					"repository", claims.Repository,
				)
				writeJSONError(w, http.StatusForbidden, "organization not allowed")
				return
			}
		} else {
			// No allowed orgs configured — reject all requests.
			writeJSONError(w, http.StatusForbidden, "no github organizations configured")
			return
		}

		// Compute secret name: gh-<first 8 chars of SHA-256 of repo name>.
		repoHash := sha256.Sum256([]byte(claims.Repository))
		secretName := "gh-" + hex.EncodeToString(repoHash[:])[:8]

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels: map[string]string{
					"blip.azure.com/repo": strings.ReplaceAll(claims.Repository, "/", "_"),
				},
				Annotations: map[string]string{
					"blip.azure.com/repo": claims.Repository,
				},
			},
			Data: map[string][]byte{
				"token": []byte(token),
			},
		}

		// Create or update the secret.
		existing := &corev1.Secret{}
		err = kubeWriter.Get(r.Context(), client.ObjectKey{Namespace: namespace, Name: secretName}, existing)
		if k8serrors.IsNotFound(err) {
			// Secret doesn't exist, create it.
			if err := kubeWriter.Create(r.Context(), secret); err != nil {
				slog.Error("failed to create github token secret", "error", err, "secret", secretName)
				writeJSONError(w, http.StatusInternalServerError, "failed to store token")
				return
			}
		} else if err != nil {
			slog.Error("failed to get github token secret", "error", err, "secret", secretName)
			writeJSONError(w, http.StatusInternalServerError, "failed to store token")
			return
		} else {
			// Secret exists, update it.
			existing.Data = secret.Data
			existing.Labels = secret.Labels
			existing.Annotations = secret.Annotations
			if err := kubeWriter.Update(r.Context(), existing); err != nil {
				slog.Error("failed to update github token secret", "error", err, "secret", secretName)
				writeJSONError(w, http.StatusInternalServerError, "failed to store token")
				return
			}
		}

		slog.Info("github token stored",
			"repository", claims.Repository,
			"secret", secretName,
		)
		writeJSON(w, http.StatusOK, map[string]string{
			"secret":     secretName,
			"repository": claims.Repository,
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

	// Perform the initial load from the cache. The cache is already synced
	// (WaitForCacheSync was called during vm.Client creation), so this Get
	// reads from the local store.
	var secret corev1.Secret
	if err := informerCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &secret); err != nil {
		return nil, fmt.Errorf("get tls secret %s/%s: %w", namespace, secretName, err)
	}
	if err := w.parseAndCache(&secret); err != nil {
		return nil, fmt.Errorf("parse tls secret %s/%s: %w", namespace, secretName, err)
	}
	slog.Info("tls certificate loaded from secret", "namespace", namespace, "secret", secretName)

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
