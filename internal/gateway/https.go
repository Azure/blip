package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
}

// NewHTTPSServer creates an HTTPS server with:
//   - TLS certificate watched from a Kubernetes Secret via controller-runtime cache
//   - OIDC bearer token authentication against a single trusted issuer
//   - A stub handler that returns 200 OK
//
// The informerCache must already be started and synced.
func NewHTTPSServer(ctx context.Context, cfg HTTPSConfig, informerCache crcache.Cache) (*http.Server, error) {
	// Start the TLS cert watcher using the shared cache.
	certWatcher, err := newTLSCertWatcher(ctx, informerCache, cfg.TLSSecretNamespace, cfg.TLSSecretName)
	if err != nil {
		return nil, fmt.Errorf("create tls cert watcher: %w", err)
	}

	// Set up the OIDC provider and verifier. The provider fetches the
	// issuer's discovery document and JWKS keys (cached internally).
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("create oidc provider for %s: %w", cfg.OIDCIssuerURL, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.OIDCAudience,
	})

	mux := http.NewServeMux()
	mux.Handle("/", oidcAuthMiddleware(verifier, stubHandler()))

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

	return srv, nil
}

// oidcAuthMiddleware validates the Authorization: Bearer <token> header
// against the provided OIDC verifier. On success, the request is passed
// to the next handler. On failure, a 401 response is returned.
func oidcAuthMiddleware(verifier *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := parseBearerToken(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}

		idToken, err := verifier.Verify(r.Context(), token)
		if err != nil {
			slog.Debug("oidc token verification failed", "error", err)
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Stash the verified token subject in the request context for
		// downstream handlers to use.
		ctx := context.WithValue(r.Context(), oidcSubjectKey{}, idToken.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// stubHandler returns a placeholder handler. This will be replaced with
// real API routes.
func stubHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})
}

// oidcSubjectKey is the context key for the verified OIDC subject.
type oidcSubjectKey struct{}

// OIDCSubject extracts the verified OIDC subject from the request context.
// Returns empty string if not present.
func OIDCSubject(ctx context.Context) string {
	v, _ := ctx.Value(oidcSubjectKey{}).(string)
	return v
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

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
