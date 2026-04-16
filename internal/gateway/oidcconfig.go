package gateway

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMap data keys for OIDC auth configuration.
const (
	OIDCFieldIssuerURL        = "oidc-issuer-url"
	OIDCFieldAudience         = "oidc-audience"
	OIDCFieldTLSSecretName    = "tls-secret-name"
	OIDCFieldAuthenticatorURL = "authenticator-url"
)

// oidcState holds the resolved OIDC configuration derived from a ConfigMap.
type oidcState struct {
	verifier         *oidc.IDTokenVerifier
	issuerURL        string
	audience         string
	tlsSecretName    string
	authenticatorURL string
}

// OIDCConfigWatcher watches a named ConfigMap for OIDC auth configuration
// and dynamically manages the OIDC token verifier and TLS certificate watcher.
// All methods are safe for concurrent use.
//
// When the ConfigMap data contains valid oidc-issuer-url and oidc-audience
// fields, the watcher performs OIDC discovery and creates a token verifier.
// If tls-secret-name is set, a TLS certificate watcher is started for the
// named Secret.
//
// When the ConfigMap is deleted or the required fields are removed, OIDC
// auth is disabled and API requests return 503.
type OIDCConfigWatcher struct {
	configMapName string
	namespace     string
	informerCache crcache.Cache

	// mu protects state.
	mu    sync.RWMutex
	state *oidcState // nil when no valid config is present

	// tlsMu protects tlsCertWatcher and tlsSecretName.
	tlsMu          sync.RWMutex
	tlsCertWatcher *tlsCertWatcher
	tlsSecretName  string

	// ctx for background operations (OIDC discovery, TLS watcher creation).
	ctx context.Context
}

// NewOIDCConfigWatcher creates a watcher on the named ConfigMap. It performs
// an initial load if the ConfigMap exists, then watches for changes. The
// informerCache must already be started and synced.
func NewOIDCConfigWatcher(ctx context.Context, informerCache crcache.Cache, namespace, configMapName string) (*OIDCConfigWatcher, error) {
	w := &OIDCConfigWatcher{
		configMapName: configMapName,
		namespace:     namespace,
		informerCache: informerCache,
		ctx:           ctx,
	}

	// Get the ConfigMap informer and register event handler.
	cmInformer, err := informerCache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return nil, fmt.Errorf("get configmap informer: %w", err)
	}

	// Try initial load (ConfigMap may not exist yet or may be empty).
	var cm corev1.ConfigMap
	if err := informerCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configMapName}, &cm); err == nil {
		w.reconcile(&cm)
	} else {
		slog.Info("oidc config configmap not found, OIDC auth disabled until created",
			"namespace", namespace,
			"configmap", configMapName,
		)
	}

	if _, err := cmInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handleEvent(obj) },
		UpdateFunc: func(_, newObj interface{}) { w.handleEvent(newObj) },
		DeleteFunc: func(obj interface{}) { w.handleDelete(obj) },
	}); err != nil {
		return nil, fmt.Errorf("add oidc configmap event handler: %w", err)
	}

	slog.Info("oidc config watcher started",
		"namespace", namespace,
		"configmap", configMapName,
	)
	return w, nil
}

func (w *OIDCConfigWatcher) handleEvent(obj interface{}) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != w.configMapName || cm.Namespace != w.namespace {
		return
	}
	w.reconcile(cm)
}

func (w *OIDCConfigWatcher) handleDelete(obj interface{}) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		cm, ok = tombstone.Obj.(*corev1.ConfigMap)
		if !ok {
			return
		}
	}
	if cm.Name != w.configMapName || cm.Namespace != w.namespace {
		return
	}
	w.mu.Lock()
	w.state = nil
	w.mu.Unlock()
	slog.Info("oidc config configmap deleted, OIDC auth disabled",
		"namespace", w.namespace,
		"configmap", w.configMapName,
	)
}

// reconcile reads the ConfigMap data and updates OIDC state. If the issuer
// URL or audience changed, OIDC discovery runs in a background goroutine to
// avoid blocking the informer event loop.
func (w *OIDCConfigWatcher) reconcile(cm *corev1.ConfigMap) {
	issuerURL := cm.Data[OIDCFieldIssuerURL]
	audience := cm.Data[OIDCFieldAudience]
	tlsSecretName := cm.Data[OIDCFieldTLSSecretName]
	authenticatorURL := cm.Data[OIDCFieldAuthenticatorURL]

	if issuerURL == "" || audience == "" {
		w.mu.Lock()
		prev := w.state
		w.state = nil
		w.mu.Unlock()
		if prev != nil {
			slog.Info("oidc config incomplete (missing oidc-issuer-url or oidc-audience), OIDC auth disabled")
		}
		return
	}

	// Check if OIDC config actually changed.
	w.mu.RLock()
	current := w.state
	w.mu.RUnlock()

	oidcChanged := current == nil ||
		current.issuerURL != issuerURL ||
		current.audience != audience

	if !oidcChanged {
		// Only authenticator URL or TLS secret name may have changed.
		needsUpdate := current.authenticatorURL != authenticatorURL ||
			current.tlsSecretName != tlsSecretName
		if needsUpdate {
			w.mu.Lock()
			w.state = &oidcState{
				verifier:         current.verifier,
				issuerURL:        issuerURL,
				audience:         audience,
				tlsSecretName:    tlsSecretName,
				authenticatorURL: authenticatorURL,
			}
			w.mu.Unlock()
			slog.Info("oidc config updated (non-issuer fields)",
				"tls_secret", tlsSecretName,
				"authenticator_url", authenticatorURL,
			)
		}
		if tlsSecretName != "" {
			w.ensureTLSWatcher(tlsSecretName)
		}
		return
	}

	// OIDC issuer/audience changed — run discovery in background.
	go func() {
		slog.Info("oidc config: starting OIDC discovery",
			"issuer_url", issuerURL,
			"audience", audience,
		)
		provider, err := oidc.NewProvider(w.ctx, issuerURL)
		if err != nil {
			slog.Error("oidc config: failed to create OIDC provider",
				"issuer_url", issuerURL,
				"error", err,
			)
			return
		}
		verifier := provider.Verifier(&oidc.Config{
			ClientID: audience,
		})

		w.mu.Lock()
		w.state = &oidcState{
			verifier:         verifier,
			issuerURL:        issuerURL,
			audience:         audience,
			tlsSecretName:    tlsSecretName,
			authenticatorURL: authenticatorURL,
		}
		w.mu.Unlock()

		slog.Info("oidc config updated",
			"issuer_url", issuerURL,
			"audience", audience,
			"tls_secret", tlsSecretName,
			"authenticator_url", authenticatorURL,
		)

		if tlsSecretName != "" {
			w.ensureTLSWatcher(tlsSecretName)
		}
	}()
}

// ensureTLSWatcher creates or replaces the TLS cert watcher when the
// secret name changes.
func (w *OIDCConfigWatcher) ensureTLSWatcher(secretName string) {
	w.tlsMu.Lock()
	defer w.tlsMu.Unlock()
	if w.tlsSecretName == secretName && w.tlsCertWatcher != nil {
		return
	}
	watcher, err := newTLSCertWatcher(w.ctx, w.informerCache, w.namespace, secretName)
	if err != nil {
		slog.Error("oidc config: failed to create tls cert watcher",
			"secret", secretName,
			"error", err,
		)
		return
	}
	w.tlsCertWatcher = watcher
	w.tlsSecretName = secretName
	slog.Info("tls cert watcher updated for oidc config", "secret", secretName)
}

// Verifier returns the current OIDC token verifier, or nil if not configured.
func (w *OIDCConfigWatcher) Verifier() *oidc.IDTokenVerifier {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.state == nil {
		return nil
	}
	return w.state.verifier
}

// AuthenticatorURL returns the current authenticator URL, or "" if not
// configured. This implements auth.DeviceFlowProvider.
func (w *OIDCConfigWatcher) AuthenticatorURL() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.state == nil {
		return ""
	}
	return w.state.authenticatorURL
}

// GetCertificate returns the current TLS certificate for use in tls.Config.
func (w *OIDCConfigWatcher) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.tlsMu.RLock()
	watcher := w.tlsCertWatcher
	w.tlsMu.RUnlock()
	if watcher == nil {
		return nil, fmt.Errorf("no tls certificate configured")
	}
	return watcher.GetCertificate(hello)
}

// GetSigningKey returns the TLS private key as a crypto.Signer, suitable for
// signing device-flow JWTs. This implements auth.DeviceFlowProvider.
func (w *OIDCConfigWatcher) GetSigningKey() crypto.Signer {
	w.tlsMu.RLock()
	watcher := w.tlsCertWatcher
	w.tlsMu.RUnlock()
	if watcher == nil {
		return nil
	}
	return watcher.GetSigningKey()
}

// IsConfigured returns true if OIDC auth is fully configured (verifier ready).
func (w *OIDCConfigWatcher) IsConfigured() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state != nil && w.state.verifier != nil
}
