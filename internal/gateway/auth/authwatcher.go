package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMap key names inside the unified auth ConfigMap.
const (
	// KeyOIDCProviders holds the OIDC provider configuration as a YAML list.
	// Each entry specifies an issuer, audience, identity claim, and optional
	// subject allowlist.
	KeyOIDCProviders = "oidc-providers"

	// KeyAllowedPubkeys holds explicitly allowed SSH public keys
	// (one key per line in authorized_keys format).
	KeyAllowedPubkeys = "allowed-pubkeys"
)

// AuthWatcher watches a ConfigMap for OIDC provider configuration and
// explicitly allowed SSH public keys, providing thread-safe access
// to the current sets.
type AuthWatcher struct {
	cache     crcache.Cache
	namespace string
	name      string

	// k8sClient is used for writing pubkey bindings back to the ConfigMap.
	// Created once during initialization to avoid per-request overhead.
	k8sClient kubernetes.Interface

	mu            sync.RWMutex
	oidcProviders []OIDCProviderConfig
	pubkeys       map[string]string // SHA256 fingerprint -> comment (username)
}

// NewAuthWatcher creates an AuthWatcher that watches the named ConfigMap.
// It starts the informer cache, waits for the initial sync, loads the current
// value, and installs an event handler that keeps the in-memory data updated.
func NewAuthWatcher(ctx context.Context, namespace, configMapName string) (*AuthWatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register core/v1: %w", err)
	}

	mapper := newCoreRESTMapper()

	informerCache, err := crcache.New(cfg, crcache.Options{
		Scheme: s,
		Mapper: mapper,
		DefaultNamespaces: map[string]crcache.Config{
			namespace: {},
		},
		DefaultTransform: crcache.TransformStripManagedFields(),
	})
	if err != nil {
		return nil, fmt.Errorf("create configmap informer cache: %w", err)
	}

	// Create a Kubernetes clientset for writing pubkey bindings.
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}

	w := &AuthWatcher{
		cache:     informerCache,
		namespace: namespace,
		name:      configMapName,
		k8sClient: clientset,
		pubkeys:   make(map[string]string),
	}

	go func() {
		if err := informerCache.Start(ctx); err != nil {
			slog.Error("auth watcher informer cache stopped", "error", err)
		}
	}()

	if !informerCache.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("auth watcher cache sync failed")
	}

	// Load the initial value.
	w.reload(ctx)

	// Install an event handler so future updates are picked up automatically.
	informer, err := informerCache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return nil, fmt.Errorf("get configmap informer: %w", err)
	}

	reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { w.reload(ctx) },
		UpdateFunc: func(_, _ interface{}) { w.reload(ctx) },
		DeleteFunc: func(_ interface{}) { w.reload(ctx) },
	})
	if err != nil {
		return nil, fmt.Errorf("add configmap event handler: %w", err)
	}
	_ = reg // registration handle; lives as long as the informer

	slog.Info("auth watcher started",
		"namespace", namespace,
		"configmap", configMapName,
		"initial_oidc_providers", len(w.OIDCProviders()),
		"initial_pubkey_count", w.allowedPubkeyCount(),
	)

	return w, nil
}

// OIDCProviders returns a copy of the current OIDC provider configurations.
func (w *AuthWatcher) OIDCProviders() []OIDCProviderConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]OIDCProviderConfig, len(w.oidcProviders))
	copy(result, w.oidcProviders)
	return result
}

// IsPubkeyAllowed reports whether the given fingerprint (e.g. "SHA256:...")
// is in the current allowed set.
func (w *AuthWatcher) IsPubkeyAllowed(fingerprint string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.pubkeys[fingerprint]
	return ok
}

// PubkeyUsername returns the comment (username) associated with the given
// fingerprint, or "" if the fingerprint is not in the allowed set.
func (w *AuthWatcher) PubkeyUsername(fingerprint string) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pubkeys[fingerprint]
}

// allowedPubkeyCount returns the number of allowed pubkeys for logging.
func (w *AuthWatcher) allowedPubkeyCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.pubkeys)
}

// DeviceFlowProviders returns the subset of OIDC providers that have device
// flow enabled. Returns nil if none are configured.
func (w *AuthWatcher) DeviceFlowProviders() []OIDCProviderConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var result []OIDCProviderConfig
	for _, p := range w.oidcProviders {
		if p.DeviceFlow {
			result = append(result, p)
		}
	}
	return result
}

// HasDeviceFlowProviders reports whether any OIDC provider has device flow enabled.
func (w *AuthWatcher) HasDeviceFlowProviders() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, p := range w.oidcProviders {
		if p.DeviceFlow {
			return true
		}
	}
	return false
}

// BindPubkey adds an SSH public key to the allowed set, bound to the given
// OIDC identity. The key is persisted to the ConfigMap so it survives restarts.
// This is called after successful device flow authentication to enable
// subsequent connections to use fast public key auth.
func (w *AuthWatcher) BindPubkey(ctx context.Context, fingerprint, authorizedKeyLine string) error {
	// Persist to ConfigMap first. If this fails, we don't update in-memory
	// state — avoids inconsistency where the key works temporarily but is
	// lost on the next ConfigMap reload.
	if err := w.appendPubkeyToConfigMap(ctx, authorizedKeyLine); err != nil {
		return err
	}

	// Update in-memory for immediate effect (the informer will also
	// eventually pick up the ConfigMap change).
	w.mu.Lock()
	w.pubkeys[fingerprint] = extractPubkeyComment(authorizedKeyLine)
	w.mu.Unlock()

	return nil
}

// extractPubkeyComment returns the comment field from an authorized_keys line.
func extractPubkeyComment(line string) string {
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return comment
}

// appendPubkeyToConfigMap reads the current ConfigMap, appends the key line
// to allowed-pubkeys, and writes it back with optimistic concurrency.
func (w *AuthWatcher) appendPubkeyToConfigMap(ctx context.Context, keyLine string) error {
	// Pre-parse the new key to avoid panics inside the loop and to
	// compute the fingerprint once.
	newPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return fmt.Errorf("invalid key line for binding: %w", err)
	}
	newFingerprint := ssh.FingerprintSHA256(newPub)

	cmClient := w.k8sClient.CoreV1().ConfigMaps(w.namespace)

	// Retry on conflict (optimistic concurrency).
	for attempt := 0; attempt < 3; attempt++ {
		cm, err := cmClient.Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get ConfigMap %s/%s: %w", w.namespace, w.name, err)
		}

		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}

		// Check if the key is already present to avoid duplicates.
		existing := cm.Data[KeyAllowedPubkeys]
		alreadyBound := false
		for _, line := range strings.Split(existing, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			if ssh.FingerprintSHA256(pub) == newFingerprint {
				slog.Info("pubkey already bound, skipping",
					"fingerprint", newFingerprint,
				)
				alreadyBound = true
				break
			}
		}
		if alreadyBound {
			return nil
		}

		// Append the new key.
		if existing != "" && !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		cm.Data[KeyAllowedPubkeys] = existing + keyLine + "\n"

		_, err = cmClient.Update(ctx, cm, metav1.UpdateOptions{})
		if err == nil {
			slog.Info("pubkey bound to ConfigMap",
				"configmap", w.name,
				"fingerprint", newFingerprint,
			)
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("update ConfigMap %s/%s: %w", w.namespace, w.name, err)
		}
		slog.Debug("ConfigMap update conflict, retrying",
			"attempt", attempt+1,
			"error", err,
		)
	}

	return fmt.Errorf("failed to update ConfigMap %s/%s after 3 conflict retries", w.namespace, w.name)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// reload reads the ConfigMap from the cache and replaces the in-memory data.
func (w *AuthWatcher) reload(ctx context.Context) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: w.namespace, Name: w.name}
	if err := w.cache.Get(ctx, key, &cm); err != nil {
		// If the context was cancelled (shutdown), don't clear auth data —
		// in-flight authentication should continue to work during drain.
		if ctx.Err() != nil {
			return
		}
		slog.Warn("auth watcher: ConfigMap not found, clearing auth data",
			"namespace", w.namespace,
			"configmap", w.name,
			"error", err,
		)
		w.mu.Lock()
		w.oidcProviders = nil
		w.pubkeys = make(map[string]string)
		w.mu.Unlock()
		pruneProviderCache(nil)
		return
	}

	providers := parseOIDCProviders(cm.Data[KeyOIDCProviders])
	pubkeys := parsePubkeyList(cm.Data[KeyAllowedPubkeys])

	w.mu.Lock()
	w.oidcProviders = providers
	w.pubkeys = pubkeys
	w.mu.Unlock()

	// Evict cached OIDC providers that are no longer in the active set.
	activeIssuers := make(map[string]bool, len(providers))
	issuers := make([]string, len(providers))
	for i, p := range providers {
		activeIssuers[p.Issuer] = true
		issuers[i] = p.Issuer
	}
	pruneProviderCache(activeIssuers)

	slog.Info("auth watcher: config updated",
		"configmap", w.name,
		"oidc_providers", issuers,
		"allowed_pubkey_count", len(pubkeys),
	)
}

// parseOIDCProviders parses the YAML-formatted OIDC provider configuration.
// The format is a YAML list:
//
//   - issuer: https://token.actions.githubusercontent.com
//     audience: blip
//     identity-claim: sub
//     allowed-subjects:
//   - "repo:my-org/my-repo:*"
func parseOIDCProviders(raw string) []OIDCProviderConfig {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var providers []OIDCProviderConfig
	if err := yaml.Unmarshal([]byte(raw), &providers); err != nil {
		slog.Error("auth watcher: failed to parse oidc-providers YAML",
			"error", err,
		)
		return nil
	}

	// Validate and filter out invalid entries.
	var valid []OIDCProviderConfig
	for _, p := range providers {
		p.Issuer = strings.TrimSpace(p.Issuer)
		p.Audience = strings.TrimSpace(p.Audience)
		p.IdentityClaim = strings.TrimSpace(p.IdentityClaim)
		p.ClientID = strings.TrimSpace(p.ClientID)
		p.DeviceAuthURL = strings.TrimSpace(p.DeviceAuthURL)
		p.TokenURL = strings.TrimSpace(p.TokenURL)

		if p.Issuer == "" {
			slog.Warn("auth watcher: skipping OIDC provider with empty issuer")
			continue
		}
		if !strings.HasPrefix(p.Issuer, "https://") {
			slog.Warn("auth watcher: skipping OIDC provider with non-HTTPS issuer",
				"issuer", p.Issuer,
			)
			continue
		}
		// Normalize trailing slash to prevent duplicate cache entries.
		p.Issuer = strings.TrimRight(p.Issuer, "/")

		if p.Audience == "" {
			slog.Warn("auth watcher: skipping OIDC provider with empty audience",
				"issuer", p.Issuer,
			)
			continue
		}

		// Validate device flow configuration.
		if p.DeviceFlow {
			if p.ClientID == "" {
				slog.Warn("auth watcher: skipping device-flow provider with empty client-id",
					"issuer", p.Issuer,
				)
				continue
			}
			if p.DeviceAuthURL == "" {
				slog.Warn("auth watcher: skipping device-flow provider with empty device-auth-url",
					"issuer", p.Issuer,
				)
				continue
			}
			if !strings.HasPrefix(p.DeviceAuthURL, "https://") {
				slog.Warn("auth watcher: skipping device-flow provider with non-HTTPS device-auth-url",
					"issuer", p.Issuer,
					"device-auth-url", p.DeviceAuthURL,
				)
				continue
			}
			if p.TokenURL == "" {
				slog.Warn("auth watcher: skipping device-flow provider with empty token-url",
					"issuer", p.Issuer,
				)
				continue
			}
			if !strings.HasPrefix(p.TokenURL, "https://") {
				slog.Warn("auth watcher: skipping device-flow provider with non-HTTPS token-url",
					"issuer", p.Issuer,
					"token-url", p.TokenURL,
				)
				continue
			}
		}

		valid = append(valid, p)
	}
	return valid
}

// parsePubkeyList parses newline-delimited authorized_keys entries and returns
// a map of their SHA256 fingerprints to the comment (username) field.
func parsePubkeyList(raw string) map[string]string {
	fps := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			slog.Warn("auth watcher: skipping invalid public key line",
				"error", err,
				"line", line,
			)
			continue
		}
		fp := ssh.FingerprintSHA256(pub)
		fps[fp] = comment
		slog.Debug("auth watcher: loaded allowed pubkey",
			"fingerprint", fp,
			"comment", comment,
		)
	}
	return fps
}

// NewTestAuthWatcher creates an AuthWatcher pre-loaded with the given OIDC
// providers and pubkey fingerprints (fingerprint -> comment), without starting
// an informer cache. Intended for use in tests outside of this package.
func NewTestAuthWatcher(providers []OIDCProviderConfig, pubkeyFingerprints map[string]string) *AuthWatcher {
	if pubkeyFingerprints == nil {
		pubkeyFingerprints = make(map[string]string)
	}
	return &AuthWatcher{oidcProviders: providers, pubkeys: pubkeyFingerprints}
}

func newCoreRESTMapper() meta.RESTMapper {
	return restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "v1", Version: "v1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1": {
					{Name: "configmaps", Namespaced: true, Kind: "ConfigMap"},
				},
			},
		},
	})
}
