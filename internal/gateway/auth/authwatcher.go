package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// PubkeyUserLabel is the label on ConfigMaps that marks them as trusted
	// pubkeys. The label value is the user identity used by the quota logic.
	PubkeyUserLabel = "blip.azure.com/user"

	// PubkeyDataKey is the data key in the ConfigMap containing the SSH
	// public key in authorized_keys format.
	PubkeyDataKey = "pubkey"
)

// AuthWatcher watches ConfigMaps with the blip.azure.com/user label for
// trusted SSH public keys, providing thread-safe access to the current set.
type AuthWatcher struct {
	cache     crcache.Cache
	namespace string

	mu      sync.RWMutex
	pubkeys map[string]pubkeyEntry // SHA256 fingerprint -> entry
}

// pubkeyEntry holds the parsed data for a trusted public key.
type pubkeyEntry struct {
	// UserIdentity is the value of the blip.azure.com/user label.
	UserIdentity string
}

// NewAuthWatcher creates an AuthWatcher that watches ConfigMaps with the
// blip.azure.com/user label in the given namespace. It starts an informer
// cache, waits for the initial sync, loads the current values, and installs
// an event handler that keeps the in-memory data updated.
func NewAuthWatcher(ctx context.Context, namespace string) (*AuthWatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register core/v1: %w", err)
	}

	informerCache, err := crcache.New(cfg, crcache.Options{
		Scheme: s,
		DefaultNamespaces: map[string]crcache.Config{
			namespace: {},
		},
		DefaultTransform: crcache.TransformStripManagedFields(),
	})
	if err != nil {
		return nil, fmt.Errorf("create configmap informer cache: %w", err)
	}

	w := &AuthWatcher{
		cache:     informerCache,
		namespace: namespace,
		pubkeys:   make(map[string]pubkeyEntry),
	}

	go func() {
		if err := informerCache.Start(ctx); err != nil {
			slog.Error("auth watcher informer cache stopped", "error", err)
		}
	}()

	if !informerCache.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("auth watcher cache sync failed")
	}

	// Load the initial values from all matching ConfigMaps.
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
		"initial_pubkey_count", w.allowedPubkeyCount(),
	)

	return w, nil
}

// IsPubkeyAllowed reports whether the given fingerprint (e.g. "SHA256:...")
// is in the current allowed set.
func (w *AuthWatcher) IsPubkeyAllowed(fingerprint string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.pubkeys[fingerprint]
	return ok
}

// PubkeyUserIdentity returns the user identity for the given fingerprint,
// or "" if the fingerprint is not in the allowed set.
func (w *AuthWatcher) PubkeyUserIdentity(fingerprint string) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry, ok := w.pubkeys[fingerprint]
	if !ok {
		return ""
	}
	return entry.UserIdentity
}

// allowedPubkeyCount returns the number of allowed pubkeys for logging.
func (w *AuthWatcher) allowedPubkeyCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.pubkeys)
}

// reload reads all matching ConfigMaps from the cache and replaces the in-memory data.
func (w *AuthWatcher) reload(ctx context.Context) {
	var cms corev1.ConfigMapList
	if err := w.cache.List(ctx, &cms,
		client.InNamespace(w.namespace),
		client.HasLabels{PubkeyUserLabel},
	); err != nil {
		if ctx.Err() != nil {
			return
		}
		slog.Warn("auth watcher: failed to list pubkey ConfigMaps, clearing auth data",
			"namespace", w.namespace,
			"error", err,
		)
		w.mu.Lock()
		w.pubkeys = make(map[string]pubkeyEntry)
		w.mu.Unlock()
		return
	}

	pubkeys := make(map[string]pubkeyEntry)
	for i := range cms.Items {
		cm := &cms.Items[i]
		userIdentity := cm.Labels[PubkeyUserLabel]
		if userIdentity == "" {
			continue
		}

		pubkeyStr, ok := cm.Data[PubkeyDataKey]
		if !ok || strings.TrimSpace(pubkeyStr) == "" {
			slog.Warn("auth watcher: skipping ConfigMap with missing/empty pubkey data",
				"configmap", cm.Name,
			)
			continue
		}

		fp, err := parsePubkeyFingerprint(pubkeyStr)
		if err != nil {
			slog.Warn("auth watcher: skipping ConfigMap with invalid pubkey",
				"configmap", cm.Name,
				"error", err,
			)
			continue
		}

		if existing, dup := pubkeys[fp]; dup {
			slog.Warn("auth watcher: duplicate pubkey fingerprint, last writer wins",
				"fingerprint", fp,
				"configmap", cm.Name,
				"existing_user", existing.UserIdentity,
				"new_user", userIdentity,
			)
		}

		pubkeys[fp] = pubkeyEntry{UserIdentity: userIdentity}
	}

	w.mu.Lock()
	w.pubkeys = pubkeys
	w.mu.Unlock()

	slog.Info("auth watcher: config updated from pubkey ConfigMaps",
		"configmap_count", len(cms.Items),
		"allowed_pubkey_count", len(pubkeys),
	)
}

// parsePubkeyFingerprint parses an SSH public key in authorized_keys format
// and returns its SHA256 fingerprint.
func parsePubkeyFingerprint(publicKey string) (string, error) {
	line := strings.TrimSpace(publicKey)
	if line == "" {
		return "", fmt.Errorf("empty key")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", fmt.Errorf("parse SSH public key: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}

// NewTestAuthWatcher creates an AuthWatcher pre-loaded with the given
// pubkey fingerprints (fingerprint -> user identity), without starting an
// informer cache. Intended for use in tests outside of this package.
func NewTestAuthWatcher(pubkeyFingerprints map[string]string) *AuthWatcher {
	pubkeys := make(map[string]pubkeyEntry)
	for fp, user := range pubkeyFingerprints {
		pubkeys[fp] = pubkeyEntry{UserIdentity: user}
	}
	return &AuthWatcher{pubkeys: pubkeys}
}
