package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// PubkeyUserLabel is the label on session ConfigMaps that marks them as
	// trusted pubkeys. The label value is the user identity used by the quota logic.
	PubkeyUserLabel = "blip.azure.com/user"

	// PubkeyDataKey is the data key in the session ConfigMap containing the
	// SSH public key in authorized_keys format.
	PubkeyDataKey = "pubkey"

	// PubkeySubjectAnnotation stores the original OIDC subject for dynamic
	// auth ConfigMaps. Static pubkey ConfigMaps leave this unset.
	PubkeySubjectAnnotation = "blip.azure.com/subject"
)

// AuthWatcher watches session ConfigMaps with the blip.azure.com/user label
// for trusted SSH public keys, providing thread-safe access to the current set.
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

	// Subject is the original authenticated subject, when provided by OIDC.
	Subject string
}

// NewAuthWatcher creates an AuthWatcher that watches session ConfigMaps with
// the blip.azure.com/user label in the given namespace. It starts an informer
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

// Lookup returns the trusted public key entry for a fingerprint.
func (w *AuthWatcher) Lookup(fingerprint string) (pubkeyEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry, ok := w.pubkeys[fingerprint]
	return entry, ok
}

// WaitForAuth blocks until a trusted public key ConfigMap matching the given
// fingerprint exists, or until the context is cancelled / timeout expires.
func (w *AuthWatcher) WaitForAuth(ctx context.Context, fingerprint string, timeout time.Duration) (pubkeyEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	notifyCh := make(chan pubkeyEntry, 1)

	informer, err := w.cache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return pubkeyEntry{}, fmt.Errorf("get configmap informer: %w", err)
	}

	reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { w.notifyIfFingerprintMatches(obj, fingerprint, notifyCh) },
		UpdateFunc: func(_, newObj interface{}) {
			w.notifyIfFingerprintMatches(newObj, fingerprint, notifyCh)
		},
	})
	if err != nil {
		return pubkeyEntry{}, fmt.Errorf("add auth configmap event handler: %w", err)
	}
	defer func() {
		if err := informer.RemoveEventHandler(reg); err != nil {
			slog.Warn("failed to remove auth configmap event handler", "error", err)
		}
	}()

	if entry, found := w.Lookup(fingerprint); found {
		return entry, nil
	}

	select {
	case entry := <-notifyCh:
		return entry, nil
	case <-ctx.Done():
		return pubkeyEntry{}, fmt.Errorf("device flow auth timed out waiting for browser authentication")
	}
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
		slog.Warn("auth watcher: failed to list session ConfigMaps, clearing auth data",
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

		pubkeys[fp] = pubkeyEntry{
			UserIdentity: userIdentity,
			Subject:      cm.Annotations[PubkeySubjectAnnotation],
		}
	}

	w.mu.Lock()
	w.pubkeys = pubkeys
	w.mu.Unlock()

	slog.Info("auth watcher: config updated from session ConfigMaps",
		"configmap_count", len(cms.Items),
		"allowed_pubkey_count", len(pubkeys),
	)
}

func (w *AuthWatcher) notifyIfFingerprintMatches(obj interface{}, fingerprint string, notifyCh chan<- pubkeyEntry) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	if cm.Namespace != w.namespace || cm.Labels[PubkeyUserLabel] == "" {
		return
	}
	pubkeyStr := cm.Data[PubkeyDataKey]
	fp, err := parsePubkeyFingerprint(pubkeyStr)
	if err != nil || fp != fingerprint {
		return
	}
	entry := pubkeyEntry{
		UserIdentity: cm.Labels[PubkeyUserLabel],
		Subject:      cm.Annotations[PubkeySubjectAnnotation],
	}
	select {
	case notifyCh <- entry:
	default:
	}
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

// NewTestOIDCAuthWatcher creates an AuthWatcher pre-loaded with OIDC-backed
// pubkey entries. Intended for use in tests outside of this package.
func NewTestOIDCAuthWatcher(pubkeyFingerprints map[string]string) *AuthWatcher {
	pubkeys := make(map[string]pubkeyEntry)
	for fp, subject := range pubkeyFingerprints {
		pubkeys[fp] = pubkeyEntry{UserIdentity: subject, Subject: subject}
	}
	return &AuthWatcher{pubkeys: pubkeys}
}
