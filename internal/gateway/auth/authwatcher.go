package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMap key names inside the unified auth ConfigMap.
const (
	// KeyAllowedRepos holds the allowed GitHub Actions repository list
	// (one owner/repo per line).
	KeyAllowedRepos = "allowed-repos"

	// KeyAllowedPubkeys holds explicitly allowed SSH public keys
	// (one key per line in authorized_keys format).
	KeyAllowedPubkeys = "allowed-pubkeys"
)

// AuthWatcher watches a ConfigMap for the allowed GitHub Actions repository
// list and explicitly allowed SSH public keys, providing thread-safe access
// to the current sets.
type AuthWatcher struct {
	cache     crcache.Cache
	namespace string
	name      string

	mu      sync.RWMutex
	repos   []string
	pubkeys map[string]bool // SHA256 fingerprint -> true
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

	w := &AuthWatcher{
		cache:     informerCache,
		namespace: namespace,
		name:      configMapName,
		pubkeys:   make(map[string]bool),
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
		"initial_repos", w.AllowedRepos(),
		"initial_pubkey_count", len(w.allowedPubkeyFingerprints()),
	)

	return w, nil
}

// AllowedRepos returns the current snapshot of allowed repos. The returned
// slice must not be modified by the caller.
func (w *AuthWatcher) AllowedRepos() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.repos
}

// IsPubkeyAllowed reports whether the given fingerprint (e.g. "SHA256:...")
// is in the current allowed set.
func (w *AuthWatcher) IsPubkeyAllowed(fingerprint string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pubkeys[fingerprint]
}

// allowedPubkeyFingerprints returns the count for logging. Lock must not be held.
func (w *AuthWatcher) allowedPubkeyFingerprints() map[string]bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pubkeys
}

// reload reads the ConfigMap from the cache and replaces the in-memory data.
func (w *AuthWatcher) reload(ctx context.Context) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: w.namespace, Name: w.name}
	if err := w.cache.Get(ctx, key, &cm); err != nil {
		slog.Warn("auth watcher: ConfigMap not found, clearing auth data",
			"namespace", w.namespace,
			"configmap", w.name,
			"error", err,
		)
		w.mu.Lock()
		w.repos = nil
		w.pubkeys = make(map[string]bool)
		w.mu.Unlock()
		return
	}

	repos := parseLineList(cm.Data[KeyAllowedRepos])
	pubkeys := parsePubkeyList(cm.Data[KeyAllowedPubkeys])

	w.mu.Lock()
	w.repos = repos
	w.pubkeys = pubkeys
	w.mu.Unlock()

	slog.Info("auth watcher: config updated",
		"configmap", w.name,
		"repos", repos,
		"allowed_pubkey_count", len(pubkeys),
	)
}

// parseLineList splits a newline-delimited string into trimmed, non-empty entries.
// Lines starting with # are treated as comments.
func parseLineList(raw string) []string {
	var items []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items = append(items, line)
	}
	return items
}

// parsePubkeyList parses newline-delimited authorized_keys entries and returns
// a set of their SHA256 fingerprints.
func parsePubkeyList(raw string) map[string]bool {
	fps := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			slog.Warn("auth watcher: skipping invalid public key line",
				"error", err,
				"line", line,
			)
			continue
		}
		fp := ssh.FingerprintSHA256(pub)
		fps[fp] = true
		slog.Debug("auth watcher: loaded allowed pubkey",
			"fingerprint", fp,
		)
	}
	return fps
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
