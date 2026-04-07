package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

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

// RepoWatcherConfigMapKey is the single key inside the ConfigMap that holds
// the allowed repository list (one owner/repo per line).
const RepoWatcherConfigMapKey = "repos"

// RepoWatcher watches a ConfigMap for the allowed GitHub Actions repository
// list and provides thread-safe access to the current set.
type RepoWatcher struct {
	cache     crcache.Cache
	namespace string
	name      string

	mu    sync.RWMutex
	repos []string
}

// NewRepoWatcher creates a RepoWatcher that watches the named ConfigMap.
// It starts the informer cache, waits for the initial sync, loads the current
// value, and installs an event handler that keeps the in-memory list updated.
func NewRepoWatcher(ctx context.Context, namespace, configMapName string) (*RepoWatcher, error) {
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

	w := &RepoWatcher{
		cache:     informerCache,
		namespace: namespace,
		name:      configMapName,
	}

	go func() {
		if err := informerCache.Start(ctx); err != nil {
			slog.Error("repo watcher informer cache stopped", "error", err)
		}
	}()

	if !informerCache.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("repo watcher cache sync failed")
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

	slog.Info("repo watcher started",
		"namespace", namespace,
		"configmap", configMapName,
		"initial_repos", w.AllowedRepos(),
	)

	return w, nil
}

// AllowedRepos returns the current snapshot of allowed repos. The returned
// slice must not be modified by the caller.
func (w *RepoWatcher) AllowedRepos() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.repos
}

// reload reads the ConfigMap from the cache and replaces the in-memory list.
func (w *RepoWatcher) reload(ctx context.Context) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: w.namespace, Name: w.name}
	if err := w.cache.Get(ctx, key, &cm); err != nil {
		slog.Warn("repo watcher: ConfigMap not found, disabling OIDC auth",
			"namespace", w.namespace,
			"configmap", w.name,
			"error", err,
		)
		w.mu.Lock()
		w.repos = nil
		w.mu.Unlock()
		return
	}

	raw, ok := cm.Data[RepoWatcherConfigMapKey]
	if !ok {
		slog.Warn("repo watcher: ConfigMap missing key, disabling OIDC auth",
			"namespace", w.namespace,
			"configmap", w.name,
			"key", RepoWatcherConfigMapKey,
		)
		w.mu.Lock()
		w.repos = nil
		w.mu.Unlock()
		return
	}

	repos := parseRepoList(raw)

	w.mu.Lock()
	w.repos = repos
	w.mu.Unlock()

	slog.Info("repo watcher: allowed repos updated",
		"configmap", w.name,
		"repos", repos,
	)
}

// parseRepoList splits a newline-delimited string into trimmed, non-empty entries.
func parseRepoList(raw string) []string {
	var repos []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		repos = append(repos, line)
	}
	return repos
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
