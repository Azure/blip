// Package actions — ActionsConfigWatcher watches a well-known ConfigMap for
// GitHub Actions runner configuration (runner labels and trusted repos).
// This allows enabling and reconfiguring the actions runner backend at runtime
// by editing a ConfigMap, without restarting any pods.
package actions

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Well-known ConfigMap name and keys.
const (
	// ActionsConfigMapName is the well-known ConfigMap name for GitHub Actions
	// runner configuration. Users create this ConfigMap to enable the feature.
	ActionsConfigMapName = "github-actions"

	// ActionsConfigKeyLabels is the ConfigMap key for comma-separated runner labels.
	ActionsConfigKeyLabels = "runner-labels"

	// ActionsConfigKeyRepos is the ConfigMap key for comma-separated repos (owner/repo).
	ActionsConfigKeyRepos = "repos"

	// DefaultPATSecretName is the well-known Secret name for the GitHub PAT.
	DefaultPATSecretName = "github-pat"
)

// ActionsConfig holds the parsed runner configuration from the ConfigMap.
type ActionsConfig struct {
	RunnerLabels []string
	Repos        []string
}

// Valid returns true if the configuration has both labels and repos.
func (c *ActionsConfig) Valid() bool {
	return len(c.RunnerLabels) > 0 && len(c.Repos) > 0
}

// ActionsConfigWatcher watches the github-actions ConfigMap for runner
// configuration. All methods are safe for concurrent use.
type ActionsConfigWatcher struct {
	configMapName string
	namespace     string

	mu     sync.RWMutex
	config *ActionsConfig // nil when no valid config is present
}

// NewActionsConfigWatcher creates a watcher on the github-actions ConfigMap.
// It performs an initial load if the ConfigMap exists, then watches for changes.
// The informerCache must already be started and synced.
func NewActionsConfigWatcher(ctx context.Context, informerCache crcache.Cache, namespace string) (*ActionsConfigWatcher, error) {
	w := &ActionsConfigWatcher{
		configMapName: ActionsConfigMapName,
		namespace:     namespace,
	}

	// Get the ConfigMap informer and register event handler.
	cmInformer, err := informerCache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return nil, fmt.Errorf("get configmap informer: %w", err)
	}

	// Try initial load (ConfigMap may not exist yet).
	var cm corev1.ConfigMap
	if err := informerCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ActionsConfigMapName}, &cm); err == nil {
		w.reconcile(&cm)
	} else {
		slog.Info("github-actions configmap not found, actions runner disabled until created",
			"namespace", namespace,
			"configmap", ActionsConfigMapName,
		)
	}

	if _, err := cmInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handleEvent(obj) },
		UpdateFunc: func(_, newObj interface{}) { w.handleEvent(newObj) },
		DeleteFunc: func(obj interface{}) { w.handleDelete(obj) },
	}); err != nil {
		return nil, fmt.Errorf("add github-actions configmap event handler: %w", err)
	}

	slog.Info("actions config watcher started",
		"namespace", namespace,
		"configmap", ActionsConfigMapName,
	)
	return w, nil
}

func (w *ActionsConfigWatcher) handleEvent(obj interface{}) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != w.configMapName || cm.Namespace != w.namespace {
		return
	}
	w.reconcile(cm)
}

func (w *ActionsConfigWatcher) handleDelete(obj interface{}) {
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
	w.config = nil
	w.mu.Unlock()
	slog.Info("github-actions configmap deleted, actions runner disabled",
		"namespace", w.namespace,
		"configmap", w.configMapName,
	)
}

func (w *ActionsConfigWatcher) reconcile(cm *corev1.ConfigMap) {
	labels := parseCSV(cm.Data[ActionsConfigKeyLabels])
	repos := parseCSV(cm.Data[ActionsConfigKeyRepos])

	cfg := &ActionsConfig{
		RunnerLabels: labels,
		Repos:        repos,
	}

	w.mu.Lock()
	w.config = cfg
	w.mu.Unlock()

	if cfg.Valid() {
		slog.Info("actions config updated",
			"labels", labels,
			"repos", repos,
		)
	} else {
		slog.Warn("actions config incomplete (need both runner-labels and repos)",
			"labels", labels,
			"repos", repos,
		)
	}
}

// Config returns the current actions configuration, or nil if not configured.
func (w *ActionsConfigWatcher) Config() *ActionsConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.config == nil {
		return nil
	}
	// Return a copy to avoid data races.
	c := *w.config
	c.RunnerLabels = append([]string(nil), w.config.RunnerLabels...)
	c.Repos = append([]string(nil), w.config.Repos...)
	return &c
}

// RunnerLabels returns the current runner labels, or nil if not configured.
// This implements the runnerconfig.ConfigProvider interface.
func (w *ActionsConfigWatcher) RunnerLabels() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.config == nil {
		return nil
	}
	return append([]string(nil), w.config.RunnerLabels...)
}

// parseCSV splits a comma-separated string into trimmed, non-empty values.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}
