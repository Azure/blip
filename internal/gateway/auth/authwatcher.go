package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	blipv1alpha1 "github.com/project-unbounded/blip/api/v1alpha1"
)

// AuthWatcher watches BlipOwner custom resources for OIDC provider
// configuration, explicitly allowed SSH public keys, and GitHub Actions
// repo associations — providing thread-safe access to the current sets.
type AuthWatcher struct {
	cache     crcache.Cache
	namespace string

	// k8sClient is a controller-runtime client for creating BlipOwner CRs
	// during pubkey binding.
	k8sClient client.Client

	mu            sync.RWMutex
	oidcProviders []OIDCProviderConfig
	pubkeys       map[string]string // SHA256 fingerprint -> comment (username)
	actionsRepos  []string
}

// NewAuthWatcher creates an AuthWatcher that watches BlipOwner CRs in the
// given namespace. It starts the informer cache, waits for the initial sync,
// loads the current values, and installs an event handler that keeps the
// in-memory data updated.
func NewAuthWatcher(ctx context.Context, namespace string) (*AuthWatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	s := runtime.NewScheme()
	if err := blipv1alpha1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register blip.io/v1alpha1: %w", err)
	}

	mapper := newBlipOwnerRESTMapper()

	informerCache, err := crcache.New(cfg, crcache.Options{
		Scheme: s,
		Mapper: mapper,
		DefaultNamespaces: map[string]crcache.Config{
			namespace: {},
		},
		DefaultTransform: crcache.TransformStripManagedFields(),
	})
	if err != nil {
		return nil, fmt.Errorf("create blipowner informer cache: %w", err)
	}

	// Create a controller-runtime client for writing BlipOwner CRs.
	k8sClient, err := client.New(cfg, client.Options{Scheme: s, Mapper: mapper})
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	w := &AuthWatcher{
		cache:     informerCache,
		namespace: namespace,
		k8sClient: k8sClient,
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

	// Load the initial values from all BlipOwner CRs.
	w.reload(ctx)

	// Install an event handler so future updates are picked up automatically.
	informer, err := informerCache.GetInformer(ctx, &blipv1alpha1.BlipOwner{})
	if err != nil {
		return nil, fmt.Errorf("get blipowner informer: %w", err)
	}

	reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { w.reload(ctx) },
		UpdateFunc: func(_, _ interface{}) { w.reload(ctx) },
		DeleteFunc: func(_ interface{}) { w.reload(ctx) },
	})
	if err != nil {
		return nil, fmt.Errorf("add blipowner event handler: %w", err)
	}
	_ = reg // registration handle; lives as long as the informer

	slog.Info("auth watcher started",
		"namespace", namespace,
		"initial_oidc_providers", len(w.OIDCProviders()),
		"initial_pubkey_count", w.allowedPubkeyCount(),
		"initial_actions_repos", len(w.ActionsRepos()),
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

// ActionsRepos returns a copy of the current list of repos to poll for
// queued GitHub Actions workflow jobs.
func (w *AuthWatcher) ActionsRepos() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]string, len(w.actionsRepos))
	copy(result, w.actionsRepos)
	return result
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

// BindPubkey adds an SSH public key to the allowed set by creating a new
// BlipOwner CR. The CR name is derived from the key's fingerprint for
// idempotency — concurrent binds of the same key safely no-op.
func (w *AuthWatcher) BindPubkey(ctx context.Context, fingerprint, authorizedKeyLine string) error {
	// Validate the key parses before attempting to create the CR.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
	if err != nil {
		return fmt.Errorf("invalid key line for binding: %w", err)
	}
	computedFP := ssh.FingerprintSHA256(pub)

	// Derive a deterministic CR name from the fingerprint.
	crName := fingerprintToCRName(computedFP)

	// Extract the comment for the publicKey field.
	comment := extractPubkeyComment(authorizedKeyLine)

	// Build the authorized_keys line with the comment.
	pubkeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		pubkeyLine += " " + comment
	}

	bo := &blipv1alpha1.BlipOwner{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crName,
			Namespace: w.namespace,
			Labels: map[string]string{
				"blip.io/bound-by": "device-flow",
			},
		},
		Spec: blipv1alpha1.BlipOwnerSpec{
			SSHKey: &blipv1alpha1.SSHKeySpec{
				PublicKey: pubkeyLine,
			},
		},
	}

	err = w.k8sClient.Create(ctx, bo)
	if err != nil {
		if client.IgnoreAlreadyExists(err) == nil {
			slog.Info("pubkey BlipOwner already exists, skipping",
				"name", crName,
				"fingerprint", computedFP,
			)
			return nil
		}
		return fmt.Errorf("create BlipOwner %s/%s: %w", w.namespace, crName, err)
	}

	// Update in-memory for immediate effect (the informer will also
	// eventually pick up the CR change).
	w.mu.Lock()
	w.pubkeys[computedFP] = comment
	w.mu.Unlock()

	slog.Info("pubkey bound via BlipOwner CR",
		"name", crName,
		"fingerprint", computedFP,
	)
	return nil
}

// fingerprintToCRName converts a SHA256 fingerprint (e.g. "SHA256:abc123...")
// to a valid Kubernetes resource name like "bound-<hex>".
func fingerprintToCRName(fingerprint string) string {
	// Hash the fingerprint to get a short, deterministic, DNS-safe name.
	h := sha256.Sum256([]byte(fingerprint))
	return "bound-" + hex.EncodeToString(h[:12])
}

// extractPubkeyComment returns the comment field from an authorized_keys line.
func extractPubkeyComment(line string) string {
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return comment
}

// reload reads all BlipOwner CRs from the cache and replaces the in-memory data.
func (w *AuthWatcher) reload(ctx context.Context) {
	var owners blipv1alpha1.BlipOwnerList
	if err := w.cache.List(ctx, &owners, client.InNamespace(w.namespace)); err != nil {
		// If the context was cancelled (shutdown), don't clear auth data —
		// in-flight authentication should continue to work during drain.
		if ctx.Err() != nil {
			return
		}
		slog.Warn("auth watcher: failed to list BlipOwner CRs, clearing auth data",
			"namespace", w.namespace,
			"error", err,
		)
		w.mu.Lock()
		w.oidcProviders = nil
		w.pubkeys = make(map[string]string)
		w.actionsRepos = nil
		w.mu.Unlock()
		pruneProviderCache(nil)
		return
	}

	var providers []OIDCProviderConfig
	pubkeys := make(map[string]string)
	var repos []string

	for i := range owners.Items {
		bo := &owners.Items[i]
		switch {
		case bo.Spec.SSHKey != nil:
			fp, comment := parseSSHKeyFromCR(bo.Spec.SSHKey.PublicKey)
			if fp != "" {
				pubkeys[fp] = comment
			}

		case bo.Spec.OIDC != nil:
			if p, ok := validateOIDCFromCR(bo.Spec.OIDC); ok {
				providers = append(providers, p)
			}

		case bo.Spec.ActionsRepo != nil:
			repo := strings.TrimSpace(bo.Spec.ActionsRepo.Repo)
			if repo != "" {
				repos = append(repos, repo)
			}
		}
	}

	w.mu.Lock()
	w.oidcProviders = providers
	w.pubkeys = pubkeys
	w.actionsRepos = repos
	w.mu.Unlock()

	// Evict cached OIDC providers that are no longer in the active set.
	activeIssuers := make(map[string]bool, len(providers))
	issuers := make([]string, len(providers))
	for i, p := range providers {
		activeIssuers[p.Issuer] = true
		issuers[i] = p.Issuer
	}
	pruneProviderCache(activeIssuers)

	slog.Info("auth watcher: config updated from BlipOwner CRs",
		"blipowner_count", len(owners.Items),
		"oidc_providers", issuers,
		"allowed_pubkey_count", len(pubkeys),
		"actions_repos_count", len(repos),
	)
}

// parseSSHKeyFromCR parses a public key from a BlipOwner SSHKey spec and
// returns its SHA256 fingerprint and comment. Returns empty fingerprint on error.
func parseSSHKeyFromCR(publicKey string) (fingerprint string, comment string) {
	line := strings.TrimSpace(publicKey)
	if line == "" {
		return "", ""
	}
	pub, c, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		slog.Warn("auth watcher: skipping invalid SSH public key from BlipOwner",
			"error", err,
			"key", truncate(line, 80),
		)
		return "", ""
	}
	fp := ssh.FingerprintSHA256(pub)
	slog.Debug("auth watcher: loaded allowed pubkey from BlipOwner",
		"fingerprint", fp,
		"comment", c,
	)
	return fp, c
}

// validateOIDCFromCR validates and normalizes an OIDC spec from a BlipOwner CR.
// Returns the config and true if valid, or zero-value and false if invalid.
func validateOIDCFromCR(spec *blipv1alpha1.OIDCSpec) (OIDCProviderConfig, bool) {
	p := OIDCProviderConfig{
		Issuer:          strings.TrimSpace(spec.Issuer),
		Audience:        strings.TrimSpace(spec.Audience),
		IdentityClaim:   strings.TrimSpace(spec.IdentityClaim),
		AllowedSubjects: spec.AllowedSubjects,
		DeviceFlow:      spec.DeviceFlow,
		ClientID:        strings.TrimSpace(spec.ClientID),
		DeviceAuthURL:   strings.TrimSpace(spec.DeviceAuthURL),
		TokenURL:        strings.TrimSpace(spec.TokenURL),
		Scopes:          spec.Scopes,
	}

	if p.Issuer == "" {
		slog.Warn("auth watcher: skipping OIDC BlipOwner with empty issuer")
		return OIDCProviderConfig{}, false
	}
	if !strings.HasPrefix(p.Issuer, "https://") {
		slog.Warn("auth watcher: skipping OIDC BlipOwner with non-HTTPS issuer",
			"issuer", p.Issuer,
		)
		return OIDCProviderConfig{}, false
	}
	// Normalize trailing slash to prevent duplicate cache entries.
	p.Issuer = strings.TrimRight(p.Issuer, "/")

	if p.Audience == "" {
		slog.Warn("auth watcher: skipping OIDC BlipOwner with empty audience",
			"issuer", p.Issuer,
		)
		return OIDCProviderConfig{}, false
	}

	// Validate device flow configuration.
	if p.DeviceFlow {
		if p.ClientID == "" {
			slog.Warn("auth watcher: skipping device-flow BlipOwner with empty client-id",
				"issuer", p.Issuer,
			)
			return OIDCProviderConfig{}, false
		}
		if p.DeviceAuthURL == "" {
			slog.Warn("auth watcher: skipping device-flow BlipOwner with empty device-auth-url",
				"issuer", p.Issuer,
			)
			return OIDCProviderConfig{}, false
		}
		if !strings.HasPrefix(p.DeviceAuthURL, "https://") {
			slog.Warn("auth watcher: skipping device-flow BlipOwner with non-HTTPS device-auth-url",
				"issuer", p.Issuer,
				"device-auth-url", p.DeviceAuthURL,
			)
			return OIDCProviderConfig{}, false
		}
		if p.TokenURL == "" {
			slog.Warn("auth watcher: skipping device-flow BlipOwner with empty token-url",
				"issuer", p.Issuer,
			)
			return OIDCProviderConfig{}, false
		}
		if !strings.HasPrefix(p.TokenURL, "https://") {
			slog.Warn("auth watcher: skipping device-flow BlipOwner with non-HTTPS token-url",
				"issuer", p.Issuer,
				"token-url", p.TokenURL,
			)
			return OIDCProviderConfig{}, false
		}
	}

	return p, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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

// NewTestAuthWatcherWithRepos is like NewTestAuthWatcher but also sets the
// actions-repos list.
func NewTestAuthWatcherWithRepos(providers []OIDCProviderConfig, pubkeyFingerprints map[string]string, repos []string) *AuthWatcher {
	w := NewTestAuthWatcher(providers, pubkeyFingerprints)
	w.actionsRepos = repos
	return w
}

func newBlipOwnerRESTMapper() meta.RESTMapper {
	return restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "blip.io",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "blip.io/v1alpha1", Version: "v1alpha1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1alpha1": {
					{Name: "blipowners", Namespaced: true, Kind: "BlipOwner"},
				},
			},
		},
	})
}
