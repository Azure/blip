package ghactions

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// TokenWatcher watches a Kubernetes Secret for registration token updates
// and feeds them to a ScaleSetClient. It uses a client-go informer
// (not controller-runtime) so it can run independently of any manager.
type TokenWatcher struct {
	client    *ScaleSetClient
	namespace string
	name      string // Secret name, e.g. "runner-registration-token"
	clientset kubernetes.Interface
	stopCh    chan struct{}
}

// NewTokenWatcher creates a TokenWatcher that watches the named Secret and
// updates the ScaleSetClient whenever the "token" key changes. It uses an
// in-cluster Kubernetes client.
func NewTokenWatcher(ssClient *ScaleSetClient, namespace, secretName string) (*TokenWatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("create in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return &TokenWatcher{
		client:    ssClient,
		namespace: namespace,
		name:      secretName,
		clientset: clientset,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start begins watching the Secret. It performs an initial load, then starts
// a background informer. Call Stop to clean up. Blocks briefly for the initial
// cache sync.
func (tw *TokenWatcher) Start(ctx context.Context) error {
	// Perform initial load directly.
	if err := tw.initialLoad(ctx); err != nil {
		return err
	}

	// Create an informer factory scoped to the specific Secret by field selector.
	tweakListOptions := func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", tw.name).String()
	}
	factory := informers.NewSharedInformerFactoryWithOptions(
		tw.clientset,
		30*time.Second, // resync period
		informers.WithNamespace(tw.namespace),
		informers.WithTweakListOptions(tweakListOptions),
	)

	secretInformer := factory.Core().V1().Secrets().Informer()

	if _, err := secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			tw.handleSecretEvent(obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			tw.handleSecretEvent(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			slog.Warn("registration token Secret was deleted",
				"namespace", tw.namespace,
				"secret", tw.name,
			)
		},
	}); err != nil {
		return fmt.Errorf("add secret event handler: %w", err)
	}

	// Start the informer in background.
	factory.Start(tw.stopCh)

	// Wait for the cache to sync.
	if !cache.WaitForCacheSync(tw.stopCh, secretInformer.HasSynced) {
		return fmt.Errorf("failed to sync secret informer cache")
	}

	slog.Info("token watcher started",
		"namespace", tw.namespace,
		"secret", tw.name,
	)
	return nil
}

// Stop stops the token watcher informer.
func (tw *TokenWatcher) Stop() {
	close(tw.stopCh)
}

// handleSecretEvent extracts the token from a Secret event and updates the client.
func (tw *TokenWatcher) handleSecretEvent(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	if secret.Name != tw.name || secret.Namespace != tw.namespace {
		return
	}

	tokenBytes, ok := secret.Data["token"]
	if !ok || len(tokenBytes) == 0 {
		slog.Warn("registration token Secret missing 'token' key",
			"namespace", tw.namespace,
			"secret", tw.name,
		)
		return
	}

	tw.client.UpdateRegistrationToken(string(tokenBytes))

	if expiresAt, ok := secret.Data["expires_at"]; ok {
		slog.Info("registration token updated from Secret",
			"namespace", tw.namespace,
			"secret", tw.name,
			"expires_at", string(expiresAt),
		)
	} else {
		slog.Info("registration token updated from Secret",
			"namespace", tw.namespace,
			"secret", tw.name,
		)
	}
}

// initialLoad reads the Secret once and updates the ScaleSetClient.
func (tw *TokenWatcher) initialLoad(ctx context.Context) error {
	secret, err := tw.clientset.CoreV1().Secrets(tw.namespace).Get(ctx, tw.name, metav1.GetOptions{})
	if err != nil {
		slog.Warn("registration token Secret not found during initial load",
			"namespace", tw.namespace,
			"secret", tw.name,
			"error", err,
		)
		// Not fatal: the Secret may be created later by the cron workflow.
		return nil
	}

	tokenBytes, ok := secret.Data["token"]
	if !ok || len(tokenBytes) == 0 {
		slog.Warn("registration token Secret exists but missing 'token' key",
			"namespace", tw.namespace,
			"secret", tw.name,
		)
		return nil
	}

	tw.client.UpdateRegistrationToken(string(tokenBytes))
	slog.Info("registration token loaded from Secret on startup",
		"namespace", tw.namespace,
		"secret", tw.name,
	)
	return nil
}
