package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/server"
	"github.com/project-unbounded/blip/internal/gateway/session"
	"github.com/project-unbounded/blip/internal/gateway/vm"
	"github.com/project-unbounded/blip/internal/webhook"
)

type GatewayConfig struct {
	ListenAddr         string
	HostKeyPath        string
	ClientKeyPath      string
	VMNamespace        string
	VMPoolName         string
	PodName            string
	MaxSessionDuration time.Duration

	// AuthConfigMap is the name of the ConfigMap (in VMNamespace) that holds
	// OIDC provider configuration (key: "oidc-providers") and explicitly
	// allowed SSH public keys (key: "allowed-pubkeys").
	// Empty disables OIDC and explicit pubkey auth.
	AuthConfigMap string

	MaxBlipsPerUser int

	// HostPrincipals are the hostnames/IPs used for gateway identification.
	HostPrincipals []string

	// ExternalHost is the public hostname for the gateway, used in
	// reconnect instructions shown to users (e.g. "ssh blip-xxx@<host>").
	// When empty, reconnect messages fall back to <gateway-host> placeholder.
	ExternalHost string

	LoginGraceTime    time.Duration
	MaxAuthTries      int
	KeepAliveInterval time.Duration
	KeepAliveMax      int

	// HTTPListenAddr is the address for the HTTP server that serves webhook
	// endpoints and health checks. Default: ":8080".
	HTTPListenAddr string

	// Actions configures the GitHub Actions webhook handler. When nil (or
	// GitHubAppID is 0), the webhook endpoint is not registered and the
	// HTTP server only serves health checks.
	Actions *ActionsConfig
}

// ActionsConfig holds the configuration for the GitHub Actions webhook
// integration. When enabled, the gateway accepts GitHub workflow_job
// webhooks and allocates Blip VMs as just-in-time self-hosted runners.
type ActionsConfig struct {
	// WebhookSecret is the shared secret for validating X-Hub-Signature-256.
	// Empty disables signature validation (not recommended for production).
	WebhookSecret string

	// GitHubAppID is the GitHub App ID used for authentication.
	GitHubAppID int64

	// GitHubInstallID is the GitHub App installation ID.
	GitHubInstallID int64

	// GitHubKeyPath is the path to the PEM-encoded RSA private key for
	// the GitHub App.
	GitHubKeyPath string

	// RunnerLabels are the self-hosted runner labels to match against
	// workflow_job labels (e.g. ["self-hosted", "blip"]).
	RunnerLabels []string

	// MaxSessionDuration is the TTL for claimed runner VMs in seconds.
	// Separate from the SSH session max duration.
	MaxSessionDuration int
}

func RunGateway(cfg *GatewayConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the ConfigMap-backed auth watcher for OIDC and pubkey auth.
	var authWatcher *auth.AuthWatcher
	if cfg.AuthConfigMap != "" {
		var err error
		authWatcher, err = auth.NewAuthWatcher(ctx, cfg.VMNamespace, cfg.AuthConfigMap)
		if err != nil {
			return fmt.Errorf("start auth watcher: %w", err)
		}
	}

	// Start the identity store for refresh token storage and
	// SSH pubkey-to-OIDC identity linking.
	var identityStore *auth.IdentityStore
	if authWatcher != nil {
		var err error
		identityStore, err = auth.NewIdentityStore(ctx, cfg.VMNamespace, auth.DefaultPubkeyLinkTTL)
		if err != nil {
			return fmt.Errorf("start identity store: %w", err)
		}
	}

	vmcl, err := vm.New(ctx, cfg.VMNamespace)
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	// Create the VM key resolver adapter for the auth system.
	vmKeyResolver := &vmKeyResolverAdapter{vmClient: vmcl}

	srv, err := server.New(ctx, server.Config{
		ListenAddr:         cfg.ListenAddr,
		HostKeyPath:        cfg.HostKeyPath,
		PodName:            cfg.PodName,
		MaxSessionDuration: cfg.MaxSessionDuration,
		LoginGraceTime:     cfg.LoginGraceTime,
		MaxAuthTries:       cfg.MaxAuthTries,
		AuthWatcher:        authWatcher,
		VMKeyResolver:      vmKeyResolver,
		IdentityStore:      identityStore,
	})
	if err != nil {
		return err
	}

	// Load the stable shared client key for dialing upstream VMs.
	clientSigner, err := server.LoadSigner(cfg.ClientKeyPath, "gateway client key")
	if err != nil {
		return err
	}
	slog.Info("gateway client key loaded",
		"fingerprint", ssh.FingerprintSHA256(clientSigner.PublicKey()),
	)

	gatewayHost := ""
	if len(cfg.HostPrincipals) > 0 {
		gatewayHost = cfg.HostPrincipals[0]
	}

	mgr := session.New(session.Config{
		GatewaySigner:      clientSigner,
		GatewayHost:        gatewayHost,
		ExternalHost:       cfg.ExternalHost,
		VMClient:           vmcl,
		VMPoolName:         cfg.VMPoolName,
		PodName:            cfg.PodName,
		MaxBlipsPerUser:    cfg.MaxBlipsPerUser,
		MaxSessionDuration: cfg.MaxSessionDuration,
		KeepAliveInterval:  cfg.KeepAliveInterval,
		KeepAliveMax:       cfg.KeepAliveMax,
		AuthWatcher:        authWatcher,
		IdentityStore:      identityStore,
	})

	// --- HTTP server for health checks and optional webhook endpoint ---
	var webhookHandler *webhook.Handler
	if cfg.Actions != nil && cfg.Actions.GitHubAppID > 0 {
		ghClient, err := webhook.NewGitHubClient(
			cfg.Actions.GitHubAppID,
			cfg.Actions.GitHubInstallID,
			cfg.Actions.GitHubKeyPath,
		)
		if err != nil {
			return fmt.Errorf("create GitHub client: %w", err)
		}

		// Reuse the vm.Client's Kubernetes writer for the VMAnnotator
		// rather than creating a separate Kubernetes client.
		annotator := webhook.NewVMAnnotator(vmcl.Writer(), cfg.VMNamespace)

		actionsMaxDuration := cfg.Actions.MaxSessionDuration
		if actionsMaxDuration <= 0 {
			actionsMaxDuration = int(webhook.DefaultActionsTTL.Seconds())
		}

		webhookHandler = webhook.NewHandler(webhook.HandlerConfig{
			WebhookSecret:      []byte(cfg.Actions.WebhookSecret),
			VMClaimer:          vmcl,
			RunnerConfigStore:  annotator,
			TokenProvider:      ghClient,
			VMPoolName:         cfg.VMPoolName,
			RunnerLabels:       cfg.Actions.RunnerLabels,
			MaxSessionDuration: actionsMaxDuration,
			PodName:            cfg.PodName,
		})

		slog.Info("github actions webhook handler enabled",
			"runner_labels", cfg.Actions.RunnerLabels,
			"actions_max_session", actionsMaxDuration,
		)
	}

	httpAddr := cfg.HTTPListenAddr
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	// shuttingDown is set to 1 when a shutdown signal is received.
	// The readiness probe uses this to report not-ready during drain.
	var shuttingDown atomic.Int32

	mux := http.NewServeMux()
	if webhookHandler != nil {
		mux.Handle("/webhook", webhookHandler)
	}
	mux.HandleFunc("/healthz", healthzHandler(webhookHandler))
	mux.HandleFunc("/readyz", readyzHandler(webhookHandler, &shuttingDown))

	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("ssh-gateway starting",
		"listen", cfg.ListenAddr,
		"http_listen", httpAddr,
		"namespace", cfg.VMNamespace,
		"pool", cfg.VMPoolName,
		"max_session", cfg.MaxSessionDuration.String(),
		"oidc_auth", authWatcher != nil,
		"auth_configmap", cfg.AuthConfigMap,
		"actions_enabled", webhookHandler != nil,
	)

	// Start HTTP server in background. If it fails to bind (e.g. port
	// conflict), the error is surfaced immediately via httpErrCh.
	httpErrCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpErrCh <- err
		}
	}()

	// Give the HTTP server a moment to fail on bind errors before
	// committing to the SSH accept loop.
	select {
	case err := <-httpErrCh:
		return fmt.Errorf("HTTP server failed to start: %w", err)
	case <-time.After(50 * time.Millisecond):
		// HTTP server is likely listening — proceed.
	}

	// Maximum time to wait for active SSH sessions to drain after a signal.
	const drainTimeout = 30 * time.Second

	// sshDone signals when the SSH server's Serve() method returns.
	sshDone := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, starting graceful shutdown",
			"signal", sig.String(),
			"drain_timeout", drainTimeout.String(),
		)

		// Mark as shutting down so /readyz returns 503.
		shuttingDown.Store(1)

		// Cancel the main context — this triggers srv.listener.Close()
		// via context.AfterFunc in server.New, which unblocks Serve().
		cancel()

		// Notify active SSH sessions of the impending shutdown.
		mgr.NotifyShutdown()

		// Shut down the HTTP server gracefully. This stops accepting
		// new webhooks and waits for in-flight HTTP handlers to complete.
		httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpShutdownCancel()
		if err := httpServer.Shutdown(httpShutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}

		// Drain in-flight webhook goroutines. These run detached from
		// the HTTP handler and have their own timeouts (up to 2 min for
		// queued jobs). We cap the wait to keep it within the Kubernetes
		// termination grace period.
		if webhookHandler != nil {
			webhookDrainDone := make(chan struct{})
			go func() {
				webhookHandler.WaitForPending()
				close(webhookDrainDone)
			}()
			select {
			case <-webhookDrainDone:
				slog.Info("webhook goroutines drained")
			case <-time.After(drainTimeout):
				slog.Warn("webhook drain timeout, some operations may be interrupted")
			}
		}

		// Wait for SSH sessions to drain, or timeout.
		select {
		case <-sshDone:
			slog.Info("ssh server stopped, all sessions drained")
		case <-time.After(drainTimeout):
			slog.Warn("session drain timeout, forcing exit")
			os.Exit(0)
		}
	}()

	err = srv.Serve(ctx, mgr.HandleConnection)
	close(sshDone)
	return err
}

// healthzHandler returns an HTTP handler that always reports healthy (the process
// is alive). When a webhook handler is configured, the response includes the
// active webhook session count.
func healthzHandler(wh *webhook.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if wh != nil {
			resp["active_webhook_sessions"] = wh.ActiveSessionCount()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// readyzHandler returns an HTTP handler that reports readiness. It returns
// 503 Service Unavailable during shutdown so Kubernetes stops routing new
// traffic to the pod while it drains.
func readyzHandler(wh *webhook.Handler, shuttingDown *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if shuttingDown.Load() != 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":    "shutting_down",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if wh != nil {
			resp["active_webhook_sessions"] = wh.ActiveSessionCount()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// vmKeyResolverAdapter adapts vm.Client to the auth.VMKeyResolver interface
// by looking up the VM client key annotation and resolving the root identity
// and auth fingerprint.
type vmKeyResolverAdapter struct {
	vmClient *vm.Client
}

func (a *vmKeyResolverAdapter) ResolveRootIdentity(fingerprint string) (string, string, error) {
	return a.vmClient.ResolveRootIdentity(context.Background(), fingerprint)
}
