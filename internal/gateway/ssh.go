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
	"github.com/project-unbounded/blip/internal/ghactions"
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
	// OIDC provider configuration (key: "oidc-providers"), explicitly
	// allowed SSH public keys (key: "allowed-pubkeys"), and the list of
	// GitHub repos to poll for Actions jobs (key: "actions-repos").
	// Empty disables OIDC, explicit pubkey auth, and Actions polling.
	AuthConfigMap string

	MaxBlipsPerUser int

	// HostPrincipals are the hostnames/IPs used for gateway identification.
	HostPrincipals []string

	// ExternalHost is the public hostname for the gateway, used in
	// reconnect instructions shown to users (e.g. "ssh blip-xxx@<host>").
	// When empty, reconnect messages fall back to <gateway-host> placeholder.
	ExternalHost string

	// VMRegisterSA is the name of the Kubernetes ServiceAccount used by
	// VMs to authenticate during key registration. When set, the gateway
	// creates a TokenReviewer that validates SA tokens from this account.
	VMRegisterSA string

	LoginGraceTime    time.Duration
	MaxAuthTries      int
	KeepAliveInterval time.Duration
	KeepAliveMax      int

	// HTTPListenAddr is the address for the HTTP server that serves health
	// checks. Default: ":8080".
	HTTPListenAddr string

	// Actions configures the GitHub Actions polling handler. When nil (or
	// GitHubAppID is 0), Actions polling is disabled.
	Actions *ActionsConfig
}

// ActionsConfig holds the configuration for the GitHub Actions polling
// integration. When enabled, the gateway polls the GitHub API for queued
// workflow jobs and allocates Blip VMs as just-in-time self-hosted runners.
// The list of repos to poll is read from the auth ConfigMap (key: "actions-repos").
type ActionsConfig struct {
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

	// PollInterval is how often to poll for queued jobs. Default: 10s.
	PollInterval time.Duration
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

	// Create the TokenReviewer for _register SA token validation.
	var tokenReviewer auth.TokenReviewer
	if cfg.VMRegisterSA != "" {
		var err error
		tokenReviewer, err = auth.NewKubeTokenReviewer(cfg.VMNamespace, cfg.VMRegisterSA)
		if err != nil {
			return fmt.Errorf("create token reviewer: %w", err)
		}
		slog.Info("VM registration token reviewer enabled",
			"expected_sa", cfg.VMRegisterSA,
			"namespace", cfg.VMNamespace,
		)
	}

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
		TokenReviewer:      tokenReviewer,
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

	// --- Actions poller (optional) ---
	var actionsPoller *ghactions.Poller
	if cfg.Actions != nil && cfg.Actions.GitHubAppID > 0 {
		if authWatcher == nil {
			return fmt.Errorf("actions polling requires --auth-configmap to be set (repos are read from the %q key)", auth.KeyActionsRepos)
		}

		ghClient, err := ghactions.NewGitHubClient(
			cfg.Actions.GitHubAppID,
			cfg.Actions.GitHubInstallID,
			cfg.Actions.GitHubKeyPath,
		)
		if err != nil {
			return fmt.Errorf("create GitHub client: %w", err)
		}

		annotator := ghactions.NewVMAnnotator(vmcl.Writer(), cfg.VMNamespace)

		actionsMaxDuration := cfg.Actions.MaxSessionDuration
		if actionsMaxDuration <= 0 {
			actionsMaxDuration = int(ghactions.DefaultActionsTTL.Seconds())
		}

		actionsPoller = ghactions.NewPoller(ghactions.PollerConfig{
			VMClaimer:          vmcl,
			RunnerConfigStore:  annotator,
			TokenProvider:      ghClient,
			JobsProvider:       ghClient,
			RepoProvider:       authWatcher,
			VMPoolName:         cfg.VMPoolName,
			RunnerLabels:       cfg.Actions.RunnerLabels,
			MaxSessionDuration: actionsMaxDuration,
			PodName:            cfg.PodName,
			PollInterval:       cfg.Actions.PollInterval,
		})

		slog.Info("github actions poller enabled",
			"runner_labels", cfg.Actions.RunnerLabels,
			"actions_max_session", actionsMaxDuration,
			"poll_interval", cfg.Actions.PollInterval,
		)
	}

	httpAddr := cfg.HTTPListenAddr
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	// shuttingDown is set to 1 when a shutdown signal is received.
	var shuttingDown atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler(actionsPoller))
	mux.HandleFunc("/readyz", readyzHandler(actionsPoller, &shuttingDown))

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
		"actions_enabled", actionsPoller != nil,
	)

	// Start HTTP server in background.
	httpErrCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpErrCh <- err
		}
	}()

	select {
	case err := <-httpErrCh:
		return fmt.Errorf("HTTP server failed to start: %w", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Start actions poller in background.
	if actionsPoller != nil {
		go actionsPoller.Run(ctx)
	}

	const drainTimeout = 30 * time.Second

	sshDone := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, starting graceful shutdown",
			"signal", sig.String(),
			"drain_timeout", drainTimeout.String(),
		)

		shuttingDown.Store(1)

		// Cancel the main context — stops poller and SSH listener.
		cancel()

		mgr.NotifyShutdown()

		httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpShutdownCancel()
		if err := httpServer.Shutdown(httpShutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}

		// Drain in-flight poller goroutines.
		if actionsPoller != nil {
			pollerDrainDone := make(chan struct{})
			go func() {
				actionsPoller.WaitForPending()
				close(pollerDrainDone)
			}()
			select {
			case <-pollerDrainDone:
				slog.Info("actions poller goroutines drained")
			case <-time.After(drainTimeout):
				slog.Warn("poller drain timeout, some operations may be interrupted")
			}
		}

		select {
		case <-sshDone:
			slog.Info("ssh server stopped, all sessions drained")
		case <-time.After(drainTimeout):
			slog.Warn("session drain timeout, forcing exit")
			os.Exit(0)
		}
	}()

	// Route incoming SSH connections: VM management commands
	// (_blip/_register users) go to the command handler; everything
	// else goes through the normal session proxy flow.
	connHandler := func(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		if session.IsVMCommandConnection(serverConn) {
			mgr.HandleVMCommand(ctx, serverConn, chans, reqs)
			return
		}
		mgr.HandleConnection(ctx, serverConn, chans, reqs)
	}

	err = srv.Serve(ctx, connHandler)
	close(sshDone)
	return err
}

// healthzHandler returns an HTTP handler that always reports healthy.
func healthzHandler(poller *ghactions.Poller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if poller != nil {
			resp["active_actions_sessions"] = poller.ActiveSessionCount()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// readyzHandler returns an HTTP handler that reports readiness.
func readyzHandler(poller *ghactions.Poller, shuttingDown *atomic.Int32) http.HandlerFunc {
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
		if poller != nil {
			resp["active_actions_sessions"] = poller.ActiveSessionCount()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// vmKeyResolverAdapter adapts vm.Client to the auth.VMKeyResolver interface.
type vmKeyResolverAdapter struct {
	vmClient *vm.Client
}

func (a *vmKeyResolverAdapter) ResolveRootIdentity(fingerprint string) (string, string, error) {
	return a.vmClient.ResolveRootIdentity(context.Background(), fingerprint)
}
