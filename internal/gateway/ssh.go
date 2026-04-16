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

	"github.com/project-unbounded/blip/internal/gateway/actions"
	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/server"
	"github.com/project-unbounded/blip/internal/gateway/session"
	"github.com/project-unbounded/blip/internal/gateway/vm"

	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type GatewayConfig struct {
	ListenAddr         string
	HostKeyPath        string
	ClientKeyPath      string
	VMNamespace        string
	VMPoolName         string
	PodName            string
	MaxSessionDuration time.Duration

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

	// HTTPS is the optional configuration for the HTTPS API server.
	// When non-nil, the gateway starts an additional TLS listener with
	// OIDC-authenticated endpoints.
	HTTPS *HTTPSConfig

	// Actions configures the GitHub Actions polling handler. When nil (or
	// GitHubAppID is 0), Actions polling is disabled.
	Actions *ActionsConfig

	// ScaleSet configures the GitHub Actions scale set listener. When nil,
	// scale set mode is disabled. Mutually exclusive with Actions.
	ScaleSet *ScaleSetConfig

	// KubeWriter is the controller-runtime client used for Kubernetes write
	// operations. It is created by vm.NewKubeClients in main and shared
	// across components.
	KubeWriter client.Client

	// KubeCache is the controller-runtime informer cache. It is created by
	// vm.NewKubeClients in main and shared across components (e.g. the VM
	// client and the HTTPS API server).
	KubeCache crcache.Cache

	// ActionsRepos is the static list of GitHub repos to poll for queued
	// Actions workflow jobs. Each entry is in "owner/repo" format. Used
	// when Actions polling is enabled.
	ActionsRepos []string
}

// ActionsConfig holds the configuration for the GitHub Actions polling
// integration. When enabled, the gateway polls the GitHub API for queued
// workflow jobs and allocates Blip VMs as just-in-time self-hosted runners.
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

// ScaleSetConfig holds the configuration for the GitHub Actions scale set
// listener integration. When enabled, the gateway uses the Runner Scale Set
// protocol to receive job assignments via long-poll from the Actions Service.
// This does not require a GitHub App -- only a registration token stored in
// a K8s Secret.
type ScaleSetConfig struct {
	// ConfigURL is the GitHub URL (repo or org) for the scale set.
	// e.g. "https://github.com/my-org/my-repo"
	ConfigURL string

	// TokenSecretName is the K8s Secret containing the registration token.
	// The Secret must have a "token" key.
	TokenSecretName string

	// ScaleSetName is the name for the runner scale set.
	ScaleSetName string

	// RunnerLabels are the labels for the scale set runners.
	RunnerLabels []string

	// MaxRunners is the maximum number of concurrent runners.
	MaxRunners int
}

// staticRepoProvider implements ghactions.RepoProvider with a static list.
type staticRepoProvider struct {
	repos []string
}

func (p *staticRepoProvider) ActionsRepos() []string {
	result := make([]string, len(p.repos))
	copy(result, p.repos)
	return result
}

func RunGateway(cfg *GatewayConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the ConfigMap-backed auth watcher for pubkey auth.
	authWatcher, err := auth.NewAuthWatcher(ctx, cfg.VMNamespace)
	if err != nil {
		return fmt.Errorf("start auth watcher: %w", err)
	}

	vmcl, err := vm.New(ctx, cfg.KubeWriter, cfg.KubeCache, cfg.VMNamespace)
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
		TokenReviewer:      tokenReviewer,
	})

	httpAddr := cfg.HTTPListenAddr
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	// shuttingDown is set to 1 when a shutdown signal is received.
	var shuttingDown atomic.Int32

	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      nil, // TODO
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

	// Start HTTPS API server in background (optional).
	var httpsServer *http.Server
	if cfg.HTTPS != nil {
		var err error
		httpsServer, err = NewHTTPSServer(ctx, *cfg.HTTPS, cfg.KubeCache, cfg.KubeWriter, cfg.VMNamespace)
		if err != nil {
			return fmt.Errorf("create HTTPS server: %w", err)
		}
		httpsErrCh := StartHTTPSServer(httpsServer)
		select {
		case err := <-httpsErrCh:
			return fmt.Errorf("HTTPS server failed to start: %w", err)
		case <-time.After(50 * time.Millisecond):
		}
		// Monitor for runtime errors.
		go func() {
			if err, ok := <-httpsErrCh; ok {
				slog.Error("https server error", "error", err)
			}
		}()
		slog.Info("https api server started", "addr", cfg.HTTPS.Addr)
	}

	// Start the Actions runner backend if the HTTPS server is enabled
	// (which means GitHub token secrets may be created via /auth/github).
	var actionsRunner *actions.Runner
	if cfg.HTTPS != nil && len(cfg.HTTPS.GitHubAllowedOrgs) > 0 {
		actionsRunner = actions.New(actions.Config{
			VMClient:  vmcl,
			KubeCache: cfg.KubeCache,
			Namespace: cfg.VMNamespace,
			PoolName:  cfg.VMPoolName,
			PodName:   cfg.PodName,
		})
		go func() {
			if err := actionsRunner.Start(ctx); err != nil {
				slog.Error("actions runner backend error", "error", err)
			}
		}()
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

		// Cancel the main context — stops poller, listener, and SSH listener.
		cancel()

		mgr.NotifyShutdown()

		httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpShutdownCancel()
		if err := httpServer.Shutdown(httpShutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}

		if httpsServer != nil {
			ShutdownHTTPSServer(httpsServer)
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

// activeSessionProvider abstracts session counting for health endpoints.
// Both Poller and Listener implement this interface.
type activeSessionProvider interface {
	ActiveSessionCount() int
}

// healthzHandler returns an HTTP handler that always reports healthy.
func healthzHandler(provider activeSessionProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if provider != nil {
			resp["active_actions_sessions"] = provider.ActiveSessionCount()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// readyzHandler returns an HTTP handler that reports readiness.
func readyzHandler(provider activeSessionProvider, shuttingDown *atomic.Int32) http.HandlerFunc {
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
		if provider != nil {
			resp["active_actions_sessions"] = provider.ActiveSessionCount()
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
