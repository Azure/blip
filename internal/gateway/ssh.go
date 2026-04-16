package gateway

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
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

	// AuthenticatorURL is the URL of the web authenticator for device-flow
	// SSH authentication. When set and an unrecognized pubkey connects, the
	// user is shown a URL to authenticate in their browser. The gateway
	// blocks until the login workflow creates a matching auth session secret.
	AuthenticatorURL string

	// HTTPS is the optional configuration for the HTTPS API server.
	// When non-nil, the gateway starts an additional TLS listener with
	// OIDC-authenticated endpoints.
	HTTPS *HTTPSConfig

	// Actions configures the GitHub Actions polling handler. When nil,
	// Actions polling is disabled.
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
// Authentication is via a GitHub Personal Access Token stored in a Kubernetes
// Secret and watched via an informer.
type ActionsConfig struct {
	// PATSecretName is the name of the Kubernetes Secret containing the
	// GitHub PAT in a "token" key. The Secret is watched via the shared
	// informer cache so token rotations are picked up immediately.
	PATSecretName string

	// RunnerLabels are the self-hosted runner labels to match against
	// workflow_job labels (e.g. ["self-hosted", "blip"]).
	RunnerLabels []string
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

	// Set up device-flow auth components if authenticator URL is configured.
	var authSessionWatcher *auth.AuthSessionWatcher
	var pendingFingerprints *auth.PendingFingerprints
	var jwtSigningKeyProvider *lazySigningKeyProvider
	jwtIssuer := cfg.ExternalHost

	if cfg.AuthenticatorURL != "" {
		var err error
		authSessionWatcher, err = auth.NewAuthSessionWatcher(ctx, cfg.KubeCache, cfg.VMNamespace)
		if err != nil {
			return fmt.Errorf("create auth session watcher: %w", err)
		}
		pendingFingerprints = auth.NewPendingFingerprints(ctx)
		jwtSigningKeyProvider = &lazySigningKeyProvider{}

		if cfg.HTTPS == nil {
			return fmt.Errorf("--authenticator-url requires HTTPS to be configured (set --oidc-issuer-url)")
		}

		slog.Info("device flow auth enabled",
			"authenticator_url", cfg.AuthenticatorURL,
		)
	}

	// Increase MaxAuthTries when device flow is enabled, since SSH clients
	// may try multiple keys from ssh-agent before falling back to
	// keyboard-interactive.
	maxAuthTries := cfg.MaxAuthTries
	if cfg.AuthenticatorURL != "" && maxAuthTries < 6 {
		maxAuthTries = 6
	}

	srv, err := server.New(ctx, server.Config{
		ListenAddr:         cfg.ListenAddr,
		HostKeyPath:        cfg.HostKeyPath,
		PodName:            cfg.PodName,
		MaxSessionDuration: cfg.MaxSessionDuration,
		LoginGraceTime:     cfg.LoginGraceTime,
		MaxAuthTries:       maxAuthTries,
		AuthWatcher:        authWatcher,
		VMKeyResolver:      vmKeyResolver,
		TokenReviewer:      tokenReviewer,

		// Device flow auth parameters.
		AuthSessionWatcher:  authSessionWatcher,
		PendingFingerprints: pendingFingerprints,
		AuthenticatorURL:    cfg.AuthenticatorURL,
		JWTSigner:           jwtSigningKeyProvider,
		JWTIssuer:           jwtIssuer,
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

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("GET /healthz", healthzHandler(nil))
	httpMux.HandleFunc("GET /readyz", readyzHandler(nil, &shuttingDown))

	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      httpMux,
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
		var certWatcher *tlsCertWatcher
		var err error
		httpsServer, certWatcher, err = NewHTTPSServer(ctx, *cfg.HTTPS, cfg.KubeCache, cfg.KubeWriter, cfg.VMNamespace)
		if err != nil {
			return fmt.Errorf("create HTTPS server: %w", err)
		}

		// Wire the TLS cert watcher as the JWT signing key provider
		// for device-flow auth (the SSH server was created before the
		// HTTPS server, so the lazy provider bridges the gap).
		if jwtSigningKeyProvider != nil {
			jwtSigningKeyProvider.SetProvider(certWatcher)
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

	// Start the Actions runner backend if configured.
	var actionsRunner *actions.Runner
	if cfg.Actions != nil && cfg.Actions.PATSecretName != "" && len(cfg.ActionsRepos) > 0 {
		pat, err := actions.NewPATProvider(ctx, cfg.KubeCache, cfg.VMNamespace, cfg.Actions.PATSecretName)
		if err != nil {
			return fmt.Errorf("create PAT provider: %w", err)
		}

		actionsCfg := actions.Config{
			VMClient:     vmcl,
			Namespace:    cfg.VMNamespace,
			PoolName:     cfg.VMPoolName,
			PodName:      cfg.PodName,
			PAT:          pat,
			Repos:        cfg.ActionsRepos,
			RunnerLabels: cfg.Actions.RunnerLabels,
		}

		slog.Info("actions runner configured with PAT",
			"pat_secret", cfg.Actions.PATSecretName,
			"repos", cfg.ActionsRepos,
			"labels", cfg.Actions.RunnerLabels,
		)

		actionsRunner = actions.New(actionsCfg)
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
	//
	// For device-flow auth, connections with ExtPendingDeviceAuth block
	// here until the user completes browser authentication.
	connHandler := func(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		if session.IsVMCommandConnection(serverConn) {
			mgr.HandleVMCommand(ctx, serverConn, chans, reqs)
			return
		}

		// If this connection came through device-flow keyboard-interactive,
		// block until the auth session secret appears before proxying.
		if serverConn.Permissions != nil &&
			serverConn.Permissions.Extensions[auth.ExtPendingDeviceAuth] == "true" &&
			authSessionWatcher != nil {

			fingerprint := serverConn.Permissions.Extensions[auth.ExtDeviceFlowFingerprint]
			slog.Info("device flow: waiting for browser authentication",
				"remote", serverConn.RemoteAddr().String(),
				"fingerprint", fingerprint,
			)

			subject, err := authSessionWatcher.WaitForAuth(ctx, fingerprint, 5*time.Minute)
			if err != nil {
				slog.Info("device flow auth failed",
					"remote", serverConn.RemoteAddr().String(),
					"fingerprint", fingerprint,
					"error", err,
				)
				serverConn.Close()
				return
			}

			// Update the permissions with the authenticated identity.
			// Create a new map to avoid data races with any concurrent
			// readers of the extensions map.
			newExts := make(map[string]string, len(serverConn.Permissions.Extensions))
			for k, v := range serverConn.Permissions.Extensions {
				newExts[k] = v
			}
			newExts[auth.ExtIdentity] = fmt.Sprintf("device:%s", subject)
			delete(newExts, auth.ExtPendingDeviceAuth)
			serverConn.Permissions.Extensions = newExts

			slog.Info("device flow auth succeeded",
				"remote", serverConn.RemoteAddr().String(),
				"fingerprint", fingerprint,
				"subject", subject,
			)
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

// lazySigningKeyProvider wraps a tlsCertWatcher that may not be available at
// construction time (the HTTPS server starts after the SSH server). The
// underlying provider is set once the HTTPS server is created.
type lazySigningKeyProvider struct {
	mu       sync.Mutex
	provider auth.SigningKeyProvider
}

func (l *lazySigningKeyProvider) SetProvider(p auth.SigningKeyProvider) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.provider = p
}

func (l *lazySigningKeyProvider) GetSigningKey() crypto.Signer {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.provider == nil {
		return nil
	}
	return l.provider.GetSigningKey()
}
