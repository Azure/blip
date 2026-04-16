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

	// OIDCConfigMapName is the name of the ConfigMap watched for OIDC auth
	// configuration. When non-empty, the gateway creates an OIDCConfigWatcher
	// and starts the HTTPS server. The ConfigMap may be empty initially;
	// OIDC auth activates when valid configuration data is added.
	OIDCConfigMapName string

	// HTTPS is the optional configuration for the HTTPS API server.
	// When non-nil, the gateway starts an additional TLS listener with
	// OIDC-authenticated endpoints. The OIDCConfigWatcher must be set in
	// HTTPS.OIDCConfig.
	HTTPS *HTTPSConfig

	// KubeWriter is the controller-runtime client used for Kubernetes write
	// operations. It is created by vm.NewKubeClients in main and shared
	// across components.
	KubeWriter client.Client

	// KubeCache is the controller-runtime informer cache. It is created by
	// vm.NewKubeClients in main and shared across components (e.g. the VM
	// client and the HTTPS API server).
	KubeCache crcache.Cache
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

	// Create the OIDCConfigWatcher if a ConfigMap name is specified.
	// This watches the named ConfigMap for OIDC auth settings and manages
	// the OIDC verifier and TLS certificate watcher dynamically.
	var oidcConfigWatcher *OIDCConfigWatcher
	if cfg.OIDCConfigMapName != "" {
		var err error
		oidcConfigWatcher, err = NewOIDCConfigWatcher(ctx, cfg.KubeCache, cfg.VMNamespace, cfg.OIDCConfigMapName)
		if err != nil {
			return fmt.Errorf("create oidc config watcher: %w", err)
		}
	}

	// Set up device-flow auth components. These are always created when an
	// OIDC ConfigMap is watched so that device-flow auth can be enabled at
	// runtime. When no OIDC config is present in the ConfigMap, the
	// keyboard-interactive callback returns an error and the auth session
	// watcher is idle.
	var authSessionWatcher *auth.AuthSessionWatcher
	var pendingFingerprints *auth.PendingFingerprints
	var deviceFlowProvider auth.DeviceFlowProvider
	jwtIssuer := cfg.ExternalHost

	if oidcConfigWatcher != nil {
		var err error
		authSessionWatcher, err = auth.NewAuthSessionWatcher(ctx, cfg.KubeCache, cfg.VMNamespace)
		if err != nil {
			return fmt.Errorf("create auth session watcher: %w", err)
		}
		pendingFingerprints = auth.NewPendingFingerprints(ctx)
		deviceFlowProvider = oidcConfigWatcher

		slog.Info("device flow auth infrastructure created (activates when OIDC ConfigMap is configured)")
	}

	// Increase MaxAuthTries when device flow infrastructure is available,
	// since SSH clients may try multiple keys from ssh-agent before falling
	// back to keyboard-interactive.
	maxAuthTries := cfg.MaxAuthTries
	if deviceFlowProvider != nil && maxAuthTries < 6 {
		maxAuthTries = 6
	}

	srv, err := server.New(ctx, server.Config{
		ListenAddr:         cfg.ListenAddr,
		HostKeyPath:        cfg.HostKeyPath,
		MaxSessionDuration: cfg.MaxSessionDuration,
		LoginGraceTime:     cfg.LoginGraceTime,
		MaxAuthTries:       maxAuthTries,
		AuthWatcher:        authWatcher,
		VMKeyResolver:      vmKeyResolver,
		TokenReviewer:      tokenReviewer,

		// Device flow auth parameters.
		AuthSessionWatcher:  authSessionWatcher,
		PendingFingerprints: pendingFingerprints,
		DeviceFlow:          deviceFlowProvider,
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
	httpMux.HandleFunc("GET /healthz", healthzHandler())
	httpMux.HandleFunc("GET /readyz", readyzHandler(&shuttingDown))

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

	// Start HTTPS API server in background when OIDC ConfigMap is watched.
	var httpsServer *http.Server
	if oidcConfigWatcher != nil {
		httpsAddr := ":8443"
		if cfg.HTTPS != nil && cfg.HTTPS.Addr != "" {
			httpsAddr = cfg.HTTPS.Addr
		}
		jwtIss := cfg.ExternalHost
		if cfg.HTTPS != nil && cfg.HTTPS.JWTIssuer != "" {
			jwtIss = cfg.HTTPS.JWTIssuer
		}
		httpsCfg := HTTPSConfig{
			Addr:       httpsAddr,
			JWTIssuer:  jwtIss,
			OIDCConfig: oidcConfigWatcher,
		}
		var err error
		httpsServer, err = NewHTTPSServer(ctx, httpsCfg, cfg.KubeWriter, cfg.VMNamespace)
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
		slog.Info("https api server started", "addr", httpsAddr)
	}

	// Note: GitHub Actions runner polling is now handled by the actions
	// controller in blip-controller. The gateway no longer manages runner
	// goroutines or in-memory job state.

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

// healthzHandler returns an HTTP handler that always reports healthy.
func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// readyzHandler returns an HTTP handler that reports readiness.
func readyzHandler(shuttingDown *atomic.Int32) http.HandlerFunc {
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
