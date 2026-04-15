package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/server"
	"github.com/project-unbounded/blip/internal/gateway/session"
	"github.com/project-unbounded/blip/internal/gateway/vm"
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

	slog.Info("ssh-gateway starting",
		"listen", cfg.ListenAddr,
		"namespace", cfg.VMNamespace,
		"pool", cfg.VMPoolName,
		"max_session", cfg.MaxSessionDuration.String(),
		"oidc_auth", authWatcher != nil,
		"auth_configmap", cfg.AuthConfigMap,
	)

	// Maximum time to wait for active sessions to drain after a signal.
	const drainTimeout = 30 * time.Second

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, starting graceful shutdown",
			"signal", sig.String(),
			"drain_timeout", drainTimeout.String(),
		)

		cancel()
		srv.Close()
		mgr.NotifyShutdown()

		time.Sleep(drainTimeout)
		slog.Warn("session drain timeout, forcing exit")
		os.Exit(0)
	}()

	return srv.Serve(ctx, mgr.HandleConnection)
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
