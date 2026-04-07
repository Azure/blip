package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	VMNamespace        string
	VMPoolName         string
	PodName            string
	MaxSessionDuration time.Duration

	// AuthConfigMap is the name of the ConfigMap (in VMNamespace) that holds
	// the allowed GitHub Actions repository list (key: "allowed-repos") and
	// explicitly allowed SSH public keys (key: "allowed-pubkeys").
	// Empty disables OIDC and explicit pubkey auth.
	AuthConfigMap string

	MaxBlipsPerUser int

	// HostPrincipals are the hostnames/IPs used for gateway identification.
	HostPrincipals []string

	LoginGraceTime    time.Duration
	MaxAuthTries      int
	KeepAliveInterval time.Duration
	KeepAliveMax      int
}

func RunGateway(cfg *GatewayConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the ConfigMap-backed auth watcher for OIDC and explicit pubkey auth.
	var authWatcher *auth.AuthWatcher
	if cfg.AuthConfigMap != "" {
		var err error
		authWatcher, err = auth.NewAuthWatcher(ctx, cfg.VMNamespace, cfg.AuthConfigMap)
		if err != nil {
			return fmt.Errorf("start auth watcher: %w", err)
		}
	}

	srv, err := server.New(server.Config{
		ListenAddr:         cfg.ListenAddr,
		HostKeyPath:        cfg.HostKeyPath,
		PodName:            cfg.PodName,
		MaxSessionDuration: cfg.MaxSessionDuration,
		LoginGraceTime:     cfg.LoginGraceTime,
		MaxAuthTries:       cfg.MaxAuthTries,
		AuthWatcher:        authWatcher,
	})
	if err != nil {
		return err
	}

	// Generate an ephemeral key pair for dialing upstream VMs.
	upstreamSigner, err := generateEphemeralSigner()
	if err != nil {
		return fmt.Errorf("generate ephemeral upstream key: %w", err)
	}
	slog.Info("ephemeral upstream key generated",
		"fingerprint", ssh.FingerprintSHA256(upstreamSigner.PublicKey()),
	)

	vmcl, err := vm.New(ctx, cfg.VMNamespace)
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	gatewayHost := ""
	if len(cfg.HostPrincipals) > 0 {
		gatewayHost = cfg.HostPrincipals[0]
	}

	mgr := session.New(session.Config{
		GatewaySigner:      upstreamSigner,
		GatewayHost:        gatewayHost,
		VMClient:           vmcl,
		VMPoolName:         cfg.VMPoolName,
		PodName:            cfg.PodName,
		MaxBlipsPerUser:    cfg.MaxBlipsPerUser,
		MaxSessionDuration: cfg.MaxSessionDuration,
		KeepAliveInterval:  cfg.KeepAliveInterval,
		KeepAliveMax:       cfg.KeepAliveMax,
	})

	slog.Info("ssh-gateway starting",
		"listen", cfg.ListenAddr,
		"namespace", cfg.VMNamespace,
		"pool", cfg.VMPoolName,
		"max_session", cfg.MaxSessionDuration.String(),
		"github_actions_auth", authWatcher != nil,
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

		done := make(chan struct{})
		go func() {
			<-done
		}()

		select {
		case <-done:
			slog.Info("all sessions drained, exiting")
		case <-time.After(drainTimeout):
			slog.Warn("session drain timeout, forcing exit")
		}
		os.Exit(0)
	}()

	return srv.Serve(ctx, mgr.HandleConnection)
}

// generateEphemeralSigner creates a fresh Ed25519 key pair for upstream VM connections.
func generateEphemeralSigner() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create ephemeral signer: %w", err)
	}
	return signer, nil
}
