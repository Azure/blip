package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/server"
	"github.com/project-unbounded/blip/internal/gateway/session"
	"github.com/project-unbounded/blip/internal/gateway/vm"
	"github.com/project-unbounded/blip/internal/sshca"
)

type GatewayConfig struct {
	ListenAddr         string
	CAKeyPath          string
	CAPubKeyPath       string
	HostKeyPath        string
	VMNamespace        string
	VMPoolName         string
	PodName            string
	MaxSessionDuration time.Duration

	// AllowedReposConfigMap is the name of the ConfigMap (in VMNamespace) that holds
	// the allowed GitHub Actions repository list. Empty disables OIDC auth.
	AllowedReposConfigMap string

	MaxBlipsPerUser int

	// HostPrincipals are the hostnames/IPs embedded in the host certificate for client verification.
	HostPrincipals []string

	LoginGraceTime    time.Duration
	MaxAuthTries      int
	KeepAliveInterval time.Duration
	KeepAliveMax      int
}

func RunGateway(cfg *GatewayConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the ConfigMap-backed repo watcher for GitHub Actions OIDC auth.
	var repoWatcher *auth.RepoWatcher
	if cfg.AllowedReposConfigMap != "" {
		var err error
		repoWatcher, err = auth.NewRepoWatcher(ctx, cfg.VMNamespace, cfg.AllowedReposConfigMap)
		if err != nil {
			return fmt.Errorf("start repo watcher: %w", err)
		}
	}

	srv, err := server.New(server.Config{
		ListenAddr:         cfg.ListenAddr,
		CAKeyPath:          cfg.CAKeyPath,
		CAPubKeyPath:       cfg.CAPubKeyPath,
		HostKeyPath:        cfg.HostKeyPath,
		PodName:            cfg.PodName,
		HostPrincipals:     cfg.HostPrincipals,
		MaxSessionDuration: cfg.MaxSessionDuration,
		LoginGraceTime:     cfg.LoginGraceTime,
		MaxAuthTries:       cfg.MaxAuthTries,
		RepoWatcher:        repoWatcher,
	})
	if err != nil {
		return err
	}

	caSigner, err := loadSigner(cfg.CAKeyPath, "CA key")
	if err != nil {
		return err
	}

	keyID := fmt.Sprintf("gateway:%s", cfg.PodName)
	upstreamSigner, cert, err := sshca.GenerateAndSignEphemeralKey(
		caSigner,
		keyID,
		[]string{"runner"},
		cfg.MaxSessionDuration+1*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("generate ephemeral gateway cert: %w", err)
	}
	slog.Info("ephemeral gateway certificate generated",
		"key_id", cert.KeyId,
		"serial", cert.Serial,
		"valid_before", time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
	)

	vmcl, err := vm.New(ctx, cfg.VMNamespace)
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	caPubKeyData, err := os.ReadFile(cfg.CAPubKeyPath)
	if err != nil {
		return fmt.Errorf("read CA public key for VM injection: %w", err)
	}
	caPubKey := strings.TrimSpace(string(caPubKeyData))

	gatewayHost := ""
	if len(cfg.HostPrincipals) > 0 {
		gatewayHost = cfg.HostPrincipals[0]
	}

	mgr := session.New(session.Config{
		GatewaySigner:      upstreamSigner,
		CASigner:           caSigner,
		CAPubKey:           caPubKey,
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
		"github_actions_auth", repoWatcher != nil,
		"allowed_repos_configmap", cfg.AllowedReposConfigMap,
		"ca_cert_enabled", true,
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

func loadSigner(path, label string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", label, path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	return signer, nil
}
