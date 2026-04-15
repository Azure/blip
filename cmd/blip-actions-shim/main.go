package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/project-unbounded/blip/internal/gateway/vm"
	"github.com/project-unbounded/blip/internal/webhook"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		listenAddr         string
		webhookSecret      string
		githubAppID        int64
		githubInstallID    int64
		githubKeyPath      string
		vmNamespace        string
		vmPoolName         string
		podName            string
		maxSessionDuration int
		runnerLabels       []string
	)

	cmd := &cobra.Command{
		Use:   "blip-actions-shim",
		Short: "GitHub Actions webhook handler for Blip",
		Long:  "Receives GitHub workflow_job webhooks and allocates Blip VMs as just-in-time self-hosted runners.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if githubAppID <= 0 {
				return fmt.Errorf("--github-app-id is required")
			}
			if githubInstallID <= 0 {
				return fmt.Errorf("--github-install-id is required")
			}
			if githubKeyPath == "" {
				return fmt.Errorf("--github-key-path is required")
			}
			if maxSessionDuration <= 0 {
				return fmt.Errorf("--max-session-duration must be > 0")
			}
			if len(runnerLabels) == 0 {
				return fmt.Errorf("--runner-labels is required (e.g. 'self-hosted,blip')")
			}
			if webhookSecret == "" {
				slog.Warn("SECURITY WARNING: --webhook-secret is not set; webhook payloads will not be verified")
			}

			return run(runConfig{
				listenAddr:         listenAddr,
				webhookSecret:      webhookSecret,
				githubAppID:        githubAppID,
				githubInstallID:    githubInstallID,
				githubKeyPath:      githubKeyPath,
				vmNamespace:        vmNamespace,
				vmPoolName:         vmPoolName,
				podName:            podName,
				maxSessionDuration: maxSessionDuration,
				runnerLabels:       runnerLabels,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&listenAddr, "listen-address", envOrDefault("LISTEN_ADDRESS", ":8080"), "HTTP address to listen on (env: LISTEN_ADDRESS)")
	cmd.Flags().StringVar(&webhookSecret, "webhook-secret", envOrDefault("WEBHOOK_SECRET", ""), "GitHub webhook secret for signature validation (env: WEBHOOK_SECRET)")
	cmd.Flags().Int64Var(&githubAppID, "github-app-id", envOrDefaultInt64("GITHUB_APP_ID", 0), "GitHub App ID (env: GITHUB_APP_ID)")
	cmd.Flags().Int64Var(&githubInstallID, "github-install-id", envOrDefaultInt64("GITHUB_INSTALL_ID", 0), "GitHub App installation ID (env: GITHUB_INSTALL_ID)")
	cmd.Flags().StringVar(&githubKeyPath, "github-key-path", envOrDefault("GITHUB_KEY_PATH", ""), "Path to GitHub App PEM private key (env: GITHUB_KEY_PATH)")
	cmd.Flags().StringVar(&vmNamespace, "namespace", envOrDefault("VM_NAMESPACE", "blip"), "Kubernetes namespace for blips (env: VM_NAMESPACE)")
	cmd.Flags().StringVar(&vmPoolName, "pool-name", envOrDefault("VM_POOL_NAME", "default"), "Blip pool name (env: VM_POOL_NAME)")
	cmd.Flags().StringVar(&podName, "pod-name", envOrDefault("POD_NAME", "blip-actions-shim"), "Pod name for identification (env: POD_NAME)")
	cmd.Flags().IntVar(&maxSessionDuration, "max-session-duration", envOrDefaultInt("MAX_SESSION_DURATION", 3600), "Maximum runner session duration in seconds (env: MAX_SESSION_DURATION)")
	cmd.Flags().StringSliceVar(&runnerLabels, "runner-labels", envOrDefaultStringSlice("RUNNER_LABELS"), "Runner labels to match against workflow_job labels, comma-separated (env: RUNNER_LABELS)")

	return cmd
}

type runConfig struct {
	listenAddr         string
	webhookSecret      string
	githubAppID        int64
	githubInstallID    int64
	githubKeyPath      string
	vmNamespace        string
	vmPoolName         string
	podName            string
	maxSessionDuration int
	runnerLabels       []string
}

func run(cfg runConfig) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Initialize the GitHub App client.
	ghClient, err := webhook.NewGitHubClient(cfg.githubAppID, cfg.githubInstallID, cfg.githubKeyPath)
	if err != nil {
		return fmt.Errorf("create GitHub client: %w", err)
	}

	// Initialize the VM client (in-cluster, with informer cache).
	vmClient, err := vm.New(ctx, cfg.vmNamespace)
	if err != nil {
		return fmt.Errorf("create VM client: %w", err)
	}

	// Initialize the VM annotator for patching runner config.
	// We need a direct Kubernetes client for patching — reuse the same approach as vm.New
	// but we only need a writer client.
	annotator, err := newAnnotator(cfg.vmNamespace)
	if err != nil {
		return fmt.Errorf("create VM annotator: %w", err)
	}

	// Create the webhook handler.
	handler := webhook.NewHandler(webhook.HandlerConfig{
		WebhookSecret:      []byte(cfg.webhookSecret),
		VMClaimer:          vmClient,
		RunnerConfigStore:  annotator,
		TokenProvider:      ghClient,
		VMPoolName:         cfg.vmPoolName,
		RunnerLabels:       cfg.runnerLabels,
		MaxSessionDuration: cfg.maxSessionDuration,
		PodName:            cfg.podName,
	})

	mux := http.NewServeMux()
	mux.Handle("/webhook", handler)
	mux.HandleFunc("/healthz", handler.Healthz())
	mux.HandleFunc("/readyz", handler.Healthz())

	server := &http.Server{
		Addr:         cfg.listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in background.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("blip-actions-shim starting",
			"address", cfg.listenAddr,
			"pool", cfg.vmPoolName,
			"namespace", cfg.vmNamespace,
			"runner_labels", cfg.runnerLabels,
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or error.
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("HTTP server error: %w", err)
	}

	// Graceful shutdown with 10s timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("HTTP server shutdown: %w", err)
	}

	// Drain in-flight async goroutines (VM claims/releases) before exiting.
	handler.WaitForPending()

	slog.Info("blip-actions-shim stopped")
	return nil
}

// newAnnotator creates a VMAnnotator using an in-cluster Kubernetes client.
func newAnnotator(namespace string) (*webhook.VMAnnotator, error) {
	cfg, err := restConfig()
	if err != nil {
		return nil, err
	}

	s, err := newScheme()
	if err != nil {
		return nil, err
	}

	writer, err := newClient(cfg, s)
	if err != nil {
		return nil, err
	}

	return webhook.NewVMAnnotator(writer, namespace), nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		slog.Error("invalid integer environment variable", "key", key, "value", v)
		os.Exit(1)
	}
	return n
}

func envOrDefaultInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		slog.Error("invalid integer environment variable", "key", key, "value", v)
		os.Exit(1)
	}
	return n
}

func envOrDefaultStringSlice(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var result []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
