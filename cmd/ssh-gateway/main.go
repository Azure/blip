package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	sshgw "github.com/project-unbounded/blip/internal/gateway"
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
		hostKeyPath        string
		clientKeyPath      string
		vmNamespace        string
		vmPoolName         string
		podName            string
		maxSessionDuration int
		maxBlipsPerUser    int
		enableAuth         bool
		hostPrincipals     []string
		externalHost       string
		vmRegisterSA       string

		// HTTP server for health checks.
		httpListenAddr string

		// GitHub Actions polling integration (optional).
		githubAppID            int64
		githubInstallID        int64
		githubKeyPath          string
		runnerLabels           []string
		actionsSessionDuration int
		actionsPollInterval    int
	)

	cmd := &cobra.Command{
		Use:   "ssh-gateway",
		Short: "Blip SSH gateway server",
		Long:  "SSH gateway that authenticates users and proxies connections to blips.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxSessionDuration <= 0 {
				return fmt.Errorf("--max-session-duration must be greater than 0, got %d", maxSessionDuration)
			}
			if hostKeyPath == "" {
				return fmt.Errorf("--host-key-path must be set (path to stable host key shared across replicas)")
			}
			if clientKeyPath == "" {
				return fmt.Errorf("--client-key-path must be set (path to stable client key shared across replicas)")
			}

			cfg := &sshgw.GatewayConfig{
				ListenAddr:         listenAddr,
				HostKeyPath:        hostKeyPath,
				ClientKeyPath:      clientKeyPath,
				VMNamespace:        vmNamespace,
				VMPoolName:         vmPoolName,
				PodName:            podName,
				MaxSessionDuration: time.Duration(maxSessionDuration) * time.Second,
				MaxBlipsPerUser:    maxBlipsPerUser,
				EnableAuth:         enableAuth,
				HostPrincipals:     hostPrincipals,
				ExternalHost:       externalHost,
				VMRegisterSA:       vmRegisterSA,
				LoginGraceTime:     30 * time.Second,
				MaxAuthTries:       3,
				KeepAliveInterval:  60 * time.Second,
				KeepAliveMax:       3,
				HTTPListenAddr:     httpListenAddr,
			}

			// Enable GitHub Actions polling integration if configured.
			if githubAppID > 0 {
				if githubInstallID <= 0 {
					return fmt.Errorf("--github-install-id is required when --github-app-id is set")
				}
				if githubKeyPath == "" {
					return fmt.Errorf("--github-key-path is required when --github-app-id is set")
				}
				if len(runnerLabels) == 0 {
					return fmt.Errorf("--runner-labels is required when --github-app-id is set (e.g. 'self-hosted,blip')")
				}
				if !enableAuth {
					return fmt.Errorf("--enable-auth is required when --github-app-id is set (repos are read from BlipOwner CRs)")
				}
				cfg.Actions = &sshgw.ActionsConfig{
					GitHubAppID:        githubAppID,
					GitHubInstallID:    githubInstallID,
					GitHubKeyPath:      githubKeyPath,
					RunnerLabels:       runnerLabels,
					MaxSessionDuration: actionsSessionDuration,
					PollInterval:       time.Duration(actionsPollInterval) * time.Second,
				}
			}

			return sshgw.RunGateway(cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&listenAddr, "listen-address", envOrDefault("LISTEN_ADDRESS", ":2222"), "TCP address to listen on (env: LISTEN_ADDRESS)")
	cmd.Flags().StringVar(&hostKeyPath, "host-key-path", envOrDefault("HOST_KEY_PATH", "/etc/blip/host-key/host_key"), "Path to stable host key shared across replicas (env: HOST_KEY_PATH)")
	cmd.Flags().StringVar(&clientKeyPath, "client-key-path", envOrDefault("CLIENT_KEY_PATH", "/etc/blip/client-key/client_key"), "Path to stable client key shared across replicas (env: CLIENT_KEY_PATH)")
	cmd.Flags().StringVar(&vmNamespace, "namespace", envOrDefault("VM_NAMESPACE", "blip"), "Kubernetes namespace for blips (env: VM_NAMESPACE)")
	cmd.Flags().StringVar(&vmPoolName, "pool-name", envOrDefault("VM_POOL_NAME", "default"), "Blip pool name (env: VM_POOL_NAME)")
	cmd.Flags().StringVar(&podName, "pod-name", envOrDefault("POD_NAME", "unknown"), "Pod name for identification (env: POD_NAME)")
	cmd.Flags().IntVar(&maxSessionDuration, "max-session-duration", envOrDefaultInt("MAX_SESSION_DURATION", 43200), "Maximum session duration in seconds (env: MAX_SESSION_DURATION)")
	cmd.Flags().IntVar(&maxBlipsPerUser, "max-blips-per-user", envOrDefaultInt("MAX_BLIPS_PER_USER", 0), "Per-user blip quota, 0 = unlimited (env: MAX_BLIPS_PER_USER)")
	cmd.Flags().BoolVar(&enableAuth, "enable-auth", envOrDefaultBool("ENABLE_AUTH", false), "Enable BlipOwner CRD-based auth: OIDC providers, SSH pubkeys, and actions repos (env: ENABLE_AUTH)")
	cmd.Flags().StringSliceVar(&hostPrincipals, "host-principals", envOrDefaultStringSlice("GATEWAY_HOST_PRINCIPALS"), "Hostnames/IPs for gateway identification, comma-separated (env: GATEWAY_HOST_PRINCIPALS)")
	cmd.Flags().StringVar(&externalHost, "external-host", envOrDefault("GATEWAY_EXTERNAL_HOST", ""), "Public hostname for the gateway, shown in reconnect instructions (env: GATEWAY_EXTERNAL_HOST)")
	cmd.Flags().StringVar(&vmRegisterSA, "vm-register-sa", envOrDefault("VM_REGISTER_SA", "vm-register"), "ServiceAccount name for VM registration token validation (env: VM_REGISTER_SA)")

	// HTTP server flags.
	cmd.Flags().StringVar(&httpListenAddr, "http-address", envOrDefault("HTTP_ADDRESS", ":8080"), "HTTP address for health checks (env: HTTP_ADDRESS)")

	// GitHub Actions polling flags (optional).
	cmd.Flags().Int64Var(&githubAppID, "github-app-id", envOrDefaultInt64("GITHUB_APP_ID", 0), "GitHub App ID for Actions polling integration (env: GITHUB_APP_ID)")
	cmd.Flags().Int64Var(&githubInstallID, "github-install-id", envOrDefaultInt64("GITHUB_INSTALL_ID", 0), "GitHub App installation ID (env: GITHUB_INSTALL_ID)")
	cmd.Flags().StringVar(&githubKeyPath, "github-key-path", envOrDefault("GITHUB_KEY_PATH", ""), "Path to GitHub App PEM private key (env: GITHUB_KEY_PATH)")
	cmd.Flags().StringSliceVar(&runnerLabels, "runner-labels", envOrDefaultStringSlice("RUNNER_LABELS"), "Runner labels to match against workflow_job labels, comma-separated (env: RUNNER_LABELS)")
	cmd.Flags().IntVar(&actionsSessionDuration, "actions-session-duration", envOrDefaultInt("ACTIONS_SESSION_DURATION", 3600), "Maximum runner session duration in seconds (env: ACTIONS_SESSION_DURATION)")
	cmd.Flags().IntVar(&actionsPollInterval, "actions-poll-interval", envOrDefaultInt("ACTIONS_POLL_INTERVAL", 10), "How often to poll for queued jobs in seconds (env: ACTIONS_POLL_INTERVAL)")

	return cmd
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

func envOrDefaultBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}
