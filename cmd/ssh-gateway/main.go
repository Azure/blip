package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	sshgw "github.com/project-unbounded/blip/internal/gateway"
	"github.com/project-unbounded/blip/internal/gateway/vm"
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
		actionsRepos       []string
		hostPrincipals     []string
		externalHost       string
		vmRegisterSA       string

		// HTTP server for health checks.
		httpListenAddr string

		// HTTPS API server (optional, enabled when --oidc-issuer-url is set).
		httpsListenAddr   string
		tlsSecretName     string
		oidcIssuerURL     string
		oidcAudience      string
		githubAllowedOrgs []string

		// GitHub Actions polling integration (optional).
		githubAppID            int64
		githubInstallID        int64
		githubKeyPath          string
		runnerLabels           []string
		actionsSessionDuration int
		actionsPollInterval    int

		// GitHub Actions scale set integration (optional, mutually exclusive with polling).
		scalesetConfigURL   string
		scalesetTokenSecret string
		scalesetName        string
		scalesetMaxRunners  int
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

			// Create the shared controller-runtime Kubernetes clients.
			// These are passed into GatewayConfig so that both the VM client
			// and the HTTPS API server can share the same writer and cache.
			kubeWriter, kubeCache, err := vm.NewKubeClients(vmNamespace)
			if err != nil {
				return fmt.Errorf("create kubernetes clients: %w", err)
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
				HostPrincipals:     hostPrincipals,
				ActionsRepos:       actionsRepos,
				ExternalHost:       externalHost,
				VMRegisterSA:       vmRegisterSA,
				LoginGraceTime:     30 * time.Second,
				MaxAuthTries:       3,
				KeepAliveInterval:  60 * time.Second,
				KeepAliveMax:       3,
				HTTPListenAddr:     httpListenAddr,
				KubeWriter:         kubeWriter,
				KubeCache:          kubeCache,
			}

			// Enable HTTPS API server if OIDC issuer is configured.
			if oidcIssuerURL != "" {
				if tlsSecretName == "" {
					return fmt.Errorf("--tls-secret-name is required when --oidc-issuer-url is set")
				}
				if oidcAudience == "" {
					return fmt.Errorf("--oidc-audience is required when --oidc-issuer-url is set")
				}
				cfg.HTTPS = &sshgw.HTTPSConfig{
					Addr:               httpsListenAddr,
					TLSSecretName:      tlsSecretName,
					TLSSecretNamespace: vmNamespace,
					OIDCIssuerURL:      oidcIssuerURL,
					OIDCAudience:       oidcAudience,
					GitHubAllowedOrgs:  githubAllowedOrgs,
				}
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
				if len(actionsRepos) == 0 {
					return fmt.Errorf("--actions-repos is required when --github-app-id is set (e.g. 'my-org/my-repo')")
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

			// Enable GitHub Actions scale set integration if configured.
			if scalesetConfigURL != "" {
				if githubAppID > 0 {
					return fmt.Errorf("cannot use both --github-app-id and --scaleset-config-url; choose one mode")
				}
				if scalesetTokenSecret == "" {
					return fmt.Errorf("--scaleset-token-secret is required when --scaleset-config-url is set")
				}
				ssName := scalesetName
				if ssName == "" {
					ssName = "blip"
				}
				// Reuse --runner-labels for the scale set labels if provided.
				ssLabels := runnerLabels
				cfg.ScaleSet = &sshgw.ScaleSetConfig{
					ConfigURL:       scalesetConfigURL,
					TokenSecretName: scalesetTokenSecret,
					ScaleSetName:    ssName,
					RunnerLabels:    ssLabels,
					MaxRunners:      scalesetMaxRunners,
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
	cmd.Flags().StringSliceVar(&actionsRepos, "actions-repos", envOrDefaultStringSlice("ACTIONS_REPOS"), "GitHub repos for Actions polling, comma-separated owner/repo (env: ACTIONS_REPOS)")
	cmd.Flags().StringSliceVar(&hostPrincipals, "host-principals", envOrDefaultStringSlice("GATEWAY_HOST_PRINCIPALS"), "Hostnames/IPs for gateway identification, comma-separated (env: GATEWAY_HOST_PRINCIPALS)")
	cmd.Flags().StringVar(&externalHost, "external-host", envOrDefault("GATEWAY_EXTERNAL_HOST", ""), "Public hostname for the gateway, shown in reconnect instructions (env: GATEWAY_EXTERNAL_HOST)")
	cmd.Flags().StringVar(&vmRegisterSA, "vm-register-sa", envOrDefault("VM_REGISTER_SA", "vm-register"), "ServiceAccount name for VM registration token validation (env: VM_REGISTER_SA)")

	// HTTP server flags.
	cmd.Flags().StringVar(&httpListenAddr, "http-address", envOrDefault("HTTP_ADDRESS", ":8080"), "HTTP address for health checks (env: HTTP_ADDRESS)")

	// HTTPS API server flags (optional, enabled when --oidc-issuer-url is set).
	cmd.Flags().StringVar(&httpsListenAddr, "https-address", envOrDefault("HTTPS_ADDRESS", ":8443"), "HTTPS address for the API server (env: HTTPS_ADDRESS)")
	cmd.Flags().StringVar(&tlsSecretName, "tls-secret-name", envOrDefault("TLS_SECRET_NAME", "gateway-tls-key"), "Kubernetes Secret containing tls.crt and tls.key (env: TLS_SECRET_NAME)")
	cmd.Flags().StringVar(&oidcIssuerURL, "oidc-issuer-url", envOrDefault("OIDC_ISSUER_URL", ""), "Trusted OIDC issuer URL for API authentication (env: OIDC_ISSUER_URL)")
	cmd.Flags().StringVar(&oidcAudience, "oidc-audience", envOrDefault("OIDC_AUDIENCE", ""), "Expected OIDC audience claim (env: OIDC_AUDIENCE)")
	cmd.Flags().StringSliceVar(&githubAllowedOrgs, "github-allowed-orgs", envOrDefaultStringSlice("GITHUB_ALLOWED_ORGS"), "Comma-separated list of GitHub orgs allowed to authenticate via /auth/github (env: GITHUB_ALLOWED_ORGS)")

	// GitHub Actions polling flags (optional).
	cmd.Flags().Int64Var(&githubAppID, "github-app-id", envOrDefaultInt64("GITHUB_APP_ID", 0), "GitHub App ID for Actions polling integration (env: GITHUB_APP_ID)")
	cmd.Flags().Int64Var(&githubInstallID, "github-install-id", envOrDefaultInt64("GITHUB_INSTALL_ID", 0), "GitHub App installation ID (env: GITHUB_INSTALL_ID)")
	cmd.Flags().StringVar(&githubKeyPath, "github-key-path", envOrDefault("GITHUB_KEY_PATH", ""), "Path to GitHub App PEM private key (env: GITHUB_KEY_PATH)")
	cmd.Flags().StringSliceVar(&runnerLabels, "runner-labels", envOrDefaultStringSlice("RUNNER_LABELS"), "Runner labels to match against workflow_job labels, comma-separated (env: RUNNER_LABELS)")
	cmd.Flags().IntVar(&actionsSessionDuration, "actions-session-duration", envOrDefaultInt("ACTIONS_SESSION_DURATION", 3600), "Maximum runner session duration in seconds (env: ACTIONS_SESSION_DURATION)")
	cmd.Flags().IntVar(&actionsPollInterval, "actions-poll-interval", envOrDefaultInt("ACTIONS_POLL_INTERVAL", 10), "How often to poll for queued jobs in seconds (env: ACTIONS_POLL_INTERVAL)")

	// GitHub Actions scale set flags (optional, mutually exclusive with polling).
	cmd.Flags().StringVar(&scalesetConfigURL, "scaleset-config-url", envOrDefault("SCALESET_CONFIG_URL", ""), "GitHub repo/org URL for scale set mode (env: SCALESET_CONFIG_URL)")
	cmd.Flags().StringVar(&scalesetTokenSecret, "scaleset-token-secret", envOrDefault("SCALESET_TOKEN_SECRET", ""), "K8s Secret name for registration token (env: SCALESET_TOKEN_SECRET)")
	cmd.Flags().StringVar(&scalesetName, "scaleset-name", envOrDefault("SCALESET_NAME", "blip"), "Scale set name (env: SCALESET_NAME)")
	cmd.Flags().IntVar(&scalesetMaxRunners, "scaleset-max-runners", envOrDefaultInt("SCALESET_MAX_RUNNERS", 10), "Maximum concurrent runners for scale set (env: SCALESET_MAX_RUNNERS)")

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
