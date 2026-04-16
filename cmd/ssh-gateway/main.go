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
		hostPrincipals     []string
		externalHost       string
		vmRegisterSA       string

		// HTTP server for health checks.
		httpListenAddr string

		// HTTPS API server (enabled when OIDC ConfigMap is watched).
		httpsListenAddr   string
		oidcConfigMapName string
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

			// Enable HTTPS API server with dynamic OIDC config from ConfigMap.
			if oidcConfigMapName != "" {
				cfg.HTTPS = &sshgw.HTTPSConfig{
					Addr:      httpsListenAddr,
					JWTIssuer: externalHost,
				}
				// The OIDCConfigWatcher is created in RunGateway after the
				// cache is started; we pass the ConfigMap name via a field.
				cfg.OIDCConfigMapName = oidcConfigMapName
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
	cmd.Flags().StringSliceVar(&hostPrincipals, "host-principals", envOrDefaultStringSlice("GATEWAY_HOST_PRINCIPALS"), "Hostnames/IPs for gateway identification, comma-separated (env: GATEWAY_HOST_PRINCIPALS)")
	cmd.Flags().StringVar(&externalHost, "external-host", envOrDefault("GATEWAY_EXTERNAL_HOST", ""), "Public hostname for the gateway, shown in reconnect instructions (env: GATEWAY_EXTERNAL_HOST)")
	cmd.Flags().StringVar(&vmRegisterSA, "vm-register-sa", envOrDefault("VM_REGISTER_SA", "vm-register"), "ServiceAccount name for VM registration token validation (env: VM_REGISTER_SA)")

	// HTTP server flags.
	cmd.Flags().StringVar(&httpListenAddr, "http-address", envOrDefault("HTTP_ADDRESS", ":8080"), "HTTP address for health checks (env: HTTP_ADDRESS)")

	// HTTPS API server flags. The OIDC auth configuration (issuer URL,
	// audience, TLS secret name, authenticator URL) is read from the named
	// ConfigMap at runtime, allowing reconfiguration without restarting.
	cmd.Flags().StringVar(&httpsListenAddr, "https-address", envOrDefault("HTTPS_ADDRESS", ":8443"), "HTTPS address for the API server (env: HTTPS_ADDRESS)")
	cmd.Flags().StringVar(&oidcConfigMapName, "oidc-config", envOrDefault("OIDC_CONFIG", ""), "ConfigMap name for OIDC auth configuration (env: OIDC_CONFIG)")

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
