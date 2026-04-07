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
		vmNamespace        string
		vmPoolName         string
		podName            string
		maxSessionDuration int
		maxBlipsPerUser    int
		authConfigMap      string
		hostPrincipals     []string
	)

	cmd := &cobra.Command{
		Use:   "ssh-gateway",
		Short: "Blip SSH gateway server",
		Long:  "SSH gateway that authenticates users and proxies connections to Blip VMs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxSessionDuration <= 0 {
				return fmt.Errorf("--max-session-duration must be greater than 0, got %d", maxSessionDuration)
			}
			if hostKeyPath == "" {
				return fmt.Errorf("--host-key-path must be set (path to stable host key shared across replicas)")
			}

			cfg := &sshgw.GatewayConfig{
				ListenAddr:         listenAddr,
				HostKeyPath:        hostKeyPath,
				VMNamespace:        vmNamespace,
				VMPoolName:         vmPoolName,
				PodName:            podName,
				MaxSessionDuration: time.Duration(maxSessionDuration) * time.Second,
				MaxBlipsPerUser:    maxBlipsPerUser,
				AuthConfigMap:      authConfigMap,
				HostPrincipals:     hostPrincipals,
				LoginGraceTime:     30 * time.Second,
				MaxAuthTries:       3,
				KeepAliveInterval:  60 * time.Second,
				KeepAliveMax:       3,
			}

			return sshgw.RunGateway(cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&listenAddr, "listen-address", envOrDefault("LISTEN_ADDRESS", ":2222"), "TCP address to listen on (env: LISTEN_ADDRESS)")
	cmd.Flags().StringVar(&hostKeyPath, "host-key-path", envOrDefault("HOST_KEY_PATH", "/etc/blip/host-key/host_key"), "Path to stable host key shared across replicas (env: HOST_KEY_PATH)")
	cmd.Flags().StringVar(&vmNamespace, "namespace", envOrDefault("VM_NAMESPACE", "blip"), "Kubernetes namespace for VMs (env: VM_NAMESPACE)")
	cmd.Flags().StringVar(&vmPoolName, "pool-name", envOrDefault("VM_POOL_NAME", "default"), "VM pool name (env: VM_POOL_NAME)")
	cmd.Flags().StringVar(&podName, "pod-name", envOrDefault("POD_NAME", "unknown"), "Pod name for identification (env: POD_NAME)")
	cmd.Flags().IntVar(&maxSessionDuration, "max-session-duration", envOrDefaultInt("MAX_SESSION_DURATION", 43200), "Maximum session duration in seconds (env: MAX_SESSION_DURATION)")
	cmd.Flags().IntVar(&maxBlipsPerUser, "max-blips-per-user", envOrDefaultInt("MAX_BLIPS_PER_USER", 0), "Per-user blip quota, 0 = unlimited (env: MAX_BLIPS_PER_USER)")
	cmd.Flags().StringVar(&authConfigMap, "auth-configmap", envOrDefault("AUTH_CONFIGMAP", ""), "ConfigMap name for auth config: allowed GitHub repos (key: \"allowed-repos\") and allowed SSH pubkeys (key: \"allowed-pubkeys\") (env: AUTH_CONFIGMAP)")
	cmd.Flags().StringSliceVar(&hostPrincipals, "host-principals", envOrDefaultStringSlice("GATEWAY_HOST_PRINCIPALS"), "Hostnames/IPs for gateway identification, comma-separated (env: GATEWAY_HOST_PRINCIPALS)")

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
