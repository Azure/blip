package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/project-unbounded/blip/internal/controllers/actions"
	"github.com/project-unbounded/blip/internal/controllers/deallocation"
	"github.com/project-unbounded/blip/internal/controllers/keygen"
	"github.com/project-unbounded/blip/internal/controllers/sshpubkey"
	"github.com/project-unbounded/blip/internal/controllers/tlscert"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		namespace       string
		poolName        string
		leaseNamespace  string
		leaseName       string
		gatewayHostname string

		// GitHub Actions runner flags.
		actionsRepos     []string
		actionsPATSecret string
		runnerLabels     []string
		actionsPodName   string
	)

	cmd := &cobra.Command{
		Use:   "blip-controller",
		Short: "Kubernetes controller for Blip lifecycle management",
		Long:  "Manages SSH host key generation, SSH public key expiration, and blip deallocation for the Blip platform.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("lease-namespace") {
				leaseNamespace = namespace
			}
			return run(namespace, poolName, leaseNamespace, leaseName, gatewayHostname, actionsRepos, actionsPATSecret, runnerLabels, actionsPodName)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&namespace, "namespace", envOrDefault("VM_NAMESPACE", "blip"), "Kubernetes namespace for blips (env: VM_NAMESPACE)")
	cmd.Flags().StringVar(&poolName, "pool-name", envOrDefault("VM_POOL_NAME", "default"), "Blip pool name (env: VM_POOL_NAME)")
	cmd.Flags().StringVar(&leaseNamespace, "lease-namespace", envOrDefault("LEASE_NAMESPACE", ""), "Namespace for leader election lease; defaults to --namespace (env: LEASE_NAMESPACE)")
	cmd.Flags().StringVar(&leaseName, "lease-name", envOrDefault("LEASE_NAME", "blip-controller"), "Name of the leader election lease (env: LEASE_NAME)")
	cmd.Flags().StringVar(&gatewayHostname, "gateway-hostname", envOrDefault("GATEWAY_HOSTNAME", ""), "Gateway hostname for TLS certificate generation (env: GATEWAY_HOSTNAME)")

	// GitHub Actions runner flags.
	cmd.Flags().StringSliceVar(&actionsRepos, "actions-repos", envOrDefaultStringSlice("ACTIONS_REPOS"), "GitHub repos for Actions polling, comma-separated owner/repo (env: ACTIONS_REPOS)")
	cmd.Flags().StringVar(&actionsPATSecret, "github-pat-secret", envOrDefault("GITHUB_PAT_SECRET", ""), "Kubernetes Secret name containing the GitHub PAT in a 'token' key (env: GITHUB_PAT_SECRET)")
	cmd.Flags().StringSliceVar(&runnerLabels, "runner-labels", envOrDefaultStringSlice("RUNNER_LABELS"), "Runner labels for JIT runners, comma-separated (env: RUNNER_LABELS)")
	cmd.Flags().StringVar(&actionsPodName, "pod-name", envOrDefault("POD_NAME", "blip-controller"), "Pod name for identification in VM annotations (env: POD_NAME)")

	return cmd
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(namespace, poolName, leaseNamespace, leaseName, gatewayHostname string, actionsRepos []string, actionsPATSecret string, runnerLabels []string, actionsPodName string) error {
	s, err := newScheme()
	if err != nil {
		return fmt.Errorf("create scheme: %w", err)
	}

	logger := logr.FromSlogHandler(slog.Default().Handler())
	ctrl.SetLogger(logger)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: s,
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				namespace:               {},
				tlscert.PublicNamespace: {},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress: "0", // disable metrics server
		},
		HealthProbeBindAddress:        ":8081",
		LeaderElection:                true,
		LeaderElectionID:              leaseName,
		LeaderElectionNamespace:       leaseNamespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	err = keygen.Add(mgr, namespace)
	if err != nil {
		return fmt.Errorf("adding keygen controller: %w", err)
	}

	if gatewayHostname != "" {
		if err := tlscert.Add(mgr, namespace, gatewayHostname); err != nil {
			return fmt.Errorf("adding tlscert controller: %w", err)
		}
	}

	err = deallocation.Add(mgr, namespace, poolName)
	if err != nil {
		return fmt.Errorf("adding deallocation controller: %w", err)
	}

	if err := sshpubkey.Add(mgr, namespace); err != nil {
		return fmt.Errorf("adding sshpubkey controller: %w", err)
	}

	// Register the GitHub Actions runner controller if configured.
	if actionsPATSecret != "" && len(actionsRepos) > 0 {
		if len(runnerLabels) == 0 {
			return fmt.Errorf("--runner-labels is required when --github-pat-secret is set")
		}
		if err := actions.Add(mgr, actions.Config{
			Namespace:     namespace,
			PoolName:      poolName,
			PodName:       actionsPodName,
			PATSecretName: actionsPATSecret,
			Repos:         actionsRepos,
			RunnerLabels:  runnerLabels,
		}); err != nil {
			return fmt.Errorf("adding actions controller: %w", err)
		}
	}

	slog.Info("blip-controller starting")
	return mgr.Start(ctrl.SetupSignalHandler())
}

func newScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register core/v1: %w", err)
	}
	if err := kubevirtv1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register kubevirt/v1: %w", err)
	}
	return s, nil
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
