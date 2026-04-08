package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/project-unbounded/blip/internal/controllers/deallocation"
	"github.com/project-unbounded/blip/internal/controllers/keygen"
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
		namespace      string
		poolName       string
		leaseNamespace string
		leaseName      string
	)

	cmd := &cobra.Command{
		Use:   "blip-controller",
		Short: "Kubernetes controller for Blip VM lifecycle management",
		Long:  "Manages SSH host key generation and VM deallocation for the Blip platform.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("lease-namespace") {
				leaseNamespace = namespace
			}
			return run(namespace, poolName, leaseNamespace, leaseName)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&namespace, "namespace", envOrDefault("VM_NAMESPACE", "blip"), "Kubernetes namespace for VMs (env: VM_NAMESPACE)")
	cmd.Flags().StringVar(&poolName, "pool-name", envOrDefault("VM_POOL_NAME", "default"), "VM pool name (env: VM_POOL_NAME)")
	cmd.Flags().StringVar(&leaseNamespace, "lease-namespace", envOrDefault("LEASE_NAMESPACE", ""), "Namespace for leader election lease; defaults to --namespace (env: LEASE_NAMESPACE)")
	cmd.Flags().StringVar(&leaseName, "lease-name", envOrDefault("LEASE_NAME", "blip-controller"), "Name of the leader election lease (env: LEASE_NAME)")

	return cmd
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(namespace, poolName, leaseNamespace, leaseName string) error {
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
				namespace: {},
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

	err = deallocation.Add(mgr, namespace, poolName)
	if err != nil {
		return fmt.Errorf("adding deallocation controller: %w", err)
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
