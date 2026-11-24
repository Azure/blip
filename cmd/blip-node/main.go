// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command blip-node is the node agent DaemonSet.
// +kubebuilder:rbac:groups=blip.dev,resources=blips;blipstates;blippools;blipnodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=blip.dev,resources=blipnodes,verbs=create;update
// +kubebuilder:rbac:groups=blip.dev,resources=blipnodes/status;blipstates/status,verbs=patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=extension-apiserver-authentication,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/internal/diskkey"
	"github.com/Azure/blip/internal/node"
	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

func main() {
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		dataDir        string
		poolSize       string
		insecure       []string
		streamListen   string
		streamClientCA string
		nvmeTransport  string
	)
	cmd := &cobra.Command{
		Use:          "blip-node",
		Short:        "Blip node agent",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch nvmeTransport {
			case "tcp", "auto", "rdma":
			default:
				return fmt.Errorf("--nvme-transport: %q is not tcp, auto, or rdma", nvmeTransport)
			}
			cfg := node.Config{
				NodeName: os.Getenv("NODE_NAME"),
				HostIP:   os.Getenv("HOST_IP"),
				DataDir:  dataDir,
				Insecure: insecure,
			}
			namespace := os.Getenv("POD_NAMESPACE")
			if cfg.NodeName == "" || cfg.HostIP == "" || namespace == "" {
				return fmt.Errorf("NODE_NAME, HOST_IP and POD_NAMESPACE must be set")
			}
			size, err := resource.ParseQuantity(poolSize)
			if err != nil {
				return fmt.Errorf("--pool-size: %w", err)
			}
			restCfg, err := ctrl.GetConfig()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if err := writableSysfs(); err != nil {
				return err
			}
			node.LoadKernelModules(ctx)
			rdma := false
			if nvmeTransport != "tcp" {
				node.LoadRDMAKernelModules(ctx)
				err := nvme.RDMAReady(cfg.HostIP)
				if err == nil && !nvme.Multipath() {
					err = errors.New("native multipath is off")
				}
				switch {
				case err == nil:
					rdma = true
				case nvmeTransport == "rdma":
					return fmt.Errorf("--nvme-transport=rdma: %w", err)
				default:
					slog.Warn("NVMe/RDMA unavailable; using NVMe/TCP", "err", err)
				}
			}
			cfg.NVMeRDMA = rdma
			cfg.NVMeRDMARequired = nvmeTransport == "rdma"
			kc, err := client.New(restCfg, client.Options{})
			if err != nil {
				return err
			}
			key, err := diskkey.Load(ctx, kc, namespace)
			if err != nil {
				return fmt.Errorf("load disk key: %w", err)
			}
			cfg.DiskKey = key
			cfg.Identity, err = peer.LoadIdentity(dataDir)
			if err != nil {
				return fmt.Errorf("load peer identity: %w", err)
			}
			cfg.Peers = peer.NewRegistry()
			cfg.PeerClient = peer.NewClientWithOptions(cfg.Identity, cfg.Peers, key, peer.ClientOptions{RDMA: rdma})
			cfg.Stream = node.StreamConfig{Listen: streamListen, Namespace: namespace, ClientCA: streamClientCA}
			defer cfg.PeerClient.Close()
			st, err := storage.Open(ctx, storage.Config{
				DataDir:       dataDir,
				NodeName:      cfg.NodeName,
				PoolBytes:     size.Value(),
				Key:           key,
				ReleaseRemote: cfg.PeerClient.ReleaseRemote,
				ResumeRemote:  cfg.PeerClient.ResumeRemote,
			})
			if err != nil {
				return fmt.Errorf("open storage: %w", err)
			}
			defer st.Close()
			return node.Run(ctx, cfg, restCfg, st)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", podapi.DataDir, "node data directory")
	cmd.Flags().StringVar(&poolSize, "pool-size", "40Gi", "size of the thin pool data file")
	cmd.Flags().StringSliceVar(&insecure, "insecure-registry", nil, "registries to reach over plain HTTP")
	cmd.Flags().StringVar(&streamListen, "stream-listen", ":7891", "aggregated stream API listen address (empty disables)")
	cmd.Flags().StringVar(&streamClientCA, "stream-client-ca", "", "optional file with the front-proxy CA; defaults to the kube-apiserver's published ConfigMap")
	cmd.Flags().StringVar(&nvmeTransport, "nvme-transport", "tcp", "tcp, auto, or rdma; auto/rdma add an NVMe/RDMA path when the host supports it")
	return cmd
}
