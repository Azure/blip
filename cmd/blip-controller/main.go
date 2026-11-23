// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command blip-controller runs the blip control plane: the enrollment, node,
// pool, state, and blip reconcilers, plus garbage collection of old finished
// blips.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/controller"
	"github.com/Azure/blip/internal/diskkey"
)

// +kubebuilder:rbac:groups=apiregistration.k8s.io,resources=apiservices,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update
// +kubebuilder:rbac:groups=blip.dev,resources=blips;blipstates;blippools;blipnodes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=blip.dev,resources=blips;blipstates,verbs=create
// +kubebuilder:rbac:groups=blip.dev,resources=blips;blipstates,verbs=delete
// +kubebuilder:rbac:groups=blip.dev,resources=blips/status;blipstates/status;blippools/status;blipnodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=blip.dev,resources=blips/finalizers;blipstates/finalizers;blippools/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;patch

func main() {
	var runtimeImage, insecure, namespace string
	var leaderElect bool
	var gcThreshold int
	flag.StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"), "namespace of the controller and the disk key secret")
	flag.StringVar(&runtimeImage, "runtime-image", "", "image of the VM pod's vm container (blip-runtime)")
	flag.StringVar(&insecure, "insecure-registry", "", "comma-separated registry hosts reached over plain HTTP")
	flag.BoolVar(&leaderElect, "leader-elect", false, "enable leader election")
	flag.IntVar(&gcThreshold, "terminated-blip-gc-threshold", controller.DefaultTerminatedBlipGCThreshold, "delete the oldest finished blips beyond this many per namespace (0 disables)")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if err := run(runtimeImage, insecure, namespace, leaderElect, gcThreshold); err != nil {
		fmt.Fprintln(os.Stderr, "blip-controller:", err)
		os.Exit(1)
	}
}

func run(runtimeImage, insecure, namespace string, leaderElect bool, gcThreshold int) error {
	if runtimeImage == "" || namespace == "" {
		return fmt.Errorf("--runtime-image and --namespace are required")
	}
	var registries []string
	for _, h := range strings.Split(insecure, ",") {
		if h = strings.TrimSpace(h); h != "" {
			registries = append(registries, h)
		}
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return err
	}
	vmPods, err := labels.NewRequirement(v1.LabelPool, selection.Exists, nil)
	if err != nil {
		return err
	}
	restCfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                        scheme,
		LeaderElection:                leaderElect,
		LeaderElectionID:              "blip-controller.blip.dev",
		LeaderElectionReleaseOnCancel: true,
		HealthProbeBindAddress:        ":8081",
		Metrics:                       metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Label: labels.NewSelector().Add(*vmPods)},
			// Only the admission policy's parameter table is cached. Endpoint
			// CA ConfigMaps are read uncached via mgr.GetAPIReader(), so this
			// field selector does not hide them from pool validation.
			&corev1.ConfigMap{}: {Field: fields.OneTermEqualSelector("metadata.name", controller.VMOwnersConfigMap)},
		}},
	})
	if err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()
	direct, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	if err := diskkey.Ensure(ctx, direct, namespace); err != nil {
		return err
	}
	cfg := controller.Config{
		RuntimeImage:    runtimeImage,
		Registry:        controller.RemoteRegistry{Insecure: registries, Reader: mgr.GetAPIReader()},
		StreamNamespace: namespace,
	}
	if err := controller.Setup(ctx, mgr, cfg); err != nil {
		return err
	}
	// Use the direct client: listing and deleting finished blips should not
	// depend on the manager's cache.
	if err := mgr.Add(controller.NewTerminatedBlipGC(direct, gcThreshold)); err != nil {
		return err
	}
	return mgr.Start(ctx)
}
