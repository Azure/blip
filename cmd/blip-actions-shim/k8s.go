package main

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func restConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return cfg, nil
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

func newClient(cfg *rest.Config, s *runtime.Scheme) (client.Client, error) {
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return c, nil
}
