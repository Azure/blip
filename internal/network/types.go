// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package network compiles IPv4 egress policies against a Kubernetes snapshot.
package network

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/Azure/blip/internal/netpolicy"
)

// Policy and Rule are defined in netpolicy so packages that only describe
// rules (notably the VM runtime) need not import Kubernetes API types.
type (
	Policy = netpolicy.Policy
	Rule   = netpolicy.Rule
)

// Destinations is a snapshot of the objects used to resolve selectors.
type Destinations struct {
	Pods           []corev1.Pod
	Namespaces     []corev1.Namespace
	Services       []corev1.Service
	EndpointSlices []discoveryv1.EndpointSlice
}
