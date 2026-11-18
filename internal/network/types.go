// Package network compiles IPv4 egress policies against a Kubernetes snapshot.
package network

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// Policy is an intersection of layers, each containing an OR of rules.
// No layers, or any empty layer, denies all traffic.
type Policy struct {
	Revision string   `json:"revision"`
	Layers   [][]Rule `json:"layers"`
}

// Rule matches an IPv4 destination excluding Except. Empty Protocol matches
// all IP protocols; Port zero matches all ports; EndPort zero means only Port.
type Rule struct {
	CIDR     string   `json:"cidr"`
	Except   []string `json:"except,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Port     int32    `json:"port,omitempty"`
	EndPort  int32    `json:"endPort,omitempty"`
}

// Destinations is a snapshot of the objects used to resolve selectors.
type Destinations struct {
	Pods           []corev1.Pod
	Namespaces     []corev1.Namespace
	Services       []corev1.Service
	EndpointSlices []discoveryv1.EndpointSlice
}
