// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestEnvoyBootstrap checks the sidecar's static config for a pool with the
// API and two endpoints: one trusted by a ConfigMap CA, one using system
// roots. The bootstrap must never contain the pool's identity: credentials
// arrive only through the per-upstream SDS files.
func TestEnvoyBootstrap(t *testing.T) {
	pool := &v1.BlipPool{Spec: v1.BlipPoolSpec{
		ServiceAccountName: "blip-agent",
		Endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "gateway", CAConfigMap: "whoami-ca"},
			{Name: "metrics", URL: "https://metrics.example.com:8443", Audience: "gateway"},
		},
	}}
	got, err := envoyBootstrap(pool, "10.0.0.1:6443")
	if err != nil {
		t.Fatal(err)
	}
	again, err := envoyBootstrap(pool, "10.0.0.1:6443")
	if err != nil {
		t.Fatal(err)
	}
	if got != again {
		t.Error("bootstrap is not deterministic")
	}
	// It must be syntactically valid YAML, not merely look like it.
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("bootstrap is not valid YAML: %v\n%s", err, got)
	}

	for _, want := range []string{
		"address: \"127.0.0.1\"\n        port_value: 15080",
		"stat_prefix: \"guest\"",
		"domains:\n              - \"kube-apiserver\"\n              - \"kube-apiserver:*\"",
		"domains:\n              - \"whoami\"\n              - \"whoami:*\"",
		"domains:\n              - \"metrics\"\n              - \"metrics:*\"",
		"domains:\n              - \"*\"",
		"use_remote_address: false",
		"skip_xff_append: true",
		"generate_request_id: false",
		"server_header_transformation: PASS_THROUGH",
		"normalize_path: false",
		"merge_slashes: false",
		"allow_request_without_credential: true",
		"overwrite: true",
		"header: authorization",
		"suppress_envoy_headers: true",
		"timeout: 0s",
		"upgrade_type: websocket",
		"upgrade_type: spdy/3.1",
		"path: \"/etc/blip/creds/kube-apiserver.yaml\"",
		"path: \"/etc/blip/creds/whoami.yaml\"",
		"path: \"/etc/blip/creds/metrics.yaml\"",
		"sni: \"10.0.0.1\"",
		"sni: \"whoami.example.com\"",
		"sni: \"metrics.example.com\"",
		"host_rewrite_literal: \"10.0.0.1\"",
		"host_rewrite_literal: \"whoami.example.com\"",
		"host_rewrite_literal: \"metrics.example.com\"",
		"port_value: 6443",
		"port_value: 8443",
		"filename: \"/etc/blip/ca/kube/ca.crt\"",
		"filename: \"/etc/blip/endpoints/0/ca.crt\"",
		"filename: \"/etc/ssl/certs/ca-certificates.crt\"",
		"direct_response:\n                  status: 421",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bootstrap lacks %q\n%s", want, got)
		}
	}
	// One HTTP connection manager fronts every upstream; each cluster gets its
	// own credential injector.
	if n := strings.Count(got, "envoy.filters.network.http_connection_manager"); n != 1 {
		t.Errorf("%d connection managers, want 1\n%s", n, got)
	}
	if n := strings.Count(got, "name: envoy.filters.http.credential_injector\n"); n != 3 {
		t.Errorf("%d credential injectors, want 3\n%s", n, got)
	}
	// No credential material (or identity name) is in the template.
	if strings.Contains(got, pool.Spec.ServiceAccountName) {
		t.Errorf("bootstrap contains the service account name %q", pool.Spec.ServiceAccountName)
	}
	if strings.Contains(got, "Bearer") {
		t.Error("bootstrap embeds a credential value")
	}
	if strings.Contains(got, "admin:") {
		t.Error("bootstrap enables the admin endpoint")
	}
}

// TestEnvoyBootstrapNoEndpoints checks the minimal pool: only the API virtual
// host and cluster, still with a credential injector so an anonymous request
// gets the upstream's 401 rather than a local failure.
func TestEnvoyBootstrapNoEndpoints(t *testing.T) {
	got, err := envoyBootstrap(&v1.BlipPool{}, "kubernetes.default.svc:443")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got, "name: envoy.filters.http.credential_injector\n"); n != 1 {
		t.Errorf("%d credential injectors, want 1\n%s", n, got)
	}
	if !strings.Contains(got, "domains:\n              - \"kube-apiserver\"") {
		t.Errorf("API virtual host missing\n%s", got)
	}
	if strings.Contains(got, "whoami") || strings.Contains(got, "/etc/blip/endpoints/") {
		t.Errorf("endpoint config in a pool without endpoints\n%s", got)
	}
	if !strings.Contains(got, "path: \"/etc/blip/creds/kube-apiserver.yaml\"") {
		t.Errorf("API credential path missing\n%s", got)
	}
}

// TestEnvoyBootstrapEndpointPort keeps the dialed port from the URL while SNI
// and the rewritten Host stay the bare hostname.
func TestEnvoyBootstrapEndpointPort(t *testing.T) {
	pool := &v1.BlipPool{Spec: v1.BlipPoolSpec{Endpoints: []v1.PoolEndpoint{
		{Name: "metrics", URL: "https://metrics.example.com:8443"},
	}}}
	got, err := envoyBootstrap(pool, "kubernetes.default.svc:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"address: \"metrics.example.com\"\n                port_value: 8443",
		"sni: \"metrics.example.com\"",
		"host_rewrite_literal: \"metrics.example.com\"",
		"cluster: \"metrics\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bootstrap lacks %q\n%s", want, got)
		}
	}
}

func TestEnvoyBootstrapRejectsBadAPIServer(t *testing.T) {
	if _, err := envoyBootstrap(&v1.BlipPool{}, "not-a-host-port"); err == nil {
		t.Fatal("malformed API server address was accepted")
	}
}

// TestEnvoyBootstrapUnauthenticatedEndpoint checks that an endpoint without an
// audience gets no credential injector, keeps TLS, and has any guest-supplied
// Authorization header removed before it reaches the upstream.
func TestEnvoyBootstrapUnauthenticatedEndpoint(t *testing.T) {
	pool := &v1.BlipPool{Spec: v1.BlipPoolSpec{Endpoints: []v1.PoolEndpoint{
		{Name: "public", URL: "https://public.example.com", CAConfigMap: "public-ca"},
	}}}
	got, err := envoyBootstrap(pool, "kubernetes.default.svc:443")
	if err != nil {
		t.Fatal(err)
	}
	// Only the API server injects a credential.
	if n := strings.Count(got, "name: envoy.filters.http.credential_injector\n"); n != 1 {
		t.Errorf("%d credential injectors, want 1\n%s", n, got)
	}
	if !strings.Contains(got, "path: \"/etc/blip/creds/kube-apiserver.yaml\"") {
		t.Errorf("API credential path missing\n%s", got)
	}
	if strings.Contains(got, "/etc/blip/creds/public.yaml") {
		t.Errorf("unauthenticated endpoint has a credential\n%s", got)
	}
	if !strings.Contains(got, "clusters:\n  - name: \"public\"") &&
		!strings.Contains(got, "  - name: \"public\"\n    type: STRICT_DNS") {
		t.Errorf("public cluster missing\n%s", got)
	}
	if n := strings.Count(got, "name: envoy.transport_sockets.tls\n"); n != 2 {
		t.Errorf("%d TLS transport sockets, want 2\n%s", n, got)
	}
	if !strings.Contains(got, "request_headers_to_remove:\n                - authorization") {
		t.Errorf("guest authorization is not stripped\n%s", got)
	}
}
