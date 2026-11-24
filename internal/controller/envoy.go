// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// Controller defaults for the Envoy sidecar. They are configuration, not pool
// spec, so a controller rollout can change them. Both are part of the pod
// template hash: warm VMs must not keep a sidecar built by an old controller.
const (
	// DefaultProxyImage runs the pod's Envoy sidecar.
	DefaultProxyImage = "envoyproxy/envoy:distroless-v1.35.0"
	// DefaultAPIServer is the in-cluster Kubernetes API address used when
	// KUBERNETES_SERVICE_HOST/PORT are unset, as in tests and out-of-cluster
	// runs.
	DefaultAPIServer = "kubernetes.default.svc:443"
)

const (
	// apiUpstream is the guest hostname of the Kubernetes API and the name of
	// its Envoy cluster. Endpoint names are validated against it.
	apiUpstream = "kube-apiserver"

	// credsMountPath holds the node agent's file-SDS generic secrets inside
	// the Envoy container. proxy-init seeds it before Envoy starts.
	credsMountPath = "/etc/blip/creds"
	// kubeCAMountPath holds the API server's CA bundle.
	kubeCAMountPath = "/etc/blip/ca/kube"
	// endpointCAMountRoot holds per-endpoint CA bundles, one directory per
	// spec.endpoints index.
	endpointCAMountRoot = "/etc/blip/endpoints"
	// endpointCAFile is the projected ConfigMap key for an endpoint CA.
	endpointCAFile = "ca.crt"
	// systemCAFile is the trust store of the Envoy image, used by an endpoint
	// that has no CAConfigMap.
	systemCAFile = "/etc/ssl/certs/ca-certificates.crt"

	httpConnectionManager = "envoy.filters.network.http_connection_manager"
	credentialInjector    = "envoy.filters.http.credential_injector"
	genericCredential     = "envoy.http.injected_credentials.generic"
	routerFilter          = "envoy.filters.http.router"
	upstreamCodec         = "envoy.filters.http.upstream_codec"
	httpProtocolOptions   = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

	credentialInjectorType = "type.googleapis.com/envoy.extensions.filters.http.credential_injector.v3.CredentialInjector"
	genericCredentialType  = "type.googleapis.com/envoy.extensions.http.injected_credentials.generic.v3.Generic"
	routerType             = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
	upstreamCodecType      = "type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec"
	hcmType                = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
	httpOptionsType        = "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
	upstreamTLSType        = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"
)

// envoyUpstream is one guest hostname the sidecar proxies.
type envoyUpstream struct {
	// name is the guest Host header, the virtual host, and the cluster.
	name string
	// host is dialed, used for TLS SNI, and written to the upstream Host.
	host string
	port uint32
	// ca is the CA bundle path; empty means system roots.
	ca string
	// auth reports whether a credential is injected. The API server always
	// has one; an endpoint has one only when it names an audience.
	auth bool
}

// envoyBootstrap renders the static bootstrap of a pool's Envoy sidecar. It is
// deterministic: the same pool and API server always produce the same YAML, so
// it can live in the pod template and the template hash.
//
// One HTTP connection manager routes by the guest's Host header. Each upstream
// cluster carries the credential injector as an upstream filter, so it reads
// that upstream's SDS file and no other. A missing or placeholder secret leaves
// the request without Authorization (allow_request_without_credential) and the
// upstream answers 401 instead of Envoy failing the request locally.
func envoyBootstrap(pool *v1.BlipPool, apiServer string) (string, error) {
	host, portText, err := net.SplitHostPort(apiServer)
	if err != nil {
		return "", fmt.Errorf("API server address %q must be host:port: %w", apiServer, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("API server address %q has an invalid port", apiServer)
	}
	upstreams := []envoyUpstream{{
		name: apiUpstream,
		host: host,
		port: uint32(port),
		ca:   kubeCAMountPath + "/" + endpointCAFile,
		auth: true,
	}}
	for i := range pool.Spec.Endpoints {
		e := &pool.Spec.Endpoints[i]
		u, err := url.Parse(e.URL)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("endpoints[%d] %q: invalid URL %q", i, e.Name, e.URL)
		}
		p := uint64(443)
		if u.Port() != "" {
			p, err = strconv.ParseUint(u.Port(), 10, 16)
			if err != nil || p == 0 {
				return "", fmt.Errorf("endpoints[%d] %q: invalid port in URL %q", i, e.Name, e.URL)
			}
		}
		ca := ""
		if e.CAConfigMap != "" {
			ca = fmt.Sprintf("%s/%d/%s", endpointCAMountRoot, i, endpointCAFile)
		}
		upstreams = append(upstreams, envoyUpstream{
			name: e.Name, host: u.Hostname(), port: uint32(p), ca: ca, auth: e.Audience != "",
		})
	}
	return renderEnvoyBootstrap(upstreams), nil
}

// renderEnvoyBootstrap writes stable, two-space-indented YAML. Scalars that
// come from configuration are double-quoted; the fixed protocol values are
// plain.
func renderEnvoyBootstrap(upstreams []envoyUpstream) string {
	var b strings.Builder
	// SDS requires an Envoy node identity even for file-based secrets.
	b.WriteString("node:\n")
	b.WriteString("  id: \"blip-proxy\"\n")
	b.WriteString("  cluster: \"blip\"\n")
	b.WriteString("static_resources:\n")
	b.WriteString("  listeners:\n")
	b.WriteString("  - name: \"guest\"\n")
	b.WriteString("    address:\n")
	b.WriteString("      socket_address:\n")
	b.WriteString("        address: \"127.0.0.1\"\n")
	fmt.Fprintf(&b, "        port_value: %d\n", podapi.ProxyPort)
	b.WriteString("    filter_chains:\n")
	b.WriteString("    - filters:\n")
	writeEnvoyConnectionManager(&b, upstreams)
	b.WriteString("  clusters:\n")
	for _, u := range upstreams {
		writeEnvoyCluster(&b, u)
	}
	return b.String()
}

// writeEnvoyConnectionManager writes the single HTTP connection manager. Its
// virtual hosts match the guest's Host header, and a catch-all host rejects
// names that are not configured. Path handling is left exactly as the guest
// sent it, and Envoy adds no forwarding or request-id headers.
func writeEnvoyConnectionManager(b *strings.Builder, upstreams []envoyUpstream) {
	fmt.Fprintf(b, "      - name: %s\n", httpConnectionManager)
	b.WriteString("        typed_config:\n")
	fmt.Fprintf(b, "          \"@type\": %s\n", hcmType)
	b.WriteString("          stat_prefix: \"guest\"\n")
	b.WriteString("          use_remote_address: false\n")
	b.WriteString("          skip_xff_append: true\n")
	b.WriteString("          generate_request_id: false\n")
	b.WriteString("          server_header_transformation: PASS_THROUGH\n")
	b.WriteString("          normalize_path: false\n")
	b.WriteString("          merge_slashes: false\n")
	b.WriteString("          http_filters:\n")
	fmt.Fprintf(b, "          - name: %s\n", routerFilter)
	b.WriteString("            typed_config:\n")
	fmt.Fprintf(b, "              \"@type\": %s\n", routerType)
	b.WriteString("              suppress_envoy_headers: true\n")
	b.WriteString("          route_config:\n")
	b.WriteString("            name: \"guest\"\n")
	b.WriteString("            virtual_hosts:\n")
	for _, u := range upstreams {
		name := yamlQuote(u.name)
		fmt.Fprintf(b, "            - name: %s\n", name)
		b.WriteString("              domains:\n")
		fmt.Fprintf(b, "              - %s\n", name)
		fmt.Fprintf(b, "              - %s\n", yamlQuote(u.name+":*"))
		b.WriteString("              routes:\n")
		b.WriteString("              - match:\n")
		b.WriteString("                  prefix: /\n")
		if !u.auth {
			// Nothing is injected, and a guest-supplied identity must not
			// reach an unauthenticated upstream. This is a Route field, not
			// part of the RouteAction below.
			b.WriteString("                request_headers_to_remove:\n")
			b.WriteString("                - authorization\n")
		}
		b.WriteString("                route:\n")
		fmt.Fprintf(b, "                  cluster: %s\n", name)
		b.WriteString("                  timeout: 0s\n")
		fmt.Fprintf(b, "                  host_rewrite_literal: %s\n", yamlQuote(u.host))
		b.WriteString("                  upgrade_configs:\n")
		b.WriteString("                  - upgrade_type: websocket\n")
		b.WriteString("                  - upgrade_type: spdy/3.1\n")
	}
	// A host the pool does not configure never reaches an upstream.
	b.WriteString("            - name: \"unconfigured\"\n")
	b.WriteString("              domains:\n")
	b.WriteString("              - \"*\"\n")
	b.WriteString("              routes:\n")
	b.WriteString("              - match:\n")
	b.WriteString("                  prefix: /\n")
	b.WriteString("                direct_response:\n")
	b.WriteString("                  status: 421\n")
}

func writeEnvoyCluster(b *strings.Builder, u envoyUpstream) {
	name := yamlQuote(u.name)
	fmt.Fprintf(b, "  - name: %s\n", name)
	b.WriteString("    type: STRICT_DNS\n")
	b.WriteString("    connect_timeout: 5s\n")
	b.WriteString("    load_assignment:\n")
	fmt.Fprintf(b, "      cluster_name: %s\n", name)
	b.WriteString("      endpoints:\n")
	b.WriteString("      - lb_endpoints:\n")
	b.WriteString("        - endpoint:\n")
	b.WriteString("            address:\n")
	b.WriteString("              socket_address:\n")
	fmt.Fprintf(b, "                address: %s\n", yamlQuote(u.host))
	fmt.Fprintf(b, "                port_value: %d\n", u.port)
	b.WriteString("    typed_extension_protocol_options:\n")
	fmt.Fprintf(b, "      %s:\n", httpProtocolOptions)
	fmt.Fprintf(b, "        \"@type\": %s\n", httpOptionsType)
	b.WriteString("        explicit_http_config:\n")
	b.WriteString("          http_protocol_options: {}\n")
	if u.auth {
		b.WriteString("        http_filters:\n")
		fmt.Fprintf(b, "        - name: %s\n", credentialInjector)
		b.WriteString("          typed_config:\n")
		fmt.Fprintf(b, "            \"@type\": %s\n", credentialInjectorType)
		b.WriteString("            overwrite: true\n")
		b.WriteString("            allow_request_without_credential: true\n")
		b.WriteString("            credential:\n")
		fmt.Fprintf(b, "              name: %s\n", genericCredential)
		b.WriteString("              typed_config:\n")
		fmt.Fprintf(b, "                \"@type\": %s\n", genericCredentialType)
		// Envoy 1.35's generic credential has no header_value_prefix, so the
		// SDS document holds the complete header value, including "Bearer ".
		b.WriteString("                header: authorization\n")
		b.WriteString("                credential:\n")
		fmt.Fprintf(b, "                  name: %s\n", name)
		b.WriteString("                  sds_config:\n")
		b.WriteString("                    path_config_source:\n")
		fmt.Fprintf(b, "                      path: %s\n", yamlQuote(credsMountPath+"/"+u.name+".yaml"))
		// Upstream filter chains must end with the codec filter.
		fmt.Fprintf(b, "        - name: %s\n", upstreamCodec)
		b.WriteString("          typed_config:\n")
		fmt.Fprintf(b, "            \"@type\": %s\n", upstreamCodecType)
	}
	b.WriteString("    transport_socket:\n")
	b.WriteString("      name: envoy.transport_sockets.tls\n")
	b.WriteString("      typed_config:\n")
	fmt.Fprintf(b, "        \"@type\": %s\n", upstreamTLSType)
	fmt.Fprintf(b, "        sni: %s\n", yamlQuote(u.host))
	b.WriteString("        common_tls_context:\n")
	if u.ca == "" {
		// Verify against the image's system trust store, like the old proxy's
		// Go TLS defaults.
		b.WriteString("          validation_context:\n")
		b.WriteString("            trusted_ca:\n")
		fmt.Fprintf(b, "              filename: %s\n", yamlQuote(systemCAFile))
		return
	}
	b.WriteString("          validation_context:\n")
	b.WriteString("            trusted_ca:\n")
	fmt.Fprintf(b, "              filename: %s\n", yamlQuote(u.ca))
}

// yamlQuote double-quotes a YAML scalar. The inputs are validated DNS names,
// hosts, and paths, so the Go string escaping is also valid YAML escaping.
func yamlQuote(s string) string {
	return strconv.Quote(s)
}
