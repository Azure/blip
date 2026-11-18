package controller

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// validateGatewaySpec rejects gateway settings that would pass admission but
// make the api-proxy sidecar exit at startup. Without this check an invalid
// pool already stored in etcd keeps creating VM pods whose sidecar
// crash-loops, while the Blip waits for a VM forever.
func validateGatewaySpec(g *v1.GatewaySpec) error {
	if g == nil {
		return nil
	}
	if err := validateGatewayAddress(g.Address); err != nil {
		return fmt.Errorf("gateway.address %q: %w", g.Address, err)
	}
	name := g.ServerName
	if name == "" {
		// The sidecar verifies the certificate against the address host
		// when no explicit server name is set.
		name, _, _ = net.SplitHostPort(g.Address)
	}
	if err := validateGatewayServerName(name); err != nil {
		return fmt.Errorf("gateway.serverName %q: %w", g.ServerName, err)
	}
	if err := validateGatewayAudience(g.Audience); err != nil {
		return fmt.Errorf("gateway.audience %q: %w", g.Audience, err)
	}
	return nil
}

// validateGatewayAddress requires a host:port dial target. The host is a DNS
// name, an IPv4 address, or a bracketed IPv6 address, and the port is 1-65535.
func validateGatewayAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.New(`must be host:port, for example "gateway.example:443" or "[::1]:443"`)
	}
	if !validGatewayHost(host) {
		return errors.New("host must be a DNS name or IP address without a scheme, path, or whitespace")
	}
	if !validGatewayPort(port) {
		return errors.New("port must be a number between 1 and 65535")
	}
	return nil
}

func validGatewayHost(host string) bool {
	// SplitHostPort removes the brackets of an IPv6 literal but leaves any
	// zone, which ParseIP rejects below.
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	return validDNSName(host)
}

// validDNSName reports whether name is a DNS name with an optional trailing
// dot and no scheme, port, path, or whitespace.
func validDNSName(name string) bool {
	if strings.ContainsAny(name, "/\\@?#[] \t\r\n") {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(name), ".")
	return host != "" && len(validation.IsDNS1123Subdomain(host)) == 0
}

func validGatewayPort(port string) bool {
	// Reject an empty or signed port, leading zeros, and more than five
	// digits before parsing so the Go validator matches the CRD pattern.
	if port == "" || len(port) > 5 || port[0] < '1' || port[0] > '9' {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

// validateGatewayServerName accepts a DNS name (with an optional trailing dot)
// or an IP address. TLS SNI takes a bare IPv6 address, never brackets.
func validateGatewayServerName(name string) error {
	if name == "" {
		return errors.New("must not be empty")
	}
	if net.ParseIP(name) != nil {
		return nil
	}
	if !validDNSName(name) {
		return errors.New("must be a DNS name or IP address without a scheme, port, or path")
	}
	return nil
}

// apiServerAudiences are the audiences a default Kubernetes API server
// accepts. A token projected for one of them is a valid API credential.
var apiServerAudiences = map[string]struct{}{
	"kubernetes.default.svc":               {},
	"kubernetes.default.svc.cluster.local": {},
}

// validateGatewayAudience keeps a gateway token from being accepted by the API
// server. The gateway receives the token, so its audience is the boundary that
// prevents a compromised or third-party gateway from holding an API credential
// for the pod's service account.
func validateGatewayAudience(audience string) error {
	if audience == "" {
		// Omitted or explicitly empty uses the default blip-gateway audience.
		return nil
	}
	if isAPIServerAudience(audience) {
		return errors.New("must not be a Kubernetes API server audience; the gateway token would authenticate to the API server")
	}
	return nil
}

func isAPIServerAudience(audience string) bool {
	s := strings.ToLower(strings.TrimSpace(audience))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".")
	// Accept an explicit port even though the default API audiences have none.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(s, ".")
	_, ok := apiServerAudiences[s]
	return ok
}
