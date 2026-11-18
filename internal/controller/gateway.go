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
	if host == "" || strings.ContainsAny(host, "/\\@?#[] \t\r\n") {
		return false
	}
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	return name != "" && len(validation.IsDNS1123Subdomain(name)) == 0
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
	host := strings.TrimSuffix(name, ".")
	if host == "" || strings.ContainsAny(name, "/\\@?#[] \t\r\n") {
		return errors.New("must be a DNS name or IP address without a scheme, port, or path")
	}
	if len(validation.IsDNS1123Subdomain(strings.ToLower(host))) != 0 {
		return errors.New("must be a DNS name or IP address without a scheme, port, or path")
	}
	return nil
}
