package controller

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// endpointNameRE matches a DNS label, the guest hostname of an endpoint.
var endpointNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// reservedEndpointNames are guest hostnames that already name something else
// in the guest or must never resolve to an external endpoint.
var reservedEndpointNames = map[string]bool{
	"blip":           true,
	"kube-apiserver": true,
	"localhost":      true,
}

// validateEndpoints rejects endpoint settings that would pass admission but
// make the proxy exit or, worse, send a workload's credentials to the wrong
// host. Running it before creating pods keeps an invalid pool from producing
// sidecars that crash-loop while Blips wait for a VM forever.
func validateEndpoints(pool *v1.BlipPool, clusterAudiences ...string) error {
	seen := map[string]bool{}
	for i := range pool.Spec.Endpoints {
		e := &pool.Spec.Endpoints[i]
		err := validateEndpoint(pool, e, clusterAudiences)
		if err == nil && seen[e.Name] {
			err = errors.New("duplicate endpoint name")
		}
		if err != nil {
			return fmt.Errorf("endpoints[%d] %q: %w", i, e.Name, err)
		}
		seen[e.Name] = true
	}
	return nil
}

func validateEndpoint(pool *v1.BlipPool, e *v1.PoolEndpoint, clusterAudiences []string) error {
	if len(e.Name) > 63 || !endpointNameRE.MatchString(e.Name) {
		return errors.New("name must be a lowercase DNS label of at most 63 characters")
	}
	if reservedEndpointNames[e.Name] {
		return errors.New("name is reserved")
	}
	if err := validateEndpointURL(e.URL); err != nil {
		return fmt.Errorf("url %q: %w", e.URL, err)
	}
	if e.Audience != "" {
		if pool.Spec.ServiceAccountName == "" {
			return errors.New("audience requires spec.serviceAccountName")
		}
		if isAPIServerAudience(e.Audience, clusterAudiences...) {
			return errors.New("audience must not be a Kubernetes API server audience; the endpoint token would authenticate to the API server")
		}
	}
	if e.CAConfigMap != "" {
		if errs := validation.IsDNS1123Subdomain(e.CAConfigMap); len(errs) > 0 {
			return fmt.Errorf("caConfigMap %q must be a DNS subdomain", e.CAConfigMap)
		}
	}
	return nil
}

// validateEndpointURL requires an HTTPS URL with a DNS host and an optional
// port. The host is dialed and used for TLS SNI, so an IP literal or a path
// would make the sidecar trust a different name than the one configured.
func validateEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("must be a valid HTTPS URL")
	}
	if u.Scheme != "https" {
		return errors.New("must use https")
	}
	if u.User != nil {
		return errors.New("must not contain user information")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("must not contain a path")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("must have a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("host must be a DNS name, not an IP address")
	}
	if !validDNSName(host) {
		return errors.New("host must be a DNS name without a scheme, path, or whitespace")
	}
	// url.Parse accepts an empty port and Port drops an invalid one, so a
	// trailing colon must be rejected explicitly.
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("port must be a number between 1 and 65535")
	}
	if port != "" && !validGatewayPort(port) {
		return errors.New("port must be a number between 1 and 65535")
	}
	return nil
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

// apiServerAudiences are the audiences a default Kubernetes API server
// accepts. A token projected for one of them is a valid API credential.
var apiServerAudiences = map[string]struct{}{
	"kubernetes.default.svc":               {},
	"kubernetes.default.svc.cluster.local": {},
}

func isAPIServerAudience(audience string, clusterAudiences ...string) bool {
	s := normalizeAudience(audience)
	if _, ok := apiServerAudiences[s]; ok {
		return true
	}
	for _, known := range clusterAudiences {
		if known != "" && s == normalizeAudience(known) {
			return true
		}
	}
	return false
}

// normalizeAudience compares audiences the way the API server does after
// ignoring a scheme, surrounding space, a port, and trailing slashes or dots.
func normalizeAudience(audience string) string {
	s := strings.ToLower(strings.TrimSpace(audience))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".")
	// Accept an explicit port even though the default API audiences have none.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return strings.TrimSuffix(s, ".")
}
