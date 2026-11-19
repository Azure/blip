package apiproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// apiHost is the reserved Host header for the Kubernetes API route.
const apiHost = "kube-apiserver"

// endpointNameRE matches DNS labels, the only names an endpoint may use.
var endpointNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// reservedEndpointNames cannot describe an endpoint: blip is the product name,
// kube-apiserver is the API route, and localhost invites confusion with the
// guest's own loopback.
var reservedEndpointNames = map[string]struct{}{
	"blip":           {},
	"kube-apiserver": {},
	"localhost":      {},
}

// newRouter builds one handler that dispatches by Host header. Transports are
// returned so Run can close their idle connections at shutdown.
func newRouter(cfg Config) (http.Handler, []*http.Transport, error) {
	if err := validateEndpoints(cfg.Endpoints); err != nil {
		return nil, nil, err
	}
	if cfg.API == nil && len(cfg.Endpoints) == 0 {
		return nil, nil, errors.New("no API or endpoints configured")
	}
	routes := make(map[string]http.Handler, len(cfg.Endpoints)+1)
	var transports []*http.Transport
	fail := func(err error) (http.Handler, []*http.Transport, error) {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
		return nil, nil, err
	}
	if cfg.API != nil {
		handler, transport, err := newAPIProxy(cfg.API, cfg.PodName, cfg.PodNamespace)
		if err != nil {
			return fail(err)
		}
		routes[apiHost] = handler
		transports = append(transports, transport)
	}
	for _, endpoint := range cfg.Endpoints {
		handler, transport, err := newEndpointProxy(endpoint)
		if err != nil {
			return fail(err)
		}
		routes[endpoint.Name] = handler
		transports = append(transports, transport)
	}
	return &router{routes: routes}, transports, nil
}

type router struct {
	routes map[string]http.Handler
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	name, ok := normalizeHost(r.Host)
	if !ok {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	handler, ok := rt.routes[name]
	if !ok {
		// Unknown hosts never reach an upstream.
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	handler.ServeHTTP(w, r)
}

// normalizeHost reduces a request Host to a route name. It accepts a bare
// hostname, an explicit port 80, or a bracketed IPv6 literal, ignoring case
// and one FQDN trailing dot. Malformed authorities, ports other than 80, and
// names with more than one trailing dot are rejected.
func normalizeHost(host string) (string, bool) {
	host = strings.ToLower(host)
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\@?#") {
		return "", false
	}
	name := host
	if strings.HasPrefix(host, "[") {
		if strings.HasSuffix(host, "]") {
			ip := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if net.ParseIP(ip) == nil {
				return "", false
			}
			return ip, true
		}
		var port string
		var err error
		name, port, err = net.SplitHostPort(host)
		if err != nil || port != "80" || net.ParseIP(name) == nil {
			return "", false
		}
		return name, true
	}
	if strings.Contains(host, ":") {
		var port string
		var err error
		name, port, err = net.SplitHostPort(host)
		if err != nil || port != "80" {
			return "", false
		}
	}
	// One trailing dot marks a fully qualified name. Trim only that one:
	// leaving another dot behind means the authority was malformed.
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.HasSuffix(name, ".") || !validHostName(name) {
		return "", false
	}
	return name, true
}

// validHostName reports whether name is a DNS name of valid labels. IPv4
// literals also pass this check; they simply never match a configured route.
func validHostName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func newAPIProxy(api *API, podName, podNamespace string) (http.Handler, *http.Transport, error) {
	if podName == "" || podNamespace == "" {
		return nil, nil, errors.New("API proxy pod identity is required")
	}
	host, port, err := net.SplitHostPort(api.Address)
	if err != nil {
		return nil, nil, errors.New("invalid Kubernetes API address")
	}
	address, err := apiAddress(host, port)
	if err != nil {
		return nil, nil, err
	}
	handler, transport, ca, err := newUpstreamProxy(upstreamOptions{
		address:    address,
		serverName: host,
		hostHeader: address,
		caFile:     api.CAFile,
		caLabel:    "Kubernetes API CA",
		tokenFile:  api.TokenFile,
		errorBody:  "Kubernetes API unavailable",
	})
	if err != nil {
		return nil, nil, err
	}
	scopeCfg := Config{API: api, PodName: podName, PodNamespace: podNamespace}
	// The scope client must share the CA-aware transport, not the base one,
	// so its identity reads drop idle connections when the projected CA
	// rotates or is revoked.
	handler = newOwnerScope(scopeCfg, ca, handler)
	return handler, transport, nil
}

func newEndpointProxy(endpoint Endpoint) (http.Handler, *http.Transport, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("endpoint %q: invalid URL", endpoint.Name)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	handler, transport, _, err := newUpstreamProxy(upstreamOptions{
		address:     net.JoinHostPort(u.Hostname(), port),
		serverName:  u.Hostname(),
		hostHeader:  u.Host,
		caFile:      endpoint.CAFile,
		caLabel:     "endpoint CA",
		systemRoots: true,
		tokenFile:   endpoint.TokenFile,
		errorBody:   "endpoint unavailable",
	})
	return handler, transport, err
}

func parseEndpoints(raw string) ([]Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if raw[0] != '[' {
		return nil, errors.New("BLIP_ENDPOINTS must be a JSON array")
	}
	var endpoints []Endpoint
	if err := json.Unmarshal([]byte(raw), &endpoints); err != nil {
		return nil, fmt.Errorf("parse BLIP_ENDPOINTS: %w", err)
	}
	if err := validateEndpoints(endpoints); err != nil {
		return nil, fmt.Errorf("BLIP_ENDPOINTS: %w", err)
	}
	return endpoints, nil
}

func validateEndpoints(endpoints []Endpoint) error {
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
		if _, ok := seen[endpoint.Name]; ok {
			return fmt.Errorf("duplicate endpoint name %q", endpoint.Name)
		}
		seen[endpoint.Name] = struct{}{}
	}
	return nil
}

func validateEndpoint(endpoint Endpoint) error {
	if len(endpoint.Name) > 63 || !endpointNameRE.MatchString(endpoint.Name) {
		return fmt.Errorf("invalid endpoint name %q", endpoint.Name)
	}
	if _, ok := reservedEndpointNames[endpoint.Name]; ok {
		return fmt.Errorf("reserved endpoint name %q", endpoint.Name)
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("endpoint %q: invalid URL: %w", endpoint.Name, err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("endpoint %q: URL scheme must be https", endpoint.Name)
	case u.User != nil:
		return fmt.Errorf("endpoint %q: URL must not contain user information", endpoint.Name)
	case u.Opaque != "":
		return fmt.Errorf("endpoint %q: URL must be hierarchical", endpoint.Name)
	case u.RawQuery != "" || u.ForceQuery:
		return fmt.Errorf("endpoint %q: URL must not contain a query", endpoint.Name)
	case u.Fragment != "":
		return fmt.Errorf("endpoint %q: URL must not contain a fragment", endpoint.Name)
	case u.Path != "" && u.Path != "/":
		return fmt.Errorf("endpoint %q: URL must not contain a path", endpoint.Name)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("endpoint %q: URL host is empty", endpoint.Name)
	}
	if strings.ContainsAny(u.Host, "[]") || net.ParseIP(host) != nil {
		return fmt.Errorf("endpoint %q: URL host must be a DNS name", endpoint.Name)
	}
	if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("endpoint %q: URL port is empty", endpoint.Name)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("endpoint %q: URL port is invalid", endpoint.Name)
		}
	}
	return nil
}
