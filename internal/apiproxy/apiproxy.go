// Package apiproxy serves the pod's Kubernetes API identity and configured
// HTTPS endpoints over the guest-to-host vsock Unix socket, routing by Host.
// Service account and endpoint credentials stay in the sidecar; upstreams
// remain responsible for authorization. Reads of Blips, BlipStates and Pods
// from a claimed VM are additionally scoped to the owner recorded on the pod
// and its Blip.
package apiproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// API is the Kubernetes API upstream and the credential the sidecar uses.
type API struct {
	// Address is the Kubernetes HTTPS authority, including its port.
	Address   string
	TokenFile string
	CAFile    string
}

// Endpoint is one named HTTPS upstream reachable from the guest by Host.
type Endpoint struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	TokenFile string `json:"tokenFile,omitempty"`
	CAFile    string `json:"caFile,omitempty"`
}

// Config contains trusted sidecar configuration, never guest request data.
type Config struct {
	SocketPath string
	// API is the Kubernetes API upstream. When nil, the kube-apiserver host is
	// not served.
	API *API
	// Endpoints are additional HTTPS upstreams, selected by Host.
	Endpoints []Endpoint
	// PodName and PodNamespace identify this API proxy's own pod. They come
	// from the downward API, never from the guest, and let the proxy derive
	// the owner it acts for. When both are empty, Kubernetes object reads are
	// not scoped (compatibility for direct local runs and unit tests).
	PodName      string
	PodNamespace string
}

// ConfigFromEnv uses the in-cluster API endpoint and explicitly projected
// service account files. BLIP_DIR defaults to /run/blip. BLIP_KUBE_API=1
// enables the Kubernetes API route; BLIP_ENDPOINTS is a JSON array of named
// HTTPS endpoints.
func ConfigFromEnv() (Config, error) {
	dir := os.Getenv("BLIP_DIR")
	if dir == "" {
		dir = podapi.MountPath
	}
	cfg := Config{
		SocketPath:   podapi.VsockListenerPath(dir, wire.EndpointPort),
		PodName:      os.Getenv("POD_NAME"),
		PodNamespace: os.Getenv("POD_NAMESPACE"),
	}
	if (cfg.PodName == "") != (cfg.PodNamespace == "") {
		return Config{}, errors.New("POD_NAME and POD_NAMESPACE must both be set")
	}
	if cfg.PodName != "" && (!validPodIdentity(cfg.PodName) || !validPodIdentity(cfg.PodNamespace)) {
		return Config{}, errors.New("invalid POD_NAME or POD_NAMESPACE")
	}
	if os.Getenv("BLIP_KUBE_API") == "1" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		address, err := apiAddress(host, port)
		if err != nil {
			return Config{}, err
		}
		cfg.API = &API{
			Address:   address,
			TokenFile: filepath.Join(serviceAccountDir, "token"),
			CAFile:    filepath.Join(serviceAccountDir, "ca.crt"),
		}
	}
	endpoints, err := parseEndpoints(os.Getenv("BLIP_ENDPOINTS"))
	if err != nil {
		return Config{}, err
	}
	cfg.Endpoints = endpoints
	if cfg.API == nil && len(cfg.Endpoints) == 0 {
		return Config{}, errors.New("no API or endpoints configured")
	}
	return cfg, nil
}

func apiAddress(host, port string) (string, error) {
	// An address is a hostname/IP and a numeric port, not a URL or proxy.
	if host == "" || strings.ContainsAny(host, "/\\@?#[] \t\r\n") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return "", errors.New("invalid service host")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", errors.New("invalid service port")
	}
	return net.JoinHostPort(host, port), nil
}

// Run serves cfg.SocketPath with mode 0600. Cancellation stops new requests,
// cancels upstream requests, and closes all streams, including hijacked
// upgrade connections. A normal context cancellation returns nil.
func Run(ctx context.Context, cfg Config) error {
	if ctx.Err() != nil {
		return nil
	}
	proxy, transports, err := newRouter(cfg)
	if err != nil {
		return err
	}
	defer func() {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
	}()
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server, err := newProxyServer(serveCtx, cfg.SocketPath, proxy)
	if err != nil {
		return err
	}
	defer server.close()
	done := make(chan error, 1)
	go func() { done <- server.server.Serve(server.tracked) }()
	var firstErr error
	cancelled := false
	select {
	case firstErr = <-done:
		// Serve returned on its own; cancel handlers so watches also end.
		cancel()
	case <-ctx.Done():
		cancelled = true
	}
	server.shutdown()
	if cancelled {
		return nil
	}
	if firstErr == nil {
		select {
		case firstErr = <-done:
		default:
		}
	}
	return firstErr
}

type proxyServer struct {
	server  *http.Server
	tracked *trackedListener
	cleanup func()
}

// connectionLifetimeKey carries the connection-scoped context. A client may
// half-close its write side after sending a complete request; net/http
// cancels the per-request context when the read side reaches EOF, even
// though the connection is still open for the response. Proxying against the
// connection lifetime (which follows server shutdown) keeps the in-flight
// request and response alive.
type connectionLifetimeKey struct{}

func newProxyServer(ctx context.Context, socketPath string, handler http.Handler) (*proxyServer, error) {
	listener, cleanup, err := listenUnix(socketPath)
	if err != nil {
		return nil, err
	}
	tracked := &trackedListener{Listener: listener, connections: make(map[*trackedConn]struct{})}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if lifetime, ok := r.Context().Value(connectionLifetimeKey{}).(context.Context); ok {
				r = r.WithContext(lifetime)
			}
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(connCtx context.Context, _ net.Conn) context.Context {
			return context.WithValue(connCtx, connectionLifetimeKey{}, connCtx)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return &proxyServer{server: server, tracked: tracked, cleanup: cleanup}, nil
}

func (s *proxyServer) shutdown() {
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	// BaseContext cancellation ends watches and upstream upgrades. Shutdown
	// gives handlers a bounded opportunity to finish their responses.
	_ = s.server.Shutdown(shutdownCtx)
	s.tracked.closeConnections()
	_ = s.server.Close()
	s.cleanup()
}

func (s *proxyServer) close() {
	_ = s.server.Close()
	s.tracked.closeConnections()
	s.cleanup()
}

// upstreamOptions describes a fixed HTTPS upstream.
type upstreamOptions struct {
	address     string // validated host:port
	serverName  string // TLS SNI; empty disables SNI
	hostHeader  string // outbound Host header
	caFile      string
	caLabel     string // error text for CA read/parse failures
	systemRoots bool   // use the system pool when caFile is empty
	tokenFile   string
	errorBody   string
}

func newUpstreamProxy(cfg upstreamOptions) (http.Handler, *http.Transport, error) {
	roots, err := certPool(cfg.caFile, cfg.caLabel, cfg.systemRoots)
	if err != nil {
		return nil, nil, err
	}
	if cfg.tokenFile != "" {
		if _, err := projectedToken(cfg.tokenFile); err != nil {
			return nil, nil, err
		}
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// Proxy is deliberately nil: HTTP(S)_PROXY cannot change the destination.
		// The dial target is fixed too, so neither the request URL nor a
		// redirect can move the connection away from the configured upstream.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, cfg.address)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: cfg.serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
		// Kubernetes exec/attach/port-forward require HTTP/1 upgrades.
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DisableCompression:    true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	var roundTripper http.RoundTripper = transport
	if cfg.tokenFile != "" {
		roundTripper = tokenTransport{base: transport, tokenFile: cfg.tokenFile}
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Build an origin-form URL from only the incoming path and query.
			// In particular, discard authority, userinfo, Opaque and fragments.
			r.Out.URL = &url.URL{
				Scheme: "https", Host: cfg.address,
				Path: r.In.URL.Path, RawPath: r.In.URL.RawPath,
				RawQuery: r.In.URL.RawQuery, ForceQuery: r.In.URL.ForceQuery,
			}
			r.Out.Host = cfg.hostHeader
			// Rewrite runs AFTER ReverseProxy's hop-by-hop cleanup. A caller
			// cannot nominate Authorization in Connection to remove our token.
			stripIdentity(r.Out.Header)
			stripIdentity(r.Out.Trailer)
		},
		Transport:     roundTripper,
		FlushInterval: -1, // Flush watches and logs as bytes arrive.
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// Transport errors can contain request details; never expose them.
			http.Error(w, cfg.errorBody, http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	return handler, transport, nil
}

func certPool(caFile, label string, systemRoots bool) (*x509.CertPool, error) {
	if caFile == "" {
		if !systemRoots {
			return nil, fmt.Errorf("read %s: CA file is empty", label)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificates for %s: %w", label, err)
		}
		return roots, nil
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s contains no certificates", label)
	}
	return roots, nil
}

// identityHeaderPrefixes are headers through which an authenticating front
// proxy asserts the caller's identity. The sidecar is the only proxy allowed
// to speak for the workload, so none of these caller values may reach an
// upstream: an upstream that trusts them would act as the caller.
var identityHeaderPrefixes = []string{
	"impersonate-",
	"x-remote-",
	"x-forwarded-",
	"x-auth-request-", // oauth2-proxy / ingress-nginx auth_request
	"remote-",         // Remote-User and friends from reverse proxies
	"tailscale-user-", // Tailscale serve identity headers
	"cf-access-authenticated-user-",
	"cf-access-jwt-assertion",
	"x-authentik-",  // authentik proxy outpost
	"x-ssl-client-", // client-certificate assertions
	"client-cert",
	"x-pomerium-",
}

// identityHeaders are caller identity headers with fixed names.
var identityHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"forwarded":           {},
	"via":                 {},
	"x-real-ip":           {},
}

func stripIdentity(headers http.Header) {
	for key := range headers {
		name := strings.ToLower(key)
		if _, ok := identityHeaders[name]; ok {
			delete(headers, key)
			continue
		}
		for _, prefix := range identityHeaderPrefixes {
			if strings.HasPrefix(name, prefix) {
				delete(headers, key)
				break
			}
		}
	}
}

type tokenTransport struct {
	base      http.RoundTripper
	tokenFile string
}

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := projectedToken(t.tokenFile)
	if err != nil {
		return nil, err
	}
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	// RoundTrip, unlike http.Client.Do, never follows redirects.
	return t.base.RoundTrip(out)
}

func projectedToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read projected service account token")
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("projected service account token is empty")
	}
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return "", errors.New("projected service account token is invalid")
		}
	}
	return token, nil
}

func listenUnix(path string) (*net.UnixListener, func(), error) {
	if path == "" {
		return nil, nil, errors.New("API proxy socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, fmt.Errorf("create API proxy socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, errors.New("API proxy socket path already exists and is not a socket")
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil, nil, errors.New("API proxy socket is already listening")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil, fmt.Errorf("check existing API proxy socket: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, fmt.Errorf("remove stale API proxy socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("check API proxy socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("listen on API proxy socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	cleanup := func() {
		_ = listener.Close()
		if current, err := os.Lstat(path); err == nil && os.SameFile(info, current) {
			_ = os.Remove(path)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("set API proxy socket permissions: %w", err)
	}
	return listener, cleanup, nil
}

// Tracking at the listener also covers hijacked connections, which
// http.Server.Shutdown and Close intentionally leave to the handler.
type trackedListener struct {
	net.Listener
	mu          sync.Mutex
	connections map[*trackedConn]struct{}
	closing     bool
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		_ = c.Close()
		return nil, net.ErrClosed
	}
	conn := &trackedConn{Conn: c, listener: l}
	l.connections[conn] = struct{}{}
	return conn, nil
}

func (l *trackedListener) closeConnections() {
	l.mu.Lock()
	l.closing = true
	connections := make([]*trackedConn, 0, len(l.connections))
	for c := range l.connections {
		connections = append(connections, c)
	}
	l.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
}

type trackedConn struct {
	net.Conn
	listener *trackedListener
}

func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.listener.mu.Lock()
	delete(c.listener.connections, c)
	c.listener.mu.Unlock()
	return err
}
