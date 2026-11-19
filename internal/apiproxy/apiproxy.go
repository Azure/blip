// Package apiproxy serves the pod's Kubernetes API identity over the
// guest-to-host vsock Unix socket. The service account credential stays in
// the sidecar; the API server remains responsible for authorization. Reads of
// Blips, BlipStates and Pods from a claimed VM are additionally scoped to the
// owner recorded on the pod and its Blip.
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

// Config contains trusted sidecar configuration, never guest request data.
type Config struct {
	SocketPath string
	// APIAddress is the Kubernetes HTTPS authority, including its port.
	APIAddress string
	TokenFile  string
	CAFile     string
	// PodName and PodNamespace identify this API proxy's own pod. They come
	// from the downward API, never from the guest, and let the proxy derive
	// the owner it acts for. When both are empty, Kubernetes object reads are
	// not scoped (compatibility for direct local runs and unit tests).
	PodName      string
	PodNamespace string
}

// ConfigFromEnv uses the in-cluster API endpoint and explicitly projected
// service account files. BLIP_DIR defaults to /run/blip.
func ConfigFromEnv() (Config, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	address, err := apiAddress(host, port)
	if err != nil {
		return Config{}, err
	}
	dir := os.Getenv("BLIP_DIR")
	if dir == "" {
		dir = podapi.MountPath
	}
	cfg := Config{
		SocketPath:   podapi.VsockListenerPath(dir, wire.APIPort),
		APIAddress:   address,
		TokenFile:    filepath.Join(serviceAccountDir, "token"),
		CAFile:       filepath.Join(serviceAccountDir, "ca.crt"),
		PodName:      os.Getenv("POD_NAME"),
		PodNamespace: os.Getenv("POD_NAMESPACE"),
	}
	if (cfg.PodName == "") != (cfg.PodNamespace == "") {
		return Config{}, errors.New("POD_NAME and POD_NAMESPACE must both be set")
	}
	if cfg.PodName != "" && (!validPodIdentity(cfg.PodName) || !validPodIdentity(cfg.PodNamespace)) {
		return Config{}, errors.New("invalid POD_NAME or POD_NAMESPACE")
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
	proxy, transport, err := newProxy(cfg)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
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

func newProxyServer(ctx context.Context, socketPath string, handler http.Handler) (*proxyServer, error) {
	listener, cleanup, err := listenUnix(socketPath)
	if err != nil {
		return nil, err
	}
	tracked := &trackedListener{Listener: listener, connections: make(map[*trackedConn]struct{})}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.New(io.Discard, "", 0),
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
	address    string // validated host:port
	serverName string // TLS SNI; empty means the URL host
	hostHeader string // outbound Host header
	caFile     string
	caLabel    string // error text for CA read/parse failures
	tokenFile  string
	errorBody  string
}

func newProxy(cfg Config) (http.Handler, *http.Transport, error) {
	host, port, err := net.SplitHostPort(cfg.APIAddress)
	if err != nil {
		return nil, nil, errors.New("invalid Kubernetes API address")
	}
	address, err := apiAddress(host, port)
	if err != nil {
		return nil, nil, err
	}
	handler, transport, err := newUpstreamProxy(upstreamOptions{
		address:    address,
		serverName: host,
		hostHeader: address,
		caFile:     cfg.CAFile,
		caLabel:    "Kubernetes CA",
		tokenFile:  cfg.TokenFile,
		errorBody:  "Kubernetes API unavailable",
	})
	if err != nil {
		return nil, nil, err
	}
	if (cfg.PodName == "") != (cfg.PodNamespace == "") {
		return nil, nil, errors.New("API proxy pod identity is incomplete")
	}
	if cfg.PodName != "" {
		handler = newOwnerScope(cfg, transport, handler)
	}
	return handler, transport, nil
}

func newUpstreamProxy(cfg upstreamOptions) (http.Handler, *http.Transport, error) {
	roots, err := certPool(cfg.caFile, cfg.caLabel)
	if err != nil {
		return nil, nil, err
	}
	if _, err := projectedToken(cfg.tokenFile); err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		// Proxy is deliberately nil: HTTP(S)_PROXY cannot change the destination.
		DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
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
		Transport:     tokenTransport{base: transport, tokenFile: cfg.tokenFile},
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

func certPool(caFile, label string) (*x509.CertPool, error) {
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

func stripIdentity(headers http.Header) {
	for key := range headers {
		name := strings.ToLower(key)
		if name == "authorization" || name == "proxy-authorization" ||
			strings.HasPrefix(name, "impersonate-") || strings.HasPrefix(name, "x-remote-") ||
			name == "forwarded" || name == "via" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") {
			delete(headers, key)
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
