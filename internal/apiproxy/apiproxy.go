// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
	"golang.org/x/sys/unix"
)

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// maxConcurrentRequests bounds the requests that may be in a handler at once.
// Watches, log streams, exec/attach upgrades, and plain long responses hold a
// request (and an upstream connection) until the stream ends, so an unbounded
// number of them exhausts the sidecar's memory limit and gets the whole
// process OOM-killed.
//
// The cap is derived from the api-proxy sidecar's 64Mi limit
// (internal/controller/pool.go). In live runs, 256 held watch streams reached
// 60.2MiB and were OOM-killed in 4 of 5 attempts: about 230KiB per stream once
// the runtime baseline is subtracted, including the two owner-scope GETs each
// scoped request performs and its relay buffers. 64 streams cost about 14MiB
// at that rate, leaving ~50MiB for the Go runtime, TLS state for the added
// scope connections, and transient payloads. limit_test.go holds every slot
// and guards the cap against being raised past this safe budget.
//
// The cap is global: kube-apiserver and endpoint routes share it. A request
// that cannot get a slot is rejected with 503 instead of queued, so excess
// streams never allocate upstream buffers.
//
// A graceful full close of a guest stream that follows a half-close may not be
// visible until the peer's orphaned FIN_WAIT2 socket expires and keepalive
// fails (~77s with default tcp_fin_timeout). That is a bounded delay rather
// than a leak; see clientGone in internal/guest/api.go. A held stream keeps its
// slot for that interval.
const maxConcurrentRequests = 64

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
	// the owner it acts for. Both are required whenever API is set.
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
		if cfg.PodName == "" {
			return Config{}, errors.New("POD_NAME and POD_NAMESPACE are required for the Kubernetes API route")
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

// requestLimiter is a counting semaphore for requests that hold a handler.
// Acquire is deliberately non-blocking: when every slot is taken, the request
// is rejected rather than waiting, because waiting still holds a client
// connection and its read buffer.
type requestLimiter struct {
	slots chan struct{}
}

func newRequestLimiter(limit int) *requestLimiter {
	return &requestLimiter{slots: make(chan struct{}, limit)}
}

func (l *requestLimiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *requestLimiter) release() {
	<-l.slots
}

// serve is the admission gate for one request. The slot is held for the whole
// handler, including watches, streams, and hijacked upgrades, and released on
// every return path. It is separate from the http.Server wiring so the decision
// can be exercised without a network listener.
func (l *requestLimiter) serve(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	if !l.acquire() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent requests", http.StatusServiceUnavailable)
		return
	}
	defer l.release()
	if lifetime, ok := r.Context().Value(connectionLifetimeKey{}).(context.Context); ok {
		r = r.WithContext(lifetime)
	}
	handler.ServeHTTP(w, r)
}

// connectionLifetimeKey carries the connection-scoped context. A client may
// half-close its write side after sending a complete request; net/http
// cancels the per-request context when the read side reaches EOF, even
// though the connection is still open for the response. Proxying against the
// connection lifetime keeps the in-flight request and response alive for a
// half-close, while cancelling it when the connection is really closed.
//
// net/http only reports read-side EOF, which is identical for a half-close
// and a full close. The underlying Unix socket does distinguish the two:
// a full close is reported as POLLHUP, a half-close only as POLLRDHUP. The
// connection lifetime is cancelled immediately on POLLHUP and on Close, so a
// guest that closes its socket stops an idle watch or stream. A full close
// that follows a half-close is invisible to Read (net/http has no reason to
// read again after EOF), so an independent poll watches for it.
type connectionLifetimeKey struct{}

func newProxyServer(ctx context.Context, socketPath string, handler http.Handler) (*proxyServer, error) {
	listener, cleanup, err := listenUnix(socketPath)
	if err != nil {
		return nil, err
	}
	tracked := &trackedListener{Listener: listener, connections: make(map[*trackedConn]struct{})}
	limiter := newRequestLimiter(maxConcurrentRequests)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The slot is held for the whole request, including watches,
			// streams, and hijacked upgrades, and released on every return
			// path: normal completion, client cancellation, and upstream
			// errors all end ServeHTTP.
			limiter.serve(w, r, handler)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(connCtx context.Context, conn net.Conn) context.Context {
			lifetime, cancel := context.WithCancel(connCtx)
			if c, ok := conn.(*trackedConn); ok {
				c.setLifetimeCancel(cancel)
			} else {
				cancel()
			}
			return context.WithValue(lifetime, connectionLifetimeKey{}, lifetime)
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

func newUpstreamProxy(cfg upstreamOptions) (http.Handler, *http.Transport, http.RoundTripper, error) {
	pool := newCAPool(cfg.caFile, cfg.caLabel, cfg.systemRoots)
	if _, _, err := pool.current(); err != nil {
		return nil, nil, nil, err
	}
	if cfg.tokenFile != "" {
		if _, err := projectedToken(cfg.tokenFile); err != nil {
			return nil, nil, nil, err
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
		// Kubernetes exec/attach/port-forward require HTTP/1 upgrades.
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DisableCompression:    true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	// TLS is set up here rather than in TLSClientConfig so every handshake
	// can use the current projected CA bundle.
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := transport.DialContext(ctx, network, cfg.address)
		if err != nil {
			return nil, err
		}
		roots, _, err := pool.current()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    roots,
			ServerName: cfg.serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	ca := &caTransport{base: transport, pool: pool}
	var roundTripper http.RoundTripper = ca
	if cfg.tokenFile != "" {
		roundTripper = tokenTransport{base: roundTripper, tokenFile: cfg.tokenFile}
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
			// ReverseProxy clones Trailer before the inbound body reaches
			// EOF, so the outbound map still has no values when net/http
			// serializes the request; only the announcement is sent. Keep
			// stripping names in case trailer forwarding is fixed later.
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
	return handler, transport, ca, nil
}

// credentialFS is the filesystem subset used for projected credential files.
// osCredentialFS is the production implementation; tests inject an in-memory
// one to make rotation and revocation deterministic.
type credentialFS interface {
	Stat(name string) (os.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

type osCredentialFS struct{}

func (osCredentialFS) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }
func (osCredentialFS) ReadFile(name string) ([]byte, error)  { return os.ReadFile(name) }

func credentialFiles(fs credentialFS) credentialFS {
	if fs != nil {
		return fs
	}
	return osCredentialFS{}
}

// caPool reads the configured CA bundle on demand. A projected ConfigMap
// volume can rotate or revoke a CA in place; the bundle is re-read whenever
// the file's modification time or size changes, so a running sidecar does not
// keep trusting an old CA until it restarts.
type caPool struct {
	caFile      string
	label       string
	systemRoots bool
	files       credentialFS

	mu      sync.Mutex
	modTime time.Time
	size    int64
	gen     uint64
	roots   *x509.CertPool
}

func newCAPool(caFile, label string, systemRoots bool) *caPool {
	return &caPool{caFile: caFile, label: label, systemRoots: systemRoots, files: osCredentialFS{}}
}

// current returns the current root pool. The generation increases on every
// successful reload so callers can drop connections that used an older CA.
func (p *caPool) current() (*x509.CertPool, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	files := credentialFiles(p.files)
	if p.caFile == "" {
		if !p.systemRoots {
			return nil, 0, fmt.Errorf("read %s: CA file is empty", p.label)
		}
		if p.roots == nil {
			roots, err := x509.SystemCertPool()
			if err != nil {
				return nil, 0, fmt.Errorf("load system certificates for %s: %w", p.label, err)
			}
			p.roots = roots
			p.gen++
		}
		return p.roots, p.gen, nil
	}
	info, err := files.Stat(p.caFile)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", p.label, err)
	}
	if p.roots != nil && info.ModTime().Equal(p.modTime) && info.Size() == p.size {
		return p.roots, p.gen, nil
	}
	ca, err := files.ReadFile(p.caFile)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", p.label, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, 0, fmt.Errorf("%s contains no certificates", p.label)
	}
	p.roots, p.modTime, p.size = roots, info.ModTime(), info.Size()
	p.gen++
	return p.roots, p.gen, nil
}

// idleClosingRoundTripper is the part of *http.Transport caTransport uses.
// Keeping it as an interface lets the simulation drive the generation and
// idle-connection decision with an in-memory upstream.
type idleClosingRoundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

// caTransport checks the CA bundle before each request and closes idle TLS
// connections after a change, so the next request handshakes against the new
// bundle instead of reusing a connection trusted under the old one.
type caTransport struct {
	base idleClosingRoundTripper
	pool *caPool

	mu  sync.Mutex
	gen uint64
}

func (t *caTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	_, gen, err := t.pool.current()
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	// The initial generation is 0 ("unset"). It must still compare unequal to
	// a pool that has already loaded a bundle, so the first request is checked
	// for a change too; otherwise an idle connection warmed outside this
	// transport could survive the first rotation.
	if t.gen != gen {
		t.base.CloseIdleConnections()
	}
	t.gen = gen
	t.mu.Unlock()
	return t.base.RoundTrip(r)
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
	"x-auth-username", // generic reverse-proxy user assertions
	"remote-",         // Remote-User and friends from reverse proxies
	"teleport-",       // Teleport app-access JWT assertions and user headers
	"x-vouch-",        // Vouch Proxy user and IdP assertions
	"x-username",      // generic front-proxy user name
	"x-impersonate-",  // generic impersonation assertions
	"x-jwt-assertion",
	"x-authenticated-", // generic authenticated-user assertions
	"tailscale-user-",  // Tailscale serve identity headers
	"cf-access-authenticated-user-",
	"cf-access-jwt-assertion",
	"x-authentik-",  // authentik proxy outpost
	"x-ssl-client-", // client-certificate assertions
	"client-cert",
	"x-pomerium-",
	"x-goog-authenticated-user-", // Google IAP and Cloud Run identity
	"x-ms-client-principal",      // Azure Easy Auth principal and its -Name/-Id variants
	"x-ms-token-",                // Azure AD / managed-identity access-token assertions
	"x-amzn-oidc-",               // AWS ALB OIDC data, identity, and access-token assertions
	"x-envoy-",                   // Envoy peer metadata and external-address assertions
}

// identityHeaders are caller identity headers with fixed names.
var identityHeaders = map[string]struct{}{
	"authorization":            {},
	"proxy-authorization":      {},
	"forwarded":                {},
	"via":                      {},
	"x-real-ip":                {},
	"x-goog-iap-jwt-assertion": {},
	"x-webauth-user":           {},
	"x-client-cert":            {},
	"x-client-dn":              {},
	"x-original-user":          {},
	"x-auth-user":              {},
	"x-auth-email":             {},
	"x-authenticated-user":     {},
	"x-user":                   {},
	"x-user-id":                {},
	"x-email":                  {},
	"x-scope":                  {},
	"x-userinfo":               {},
	"x-envoy-peer-metadata":    {},
}

func stripIdentity(headers http.Header) {
	for key := range headers {
		// Frameworks commonly expose X_Forwarded_User to applications as
		// HTTP_X_FORWARDED_USER, so a caller can smuggle a denylisted name
		// past an exact "-" match with underscores. Normalize separators
		// before matching; the original key is what gets deleted.
		name := strings.ReplaceAll(strings.ToLower(key), "_", "-")
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
	files     credentialFS
}

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := projectedTokenFrom(t.files, t.tokenFile)
	if err != nil {
		return nil, err
	}
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	// RoundTrip, unlike http.Client.Do, never follows redirects.
	return t.base.RoundTrip(out)
}

func projectedToken(path string) (string, error) {
	return projectedTokenFrom(nil, path)
}

func projectedTokenFrom(fs credentialFS, path string) (string, error) {
	data, err := credentialFiles(fs).ReadFile(path)
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
	conn := &trackedConn{Conn: c, listener: l, done: make(chan struct{})}
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
	mu       sync.Mutex
	closed   bool
	watching bool
	// done is closed by Close to stop the hangup watcher.
	done chan struct{}
	// cancelLifetime ends in-flight upstream requests for this connection.
	// It is set by ConnContext before the connection starts serving.
	cancelLifetime context.CancelFunc
}

func (c *trackedConn) setLifetimeCancel(cancel context.CancelFunc) {
	c.mu.Lock()
	c.cancelLifetime = cancel
	closed := c.closed
	c.mu.Unlock()
	if closed {
		cancel()
	}
}

// Read detects a fully closed peer. net/http reads the request and then runs a
// background read; both see EOF for a half-close and for a full close. Only a
// full close reports POLLHUP on the Unix socket, so it can end the connection
// lifetime without breaking the wave-4 half-close behaviour.
//
// The background read is the last Read net/http performs: after it returns
// EOF (which is also what a half-close produces) net/http never reads this
// connection again. A later full close therefore cannot be observed here, so
// the first EOF starts a watcher that polls for POLLHUP. Any other read error
// means the connection is already broken, except for the timeout net/http uses
// to abort a blocked background read, which must be ignored.
func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return n, err
		}
		if errors.Is(err, io.EOF) {
			c.watchFullClose()
		} else {
			c.endLifetime()
		}
	}
	return n, err
}

// fullClosePollInterval bounds how long an idle watch survives after its guest
// connection is fully closed. Half-closes are unaffected: they never report
// POLLHUP, however long they are polled.
const fullClosePollInterval = 250 * time.Millisecond

// watchFullClose starts one POLLHUP poller per connection. It stops when the
// connection is closed, when the peer is seen to be fully gone, or after
// cancelling the lifetime.
func (c *trackedConn) watchFullClose() {
	c.mu.Lock()
	if c.watching || c.closed {
		c.mu.Unlock()
		return
	}
	c.watching = true
	c.mu.Unlock()

	if socketHungUp(c.Conn) {
		c.endLifetime()
		return
	}
	go func() {
		ticker := time.NewTicker(fullClosePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				if socketHungUp(c.Conn) {
					c.endLifetime()
					return
				}
			}
		}
	}()
}

// socketHungUp reports whether conn has been fully closed by its peer rather
// than only half-closed. It is only meaningful after a read returned EOF.
func socketHungUp(conn net.Conn) bool {
	sysc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sysc.SyscallConn()
	if err != nil {
		return true
	}
	hungUp := false
	err = raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLRDHUP}}
		if n, _ := unix.Poll(fds, 0); n > 0 {
			hungUp = fds[0].Revents&unix.POLLHUP != 0
		}
	})
	// A connection that cannot expose its descriptor is already gone.
	return err != nil || hungUp
}

func (c *trackedConn) endLifetime() {
	c.mu.Lock()
	cancel := c.cancelLifetime
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	alreadyClosed := c.closed
	c.closed = true
	cancel := c.cancelLifetime
	if !alreadyClosed {
		close(c.done)
	}
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.listener.mu.Lock()
	delete(c.listener.connections, c)
	c.listener.mu.Unlock()
	return err
}
