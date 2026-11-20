// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
)

const (
	leaseRenewInterval = 5 * time.Minute
	releaseMaxAttempts = 8
	releaseMinBackoff  = time.Second
	releaseMaxBackoff  = time.Minute
)

// Client owns the node's remote leases. Construct it before storage.Open so
// recovery can release and resume remotes before the registry is ready.
type Client struct {
	identity *Identity
	peers    *Registry
	diskKey  []byte
	ctx      context.Context
	cancel   context.CancelFunc
	active   sync.Map // leaseKey -> *renewal
	mu       sync.Mutex
	released map[leaseKey]struct{} // terminal recovered leases only

	// Kernel operations are replaceable in unprivileged lifecycle tests.
	connect    func(context.Context, string, int, string, string, []byte) (string, error)
	disconnect func(string) error
	clock      Clock
	transport  func(*http.Transport) http.RoundTripper
}

// ClientOptions replaces instance boundaries without bypassing discovery,
// request encoding, response validation, or the production TLS configuration.
// Transport may wrap the freshly configured transport (for example to inject
// a connection failure after the server committed a response).
type ClientOptions struct {
	Clock      Clock
	Transport  func(*http.Transport) http.RoundTripper
	Connect    func(context.Context, string, int, string, string, []byte) (string, error)
	Disconnect func(string) error
}

type leaseKey struct{ node, id string }
type renewal struct{ cancel context.CancelFunc }

func NewClient(identity *Identity, peers *Registry, diskKey []byte) *Client {
	return NewClientWithOptions(identity, peers, diskKey, ClientOptions{})
}

func NewClientWithOptions(identity *Identity, peers *Registry, diskKey []byte, opts ClientOptions) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	if opts.Connect == nil {
		opts.Connect = nvme.Connect
	}
	if opts.Disconnect == nil {
		opts.Disconnect = nvme.Disconnect
	}
	return &Client{
		identity: identity, peers: peers, diskKey: bytes.Clone(diskKey), ctx: ctx, cancel: cancel,
		released: make(map[leaseKey]struct{}), connect: opts.Connect, disconnect: opts.Disconnect,
		clock: opts.Clock, transport: opts.Transport,
	}
}

// Close stops background renewals, release retries, and in-flight requests.
func (c *Client) Close() { c.cancel() }

// Open requests an export from the named node over key-pinned mutual TLS,
// then connects to its ciphertext device using authenticated NVMe/TCP.
func (c *Client) Open(ctx context.Context, node string, req ExportRequest) (storage.Remote, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	if err := c.ctx.Err(); err != nil {
		return storage.Remote{}, err
	}
	var resp ExportResponse
	if err := c.post(ctx, node, "/v1/export", req, &resp); err != nil {
		// Export is not idempotent. A lost response can leave an unknown
		// durable lease, reclaimed by server expiry; never retry it here.
		return storage.Remote{}, err
	}
	id := node + "/" + resp.LeaseID + "/" + resp.NQN
	addr := net.ParseIP(resp.Address)
	if _, _, _, ok := parseRemote(id); !ok || addr.To4() == nil || resp.Port != NVMePort || resp.SizeBytes <= 0 {
		// Only release a syntactically valid lease; never pass an untrusted
		// NQN to the local kernel's disconnect operation.
		if validLeaseID(resp.LeaseID) {
			go c.releaseWithRetry(c.ctx, node, resp.LeaseID, id)
		}
		return storage.Remote{}, fmt.Errorf("peer: unexpected export response from %s", node)
	}
	// Connect may return a device even when canceled (an existing namespace
	// can already be ready), so check cancellation both before and after it.
	err := ctx.Err()
	if err == nil {
		err = c.ctx.Err()
	}
	var dev string
	if err == nil {
		dev, err = c.connect(ctx, addr.String(), resp.Port, resp.NQN, req.HostNQN, c.diskKey)
	}
	if err != nil {
		c.releaseRemote(id, false)
		return storage.Remote{}, err
	}
	c.startRenewal(node, resp.LeaseID, false)
	err = ctx.Err()
	if err == nil {
		err = c.ctx.Err()
	}
	if err != nil {
		c.releaseRemote(id, false)
		return storage.Remote{}, err
	}
	var once sync.Once
	return storage.Remote{
		Device: dev, SizeBytes: resp.SizeBytes, Base: resp.Base, Regions: resp.Regions, ID: id,
		Release: func() { once.Do(func() { c.releaseRemote(id, false) }) },
	}, nil
}

func validLeaseID(id string) bool {
	if id == "" {
		return false
	}
	for _, ch := range id {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func parseRemote(id string) (node, leaseID, nqn string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] == "" || !validLeaseID(parts[1]) || parts[2] != nvme.SubsystemNQN(parts[0], parts[1]) {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// ResumeRemote renews a recovered persistent remote immediately after the
// first registry snapshot, then keeps renewing it until release or shutdown.
// Storage recovery normally calls it before starting the clone watcher that
// can release the remote; a release wins even if recovery races with it.
func (c *Client) ResumeRemote(id string) {
	if node, leaseID, _, ok := parseRemote(id); ok {
		c.startRenewal(node, leaseID, true)
	}
}

func (c *Client) startRenewal(node, leaseID string, recovered bool) func() {
	key := leaseKey{node, leaseID}
	c.mu.Lock()
	if _, released := c.released[key]; released || c.ctx.Err() != nil {
		c.mu.Unlock()
		return func() {}
	}
	ctx, cancel := context.WithCancel(c.ctx)
	r := &renewal{cancel: cancel}
	if old, loaded := c.active.Swap(key, r); loaded {
		old.(*renewal).cancel()
	}
	c.mu.Unlock()
	go func() {
		defer c.active.CompareAndDelete(key, r)
		defer cancel()
		if err := c.waitReady(ctx); err != nil {
			return
		}
		delay := leaseRenewInterval
		if recovered {
			delay = 0
		}
		for {
			if c.clock.Wait(ctx, delay) != nil {
				return
			}
			rctx, rcancel := c.clock.WithTimeout(ctx, 30*time.Second)
			err := c.post(rctx, node, "/v1/leases/"+url.PathEscape(leaseID)+"/renew", struct{}{}, nil)
			rcancel()
			if err != nil && ctx.Err() == nil {
				logf("renew lease %s/%s: %v", node, leaseID, err)
			}
			status := 0
			var response *responseError
			if errors.As(err, &response) {
				status = response.status
			}
			decision := RenewalRetry(status, err != nil, ctx.Err() != nil)
			if decision.Stop {
				// An older request completing after replacement must never
				// terminate the newly installed renewal.
				c.mu.Lock()
				if c.active.CompareAndDelete(key, r) && recovered && ctx.Err() == nil {
					c.released[key] = struct{}{}
				}
				c.mu.Unlock()
				return
			}
			// Retry transient startup failures promptly rather than waiting a
			// full interval while a recovered lease approaches expiry.
			delay = decision.Delay
		}
	}()
	return func() {
		c.active.CompareAndDelete(key, r)
		cancel()
	}
}

// endLease serializes release with renewal installation. Only recovered leases
// need terminal state to prevent a delayed ResumeRemote from restarting them;
// normal Open leases are released through their closure and never resumed.
func (c *Client) endLease(key leaseKey, remember bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remember {
		c.released[key] = struct{}{}
	}
	if r, ok := c.active.LoadAndDelete(key); ok {
		r.(*renewal).cancel()
	}
}

// ReleaseRemote releases a recovered remote whose Release closure was lost
// after restart. It disconnects the local controller and retries lease release
// asynchronously. The ID is nodeName/leaseID/NQN, never a cached endpoint.
func (c *Client) ReleaseRemote(id string) {
	c.releaseRemote(id, true)
}

func (c *Client) releaseRemote(id string, recovered bool) {
	node, leaseID, nqn, ok := parseRemote(id)
	if !ok {
		return
	}
	c.endLease(leaseKey{node, leaseID}, recovered)
	if err := c.disconnect(nqn); err != nil {
		logf("release %s: %v", id, err)
	}
	go c.releaseWithRetry(c.ctx, node, leaseID, id)
}

func (c *Client) waitReady(ctx context.Context) error {
	if c.identity == nil || c.peers == nil {
		return fmt.Errorf("peer: missing identity or registry")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-c.peers.Ready():
		if err := c.ctx.Err(); err != nil {
			return err
		}
		return ctx.Err()
	}
}

func (c *Client) releaseWithRetry(ctx context.Context, node, leaseID, id string) {
	// Startup discovery must not consume the bounded release attempts.
	if c.waitReady(ctx) != nil {
		return
	}
	for attempt := 0; attempt < releaseMaxAttempts; attempt++ {
		rctx, cancel := c.clock.WithTimeout(ctx, 30*time.Second)
		err := c.post(rctx, node, "/v1/release", map[string]string{"leaseID": leaseID}, nil)
		cancel()
		decision := ReleaseRetry(attempt+1, err == nil, ctx.Err() != nil)
		if decision.Stop {
			if err != nil && ctx.Err() == nil {
				logf("release %s: giving up; the lease expires on the server", id)
			}
			return
		}
		logf("release %s: %v (retrying in %s)", id, err, decision.Delay)
		if c.clock.Wait(ctx, decision.Delay) != nil {
			return
		}
	}
}

type responseError struct {
	status  int
	message string
}

func (e *responseError) Error() string { return e.message }

// StreamHTTPStatus exposes the peer's HTTP status so a node agent can translate
// a forwarded failure back into the stream API's error vocabulary.
func (e *responseError) StreamHTTPStatus() int { return e.status }

func (c *Client) post(ctx context.Context, node, path string, body, out any) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	if err := c.waitReady(ctx); err != nil {
		return err
	}
	// Initial discovery has its caller's deadline, not the HTTP deadline.
	ctx, requestCancel := c.clock.WithTimeout(ctx, 2*time.Minute)
	defer requestCancel()
	p, ok := c.peers.Lookup(node)
	if !ok {
		return fmt.Errorf("peer: unknown node %q", node)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := "https://" + net.JoinHostPort(p.Endpoint, strconv.Itoa(ExportPort)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Each request gets a fresh TLS handshake and current registry key check.
	// No proxy, redirects, connection reuse, or session resumption can bypass
	// the named-node pin or send a request to an unintended endpoint.
	transport := &http.Transport{
		TLSClientConfig:     c.identity.clientTLS(c.peers, node),
		DisableKeepAlives:   true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	var roundTripper http.RoundTripper = transport
	if c.transport != nil {
		roundTripper = c.transport(transport)
	}
	httpClient := &http.Client{
		Transport:     roundTripper,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		json.Unmarshal(data, &e)
		return &responseError{status: resp.StatusCode, message: fmt.Sprintf("peer: %s %s: %s: %s", node, path, resp.Status, e.Error)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
