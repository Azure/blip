package peer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
)

const leasePinPrefix = "lease:"

// RecheckInterval is how often leases are re-authorized and checked for
// expiry.
var RecheckInterval = time.Minute

// LeaseTTL is how long a lease survives without a renewal. A client renews
// every five minutes, so a crashed client's lease is reclaimed well within
// this window.
const LeaseTTL = 15 * time.Minute

type lease struct {
	ID          string        `json:"id"`
	Node        string        `json:"node"`
	Req         ExportRequest `json:"req"`
	Revoked     bool          `json:"revoked,omitempty"` // release pending (a step failed)
	LastRenewed time.Time     `json:"lastRenewed,omitempty"`
}

// Server serves POST /v1/export, /v1/release, and /v1/leases/{id}/renew on
// HostIP:ExportPort using TLS 1.3 and registered Ed25519 key pins.
type Server struct {
	cfg    ServerConfig
	target *nvme.Target
	path   string

	// Hooks, overridable in tests, perform kernel and store operations while
	// mu serializes activation with revocation and release.
	activateExport func(*lease) (string, error)
	unexport       func(leaseID string) error
	closeExport    func(leaseID string) error
	pin            func(commitID, holder string) error
	unpin          func(commitID, holder string) error
	now            func() time.Time

	mu     sync.Mutex
	leases map[string]*lease
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil || cfg.Identity == nil || cfg.Peers == nil || cfg.Authorize == nil || cfg.DataDir == "" || cfg.NodeName == "" || net.ParseIP(cfg.HostIP).To4() == nil {
		return nil, errors.New("peer: incomplete server config")
	}
	t, err := nvme.NewTarget(cfg.NodeName, cfg.HostIP, NVMePort, cfg.DiskKey)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         cfg,
		target:      t,
		path:        filepath.Join(cfg.DataDir, "leases.json"),
		leases:      map[string]*lease{},
		unexport:    t.Unexport,
		closeExport: cfg.Store.CloseExport,
		pin:         cfg.Store.Pin,
		unpin:       cfg.Store.Unpin,
		now:         time.Now,
	}
	s.activateExport = s.pinAndExport
	b, err := os.ReadFile(s.path)
	if err == nil {
		var ls []*lease
		if err := json.Unmarshal(b, &ls); err != nil {
			return nil, fmt.Errorf("peer: %s: %w", s.path, err)
		}
		for _, l := range ls {
			s.leases[l.ID] = l
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Run restores persisted exports, removes stale ones, and serves until ctx
// ends.
func (s *Server) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case <-s.cfg.Peers.Ready():
	}
	s.restore()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/export", s.handleExport)
	mux.HandleFunc("POST /v1/release", s.handleRelease)
	mux.HandleFunc("POST /v1/leases/{id}/renew", s.handleRenew)
	var ln net.Listener
	for {
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(s.cfg.HostIP, strconv.Itoa(ExportPort)))
		if err == nil {
			break
		}
		log.Printf("peer: export service: %v (retrying)", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	return s.serve(ctx, ln, mux, 5*time.Second)
}

// serve owns all work that may access the store. Shutdown closes admission
// before waiting, so even forced connection closure cannot leave an admitted
// handler or the recheck loop using the store after Run returns.
func (s *Server) serve(ctx context.Context, ln net.Listener, handler http.Handler, grace time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var handlers sync.WaitGroup
	var admission sync.Mutex
	stopping := false
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admission.Lock()
			if stopping {
				admission.Unlock()
				httpError(w, http.StatusServiceUnavailable, "export service is stopping")
				return
			}
			handlers.Add(1)
			admission.Unlock()
			defer handlers.Done()
			handler.ServeHTTP(w, r)
		}),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         s.cfg.Identity.serverTLS(s.cfg.Peers),
	}
	srv.SetKeepAlivesEnabled(false)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	recheckDone := make(chan struct{})
	go func() {
		defer close(recheckDone)
		t := time.NewTicker(RecheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if ctx.Err() != nil {
					return
				}
				s.recheck()
			}
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serveDone:
		serveDone = nil
	}
	admission.Lock()
	stopping = true
	admission.Unlock()
	cancel()
	sctx, stop := context.WithTimeout(context.Background(), grace)
	shutdownErr := srv.Shutdown(sctx)
	stop()
	if shutdownErr != nil {
		// Close unblocks body reads and other connection I/O that cancellation
		// alone cannot interrupt. It does not wait for handlers, so we do.
		if err := srv.Close(); err != nil {
			logf("close export service: %v", err)
		}
	}
	if serveDone != nil {
		serveErr = <-serveDone
	}
	handlers.Wait()
	<-recheckDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return shutdownErr
}

// Pinned reports whether a lease holds commitID.
func (s *Server) Pinned(commitID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.leases {
		if l.Req.CommitID == commitID {
			return true
		}
	}
	return false
}

// pinCommit records the lease's pin in the store.
func (s *Server) pinCommit(l *lease) error {
	if s.pin != nil {
		return s.pin(l.Req.CommitID, leasePinPrefix+l.ID)
	}
	return s.cfg.Store.Pin(l.Req.CommitID, leasePinPrefix+l.ID)
}

// unpinCommit releases the lease's pin in the store.
func (s *Server) unpinCommit(l *lease) error {
	if s.unpin != nil {
		return s.unpin(l.Req.CommitID, leasePinPrefix+l.ID)
	}
	return s.cfg.Store.Unpin(l.Req.CommitID, leasePinPrefix+l.ID)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	node, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req ExportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.CommitID == "" {
		httpError(w, http.StatusBadRequest, "bad export request")
		return
	}
	if req.HostNQN != HostNQN(node) {
		httpError(w, http.StatusForbidden, "host NQN does not belong to "+node)
		return
	}
	if err := s.cfg.Authorize(node, req); err != nil {
		httpError(w, http.StatusForbidden, err.Error())
		return
	}
	l := &lease{ID: newLeaseID(), Node: node, Req: req, LastRenewed: s.now()}
	// Pin before the lease becomes visible. Otherwise a GC pass that already
	// planned to delete the commit could race the lease insert and drop the
	// volume before pinAndExport runs, leaving a live lease that pins nothing
	// and a reader with a 404. With the pin first, either the commit exists
	// and Delete now sees the pin, or the request fails as ErrNotFound and no
	// lease is ever published. The pin is released below if persisting the
	// lease fails; a crash in between leaves an orphan pin that restore (which
	// unpins lease pins without a lease) cleans up.
	if err := s.pinCommit(l); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			code = http.StatusNotFound
		}
		httpError(w, code, err.Error())
		return
	}
	s.mu.Lock()
	s.leases[l.ID] = l
	err := s.saveLocked()
	if err != nil {
		// The lease was never persisted, so it must not linger in memory or
		// hold a pin: nothing else would export, release, or later save it.
		delete(s.leases, l.ID)
	}
	s.mu.Unlock()
	if err != nil {
		if uerr := s.unpinCommit(l); uerr != nil {
			log.Printf("peer: unpin failed export %s: %v", l.ID, uerr)
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := s.export(r.Context(), l)
	if err != nil {
		if rerr := s.release(l.ID); rerr != nil {
			log.Printf("peer: release failed export %s: %v", l.ID, rerr)
		}
		code := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			code = http.StatusNotFound
		}
		httpError(w, code, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) export(ctx context.Context, l *lease) (ExportResponse, error) {
	nqn, err := s.activate(l)
	if err != nil {
		return ExportResponse{}, err
	}
	v, ok := s.cfg.Store.Get(l.Req.CommitID)
	if !ok {
		return ExportResponse{}, storage.ErrNotFound
	}
	base, regions, err := s.cfg.Store.Diff(ctx, l.Req.CommitID, l.Req.Bases, l.Req.BaseDigests)
	if err != nil {
		return ExportResponse{}, err
	}
	if regions == nil {
		regions = []storage.Region{}
	}
	return ExportResponse{
		LeaseID: l.ID, NQN: nqn, Address: s.cfg.HostIP, Port: NVMePort,
		SizeBytes: v.SizeBytes, Base: base, Regions: regions,
	}, nil
}

// activate pins the commit and exports it; idempotent while the lease is live.
// Holding mu through the kernel/store steps prevents release from cleaning up
// an unfinished activation, and prevents a delayed activation resurrecting a
// lease already removed by recheck.
func (s *Server) activate(l *lease) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.leases[l.ID] != l || l.Revoked {
		return "", errors.New("peer: lease is no longer active")
	}
	return s.activateExport(l)
}

func (s *Server) pinAndExport(l *lease) (string, error) {
	st := s.cfg.Store
	if err := st.Pin(l.Req.CommitID, leasePinPrefix+l.ID); err != nil {
		return "", err
	}
	dev, err := st.OpenExport(l.Req.CommitID, l.ID)
	if err != nil {
		return "", err
	}
	return s.target.Export(l.ID, dev, l.Req.HostNQN)
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	node, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req struct {
		LeaseID string `json:"leaseID"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad release request")
		return
	}
	s.mu.Lock()
	l := s.leases[req.LeaseID]
	s.mu.Unlock()
	if l != nil && l.Node != node {
		httpError(w, http.StatusForbidden, "lease belongs to another node")
		return
	}
	if l != nil {
		if err := s.release(l.ID); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}\n"))
}

// handleRenew extends a lease's lifetime. Only the node that holds the lease
// may renew it.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	node, ok := s.caller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	l := s.leases[id]
	if l == nil {
		s.mu.Unlock()
		httpError(w, http.StatusNotFound, "no such lease")
		return
	}
	if l.Node != node {
		s.mu.Unlock()
		httpError(w, http.StatusForbidden, "lease belongs to another node")
		return
	}
	if l.Revoked || s.cfg.Authorize(node, l.Req) != nil {
		s.mu.Unlock()
		httpError(w, http.StatusForbidden, "lease is no longer authorized")
		return
	}
	l.LastRenewed = s.now()
	err := s.saveLocked()
	renewed := l.LastRenewed
	s.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		LeaseID     string    `json:"leaseID"`
		LastRenewed time.Time `json:"lastRenewed"`
	}{id, renewed})
}

// release unexports and unpins a lease. On failure the lease stays (still
// pinning its commit) marked revoked, and the recheck loop retries.
func (s *Server) release(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	if l == nil {
		return nil
	}
	l.Revoked = true
	s.saveLocked()
	err := s.unexport(id)
	if err == nil {
		err = s.closeExport(id)
	}
	if err == nil {
		err = s.unpin(l.Req.CommitID, leasePinPrefix+id)
	}
	if err != nil {
		return err
	}
	delete(s.leases, id)
	return s.saveLocked()
}

// recheck releases leases that are revoked, no longer authorized, or were not
// renewed within LeaseTTL.
func (s *Server) recheck() {
	now := s.now()
	s.mu.Lock()
	var drop []string
	for _, l := range s.leases {
		_, registered := s.cfg.Peers.Lookup(l.Node)
		if l.Revoked || !registered || now.Sub(l.LastRenewed) > LeaseTTL || s.cfg.Authorize(l.Node, l.Req) != nil {
			drop = append(drop, l.ID)
		}
	}
	s.mu.Unlock()
	for _, id := range drop {
		if err := s.release(id); err != nil {
			log.Printf("peer: release lease %s: %v", id, err)
		}
	}
}

// restore re-creates persisted exports after a restart and removes kernel
// and store state that no lease accounts for.
func (s *Server) restore() {
	s.mu.Lock()
	var ls []*lease
	for _, l := range s.leases {
		ls = append(ls, l)
	}
	s.mu.Unlock()
	for _, l := range ls {
		_, registered := s.cfg.Peers.Lookup(l.Node)
		if l.Revoked || !registered || s.now().Sub(l.LastRenewed) > LeaseTTL || s.cfg.Authorize(l.Node, l.Req) != nil {
			continue
		}
		if _, err := s.activate(l); err != nil {
			log.Printf("peer: restore lease %s: %v", l.ID, err)
			s.mu.Lock()
			l.Revoked = true
			s.mu.Unlock()
		}
	}
	s.recheck()

	s.mu.Lock()
	known := map[string]bool{}
	for id := range s.leases {
		known[id] = true
	}
	s.mu.Unlock()
	for _, id := range s.target.Leases() {
		if !known[id] {
			s.target.Unexport(id)
		}
	}
	for id := range s.cfg.Store.Exports() {
		if !known[id] {
			s.cfg.Store.CloseExport(id)
		}
	}
	for _, v := range s.cfg.Store.List() {
		for _, p := range v.Pins {
			if id, ok := strings.CutPrefix(p, leasePinPrefix); ok && !known[id] {
				s.cfg.Store.Unpin(v.ID, p)
			}
		}
	}
}

func (s *Server) saveLocked() error {
	ls := make([]*lease, 0, len(s.leases))
	for _, l := range s.leases {
		ls = append(ls, l)
	}
	b, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// caller authenticates each request against the current registry, including
// requests on an already authenticated connection after key revocation.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
		httpError(w, http.StatusForbidden, "mutual TLS 1.3 required")
		return "", false
	}
	key, err := certificateKey(r.TLS.PeerCertificates)
	if err != nil {
		httpError(w, http.StatusForbidden, "invalid client certificate")
		return "", false
	}
	node, ok := s.cfg.Peers.NodeForKey(key)
	if !ok {
		httpError(w, http.StatusForbidden, "unregistered client key")
	}
	return node, ok
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func newLeaseID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func logf(format string, args ...any) { log.Printf("peer: "+format, args...) }
