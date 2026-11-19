// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
	"sort"
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
const RecheckInterval = time.Minute

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
	target ExportTarget
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
	t := cfg.Target
	if t == nil {
		var err error
		t, err = nvme.NewTarget(cfg.NodeName, cfg.HostIP, NVMePort, cfg.DiskKey)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.NewLeaseID == nil {
		cfg.NewLeaseID = newLeaseID
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
		now:         cfg.Clock.Now,
	}
	s.activateExport = s.pinAndExport
	b, err := s.persistence().Load()
	if err == nil {
		var ls []*lease
		if err := json.Unmarshal(b, &ls); err != nil {
			return nil, fmt.Errorf("peer: %s: %w", s.path, err)
		}
		for _, l := range ls {
			if l == nil || !validLeaseID(l.ID) || l.Node == "" || l.Req.CommitID == "" || s.leases[l.ID] != nil {
				return nil, fmt.Errorf("peer: %s: invalid or duplicate lease", s.path)
			}
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
	if err := s.Recover(); err != nil {
		log.Printf("peer: recovery: %v", err)
	}
	mux := s.Handler()
	var ln net.Listener
	for {
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(s.cfg.HostIP, strconv.Itoa(ExportPort)))
		if err == nil {
			break
		}
		log.Printf("peer: export service: %v (retrying)", err)
		if s.clock().Wait(ctx, 2*time.Second) != nil {
			return nil
		}
	}
	return s.serve(ctx, ln, mux, 5*time.Second)
}

// Handler exposes the same authenticated protocol handlers used by Run. TLS
// termination must supply the authenticated connection state in Request.TLS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/export", s.handleExport)
	mux.HandleFunc("POST /v1/release", s.handleRelease)
	mux.HandleFunc("POST /v1/leases/{id}/renew", s.handleRenew)
	mux.HandleFunc("GET /v1/stream/log", s.handleStreamLog)
	mux.HandleFunc("POST /v1/stream/stdin", s.handleStreamStdin)
	return mux
}

func (s *Server) clock() Clock {
	if s.cfg.Clock != nil {
		return s.cfg.Clock
	}
	return realClock{}
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
		interval := s.cfg.RecheckInterval
		if interval <= 0 {
			interval = RecheckInterval
		}
		for {
			if s.clock().Wait(ctx, interval) != nil {
				return
			}
			s.recheck()
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
	var id string
	if s.cfg.NewLeaseID != nil {
		id = s.cfg.NewLeaseID()
	} else {
		id = newLeaseID()
	}
	if !validLeaseID(id) {
		httpError(w, http.StatusInternalServerError, "invalid lease ID")
		return
	}
	l := &lease{ID: id, Node: node, Req: req, LastRenewed: s.now()}
	// Pin before the lease becomes visible. Otherwise a GC pass that already
	// planned to delete the commit could race the lease insert and drop the
	// volume before pinAndExport runs, leaving a live lease that pins nothing
	// and a reader with a 404. With the pin first, either the commit exists
	// and Delete now sees the pin, or the request fails as ErrNotFound and no
	// lease is ever published. The pin is released below if persisting the
	// lease fails; a crash in between leaves an orphan pin that Recover (which
	// unpins lease pins without a lease) cleans up.
	if err := s.prepare(l); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			code = http.StatusNotFound
		}
		httpError(w, code, err.Error())
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

func (s *Server) prepare(l *lease) error {
	// Reserve the ID before touching its pin. A colliding request must never
	// pin a second commit under an existing lease's holder or roll it back.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.leases[l.ID] != nil {
		return errors.New("peer: duplicate lease ID")
	}
	err := runLeaseEffects(PrepareLease, func(effect LeaseEffect) error {
		switch effect {
		case LeasePin:
			return s.pinCommit(l)
		case LeasePersist:
			s.leases[l.ID] = l
			return s.saveLocked()
		}
		return nil
	})
	if err == nil {
		return nil
	}
	// A failed pin may still have taken effect. Retain a revoked cleanup
	// owner until rollback succeeds, so ordinary recheck can retry it without
	// requiring a restart. An ambiguous journal save must be revoked durably
	// before dropping even its pin.
	l.Revoked = true
	s.leases[l.ID] = l
	if !ambiguousSave(err) {
		if uerr := s.unpinCommit(l); uerr != nil {
			return errors.Join(err, uerr)
		}
		delete(s.leases, l.ID)
	}
	return err
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
	if s.leases[l.ID] != l || s.mustRelease(l, s.now()) {
		return "", errors.New("peer: lease is no longer active")
	}
	return s.activateExport(l)
}

func (s *Server) pinAndExport(l *lease) (string, error) {
	st := s.cfg.Store
	var dev, nqn string
	err := runLeaseEffects(ActivateLease, func(effect LeaseEffect) (err error) {
		switch effect {
		case LeasePin:
			err = s.pinCommit(l)
		case LeaseOpenDevice:
			dev, err = st.OpenExport(l.Req.CommitID, l.ID)
		case LeasePublish:
			nqn, err = s.target.Export(l.ID, dev, l.Req.HostNQN)
		}
		return err
	})
	return nqn, err
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
	now := s.now()
	if s.mustRelease(l, now) {
		l.Revoked = true
		if err := s.saveLocked(); err != nil {
			logf("persist rejected renewal %s: %v", id, err)
		}
		s.mu.Unlock()
		httpError(w, http.StatusForbidden, "lease is no longer authorized")
		return
	}
	previous := l.LastRenewed
	l.LastRenewed = now
	err := s.saveLocked()
	renewed := l.LastRenewed
	if err != nil {
		// Even an ambiguous save cannot promise a renewal. Retaining the old
		// deadline is conservative and permits an ordinary client retry.
		l.LastRenewed = previous
	}
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

// release unexports and unpins a lease. On failure cleanup ownership stays
// marked revoked, and the recheck loop retries. A pin may already be gone when
// the only remaining effect is durably forgetting the revoked lease.
func (s *Server) release(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	if l == nil {
		return nil
	}
	return runLeaseEffects(ReleaseLease, func(effect LeaseEffect) error {
		switch effect {
		case LeasePersistRevocation:
			l.Revoked = true
			return s.saveLocked()
		case LeaseUnpublish:
			return s.unexport(id)
		case LeaseCloseDevice:
			return s.closeExport(id)
		case LeaseUnpin:
			return s.unpinCommit(l)
		case LeaseForget:
			delete(s.leases, id)
			if err := s.saveLocked(); err != nil {
				// A failed deletion must remain retryable, whether or not the
				// replacement reached disk. The durable old record is revoked.
				s.leases[id] = l
				return err
			}
		}
		return nil
	})
}

func (s *Server) mustRelease(l *lease, now time.Time) bool {
	_, registered := s.cfg.Peers.Lookup(l.Node)
	// Avoid consulting an authorizer unnecessarily for terminal leases.
	authorized := !LeaseMustRelease(now, l.LastRenewed, l.Revoked, registered, true) && s.cfg.Authorize(l.Node, l.Req) == nil
	return LeaseMustRelease(now, l.LastRenewed, l.Revoked, registered, authorized)
}

// recheck releases leases that are revoked, no longer authorized, or were not
// renewed within LeaseTTL.
func (s *Server) recheck() error {
	now := s.now()
	s.mu.Lock()
	ids := make([]string, 0, len(s.leases))
	for id := range s.leases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var drop []string
	for _, id := range ids {
		l := s.leases[id]
		if s.mustRelease(l, now) {
			// Commit the terminal decision while renewal is excluded. Once
			// cleanup is selected, a later authorization change cannot allow
			// an acknowledged renewal that this pass then tears down.
			l.Revoked = true
			drop = append(drop, l.ID)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range drop {
		if err := s.release(id); err != nil {
			log.Printf("peer: release lease %s: %v", id, err)
			errs = append(errs, err)
		}
	}
	if s.target != nil {
		if err := s.cleanupOrphans(); err != nil {
			logf("orphan cleanup: %v", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Recover restores live leases and removes orphan resources in dependency
// order. Call before admitting requests, after the first registry snapshot.
// A failed orphan cleanup is safe to retry by calling Recover again.
func (s *Server) Recover() error {
	s.mu.Lock()
	var ls []*lease
	for _, l := range s.leases {
		ls = append(ls, l)
	}
	s.mu.Unlock()
	sort.Slice(ls, func(i, j int) bool { return ls[i].ID < ls[j].ID })
	var errs []error
	for _, l := range ls {
		if s.mustRelease(l, s.now()) {
			continue
		}
		if _, err := s.activate(l); err != nil {
			log.Printf("peer: restore lease %s: %v", l.ID, err)
			errs = append(errs, err)
			s.mu.Lock()
			l.Revoked = true
			s.mu.Unlock()
		}
	}
	if err := s.recheck(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// cleanupOrphans also runs after startup: a busy device or a lost cleanup
// result must not require another process restart to reclaim its resources.
// Holding mu through discovery and cleanup excludes preparations/activations
// that would otherwise be mistaken for orphan state between their effects.
func (s *Server) cleanupOrphans() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	known := map[string]bool{}
	for id := range s.leases {
		known[id] = true
	}
	orphans := map[string][]string{}
	for _, id := range s.target.Leases() {
		if !known[id] {
			orphans[id] = nil
		}
	}
	for id := range s.cfg.Store.Exports() {
		if !known[id] {
			orphans[id] = nil
		}
	}
	for _, v := range s.cfg.Store.List() {
		for _, p := range v.Pins {
			if id, ok := strings.CutPrefix(p, leasePinPrefix); ok && !known[id] {
				orphans[id] = append(orphans[id], v.ID)
			}
		}
	}
	ids := make([]string, 0, len(orphans))
	for id := range orphans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		err := runLeaseEffects(ReleaseLease, func(effect LeaseEffect) error {
			switch effect {
			case LeaseUnpublish:
				return s.unexport(id)
			case LeaseCloseDevice:
				return s.closeExport(id)
			case LeaseUnpin:
				sort.Strings(orphans[id])
				for _, commit := range orphans[id] {
					if err := s.unpin(commit, leasePinPrefix+id); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("orphan lease %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Server) saveLocked() error {
	ls := make([]*lease, 0, len(s.leases))
	for _, l := range s.leases {
		ls = append(ls, l)
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].ID < ls[j].ID })
	b, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	return s.persistence().Save(b)
}

func (s *Server) persistence() LeasePersistence {
	if s.cfg.Persistence != nil {
		return s.cfg.Persistence
	}
	return leaseFile{path: s.path}
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
