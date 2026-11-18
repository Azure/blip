package peer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type leaseTestServer struct {
	srv      *Server
	released []string
	now      time.Time
	certs    map[string]*x509.Certificate
}

func newLeaseTestServer(t *testing.T, authorize Authorizer) *leaseTestServer {
	t.Helper()
	ts := &leaseTestServer{now: time.Unix(1_700_000_000, 0), certs: map[string]*x509.Certificate{}}
	peers := NewRegistry()
	var registered []Peer
	for _, node := range []string{"n1", "n2"} {
		identity := testIdentity(t)
		cert, err := identity.certificate()
		if err != nil {
			t.Fatal(err)
		}
		ts.certs[node] = cert.Leaf
		registered = append(registered, Peer{Node: node, PublicKey: identity.PublicKey(), Endpoint: "127.0.0.1"})
	}
	peers.SetPeers(registered)
	ts.srv = &Server{
		cfg: ServerConfig{
			Peers:     peers,
			Authorize: authorize,
		},
		path:        filepath.Join(t.TempDir(), "leases.json"),
		leases:      map[string]*lease{},
		now:         func() time.Time { return ts.now },
		unexport:    func(id string) error { ts.released = append(ts.released, "unexport:"+id); return nil },
		closeExport: func(id string) error { ts.released = append(ts.released, "close:"+id); return nil },
		unpin: func(commit, holder string) error {
			ts.released = append(ts.released, "unpin:"+commit+":"+holder)
			return nil
		},
	}
	return ts
}

func (ts *leaseTestServer) add(id, node string) {
	ts.srv.leases[id] = &lease{ID: id, Node: node, Req: ExportRequest{CommitID: "c1"}, LastRenewed: ts.now}
}

func (ts *leaseTestServer) renew(t *testing.T, id, node string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/leases/{id}/renew", ts.srv.handleRenew)
	req := httptest.NewRequest(http.MethodPost, "/v1/leases/"+id+"/renew", strings.NewReader("{}"))
	req.RemoteAddr = "192.0.2.1:5000" // the source address does not identify a node
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{ts.certs[node]}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func allow(string, ExportRequest) error { return nil }

func TestLeaseRenew(t *testing.T) {
	ts := newLeaseTestServer(t, allow)
	ts.add("L1", "n1")

	ts.now = ts.now.Add(10 * time.Minute)
	if rec := ts.renew(t, "L1", "n1"); rec.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body)
	}
	if got := ts.srv.leases["L1"].LastRenewed; !got.Equal(ts.now) {
		t.Fatalf("last renewed = %v, want %v", got, ts.now)
	}
	// The renewal is persisted.
	b, err := os.ReadFile(ts.srv.path)
	if err != nil {
		t.Fatal(err)
	}
	var leases []lease
	if err := json.Unmarshal(b, &leases); err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || !leases[0].LastRenewed.Equal(ts.now) {
		t.Fatalf("persisted leases = %+v", leases)
	}

	// Another node may not renew it.
	ts.now = ts.now.Add(time.Minute)
	if rec := ts.renew(t, "L1", "n2"); rec.Code != http.StatusForbidden {
		t.Fatalf("renew by another node: %d %s", rec.Code, rec.Body)
	}
	if !ts.srv.leases["L1"].LastRenewed.Equal(ts.now.Add(-time.Minute)) {
		t.Fatal("unauthorized renewal changed the lease")
	}

	if rec := ts.renew(t, "unknown", "n1"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown lease: %d %s", rec.Code, rec.Body)
	}
}

func TestLeaseRecheckExpiry(t *testing.T) {
	ts := newLeaseTestServer(t, allow)
	ts.add("old", "n1")
	ts.add("fresh", "n1")
	ts.now = ts.now.Add(LeaseTTL + time.Minute)
	ts.srv.leases["fresh"].LastRenewed = ts.now

	ts.srv.recheck()
	if _, ok := ts.srv.leases["old"]; ok {
		t.Fatal("expired lease kept")
	}
	if _, ok := ts.srv.leases["fresh"]; !ok {
		t.Fatal("renewed lease dropped")
	}
	want := []string{"unexport:old", "close:old", "unpin:c1:lease:old"}
	if strings.Join(ts.released, ",") != strings.Join(want, ",") {
		t.Fatalf("released = %v, want %v", ts.released, want)
	}
	b, err := os.ReadFile(ts.srv.path)
	if err != nil {
		t.Fatal(err)
	}
	var leases []lease
	if err := json.Unmarshal(b, &leases); err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].ID != "fresh" {
		t.Fatalf("persisted leases = %+v", leases)
	}
}

func TestLeaseRecheckAuthorization(t *testing.T) {
	deny := func(node string, _ ExportRequest) error {
		if node == "n2" {
			return errors.New("not authorized")
		}
		return nil
	}
	ts := newLeaseTestServer(t, deny)
	ts.add("a", "n1")
	ts.add("b", "n2")
	ts.srv.recheck()
	if _, ok := ts.srv.leases["a"]; !ok {
		t.Fatal("authorized lease dropped")
	}
	if _, ok := ts.srv.leases["b"]; ok {
		t.Fatal("unauthorized lease kept")
	}
	if strings.Join(ts.released, ",") != "unexport:b,close:b,unpin:c1:lease:b" {
		t.Fatalf("released = %v", ts.released)
	}
}

func TestLeaseReleaseFailureRetries(t *testing.T) {
	ts := newLeaseTestServer(t, allow)
	ts.add("L1", "n1")
	err := errors.New("device busy")
	ts.srv.unexport = func(string) error { return err }
	if err := ts.srv.release("L1"); err == nil || err.Error() != "device busy" {
		t.Fatalf("release = %v", err)
	}
	l, ok := ts.srv.leases["L1"]
	if !ok || !l.Revoked {
		t.Fatalf("failed release did not keep a revoked lease: %+v", l)
	}
	// The next recheck retries and succeeds.
	ts.srv.unexport = func(id string) error { ts.released = append(ts.released, "unexport:"+id); return nil }
	ts.srv.recheck()
	if _, ok := ts.srv.leases["L1"]; ok {
		t.Fatal("revoked lease not released")
	}
}

func TestLeaseActivationCannotResurrectReleasedLease(t *testing.T) {
	for _, failedRelease := range []bool{false, true} {
		name := "removed"
		if failedRelease {
			name = "revoked-release-pending"
		}
		t.Run(name, func(t *testing.T) {
			ts := newLeaseTestServer(t, allow)
			ts.add("L1", "n1")
			l := ts.srv.leases["L1"]
			activated := false
			ts.srv.activateExport = func(*lease) (string, error) {
				activated = true
				return "nqn", nil
			}
			if failedRelease {
				ts.srv.unexport = func(string) error { return errors.New("busy") }
			}
			// Simulate the precise handleExport interleaving: the lease is
			// persisted, then recheck runs before activation starts.
			ts.now = ts.now.Add(LeaseTTL + time.Minute)
			ts.srv.recheck()
			if _, err := ts.srv.activate(l); err == nil {
				t.Fatal("activation accepted a released or revoked lease")
			}
			if activated {
				t.Fatal("late activation recreated kernel/store state")
			}
		})
	}
}

func TestLeaseReleaseWaitsForActivation(t *testing.T) {
	ts := newLeaseTestServer(t, allow)
	ts.add("L1", "n1")
	l := ts.srv.leases["L1"]
	entered, proceed := make(chan struct{}), make(chan struct{})
	var exported atomic.Bool
	ts.srv.activateExport = func(*lease) (string, error) {
		close(entered)
		<-proceed
		exported.Store(true)
		return "nqn", nil
	}
	ts.srv.unexport = func(string) error { exported.Store(false); return nil }
	activated := make(chan error, 1)
	go func() { _, err := ts.srv.activate(l); activated <- err }()
	<-entered
	released := make(chan error, 1)
	go func() { released <- ts.srv.release(l.ID) }()
	select {
	case err := <-released:
		close(proceed)
		<-activated
		t.Fatalf("release completed during activation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(proceed)
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if exported.Load() {
		t.Fatal("release left an untracked kernel export")
	}
	if ts.srv.Pinned(l.Req.CommitID) {
		t.Fatal("released lease still pins the commit")
	}
}
