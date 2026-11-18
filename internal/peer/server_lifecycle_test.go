package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type lifecycleServer struct {
	ts     *leaseTestServer
	client *http.Client
	ln     net.Listener
	cancel context.CancelFunc
	done   <-chan error
}

func startLifecycleServer(t *testing.T, ts *leaseTestServer, handler http.Handler, grace time.Duration) *lifecycleServer {
	t.Helper()
	serverID, clientID := testIdentity(t), testIdentity(t)
	ts.srv.cfg.Identity = serverID
	one, _ := ts.srv.cfg.Peers.Lookup("n1")
	two, _ := ts.srv.cfg.Peers.Lookup("n2")
	ts.srv.cfg.Peers.SetPeers([]Peer{one, two, testPeer("server", serverID), testPeer("client", clientID)})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- ts.srv.serve(ctx, ln, handler, grace) }()
	return &lifecycleServer{
		ts: ts, ln: ln, cancel: cancel, done: done,
		client: testHTTPClient(t, clientID.clientTLS(ts.srv.cfg.Peers, "server")),
	}
}

func (s *lifecycleServer) request() <-chan error {
	done := make(chan error, 1)
	go func() {
		resp, err := s.client.Get("https://" + s.ln.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		done <- err
	}()
	return done
}

func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server work")
	}
}

func awaitServer(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
		return nil
	}
}

func TestServerShutdownCancelsHandlersAndPreservesLeases(t *testing.T) {
	ts := newLeaseTestServer(t, allow)
	ts.add("L1", "n1")
	entered, canceled := make(chan struct{}), make(chan struct{})
	s := startLifecycleServer(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}), time.Second)
	request := s.request()
	awaitSignal(t, entered)
	s.cancel()
	if err := awaitServer(t, s.done); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, canceled)
	awaitServer(t, request)
	if len(ts.released) != 0 || !ts.srv.Pinned("c1") {
		t.Fatal("normal shutdown released a persistent lease")
	}
}

func TestServerShutdownForceClosesButStillWaitsForHandler(t *testing.T) {
	entered, canceled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(finish)
	finished := make(chan struct{})
	s := startLifecycleServer(t, newLeaseTestServer(t, allow), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-finish
		close(finished)
	}), 25*time.Millisecond)
	request := s.request()
	awaitSignal(t, entered)
	s.cancel()
	awaitSignal(t, canceled)
	// The client must be disconnected when grace expires, even though the
	// handler is still finishing store work that ignores cancellation.
	if err := awaitServer(t, request); err == nil {
		t.Fatal("grace timeout did not force-close the active connection")
	}
	select {
	case err := <-s.done:
		t.Fatalf("server returned with a handler still active: %v", err)
	default:
	}
	finish <- struct{}{}
	if err := awaitServer(t, s.done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", err)
	}
	awaitSignal(t, finished)
}

func TestServerServeFailureCancelsAndJoinsHandlers(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	s := startLifecycleServer(t, newLeaseTestServer(t, allow), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}), time.Second)
	request := s.request()
	awaitSignal(t, entered)
	if err := s.ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitServer(t, s.done); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serve error = %v, want closed listener", err)
	}
	awaitSignal(t, canceled)
	awaitServer(t, request)
}

func TestServerShutdownJoinsRecheck(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	defer close(finish)
	ts := newLeaseTestServer(t, func(string, ExportRequest) error {
		close(entered)
		<-finish
		return nil
	})
	ts.add("L1", "n1")
	ts.srv.cfg.RecheckInterval = time.Millisecond
	s := startLifecycleServer(t, ts, http.NotFoundHandler(), time.Second)
	awaitSignal(t, entered)
	s.cancel()
	select {
	case err := <-s.done:
		t.Fatalf("server returned with recheck still using the store: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	finish <- struct{}{}
	if err := awaitServer(t, s.done); err != nil {
		t.Fatal(err)
	}
	if len(ts.released) != 0 || !ts.srv.Pinned("c1") {
		t.Fatal("shutdown released a valid persistent lease")
	}
}
