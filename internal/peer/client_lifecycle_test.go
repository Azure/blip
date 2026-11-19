// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
)

func TestClientReleaseBeforeRenewalInstall(t *testing.T) {
	c := NewClient(testIdentity(t), NewRegistry(), nil)
	t.Cleanup(c.Close)
	const node, leaseID = "exporter", "recovered"
	nqn := nvme.SubsystemNQN(node, leaseID)
	id := node + "/" + leaseID + "/" + nqn
	disconnecting := make(chan string, 1)
	proceed := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(unblock)
	c.disconnect = func(nqn string) error {
		disconnecting <- nqn
		<-proceed
		return nil
	}
	done := make(chan struct{})
	go func() {
		c.ReleaseRemote(id)
		close(done)
	}()
	select {
	case got := <-disconnecting:
		if got != nqn {
			t.Fatalf("disconnect = %q, want %q", got, nqn)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("release did not reach disconnect")
	}
	// Release has stopped the previous renewal (there was none), but its
	// remote request cannot have succeeded. Resume must not install a new
	// renewal in this window, even if the release never reaches the server.
	c.ResumeRemote(id)
	if _, ok := c.active.Load(leaseKey{node, leaseID}); ok {
		t.Fatal("resume installed a renewal after release began")
	}
	// Terminal state is scoped by node as well as lease ID.
	other := "other-exporter"
	c.ResumeRemote(other + "/" + leaseID + "/" + nvme.SubsystemNQN(other, leaseID))
	if _, ok := c.active.Load(leaseKey{other, leaseID}); !ok {
		t.Fatal("release prevented another node's same-named lease from resuming")
	}
	unblock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("release did not finish")
	}
	c.ResumeRemote(id)
	if _, ok := c.active.Load(leaseKey{node, leaseID}); ok {
		t.Fatal("resume installed a renewal after release finished")
	}
}

func newLifecycleTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	serverID, clientID := testIdentity(t), testIdentity(t)
	r := NewRegistry()
	exporter := testPeer("exporter", serverID)
	exporter.Endpoint = "127.0.0.24"
	r.SetPeers([]Peer{exporter, testPeer("reader", clientID)})
	startTLSTestServer(t, serverID, r, net.JoinHostPort(exporter.Endpoint, fmt.Sprint(ExportPort)), handler)
	c := NewClient(clientID, r, nil)
	// Every kernel entry point is stubbed, including failure cleanup.
	c.connect = func(context.Context, string, int, string, string, []byte) (string, error) {
		t.Error("unexpected NVMe connect")
		return "", errors.New("unexpected NVMe connect")
	}
	c.disconnect = func(string) error { return nil }
	t.Cleanup(c.Close)
	return c
}

func TestClientTerminalRenewalResponse(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requested := make(chan struct{}, 1)
			c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/v1/leases/recovered/renew" {
					t.Errorf("unexpected request: %s", req.URL.Path)
				}
				requested <- struct{}{}
				http.Error(w, "lease is gone or revoked", status)
			}))
			key := leaseKey{"exporter", "recovered"}
			id := key.node + "/" + key.id + "/" + nvme.SubsystemNQN(key.node, key.id)
			c.ResumeRemote(id)
			select {
			case <-requested:
			case <-time.After(3 * time.Second):
				t.Fatal("no renewal request")
			}
			// Wait for response processing, not the minute-long retry timer.
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				if _, ok := c.active.Load(key); !ok {
					break
				}
				select {
				case <-tick.C:
				case <-deadline.C:
					t.Fatalf("renewal remained active after HTTP %d", status)
				}
			}
			c.ResumeRemote(id)
			if _, ok := c.active.Load(key); ok {
				t.Fatal("resume restarted a terminal lease")
			}
		})
	}
}

func TestClientOpenCancellationDuringConnect(t *testing.T) {
	for _, mode := range []string{"close-waiting-connect", "close-successful-connect", "caller-canceled-successful-connect"} {
		t.Run(mode, func(t *testing.T) {
			const node, leaseID = "exporter", "opening"
			nqn := nvme.SubsystemNQN(node, leaseID)
			released := make(chan struct{}, 1)
			c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/v1/export":
					json.NewEncoder(w).Encode(ExportResponse{
						LeaseID: leaseID, NQN: nqn, Address: "127.0.0.24", Port: NVMePort, SizeBytes: 4096,
					})
				case "/v1/release":
					released <- struct{}{}
					fmt.Fprint(w, "{}")
				default:
					t.Errorf("unexpected request: %s", req.URL.Path)
					http.NotFound(w, req)
				}
			}))
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			connecting := make(chan struct{})
			c.connect = func(connectCtx context.Context, addr string, port int, gotNQN, hostNQN string, key []byte) (string, error) {
				if addr != "127.0.0.24" || port != NVMePort || gotNQN != nqn || hostNQN != HostNQN("reader") {
					t.Errorf("unexpected connect: %s:%d %s %s", addr, port, gotNQN, hostNQN)
				}
				close(connecting)
				switch mode {
				case "close-waiting-connect":
					<-connectCtx.Done()
					return "", connectCtx.Err()
				case "close-successful-connect":
					c.Close()
				case "caller-canceled-successful-connect":
					cancel()
				}
				// A ready namespace can be returned despite cancellation.
				return "/dev/fake-nvme", nil
			}
			disconnected := make(chan string, 1)
			c.disconnect = func(nqn string) error {
				disconnected <- nqn
				return nil
			}
			type result struct {
				remote storage.Remote
				err    error
			}
			done := make(chan result, 1)
			go func() {
				remote, err := c.Open(ctx, node, ExportRequest{HostNQN: HostNQN("reader")})
				done <- result{remote, err}
			}()
			select {
			case <-connecting:
			case <-time.After(3 * time.Second):
				t.Fatal("open did not reach connect")
			}
			if mode == "close-waiting-connect" {
				c.Close()
			}
			select {
			case got := <-done:
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("Open error = %v, want context cancellation", got.err)
				}
				if got.remote.ID != "" || got.remote.Device != "" || got.remote.Release != nil {
					t.Fatalf("canceled Open returned a remote: %+v", got.remote)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not stop Open's NVMe connection")
			}
			select {
			case got := <-disconnected:
				if got != nqn {
					t.Fatalf("disconnect = %q, want %q", got, nqn)
				}
			default:
				t.Fatal("canceled Open did not disconnect its controller")
			}
			if _, ok := c.active.Load(leaseKey{node, leaseID}); ok {
				t.Fatal("canceled Open left a renewal installed")
			}
			c.mu.Lock()
			retained := len(c.released)
			c.mu.Unlock()
			if retained != 0 {
				t.Fatal("canceled Open retained terminal lease state")
			}
			if mode == "caller-canceled-successful-connect" {
				select {
				case <-released:
				case <-time.After(3 * time.Second):
					t.Fatal("canceled Open did not release its lease")
				}
			}
		})
	}
}

func TestClientOpenReleaseDoesNotRetainLease(t *testing.T) {
	const node, leaseID = "exporter", "normal"
	nqn := nvme.SubsystemNQN(node, leaseID)
	released := make(chan string, 1)
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/export":
			json.NewEncoder(w).Encode(ExportResponse{
				LeaseID: leaseID, NQN: nqn, Address: "127.0.0.24", Port: NVMePort, SizeBytes: 4096,
			})
		case "/v1/release":
			var body struct{ LeaseID string }
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Errorf("decode release: %v", err)
			}
			released <- body.LeaseID
			fmt.Fprint(w, "{}")
		default:
			t.Errorf("unexpected request: %s", req.URL.Path)
			http.NotFound(w, req)
		}
	}))
	c.connect = func(context.Context, string, int, string, string, []byte) (string, error) {
		return "/dev/fake-nvme", nil
	}
	disconnects := 0
	c.disconnect = func(got string) error {
		disconnects++
		if got != nqn {
			t.Errorf("disconnect = %q, want %q", got, nqn)
		}
		return nil
	}
	remote, err := c.Open(t.Context(), node, ExportRequest{HostNQN: HostNQN("reader")})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Release()
	key := leaseKey{node, leaseID}
	if _, ok := c.active.Load(key); !ok {
		t.Fatal("Open did not install a renewal")
	}
	remote.Release()
	remote.Release()
	if disconnects != 1 {
		t.Fatalf("disconnects = %d, want 1", disconnects)
	}
	if _, ok := c.active.Load(key); ok {
		t.Fatal("Release left a renewal installed")
	}
	c.mu.Lock()
	retained := len(c.released)
	c.mu.Unlock()
	if retained != 0 {
		t.Fatal("normal Release retained terminal lease state")
	}
	select {
	case got := <-released:
		if got != leaseID {
			t.Fatalf("released lease = %q, want %q", got, leaseID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Release did not release its lease")
	}
}
