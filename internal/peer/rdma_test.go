// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/blip/internal/nvme"
)

// pathExportTarget reports paths for a lease while delegating every other
// target operation to the world's fake.
type pathExportTarget struct {
	ExportTarget
	paths map[string][]nvme.Endpoint
}

func (t pathExportTarget) Paths(lease string) []nvme.Endpoint { return t.paths[lease] }

func TestExportAndRenewIncludePaths(t *testing.T) {
	w := newLeaseWorld(t)
	paths := []nvme.Endpoint{
		{Transport: nvme.TCP, Addr: "127.0.0.1", Port: NVMePort},
		{Transport: nvme.RDMA, Addr: "127.0.0.1", Port: NVMeRDMAPort},
	}
	w.server.target = pathExportTarget{ExportTarget: w, paths: map[string][]nvme.Endpoint{"lease1": paths}}
	want := []NVMePath{
		{Transport: string(nvme.TCP), Address: "127.0.0.1", Port: NVMePort},
		{Transport: string(nvme.RDMA), Address: "127.0.0.1", Port: NVMeRDMAPort},
	}

	rec := w.export()
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	}
	var exported ExportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	// Address and Port remain the TCP path for older clients.
	if !slices.Equal(exported.Paths, want) || exported.Address != "127.0.0.1" || exported.Port != NVMePort {
		t.Fatalf("export paths = %+v, address = %s:%d", exported.Paths, exported.Address, exported.Port)
	}

	rec = w.request("/v1/leases/lease1/renew", struct{}{})
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	}
	var renewed struct{ Paths []NVMePath }
	if err := json.Unmarshal(rec.Body.Bytes(), &renewed); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(renewed.Paths, want) {
		t.Fatalf("renew paths = %+v, want %+v", renewed.Paths, want)
	}
	if rec := w.release(); rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	}
	w.empty()
}

func TestExportAndRenewTCPOnlyWithoutPaths(t *testing.T) {
	w := newLeaseWorld(t)
	if rec := w.export(); rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	} else {
		var exported ExportResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &exported); err != nil {
			t.Fatal(err)
		}
		if len(exported.Paths) != 0 || exported.Address != "127.0.0.1" || exported.Port != NVMePort {
			t.Fatalf("export without paths = %+v", exported)
		}
	}
	if rec := w.request("/v1/leases/lease1/renew", struct{}{}); rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	} else {
		var renewed struct{ Paths []NVMePath }
		if err := json.Unmarshal(rec.Body.Bytes(), &renewed); err != nil {
			t.Fatal(err)
		}
		if len(renewed.Paths) != 0 {
			t.Fatalf("renew without paths = %+v", renewed.Paths)
		}
	}
	if rec := w.release(); rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body)
	}
	w.empty()
}

func TestClientOpenWithoutRDMAPath(t *testing.T) {
	const node, leaseID = "exporter", "tcp-only"
	nqn := nvme.SubsystemNQN(node, leaseID)
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/export" {
			t.Errorf("unexpected request: %s", req.URL.Path)
			http.NotFound(w, req)
			return
		}
		json.NewEncoder(w).Encode(ExportResponse{
			LeaseID: leaseID, NQN: nqn, Address: "127.0.0.24", Port: NVMePort, SizeBytes: 4096,
		})
	}))
	c.rdma = true
	c.addPath = func(context.Context, nvme.Endpoint, string, string, []byte) error {
		t.Error("added an RDMA path for a TCP-only export")
		return nil
	}
	c.connect = func(_ context.Context, addr string, port int, gotNQN, hostNQN string, _ []byte) (string, error) {
		if addr != "127.0.0.24" || port != NVMePort || gotNQN != nqn || hostNQN != HostNQN("reader") {
			t.Errorf("unexpected connect: %s:%d %s %s", addr, port, gotNQN, hostNQN)
		}
		return "/dev/fake-nvme", nil
	}

	remote, err := c.Open(t.Context(), node, ExportRequest{HostNQN: HostNQN("reader")})
	if err != nil {
		t.Fatal(err)
	}
	if remote.Device != "/dev/fake-nvme" {
		t.Fatalf("device = %q", remote.Device)
	}
}

func TestClientOpenAddsRDMAPath(t *testing.T) {
	const node, leaseID = "exporter", "rdma"
	nqn := nvme.SubsystemNQN(node, leaseID)
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/export" {
			t.Errorf("unexpected request: %s", req.URL.Path)
			http.NotFound(w, req)
			return
		}
		json.NewEncoder(w).Encode(ExportResponse{
			LeaseID: leaseID, NQN: nqn, Address: "127.0.0.24", Port: NVMePort, SizeBytes: 4096,
			Paths: []NVMePath{
				{Transport: string(nvme.TCP), Address: "127.0.0.24", Port: NVMePort},
				{Transport: string(nvme.RDMA), Address: "2001:db8::1", Port: NVMeRDMAPort},
				{Transport: string(nvme.RDMA), Address: "127.0.0.24", Port: NVMePort},
				{Transport: string(nvme.RDMA), Address: "127.0.0.24", Port: NVMeRDMAPort},
			},
		})
	}))
	type addedPath struct {
		ep      nvme.Endpoint
		nqn     string
		hostNQN string
	}
	var added []addedPath
	c.rdma = true
	c.addPath = func(_ context.Context, ep nvme.Endpoint, gotNQN, hostNQN string, _ []byte) error {
		added = append(added, addedPath{ep, gotNQN, hostNQN})
		return nil
	}
	c.connect = func(context.Context, string, int, string, string, []byte) (string, error) {
		return "/dev/tcp", nil
	}

	remote, err := c.Open(t.Context(), node, ExportRequest{HostNQN: HostNQN("reader")})
	if err != nil {
		t.Fatal(err)
	}
	if remote.Device != "/dev/tcp" {
		t.Fatalf("device = %q, want the TCP device", remote.Device)
	}
	want := addedPath{nvme.Endpoint{Transport: nvme.RDMA, Addr: "127.0.0.24", Port: NVMeRDMAPort}, nqn, HostNQN("reader")}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("added paths = %+v, want %+v", added, want)
	}
}

func TestClientIgnoresInvalidRDMAPaths(t *testing.T) {
	c := NewClientWithOptions(testIdentity(t), NewRegistry(), nil, ClientOptions{
		RDMA: true,
		AddPath: func(context.Context, nvme.Endpoint, string, string, []byte) error {
			t.Error("added an unusable RDMA path")
			return nil
		},
	})
	t.Cleanup(c.Close)
	const node, leaseID = "exporter", "lease1"
	nqn := nvme.SubsystemNQN(node, leaseID)
	for _, tc := range []struct {
		name string
		path NVMePath
	}{
		{"ipv6", NVMePath{Transport: string(nvme.RDMA), Address: "2001:db8::1", Port: NVMeRDMAPort}},
		{"not-ip", NVMePath{Transport: string(nvme.RDMA), Address: "exporter.example", Port: NVMeRDMAPort}},
		{"tcp-port", NVMePath{Transport: string(nvme.RDMA), Address: "127.0.0.24", Port: NVMePort}},
		{"wrong-transport", NVMePath{Transport: string(nvme.TCP), Address: "127.0.0.24", Port: NVMeRDMAPort}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.addRDMAPath(t.Context(), node, HostNQN("reader"), nqn, []NVMePath{tc.path})
		})
	}
}

func TestClientRDMAPathFailureRetriedAtRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const node, leaseID = "exporter", "lease1"
		nqn := nvme.SubsystemNQN(node, leaseID)
		paths := []NVMePath{
			{Transport: string(nvme.TCP), Address: "127.0.0.24", Port: NVMePort},
			{Transport: string(nvme.RDMA), Address: "127.0.0.24", Port: NVMeRDMAPort},
		}
		identity := testIdentity(t)
		registry := NewRegistry()
		registry.SetPeers([]Peer{testPeer(node, identity)})
		var attempts atomic.Int32
		c := NewClientWithOptions(identity, registry, nil, ClientOptions{
			RDMA:       true,
			Connect:    func(context.Context, string, int, string, string, []byte) (string, error) { return "/dev/tcp", nil },
			Disconnect: func(string) error { return nil },
			AddPath: func(context.Context, nvme.Endpoint, string, string, []byte) error {
				attempts.Add(1)
				return errors.New("rdma unavailable")
			},
			Transport: func(*http.Transport) http.RoundTripper {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					switch req.URL.Path {
					case "/v1/export":
						return jsonHTTPResponse(ExportResponse{
							LeaseID: leaseID, NQN: nqn, Address: "127.0.0.24", Port: NVMePort, SizeBytes: 4096, Paths: paths,
						})
					case "/v1/leases/" + leaseID + "/renew":
						return jsonHTTPResponse(struct {
							LeaseID string     `json:"leaseID"`
							Paths   []NVMePath `json:"paths,omitempty"`
						}{LeaseID: leaseID, Paths: paths})
					default:
						return jsonHTTPResponse(map[string]string{})
					}
				})
			},
		})
		defer c.Close()
		remote, err := c.Open(t.Context(), node, ExportRequest{HostNQN: HostNQN("reader")})
		if err != nil {
			t.Fatalf("Open failed with a broken RDMA path: %v", err)
		}
		if remote.Device != "/dev/tcp" || attempts.Load() != 1 {
			t.Fatalf("device = %q, RDMA attempts = %d", remote.Device, attempts.Load())
		}
		synctest.Wait()
		// The renewal at five minutes must stay in the backoff window.
		time.Sleep(9 * time.Minute)
		synctest.Wait()
		if attempts.Load() != 1 {
			t.Fatalf("RDMA retried before its backoff: %d attempts", attempts.Load())
		}
		// The renewal after ten minutes repairs the path.
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if attempts.Load() != 2 {
			t.Fatalf("renewal did not retry the RDMA path: %d attempts", attempts.Load())
		}
	})
}

func jsonHTTPResponse(v any) (*http.Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}, nil
}
