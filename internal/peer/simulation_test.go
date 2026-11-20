// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
)

// leaseWorld keeps durable metadata, store pins, open devices, and target
// exports independently. Restart discards Server memory, not kernel state.
// Faults occur before or after actual effects, including before HTTP delivery.
type leaseWorld struct {
	t       *testing.T
	clock   worldClock
	server  *Server
	cfg     ServerConfig
	reader  *Identity
	durable []byte
	pins    map[string]bool
	devices map[string]string
	exports map[string]string
	trace   []string
	fault   func(string, bool) error
}

type worldClock struct {
	realClock
	now time.Time
}

func (c *worldClock) Now() time.Time { return c.now }

func newLeaseWorld(t *testing.T) *leaseWorld {
	t.Helper()
	w := &leaseWorld{t: t, clock: worldClock{now: time.Now()}, pins: map[string]bool{}, devices: map[string]string{}, exports: map[string]string{}}
	w.reader = testIdentity(t)
	r := NewRegistry()
	identity := testIdentity(t)
	r.SetPeers([]Peer{testPeer("reader", w.reader), testPeer("exporter", identity)})
	w.cfg = ServerConfig{
		Store: w, Target: w, Persistence: w, Clock: &w.clock,
		NodeName: "exporter", HostIP: "127.0.0.1", DataDir: t.TempDir(),
		Identity: identity, Peers: r, Authorize: allow, NewLeaseID: func() string { return "lease1" },
	}
	w.restart()
	return w
}

func (w *leaseWorld) restart() {
	w.t.Helper()
	var err error
	w.server, err = NewServer(w.cfg)
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *leaseWorld) effect(name string, apply func()) error {
	w.trace = append(w.trace, name)
	if w.fault != nil {
		if err := w.fault(name, false); err != nil {
			return err
		}
	}
	apply()
	w.check()
	if w.fault != nil {
		return w.fault(name, true)
	}
	return nil
}

func (w *leaseWorld) check() {
	w.t.Helper()
	for id := range w.exports {
		if w.devices[id] == "" || !w.pins[leasePinPrefix+id] {
			w.t.Fatalf("target %s outlived its device or pin; trace=%v", id, w.trace)
		}
	}
	for id := range w.devices {
		if !w.pins[leasePinPrefix+id] {
			w.t.Fatalf("device %s outlived pin; trace=%v", id, w.trace)
		}
	}
}

func (w *leaseWorld) Pin(commit, holder string) error {
	if commit != "commit1" {
		return storage.ErrNotFound
	}
	return w.effect("pin", func() { w.pins[holder] = true })
}
func (w *leaseWorld) Unpin(commit, holder string) error {
	return w.effect("unpin", func() { delete(w.pins, holder) })
}
func (w *leaseWorld) OpenExport(commit, id string) (string, error) {
	err := w.effect("open", func() { w.devices[id] = "/dev/ciphertext" })
	return w.devices[id], err
}
func (w *leaseWorld) CloseExport(id string) error {
	return w.effect("close", func() { delete(w.devices, id) })
}
func (w *leaseWorld) Get(id string) (storage.Volume, bool) {
	return storage.Volume{ID: id, SizeBytes: 4096}, id == "commit1"
}
func (w *leaseWorld) Diff(context.Context, string, []string, map[string]string) (string, []storage.Region, error) {
	return "", []storage.Region{}, w.effect("diff", func() {})
}
func (w *leaseWorld) Exports() map[string]string { return w.devices }
func (w *leaseWorld) List() []storage.Volume {
	pins := make([]string, 0, len(w.pins))
	for pin := range w.pins {
		pins = append(pins, pin)
	}
	slices.Sort(pins)
	return []storage.Volume{{ID: "commit1", Pins: pins}}
}
func (w *leaseWorld) Export(id, device, host string) (string, error) {
	if host != HostNQN("reader") {
		return "", errors.New("host not authorized")
	}
	err := w.effect("publish", func() { w.exports[id] = device })
	return nvme.SubsystemNQN("exporter", id), err
}
func (w *leaseWorld) Unexport(id string) error {
	return w.effect("unpublish", func() { delete(w.exports, id) })
}
func (w *leaseWorld) Leases() []string {
	var ids []string
	for id := range w.exports {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
func (w *leaseWorld) Load() ([]byte, error) {
	if w.durable == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(w.durable), nil
}
func (w *leaseWorld) Save(data []byte) error {
	var leases []lease
	if err := json.Unmarshal(data, &leases); err != nil {
		return err
	}
	name := "save-live"
	if len(leases) == 0 {
		name = "save-empty"
	} else if leases[0].Revoked {
		name = "save-revoked"
	}
	committed := false
	err := w.effect(name, func() { w.durable = bytes.Clone(data); committed = true })
	if err != nil && committed {
		return &AmbiguousSaveError{Err: err}
	}
	return err
}

func (w *leaseWorld) request(path string, body any) *httptest.ResponseRecorder {
	w.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		w.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	cert, err := w.reader.certificate()
	if err != nil {
		w.t.Fatal(err)
	}
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert.Leaf}}
	rec := httptest.NewRecorder()
	w.server.Handler().ServeHTTP(rec, req)
	return rec
}
func (w *leaseWorld) export() *httptest.ResponseRecorder {
	return w.request("/v1/export", ExportRequest{CommitID: "commit1", HostNQN: HostNQN("reader")})
}
func (w *leaseWorld) release() *httptest.ResponseRecorder {
	return w.request("/v1/release", map[string]string{"leaseID": "lease1"})
}
func (w *leaseWorld) empty() {
	w.t.Helper()
	if len(w.pins)+len(w.devices)+len(w.exports)+len(w.server.leases) != 0 {
		w.t.Fatalf("resources remain: pins=%v devices=%v exports=%v leases=%v trace=%v", w.pins, w.devices, w.exports, w.server.leases, w.trace)
	}
}

type simulatedPowerLoss struct{}

func TestLeaseSimulationCrashAtEveryEffect(t *testing.T) {
	for _, effect := range []string{"pin", "save-live", "open", "publish", "diff", "save-revoked", "unpublish", "close", "unpin", "save-empty"} {
		t.Run(effect, func(t *testing.T) {
			w := newLeaseWorld(t)
			releasing := slices.Contains([]string{"save-revoked", "unpublish", "close", "unpin", "save-empty"}, effect)
			if releasing && w.export().Code != http.StatusOK {
				t.Fatal("initial export failed")
			}
			w.fault = func(name string, after bool) error {
				if name == effect && after {
					panic(simulatedPowerLoss{})
				}
				return nil
			}
			crashed := false
			func() {
				defer func() {
					if p := recover(); p != nil {
						if _, ok := p.(simulatedPowerLoss); !ok {
							panic(p)
						}
						crashed = true
					}
				}()
				if releasing {
					w.release()
				} else {
					w.export()
				}
			}()
			if !crashed {
				t.Fatal("fault boundary not reached")
			}
			w.fault = nil
			w.restart()
			if err := w.server.Recover(); err != nil {
				t.Fatal(err)
			}
			w.check()
			if releasing || effect == "pin" {
				w.empty()
			} else {
				if len(w.exports) != 1 || !w.pins["lease:lease1"] {
					t.Fatal("live durable lease not restored")
				}
				w.clock.now = w.clock.now.Add(LeaseTTL)
				if err := w.server.recheck(); err != nil {
					t.Fatal(err)
				}
				w.empty()
			}
		})
	}
}

func TestLeaseSimulationReleaseFailures(t *testing.T) {
	for _, effect := range []string{"save-revoked", "unpublish", "close", "unpin", "save-empty"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%v", effect, after), func(t *testing.T) {
				w := newLeaseWorld(t)
				if rec := w.export(); rec.Code != http.StatusOK {
					t.Fatal(rec.Body)
				}
				w.fault = func(name string, applied bool) error {
					if name == effect && applied == after {
						return errors.New("injected I/O failure")
					}
					return nil
				}
				if rec := w.release(); rec.Code != http.StatusInternalServerError {
					t.Fatalf("release=%d", rec.Code)
				}
				if l := w.server.leases["lease1"]; l == nil || !l.Revoked {
					t.Fatal("lost cleanup ownership")
				}
				if effect == "save-revoked" && len(w.exports) != 1 {
					t.Fatal("tore down before durable revocation")
				}
				w.fault = nil
				if err := w.server.recheck(); err != nil {
					t.Fatal(err)
				}
				w.empty()
				w.restart()
				if err := w.server.Recover(); err != nil {
					t.Fatal(err)
				}
				w.empty()
			})
		}
	}
}

func TestLeaseSimulationAmbiguousPrepare(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			w := newLeaseWorld(t)
			w.fault = func(name string, applied bool) error {
				if name == "save-live" && applied == after {
					return errors.New("journal failed")
				}
				return nil
			}
			if rec := w.export(); rec.Code != http.StatusInternalServerError {
				t.Fatalf("export=%d", rec.Code)
			}
			if after {
				if l := w.server.leases["lease1"]; l == nil || !l.Revoked || !w.pins["lease:lease1"] {
					t.Fatal("ambiguous save lost pin/cleanup ownership")
				}
			} else {
				w.empty()
			}
			w.fault = nil
			if err := w.server.recheck(); err != nil {
				t.Fatal(err)
			}
			w.empty()
		})
	}
}

func TestLeaseSimulationActivationFailures(t *testing.T) {
	for _, effect := range []string{"pin", "open", "publish", "diff"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%v", effect, after), func(t *testing.T) {
				w := newLeaseWorld(t)
				fired := false
				w.fault = func(name string, applied bool) error {
					if !fired && name == effect && applied == after {
						fired = true
						return errors.New("effect failed")
					}
					return nil
				}
				if rec := w.export(); rec.Code != http.StatusInternalServerError {
					t.Fatalf("export=%d", rec.Code)
				}
				w.check()
				w.fault = nil
				// An ambiguous first pin has no journal record yet. Recovery
				// discovers its holder and removes that orphan too.
				w.restart()
				if err := w.server.Recover(); err != nil {
					t.Fatal(err)
				}
				w.empty()
			})
		}
	}
}

func TestLeaseSimulationOrphanCleanupDependencyOrder(t *testing.T) {
	for _, effect := range []string{"unpublish", "close", "unpin"} {
		t.Run(effect, func(t *testing.T) {
			w := newLeaseWorld(t)
			w.pins["lease:orphan"] = true
			w.devices["orphan"] = "/dev/ciphertext"
			w.exports["orphan"] = "/dev/ciphertext"
			w.fault = func(name string, after bool) error {
				if name == effect && !after {
					return errors.New("busy")
				}
				return nil
			}
			if err := w.server.Recover(); err == nil {
				t.Fatal("cleanup failure not reported")
			}
			w.check()
			if !w.pins["lease:orphan"] {
				t.Fatal("failed cleanup lost pin")
			}
			w.fault = nil
			if err := w.server.Recover(); err != nil {
				t.Fatal(err)
			}
			w.empty()
		})
	}
}

func TestLeaseSimulationRenewalDurabilityAndExpiry(t *testing.T) {
	w := newLeaseWorld(t)
	if rec := w.export(); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	original := w.server.leases["lease1"].LastRenewed
	w.clock.now = original.Add(LeaseTTL - time.Nanosecond)
	w.fault = func(name string, after bool) error {
		if name == "save-live" && !after {
			return errors.New("disk full")
		}
		return nil
	}
	if rec := w.request("/v1/leases/lease1/renew", struct{}{}); rec.Code != http.StatusInternalServerError {
		t.Fatal(rec.Code)
	}
	if !w.server.leases["lease1"].LastRenewed.Equal(original) {
		t.Fatal("failed renewal extended volatile deadline")
	}
	w.fault = nil
	w.clock.now = original.Add(LeaseTTL)
	if rec := w.request("/v1/leases/lease1/renew", struct{}{}); rec.Code != http.StatusForbidden {
		t.Fatalf("expired lease renewed: %d", rec.Code)
	}
	if err := w.server.recheck(); err != nil {
		t.Fatal(err)
	}
	w.empty()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// localTransport invokes the production certificate verification callbacks and
// authenticated HTTP handler. Wire-level TLS is covered by tls_test.go; this
// deterministic transport can lose a response after all server effects commit.
func (w *leaseWorld) localTransport(transport *http.Transport) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		cert, err := w.cfg.Identity.certificate()
		if err != nil {
			return nil, err
		}
		if err := transport.TLSClientConfig.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert.Leaf}}); err != nil {
			return nil, err
		}
		client, err := transport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{client.Leaf}}
		if err := w.cfg.Identity.serverTLS(w.cfg.Peers).VerifyConnection(*req.TLS); err != nil {
			return nil, err
		}
		rec := httptest.NewRecorder()
		w.server.Handler().ServeHTTP(rec, req)
		return rec.Result(), nil
	})
}

func TestLeaseSimulationLostExportResponseExpires(t *testing.T) {
	w := newLeaseWorld(t)
	requests := 0
	c := NewClientWithOptions(w.reader, w.cfg.Peers, nil, ClientOptions{
		Transport: func(tr *http.Transport) http.RoundTripper {
			inner := w.localTransport(tr)
			return roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				resp, err := inner.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				resp.Body.Close()
				return nil, io.ErrUnexpectedEOF
			})
		},
		Connect: func(context.Context, string, int, string, string, []byte) (string, error) {
			t.Fatal("connected without an export response")
			return "", nil
		},
	})
	defer c.Close()
	if _, err := c.Open(t.Context(), "exporter", ExportRequest{CommitID: "commit1", HostNQN: HostNQN("reader")}); err == nil {
		t.Fatal("lost response accepted")
	}
	if requests != 1 || len(w.exports) != 1 {
		t.Fatalf("ambiguous export retried or rolled back: requests=%d exports=%v", requests, w.exports)
	}
	w.clock.now = w.clock.now.Add(LeaseTTL)
	if err := w.server.recheck(); err != nil {
		t.Fatal(err)
	}
	w.empty()
}

func TestClientSimulationDiscoveryRetryAndEndpointChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newLeaseWorld(t)
		if rec := w.export(); rec.Code != http.StatusOK {
			t.Fatal(rec.Body)
		}
		registry := NewRegistry()
		var endpoints []string
		var attempts []time.Time
		c := NewClientWithOptions(w.reader, registry, nil, ClientOptions{
			Disconnect: func(string) error { return nil },
			Transport: func(tr *http.Transport) http.RoundTripper {
				inner := w.localTransport(tr)
				return roundTripFunc(func(r *http.Request) (*http.Response, error) {
					endpoints = append(endpoints, r.URL.Host)
					attempts = append(attempts, time.Now())
					if len(attempts) == 1 {
						return nil, errors.New("endpoint unreachable")
					}
					resp, err := inner.RoundTrip(r)
					if err == nil && len(attempts) == 2 {
						resp.Body.Close()
						return nil, io.ErrUnexpectedEOF
					}
					return resp, err
				})
			},
		})
		defer c.Close()
		id := "exporter/lease1/" + nvme.SubsystemNQN("exporter", "lease1")
		c.ReleaseRemote(id)
		synctest.Wait()
		time.Sleep(20 * time.Minute)
		if len(attempts) != 0 {
			t.Fatal("startup discovery consumed release attempts")
		}
		p := testPeer("exporter", w.cfg.Identity)
		p.Endpoint = "127.0.0.10"
		registry.SetPeers([]Peer{p})
		synctest.Wait()
		if len(attempts) != 1 {
			t.Fatalf("attempts=%d", len(attempts))
		}
		p.Endpoint = "127.0.0.11"
		registry.SetPeers([]Peer{p})
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if !slices.Equal(endpoints, []string{"127.0.0.10:7890", "127.0.0.11:7890", "127.0.0.11:7890"}) {
			t.Fatal(endpoints)
		}
		if attempts[1].Sub(attempts[0]) != time.Second || attempts[2].Sub(attempts[1]) != 2*time.Second {
			t.Fatal(attempts)
		}
		w.empty()
		c.ResumeRemote(id)
		synctest.Wait()
		if _, ok := c.active.Load(leaseKey{"exporter", "lease1"}); ok {
			t.Fatal("released recovered lease resumed")
		}
	})
}

func TestClientSimulationRetryBudgetAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelEarly), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				identity := testIdentity(t)
				registry := NewRegistry()
				registry.SetPeers([]Peer{testPeer("exporter", identity)})
				var attempts []time.Time
				c := NewClientWithOptions(identity, registry, nil, ClientOptions{Disconnect: func(string) error { return nil }, Transport: func(*http.Transport) http.RoundTripper {
					return roundTripFunc(func(r *http.Request) (*http.Response, error) {
						attempts = append(attempts, time.Now())
						return nil, errors.New("partition")
					})
				}})
				defer c.Close()
				c.ReleaseRemote("exporter/lease1/" + nvme.SubsystemNQN("exporter", "lease1"))
				synctest.Wait()
				if cancelEarly {
					c.Close()
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if cancelEarly {
					if len(attempts) != 1 {
						t.Fatal(attempts)
					}
				} else {
					if len(attempts) != 8 {
						t.Fatal(attempts)
					}
					want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute}
					for i, d := range want {
						if attempts[i+1].Sub(attempts[i]) != d {
							t.Fatal(attempts)
						}
					}
				}
			})
		})
	}
}

func TestClientSimulationRenewTransientTerminalAndCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newLeaseWorld(t)
		if rec := w.export(); rec.Code != http.StatusOK {
			t.Fatal(rec.Body)
		}
		var attempts []time.Time
		c := NewClientWithOptions(w.reader, w.cfg.Peers, nil, ClientOptions{
			Transport: func(tr *http.Transport) http.RoundTripper {
				inner := w.localTransport(tr)
				return roundTripFunc(func(r *http.Request) (*http.Response, error) {
					attempts = append(attempts, time.Now())
					if len(attempts) == 1 {
						return nil, io.ErrUnexpectedEOF
					}
					if len(attempts) == 3 {
						return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"error":"revoked"}`)), Header: http.Header{}}, nil
					}
					return inner.RoundTrip(r)
				})
			},
		})
		defer c.Close()
		id := "exporter/lease1/" + nvme.SubsystemNQN("exporter", "lease1")
		c.ResumeRemote(id)
		synctest.Wait()
		time.Sleep(7 * time.Minute)
		synctest.Wait()
		if len(attempts) != 3 || attempts[1].Sub(attempts[0]) != time.Minute || attempts[2].Sub(attempts[1]) != 5*time.Minute {
			t.Fatal(attempts)
		}
		c.ResumeRemote(id)
		synctest.Wait()
		if len(attempts) != 3 {
			t.Fatal("terminal renewal restarted")
		}
	})
}

func TestClientSimulationCanceledRenewalCannotEndReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		identity := testIdentity(t)
		registry := NewRegistry()
		registry.SetPeers([]Peer{testPeer("exporter", identity)})
		finishOld := make(chan struct{})
		requests := 0
		c := NewClientWithOptions(identity, registry, nil, ClientOptions{Transport: func(*http.Transport) http.RoundTripper {
			return roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				status := http.StatusOK
				if requests == 1 {
					<-finishOld // A terminal response races cancellation/replacement.
					status = http.StatusForbidden
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
			})
		}})
		defer c.Close()
		id := "exporter/lease1/" + nvme.SubsystemNQN("exporter", "lease1")
		key := leaseKey{"exporter", "lease1"}
		c.ResumeRemote(id)
		synctest.Wait()
		c.ResumeRemote(id)
		synctest.Wait()
		close(finishOld)
		synctest.Wait()
		if _, ok := c.active.Load(key); !ok {
			t.Fatal("old terminal response canceled replacement")
		}
		if _, ok := c.released[key]; ok {
			t.Fatal("old terminal response marked replacement released")
		}
		c.Close()
		synctest.Wait()
		if _, ok := c.active.Load(key); ok {
			t.Fatal("Close did not stop renewal")
		}
		time.Sleep(10 * time.Minute)
		if requests != 2 {
			t.Fatal("renewal request after Close")
		}
	})
}

func TestClientSimulationReleaseCancelsInflightRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		identity := testIdentity(t)
		registry := NewRegistry()
		registry.SetPeers([]Peer{testPeer("exporter", identity)})
		renews, releases, canceled := 0, 0, false
		c := NewClientWithOptions(identity, registry, nil, ClientOptions{
			Disconnect: func(string) error { return nil },
			Transport: func(*http.Transport) http.RoundTripper {
				return roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if strings.HasSuffix(r.URL.Path, "/renew") {
						renews++
						<-r.Context().Done()
						canceled = true
						return nil, r.Context().Err()
					}
					releases++
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
				})
			},
		})
		defer c.Close()
		id := "exporter/lease1/" + nvme.SubsystemNQN("exporter", "lease1")
		c.ResumeRemote(id)
		synctest.Wait()
		c.ReleaseRemote(id)
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		if !canceled || renews != 1 || releases != 1 {
			t.Fatalf("canceled=%v renews=%d releases=%d", canceled, renews, releases)
		}
		if _, ok := c.active.Load(leaseKey{"exporter", "lease1"}); ok {
			t.Fatal("release left renewal installed")
		}
	})
}
