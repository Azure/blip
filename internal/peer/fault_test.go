// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

func TestPrepareFailureRetainsFailedRollback(t *testing.T) {
	for _, stage := range []string{"pin", "save-live"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unpin-after=%v", stage, after), func(t *testing.T) {
				w := newLeaseWorld(t)
				w.fault = func(name string, applied bool) error {
					// The pin error loses a successful result; the save error
					// happens before replacement. Neither may lose cleanup.
					if name == stage && applied == (stage == "pin") {
						return errors.New("preparation failed")
					}
					if name == "unpin" && applied == after {
						return errors.New("rollback failed")
					}
					return nil
				}
				if rec := w.export(); rec.Code != http.StatusInternalServerError {
					t.Fatal(rec.Code, rec.Body)
				}
				if l := w.server.leases["lease1"]; l == nil || !l.Revoked {
					t.Fatal("failed rollback lost its cleanup owner")
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

func TestDuplicateLeaseIDHasNoStoreEffects(t *testing.T) {
	w := newLeaseWorld(t)
	if rec := w.export(); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	original := w.server.leases["lease1"]
	before := len(w.trace)
	if rec := w.request("/v1/export", ExportRequest{CommitID: "another-commit", HostNQN: HostNQN("reader")}); rec.Code != http.StatusInternalServerError {
		t.Fatal(rec.Code, rec.Body)
	}
	if len(w.trace) != before || w.server.leases["lease1"] != original || original.Revoked {
		t.Fatalf("duplicate changed existing lease: trace=%v lease=%+v", w.trace[before:], original)
	}
	if rec := w.release(); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	w.empty()
}

func TestRejectedRenewalPersistsRevocation(t *testing.T) {
	w := newLeaseWorld(t)
	if rec := w.export(); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	w.server.cfg.Authorize = func(string, ExportRequest) error { return errors.New("access removed") }
	if rec := w.request("/v1/leases/lease1/renew", struct{}{}); rec.Code != http.StatusForbidden {
		t.Fatal(rec.Code, rec.Body)
	}
	// Access is later restored, and a crash loses all volatile decisions.
	w.restart()
	before := len(w.trace)
	if rec := w.request("/v1/leases/lease1/renew", struct{}{}); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked lease renewed after restart: %d", rec.Code)
	}
	if err := w.server.Recover(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(w.trace[before:], "publish") {
		t.Fatal("recovery reactivated a durably revoked lease")
	}
	w.empty()
}

func TestRecheckRevokesWholeSelectionBeforeRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newLeaseWorld(t)
		for _, id := range []string{"lease1", "lease2"} {
			w.server.cfg.NewLeaseID = func() string { return id }
			if rec := w.export(); rec.Code != http.StatusOK {
				t.Fatal(rec.Body)
			}
		}
		w.server.cfg.Authorize = func(string, ExportRequest) error { return errors.New("access removed") }
		entered, finish := make(chan struct{}), make(chan struct{})
		first := true
		w.fault = func(name string, after bool) error {
			if name == "unpublish" && !after && first {
				first = false
				// Recheck selected both leases. Its first cleanup holds mu,
				// while a renewal for the second queues behind it.
				if !w.server.leases["lease2"].Revoked {
					t.Error("recheck left a selected lease renewable during cleanup")
				}
				w.server.cfg.Authorize = allow
				close(entered)
				<-finish
			}
			return nil
		}
		done := make(chan error, 1)
		go func() { done <- w.server.recheck() }()
		<-entered
		renewed := make(chan int, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			renewed <- w.request("/v1/leases/lease2/renew", struct{}{}).Code
		}()
		<-started
		close(finish)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if code := <-renewed; code != http.StatusForbidden && code != http.StatusNotFound {
			t.Fatalf("acknowledged renewal during irreversible cleanup: %d", code)
		}
		w.empty()
	})
}

func TestReleaseFailureRestartDoesNotReactivate(t *testing.T) {
	for _, stage := range []string{"save-revoked", "unpublish", "close", "unpin", "save-empty"} {
		t.Run(stage, func(t *testing.T) {
			w := newLeaseWorld(t)
			if rec := w.export(); rec.Code != http.StatusOK {
				t.Fatal(rec.Body)
			}
			w.fault = func(name string, after bool) error {
				if name == stage && after {
					return errors.New("result lost after effect")
				}
				return nil
			}
			if rec := w.release(); rec.Code != http.StatusInternalServerError {
				t.Fatal(rec.Code, rec.Body)
			}
			w.fault = nil
			w.restart()
			before := len(w.trace)
			if err := w.server.Recover(); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(w.trace[before:], "publish") {
				t.Fatal("cleanup error followed by restart resurrected revoked export")
			}
			w.empty()
		})
	}
}

func TestRecoveryOrphanFailuresRetryDuringRecheck(t *testing.T) {
	for _, stage := range []string{"unpublish", "close", "unpin"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%v", stage, after), func(t *testing.T) {
				w := newLeaseWorld(t)
				w.pins["lease:orphan"] = true
				w.devices["orphan"] = "/dev/ciphertext"
				w.exports["orphan"] = "/dev/ciphertext"
				w.fault = func(name string, applied bool) error {
					if name == stage && applied == after {
						return errors.New("startup cleanup failed")
					}
					return nil
				}
				if err := w.server.Recover(); err == nil {
					t.Fatal("startup cleanup failure was lost")
				}
				w.fault = nil
				// This is the periodic entry point Run actually invokes after
				// a failed restore. No process restart or manual Recover call.
				if err := w.server.recheck(); err != nil {
					t.Fatal(err)
				}
				w.empty()
			})
		}
	}
}

func TestClientFailedConnectCleansUpAfterLostReleaseReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newLeaseWorld(t)
		connected := false
		exports, releases, disconnects := 0, 0, 0
		connectErr := errors.New("connect result lost after controller creation")
		c := NewClientWithOptions(w.reader, w.cfg.Peers, nil, ClientOptions{
			Connect: func(context.Context, string, int, string, string, []byte) (string, error) {
				connected = true
				return "", connectErr
			},
			Disconnect: func(string) error {
				disconnects++
				connected = false
				return nil
			},
			Transport: func(tr *http.Transport) http.RoundTripper {
				inner := w.localTransport(tr)
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/v1/export" {
						exports++
					} else if req.URL.Path == "/v1/release" {
						releases++
					} else {
						t.Errorf("unexpected request: %s", req.URL.Path)
					}
					resp, err := inner.RoundTrip(req)
					if err == nil && req.URL.Path == "/v1/release" && releases == 1 {
						resp.Body.Close()
						return nil, io.ErrUnexpectedEOF
					}
					return resp, err
				})
			},
		})
		defer c.Close()
		remote, err := c.Open(t.Context(), "exporter", ExportRequest{CommitID: "commit1", HostNQN: HostNQN("reader")})
		if !errors.Is(err, connectErr) || remote.ID != "" || remote.Release != nil || connected || disconnects != 1 {
			t.Fatalf("failed connect leaked local ownership: remote=%+v err=%v connected=%v disconnects=%d", remote, err, connected, disconnects)
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if exports != 1 || releases != 2 {
			t.Fatalf("requests: exports=%d releases=%d", exports, releases)
		}
		if _, ok := c.active.Load(leaseKey{"exporter", "lease1"}); ok {
			t.Fatal("failed connect retained renewal ownership")
		}
		w.empty()
	})
}
