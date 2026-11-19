package apiproxy

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// limitNamespace and limitPodName make the limit test take the same owner-scope
// path as the deployed sidecar. testConfig deliberately leaves the pod
// identity empty, because many other tests exercise unscoped pass-through
// routes; this test opts in and holds scoped watch streams, so every admitted
// request performs its two identity GETs before it starts holding a slot.
const (
	limitNamespace = "test-ns"
	limitPodName   = "test-pod"
	limitHoldPath  = "/apis/blip.dev/v1alpha1/namespaces/" + limitNamespace + "/blips?watch=true"

	// safeConcurrentRequests is the largest cap that fits the 64Mi sidecar
	// with headroom. 256 held streams peaked at 60.2MiB and OOM-killed the
	// process, so this regression keeps the cap at or below a quarter of the
	// measured-failing stream count.
	safeConcurrentRequests = 64
)

// TestConcurrentRequestLimit fills every request slot with a held scoped
// watch, checks that further streams are rejected with a cheap 503 rather than
// being admitted, and then checks that closing the held streams releases every
// slot.
func TestConcurrentRequestLimit(t *testing.T) {
	const excess = 16
	var inFlight atomic.Int64
	var maxInFlight atomic.Int64
	var identityReads atomic.Int64

	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/short":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/api/v1/namespaces/" + limitNamespace + "/pods/" + limitPodName:
			identityReads.Add(1)
			_, _ = io.WriteString(w, `{"metadata":{"name":"test-pod",`+
				`"annotations":{"blip.dev/blip":"test-blip"},`+
				`"labels":{"blip.dev/blip-uid":"uid-test"}}}`)
			return
		case "/apis/blip.dev/v1alpha1/namespaces/" + limitNamespace + "/blips/test-blip":
			identityReads.Add(1)
			_, _ = io.WriteString(w, `{"metadata":{"name":"test-blip","uid":"uid-test",`+
				`"labels":{"blip.dev/owner":"test-owner"}}}`)
			return
		}
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			max := maxInFlight.Load()
			if current <= max || maxInFlight.CompareAndSwap(max, current) {
				break
			}
		}
		// Headers make the client's Get return, then the stream is held open
		// like a watch or log tail until the client goes away.
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	cfg := testConfig(t, upstream)
	cfg.PodName, cfg.PodNamespace = limitPodName, limitNamespace
	p := startProxy(t, cfg)

	held := make([]*http.Response, 0, maxConcurrentRequests)
	for i := 0; i < maxConcurrentRequests; i++ {
		resp, err := p.client.Get("http://kube-apiserver" + limitHoldPath)
		if err != nil {
			t.Fatalf("held request %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("held request %d status = %d, want 200", i, resp.StatusCode)
		}
		held = append(held, resp)
	}
	if got := inFlight.Load(); got != maxConcurrentRequests {
		t.Fatalf("upstream requests in flight = %d, want %d", got, maxConcurrentRequests)
	}
	if identityReads.Load() == 0 {
		t.Fatal("scoped requests never performed their owner-scope identity GETs")
	}

	// Every slot is held, so these must be rejected without reaching the
	// upstream.
	for i := 0; i < excess; i++ {
		resp, err := p.client.Get("http://kube-apiserver" + limitHoldPath)
		if err != nil {
			t.Fatalf("excess request %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("excess request %d status = %d, want 503", i, resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got != "1" {
			t.Fatalf("excess request %d Retry-After = %q, want 1", i, got)
		}
		if body := responseBody(t, resp); len(body) > 64 {
			t.Fatalf("excess request %d body = %q, want a cheap body", i, body)
		}
	}
	if got := maxInFlight.Load(); got != maxConcurrentRequests {
		t.Fatalf("max upstream requests in flight = %d, want %d", got, maxConcurrentRequests)
	}

	// Cancelling the clients must release all slots. Closing a response body
	// before its stream ends closes the connection, which the proxy sees as a
	// full close and cancels the upstream request.
	for _, resp := range held {
		resp.Body.Close()
	}
	waitForLimit(t, 5*time.Second, func() bool { return inFlight.Load() == 0 })

	// More sequential short requests than the cap prove every slot was
	// released after its response; a single leaked slot would eventually
	// turn one of these into a 503.
	for i := 0; i < maxConcurrentRequests; i++ {
		resp, err := p.client.Get("http://kube-apiserver/short")
		if err != nil {
			t.Fatalf("short request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("short request %d status = %d, want 204", i, resp.StatusCode)
		}
	}
}

// TestConcurrentRequestCapFitsSidecarMemory is the regression for the 64Mi
// api-proxy sidecar: at 256 held streams it reached 60.2MiB and was
// OOM-killed, so the cap must stay at or below a quarter of that.
func TestConcurrentRequestCapFitsSidecarMemory(t *testing.T) {
	if maxConcurrentRequests > safeConcurrentRequests {
		t.Fatalf("maxConcurrentRequests = %d, want <= %d for the 64Mi sidecar",
			maxConcurrentRequests, safeConcurrentRequests)
	}
}

func waitForLimit(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
