package blipchat

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	w626HealthAddr = "127.0.0.1:18098"
	w626ChatAddr   = "127.0.0.1:18099"
	w626SyncDelay  = 5 * time.Second
)

func w626Get(url string, timeout time.Duration) (int, string) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return resp.StatusCode, string(body)
}

// w626SlowCache simulates a first informer sync that takes w626SyncDelay.
// Once the delay elapses it reports synced, so readiness can transition. The
// real cache cannot be made slow without a broken cluster.
type w626SlowCache struct {
	cache.Cache
	delay  time.Duration
	once   sync.Once
	synced chan struct{}
}

func (c *w626SlowCache) WaitForCacheSync(ctx context.Context) bool {
	c.once.Do(func() {
		go func() {
			time.Sleep(c.delay)
			close(c.synced)
		}()
	})
	select {
	case <-c.synced:
		return true
	case <-ctx.Done():
		return false
	}
}

// Setup registers the chat HTTP server through mgr.Add, which is a
// non-leader-election runnable and therefore starts only after the informer
// cache has synced ("Others"). The health server is registered as a
// manager.Server in the pre-cache HTTP group, so /healthz (liveness) answers
// while the cache is still syncing and /readyz reports 503. The chat server
// must stay unavailable until the cache is ready.
func TestW626HealthServedWhileCacheUnsynced(t *testing.T) {
	sch := k8sruntime.NewScheme()
	if err := scheme.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}

	mgr, err := ctrl.NewManager(&rest.Config{
		Host:    "https://127.0.0.1:1",
		Timeout: time.Second,
		QPS:     1,
		Burst:   1,
	}, ctrl.Options{
		Scheme:                 sch,
		HealthProbeBindAddress: "0",
		Metrics:                metricsserver.Options{BindAddress: "0"},
		LeaderElection:         false,
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			c, err := cache.New(config, opts)
			if err != nil {
				return nil, err
			}
			return &w626SlowCache{Cache: c, delay: w626SyncDelay, synced: make(chan struct{})}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Cache: mgr.GetCache(), Config: Config{Listen: w626ChatAddr, HealthListen: w626HealthAddr}}
	// Exactly what blipchat.Setup does for the probe and chat servers.
	if err := s.addHealthServer(mgr); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add(&httpRunnable{s: s}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mgr.Start(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("manager did not stop")
		}
	}()

	// The probe server is in the pre-cache HTTP group: it must answer well
	// before the synthetic cache sync delay expires.
	start := time.Now()
	healthUp := false
	for time.Since(start) < 2*time.Second {
		if code, _ := w626Get("http://"+w626HealthAddr+"/healthz", 500*time.Millisecond); code == http.StatusOK {
			healthUp = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthUp {
		t.Fatal("health /healthz never started while the cache was unsynced")
	}
	if elapsed := time.Since(start); elapsed >= w626SyncDelay {
		t.Fatalf("health /healthz started after WaitForCacheSync returned (%s)", elapsed)
	}

	// Readiness must be 503 while the cache is still syncing.
	if code, body := w626Get("http://"+w626HealthAddr+"/readyz", 5*time.Second); code != http.StatusServiceUnavailable {
		t.Errorf("health /readyz while unsynced = %d %q, want 503", code, body)
	}

	// The chat listener must not exist until the cache has synced.
	if code, _ := w626Get("http://"+w626ChatAddr+"/healthz", 500*time.Millisecond); code != 0 {
		t.Errorf("chat server answered on %s while the cache was unsynced: %d", w626ChatAddr, code)
	}

	// After the sync the health check flips to ready and the chat server starts.
	deadline := time.Now().Add(w626SyncDelay + 5*time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if code, _ := w626Get("http://"+w626HealthAddr+"/readyz", 3*time.Second); code == http.StatusOK {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("health /readyz never became ready after the cache synced")
	}
	chatUp := false
	for time.Now().Before(deadline) {
		if code, _ := w626Get("http://"+w626ChatAddr+"/healthz", 500*time.Millisecond); code == http.StatusOK {
			chatUp = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !chatUp {
		t.Fatal("chat server never started after the cache synced")
	}
}
