package blipchat

import (
	"context"
	"errors"
	"net/http"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Setup registers the sequencer, the blip watcher, coordinator steps, and the
// chat server on an existing manager.
func Setup(ctx context.Context, mgr ctrl.Manager, cfg Config) error {
	cfg.defaults()
	s := &Server{
		Client:     mgr.GetClient(),
		Config:     cfg,
		LLM:        &LLM{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, HTTP: cfg.HTTPClient},
		RestConfig: mgr.GetConfig(),
		Cache:      mgr.GetCache(),
		Log:        ctrl.Log.WithName("blipchat"),
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &v1.BlipTurn{}, turnField, func(o client.Object) []string {
		return []string{o.(*v1.BlipTurn).Spec.Thread}
	}); err != nil {
		return err
	}
	if err := (&Sequencer{Client: s.Client}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&Watcher{Client: s.Client}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := mgr.Add(&stepsRunnable{s: s}); err != nil {
		return err
	}
	return mgr.Add(&httpRunnable{s: s})
}

// stepsRunnable runs coordinator steps only on the elected leader.
type stepsRunnable struct {
	s *Server
}

func (r *stepsRunnable) Start(ctx context.Context) error { return r.s.Steps(ctx) }
func (r *stepsRunnable) NeedLeaderElection() bool        { return true }

// httpRunnable serves the chat on every replica.
type httpRunnable struct {
	s *Server
}

func (r *httpRunnable) NeedLeaderElection() bool { return false }

// HTTP server bounds. The read timeout stops slow-body and slow-header
// clients, the idle timeout closes unused keep-alive connections, and the
// write timeout bounds a client that stops reading. The write timeout is kept
// at the LLM client's own timeout so a slow completion is not cut off.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 5 * time.Minute
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 << 10
)

func newChatServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

func (r *httpRunnable) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/readyz", r.readyz)
	mux.Handle("/chat", &Chat{Server: r.s})
	return mux
}

// healthz is liveness only: the process can answer HTTP. Readiness is
// separate so a wedged informer cache removes the pod from the Service
// without triggering a restart loop.
func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (r *httpRunnable) readyz(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.s.Cache != nil {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if !r.s.Cache.WaitForCacheSync(ctx) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (r *httpRunnable) Start(ctx context.Context) error {
	srv := newChatServer(r.s.Config.Listen, r.handler())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
