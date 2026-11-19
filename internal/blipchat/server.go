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

func (r *httpRunnable) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/chat", &Chat{Server: r.s})
	srv := &http.Server{Addr: r.s.Config.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
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
