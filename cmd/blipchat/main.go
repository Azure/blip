// Command blipchat is a stateless, team-scoped chat UI for ACP agents running
// in blips. A chat is a BlipState; each turn runs a Blip whose stdin/stdout is
// the state's trajectory ring.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/blipchat"
)

func main() {
	var (
		listen       string
		namespace    string
		profilesCM   string
		profilesFile string
		autoApprove  string
		defaultPool  string
		logLevel     string
	)
	flag.StringVar(&listen, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&namespace, "namespace", "default", "default session namespace")
	flag.StringVar(&profilesCM, "profiles-configmap", "", "profiles ConfigMap as NAME or NAMESPACE/NAME (default <namespace>/blip-chat-profiles)")
	flag.StringVar(&profilesFile, "profiles-file", "", "optional JSON profiles file")
	flag.StringVar(&autoApprove, "auto-approve", "always", "permission policy: always (allow once) or never")
	flag.StringVar(&defaultPool, "default-pool", "default", "pool used by profiles that do not name one")
	flag.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	level, err := parseLevel(logLevel)
	if err != nil {
		fail(err.Error())
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	if err := run(listen, namespace, profilesCM, profilesFile, autoApprove, defaultPool); err != nil {
		fail(err.Error())
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("--log-level: unknown level %q", s)
	}
}

func run(listen, namespace, profilesCM, profilesFile, autoApprove, defaultPool string) error {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return err
	}
	kc, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if profilesCM == "" {
		profilesCM = namespace + "/blip-chat-profiles"
	}
	profiles, err := blipchat.LoadProfiles(ctx, kc, namespace, profilesCM, profilesFile, defaultPool)
	if err != nil {
		return err
	}
	wire, err := blipchat.NewWire(cfg)
	if err != nil {
		return err
	}
	srv, err := blipchat.New(blipchat.Options{
		Namespace:   namespace,
		Profiles:    profiles,
		DefaultPool: defaultPool,
		AutoApprove: autoApprove,
		Cluster:     blipchat.NewKube(kc),
		Wire:        wire,
		Log:         slog.Default(),
	})
	if err != nil {
		return err
	}
	srv.Start(ctx)
	defer srv.Close()

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "address", listen, "namespace", namespace)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "blipchat:", message)
	os.Exit(1)
}
