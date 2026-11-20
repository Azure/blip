// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
		basePath     string
		namespace    string
		profilesCM   string
		profilesFile string
		autoApprove  string
		defaultPool  string
		logLevel     string
		mcpListen    string
		mcpCert      string
		mcpKey       string
		mcpAudience  string
		mcpURL       string
		questionWait time.Duration
		service      string
		serviceNS    string
		podName      string
	)
	flag.StringVar(&listen, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&basePath, "base-path", "", "URL path prefix for a reverse proxy, e.g. /blipchat (the root stays available)")
	flag.StringVar(&namespace, "namespace", "default", "Kubernetes namespace that holds every chat (fixed at deployment time)")
	flag.StringVar(&profilesCM, "profiles-configmap", "", "profiles ConfigMap as NAME or NAMESPACE/NAME (default <namespace>/blip-chat-profiles)")
	flag.StringVar(&profilesFile, "profiles-file", "", "optional JSON profiles file")
	flag.StringVar(&autoApprove, "auto-approve", "always", "permission policy: always (allow once) or never")
	flag.StringVar(&defaultPool, "default-pool", "default", "pool used by profiles that do not name one")
	flag.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&mcpListen, "mcp-listen", "", "HTTPS listen address for the agent MCP endpoint (disabled when empty)")
	flag.StringVar(&mcpCert, "mcp-cert", "", "TLS certificate for --mcp-listen")
	flag.StringVar(&mcpKey, "mcp-key", "", "TLS key for --mcp-listen")
	flag.StringVar(&mcpAudience, "mcp-audience", "blipchat", "audience of the projected token agents use for MCP")
	flag.StringVar(&mcpURL, "mcp-url", "", "URL agents use to reach MCP; the guest-facing pool endpoint URL plus /mcp")
	flag.DurationVar(&questionWait, "question-timeout", 30*time.Second, "how long ask_user waits for an answer before the agent ends its turn")
	flag.StringVar(&service, "service", "", "Service whose endpoints shard chats across blipchat replicas (empty disables sharding)")
	flag.StringVar(&serviceNS, "service-namespace", "", "namespace of --service (default the chat namespace)")
	flag.StringVar(&podName, "pod-name", os.Getenv("POD_NAME"), "this replica's pod name, used for shard ownership")
	flag.Parse()

	level, err := parseLevel(logLevel)
	if err != nil {
		fail(err.Error())
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	opts := runOptions{
		listen: listen, basePath: basePath, namespace: namespace, profilesCM: profilesCM, profilesFile: profilesFile,
		autoApprove: autoApprove, defaultPool: defaultPool, mcpListen: mcpListen, mcpCert: mcpCert,
		mcpKey: mcpKey, mcpAudience: mcpAudience, mcpURL: mcpURL, questionWait: questionWait,
		service: service, serviceNS: serviceNS, podName: podName,
	}
	if err := run(opts); err != nil {
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

type runOptions struct {
	listen       string
	basePath     string
	namespace    string
	profilesCM   string
	profilesFile string
	autoApprove  string
	defaultPool  string
	mcpListen    string
	mcpCert      string
	mcpKey       string
	mcpAudience  string
	mcpURL       string
	questionWait time.Duration
	service      string
	serviceNS    string
	podName      string
}

func run(o runOptions) error {
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

	if o.profilesCM == "" {
		o.profilesCM = o.namespace + "/blip-chat-profiles"
	}
	profiles, err := blipchat.LoadProfiles(ctx, kc, o.namespace, o.profilesCM, o.profilesFile, o.defaultPool)
	if err != nil {
		return err
	}
	wire, err := blipchat.NewWire(cfg)
	if err != nil {
		return err
	}
	cluster := blipchat.NewKube(kc)
	if o.questionWait <= 0 {
		return errors.New("--question-timeout must be positive")
	}
	opts := blipchat.Options{
		Namespace:        o.namespace,
		BasePath:         o.basePath,
		Profiles:         profiles,
		DefaultPool:      o.defaultPool,
		AutoApprove:      o.autoApprove,
		Cluster:          cluster,
		Wire:             wire,
		Log:              slog.Default(),
		MCPURL:           o.mcpURL,
		QuestionTimeout:  o.questionWait,
		Service:          o.service,
		ServiceNamespace: o.serviceNS,
		PodName:          o.podName,
	}
	if o.mcpListen != "" {
		opts.Callers, err = blipchat.NewTokenReviewCallers(cfg, cluster, o.mcpAudience)
		if err != nil {
			return err
		}
	}
	srv, err := blipchat.New(opts)
	if err != nil {
		return err
	}
	srv.Start(ctx)
	defer srv.Close()

	httpServer := &http.Server{
		Addr:              o.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errCh := make(chan error, 2)
	go func() {
		slog.Info("listening", "address", o.listen, "namespace", o.namespace)
		errCh <- httpServer.ListenAndServe()
	}()
	var mcpServer *http.Server
	if o.mcpListen != "" {
		if o.mcpCert == "" || o.mcpKey == "" {
			return errors.New("--mcp-listen requires --mcp-cert and --mcp-key")
		}
		mcpServer = &http.Server{
			Addr:              o.mcpListen,
			Handler:           srv.MCPHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		go func() {
			slog.Info("listening for agents", "address", o.mcpListen)
			errCh <- mcpServer.ListenAndServeTLS(o.mcpCert, o.mcpKey)
		}()
	}
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
	if mcpServer != nil {
		_ = mcpServer.Shutdown(shutdown)
	}
	return httpServer.Shutdown(shutdown)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "blipchat:", message)
	os.Exit(1)
}
