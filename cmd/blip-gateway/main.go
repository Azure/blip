// Command blip-gateway is the Blip SSH gateway.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway"
	"github.com/Azure/blip/internal/session"
)

// +kubebuilder:rbac:groups=blip.dev,resources=blips;blipstates,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=get;create
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "blip-gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := gateway.Config{}
	var stateSize, listen, httpListen, identityHeader string
	var tlsCert, tlsKey, tlsClientCA string
	flag.StringVar(&cfg.Namespace, "namespace", os.Getenv("POD_NAMESPACE"), "namespace for users, host key, and sandboxes")
	flag.StringVar(&cfg.Image, "image", "", "image for new sandbox states (required)")
	flag.StringVar(&cfg.Pool, "pool", "default", "VM pool for sandboxes")
	flag.StringVar(&stateSize, "state-size", "20Gi", "size of new sandbox states")
	flag.DurationVar(&cfg.IdleTimeout, "idle-timeout", 30*time.Second, "stop idle sandboxes after this long")
	flag.DurationVar(&cfg.StartNoticeDelay, "start-notice-delay", 5*time.Second, "tell interactive sessions their sandbox is still starting after this long")
	flag.StringVar(&listen, "listen", ":2222", "SSH listen address")
	flag.StringVar(&httpListen, "http-listen", ":8443", "certificate API listen address (TLS, behind the Envoy gateway)")
	flag.StringVar(&identityHeader, "identity-header", "X-Forwarded-User", "trusted header with the authenticated user identity")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate for the certificate API (required)")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key for the certificate API (required)")
	flag.StringVar(&tlsClientCA, "tls-client-ca", "", "CA bundle that must sign the Envoy gateway's client certificate (required)")
	klog.InitFlags(nil)
	flag.Parse()
	if cfg.Namespace == "" || cfg.Image == "" {
		return fmt.Errorf("--namespace and --image are required")
	}
	if strings.TrimSpace(identityHeader) == "" {
		return fmt.Errorf("--identity-header is required")
	}
	if tlsCert == "" || tlsKey == "" || tlsClientCA == "" {
		return fmt.Errorf("--tls-cert, --tls-key and --tls-client-ca are required")
	}
	size, err := resource.ParseQuantity(stateSize)
	if err != nil {
		return fmt.Errorf("--state-size: %w", err)
	}
	cfg.StateSize = size

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Every SSH channel opens a short-lived kube pod exec. Closing it makes
	// client-go's websocket and reader goroutines log "use of closed network
	// connection" as an unhandled error, which swamps the gateway log under
	// load without saying anything about the SSH request. klog writes to
	// os.Stderr directly by default, bypassing SetOutput, so route non-fatal
	// logs through the filter and reserve stderr for fatal logs.
	if err := flag.Set("stderrthreshold", "FATAL"); err != nil {
		return err
	}
	klog.LogToStderr(false)
	klog.SetOutput(closedStreamLog{os.Stderr})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rc, err := config.GetConfig()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	kube, err := client.NewWithWatch(rc, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	sessions, err := session.NewClient(rc)
	if err != nil {
		return err
	}
	hostKey, err := gateway.LoadHostKey(ctx, cs, cfg.Namespace)
	if err != nil {
		return err
	}
	log.Info("host key", "fingerprint", ssh.FingerprintSHA256(hostKey.PublicKey()))

	ca, err := gateway.LoadUserCA(ctx, cs, cfg.Namespace)
	if err != nil {
		return err
	}
	log.Info("SSH certificate authentication", "identity-header", identityHeader,
		"ca", ssh.FingerprintSHA256(ca.PublicKey()))

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("--tls-cert/--tls-key: %w", err)
	}
	clientCAs, err := loadClientCA(tlsClientCA)
	if err != nil {
		return fmt.Errorf("--tls-client-ca: %w", err)
	}

	users := &gateway.Users{}
	users.Watch(ctx, cs, cfg.Namespace, log)
	catalog := gateway.NewCatalog(kube, cfg.Namespace)
	if err := catalog.Start(ctx); err != nil {
		return fmt.Errorf("watching sandboxes: %w", err)
	}

	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	hl, err := net.Listen("tcp", httpListen)
	if err != nil {
		return err
	}
	log.Info("listening", "address", l.Addr(), "namespace", cfg.Namespace, "image", cfg.Image)
	srv := &gateway.Server{Config: cfg, Kube: kube, Catalog: catalog, Sessions: sessions, Users: users, HostKey: hostKey, CA: ca, ClientCAs: clientCAs, IdentityHeader: identityHeader, Log: log}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
	}
	go func() {
		<-ctx.Done()
		httpSrv.Close()
	}()
	go func() {
		log.Info("certificate API listening", "address", hl.Addr())
		if err := httpSrv.ServeTLS(hl, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("certificate API stopped", "error", err)
		}
	}()
	return srv.Serve(ctx, l)
}

// loadClientCA reads a PEM bundle of CA certificates that may sign client
// certificates for the certificate API.
func loadClientCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no CA certificates", path)
	}
	return pool, nil
}

// closedStreamLog drops the client-go messages emitted while tearing down a
// pod exec stream. The stream is closed on purpose; the error does not affect
// the SSH channel, and these lines dominate the gateway log during fork
// storms.
type closedStreamLog struct{ io.Writer }

func (w closedStreamLog) Write(p []byte) (int, error) {
	s := string(p)
	if strings.Contains(s, "use of closed network connection") &&
		(strings.Contains(s, `"Unhandled Error"`) || strings.Contains(s, "Websocket Ping failed")) {
		return len(p), nil
	}
	return w.Writer.Write(p)
}
