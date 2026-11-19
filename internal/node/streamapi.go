package node

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/internal/stream"
	"github.com/Azure/blip/internal/streamapi"
)

// streamBackend adapts the agent to the aggregated stream API and maps the
// node's sentinel errors onto the API's.
type streamBackend struct{ a *Agent }

func (b streamBackend) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	return b.mapErr(b.a.StreamLog(ctx, namespace, name, from, follow, fn))
}

func (b streamBackend) Stdin(ctx context.Context, namespace, name string, data []byte, eof bool) error {
	return b.mapErr(b.a.StreamStdin(ctx, namespace, name, data, eof))
}

func (b streamBackend) mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrStreamNotFound):
		return streamapi.ErrNotFound
	case errors.Is(err, ErrStreamNotRunning):
		return streamapi.ErrNotRunning
	case errors.Is(err, ErrStreamClosed):
		return streamapi.ErrClosed
	case errors.Is(err, ErrStreamNotReady):
		return streamapi.ErrNotReady
	default:
		return err
	}
}

// clientCAPool loads a PEM CA bundle, returning nil when the file is absent.
func clientCAPool(path string) *x509.CertPool {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil
	}
	return pool
}

// serveStreamAPI waits for the serving certificate Secret, writes it below the
// data directory, and serves the aggregated API until ctx ends.
func (a *Agent) serveStreamAPI(ctx context.Context, c client.Client, cs kubernetes.Interface, cfg Config) {
	dir := filepath.Join(cfg.DataDir, "stream-tls")
	for {
		data, err := streamCertData(ctx, c, cfg.Stream.Namespace)
		if err == nil {
			if mkErr := os.MkdirAll(dir, 0o700); mkErr == nil {
				cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
				if os.WriteFile(cert, data["tls.crt"], 0o600) == nil && os.WriteFile(key, data["tls.key"], 0o600) == nil {
					srv := streamapi.New(streamapi.Options{
						Backend:           streamBackend{a: a},
						Client:            cs,
						ClientCA:          clientCAPool(cfg.Stream.ClientCA),
						TrustProxyHeaders: true,
					})
					if err := srv.ServeTLS(ctx, cfg.Stream.Listen, cert, key, slog.Default()); err != nil && ctx.Err() == nil {
						slog.Error("stream api", "err", err)
					}
					return
				}
			}
		}
		slog.Warn("stream api waiting for serving certificate", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func streamCertData(ctx context.Context, c client.Client, namespace string) (map[string][]byte, error) {
	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "blip-stream-tls"}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if len(sec.Data["tls.crt"]) == 0 || len(sec.Data["tls.key"]) == 0 {
		return nil, errors.New("serving certificate is empty")
	}
	return sec.Data, nil
}
