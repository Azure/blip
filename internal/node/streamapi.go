// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/internal/stream"
	"github.com/Azure/blip/internal/streamapi"
)

const (
	// authConfigMap is where the kube-apiserver publishes the client
	// authentication settings for aggregated API servers.
	authConfigMapNamespace = "kube-system"
	authConfigMapName      = "extension-apiserver-authentication"
	// clientAuthPollInterval is how often the published settings are
	// re-read. They change only when the API server's certificates rotate.
	clientAuthPollInterval = 30 * time.Second
)

// streamBackend adapts the agent to the aggregated stream API and maps the
// node's sentinel errors onto the API's.
type streamBackend struct{ a *Agent }

func (b streamBackend) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	return b.mapErr(b.a.StreamLog(ctx, namespace, name, from, follow, fn))
}

func (b streamBackend) Stdin(ctx context.Context, namespace, name string, data []byte, eof, note bool, after uint64) (uint64, error) {
	off, err := b.a.StreamStdin(ctx, namespace, name, data, eof, note, after)
	return off, b.mapErr(err)
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
	case errors.Is(err, ErrStreamPrecondition):
		return streamapi.ErrPrecondition
	}
	// A request may be forwarded to the node that owns the writer. Preserve
	// the status it reported instead of turning every failure into a 500.
	var status interface{ StreamHTTPStatus() int }
	if errors.As(err, &status) {
		switch status.StreamHTTPStatus() {
		case http.StatusNotFound:
			return streamapi.ErrNotFound
		case http.StatusConflict:
			return streamapi.ErrNotRunning
		case http.StatusPreconditionFailed:
			return streamapi.ErrPrecondition
		case http.StatusServiceUnavailable:
			return streamapi.ErrNotReady
		}
	}
	return err
}

// clientAuthSettings is the subset of the kube-apiserver's published client
// authentication settings that the node agent uses.
type clientAuthSettings struct {
	requestHeaderCA *x509.CertPool
	clientCA        *x509.CertPool
	allowedNames    []string
}

// parseClientAuth reads the ConfigMap keys that configure front-proxy
// authentication. A missing request-header CA is not an error: it disables
// proxy identity headers. The API server publishes requestheader-allowed-names
// as a JSON array of common names; an empty array accepts any name the
// request-header CA issued.
func parseClientAuth(data map[string]string) (clientAuthSettings, error) {
	var auth clientAuthSettings
	var err error
	if pemData := strings.TrimSpace(data["requestheader-client-ca-file"]); pemData != "" {
		if auth.requestHeaderCA, err = certPoolFromPEM([]byte(pemData)); err != nil {
			return clientAuthSettings{}, fmt.Errorf("requestheader-client-ca-file: %w", err)
		}
	}
	if pemData := strings.TrimSpace(data["client-ca-file"]); pemData != "" {
		if auth.clientCA, err = certPoolFromPEM([]byte(pemData)); err != nil {
			return clientAuthSettings{}, fmt.Errorf("client-ca-file: %w", err)
		}
	}
	if names := strings.TrimSpace(data["requestheader-allowed-names"]); names != "" {
		if err := json.Unmarshal([]byte(names), &auth.allowedNames); err != nil {
			return clientAuthSettings{}, fmt.Errorf("requestheader-allowed-names: %w", err)
		}
	}
	return auth, nil
}

// certPoolFromPEM parses a PEM CA bundle.
func certPoolFromPEM(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("no certificates found")
	}
	return pool, nil
}

// clientCAFile loads an operator-supplied CA bundle. It replaces both the
// request-header and client CAs, preserving the single-file override.
func clientCAFile(path string) (clientAuthSettings, bool) {
	if path == "" {
		return clientAuthSettings{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return clientAuthSettings{}, false
	}
	pool, err := certPoolFromPEM(data)
	if err != nil {
		return clientAuthSettings{}, false
	}
	return clientAuthSettings{requestHeaderCA: pool, clientCA: pool}, true
}

// startClientAuth applies the API server's client authentication settings to
// srv before it starts serving, then reloads them when the ConfigMap changes.
func startClientAuth(ctx context.Context, cs kubernetes.Interface, srv *streamapi.Server, override string, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	if auth, ok := clientCAFile(override); ok {
		srv.SetClientAuth(auth.requestHeaderCA, auth.clientCA, auth.allowedNames)
		log.Info("using client CA file", "path", override)
		return
	}
	if override != "" {
		log.Warn("client CA file is not usable; using the API server ConfigMap", "path", override)
	}

	lastRV, err := reloadClientAuth(ctx, cs, srv, "", log)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("load API server client authentication", "err", err)
		}
	}
	go func() {
		ticker := time.NewTicker(clientAuthPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			rv, err := reloadClientAuth(ctx, cs, srv, lastRV, log)
			if err != nil {
				if ctx.Err() == nil {
					log.Warn("load API server client authentication", "err", err)
				}
				continue
			}
			lastRV = rv
		}
	}()
}

// reloadClientAuth reads kube-system/extension-apiserver-authentication and
// swaps the server's credentials when the resource version changed.
func reloadClientAuth(ctx context.Context, cs kubernetes.Interface, srv *streamapi.Server, lastRV string, log *slog.Logger) (string, error) {
	cm, err := cs.CoreV1().ConfigMaps(authConfigMapNamespace).Get(ctx, authConfigMapName, metav1.GetOptions{})
	if err != nil {
		return lastRV, err
	}
	if lastRV != "" && cm.ResourceVersion == lastRV {
		return lastRV, nil
	}
	auth, err := parseClientAuth(cm.Data)
	if err != nil {
		return lastRV, fmt.Errorf("%s/%s: %w", authConfigMapNamespace, authConfigMapName, err)
	}
	srv.SetClientAuth(auth.requestHeaderCA, auth.clientCA, auth.allowedNames)
	if auth.requestHeaderCA == nil {
		log.Warn("request-header client CA is missing; proxy identity headers are rejected",
			"configmap", authConfigMapNamespace+"/"+authConfigMapName)
	} else {
		log.Info("applied API server client authentication",
			"configmap", authConfigMapNamespace+"/"+authConfigMapName, "resourceVersion", cm.ResourceVersion)
	}
	return cm.ResourceVersion, nil
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
						IdentityBackend:   identityBackend{client: a.client},
						Client:            cs,
						TrustProxyHeaders: true,
					})
					startClientAuth(ctx, cs, srv, cfg.Stream.ClientCA, slog.Default())
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
