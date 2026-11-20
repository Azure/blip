// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package streamapi serves blip trajectories and stdin as an aggregated
// Kubernetes API. It is a library: the caller supplies a Backend and mounts
// Handler behind the kube-apiserver's front proxy. The API group is
// stream.blip.dev/v1alpha1:
//
//	GET  .../namespaces/{ns}/blipstreams/{name}/log?offset=...
//	POST .../namespaces/{ns}/blipstreams/{name}/stdin?eof=true&note=true&after=...
//
// Backends return (or wrap) this package's sentinel errors; the server uses
// errors.Is.
package streamapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/blip/internal/stream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes"
)

const (
	// GroupName is the API group served by this package.
	GroupName = "stream.blip.dev"
	// Version is the served API version.
	Version = "v1alpha1"
	// GroupVersion is the fully qualified group and version.
	GroupVersion = GroupName + "/" + Version
	// Resource is the API resource name.
	Resource = "blipstreams"
)

// statusReasonPreconditionFailed is the metav1 Status reason for HTTP 412.
// metav1 has no constant for it.
const statusReasonPreconditionFailed metav1.StatusReason = "PreconditionFailed"

// Backend errors. A backend should return one of these (directly or wrapped)
// so the API server can choose the matching Kubernetes status code:
//
//	ErrNotFound     404
//	ErrNotRunning   409
//	ErrClosed       409
//	ErrNotReady     503
//	ErrPrecondition 412
//
// Any other error becomes 500.
var (
	// ErrNotFound means the named blipstream does not exist.
	ErrNotFound = errors.New("streamapi: blipstream not found")
	// ErrNotRunning means the blip exists but has no live command.
	ErrNotRunning = errors.New("streamapi: blip is not running")
	// ErrClosed means the stream or its stdin is closed.
	ErrClosed = errors.New("streamapi: stream is closed")
	// ErrNotReady means the node has not published the stream yet.
	ErrNotReady = errors.New("streamapi: stream is not ready")
	// ErrPrecondition means a conditional stdin write lost its race with
	// another writer. The server answers 412.
	ErrPrecondition = errors.New("streamapi: stdin precondition failed")
)

// Backend supplies the live data behind the API. Log calls fn for each record
// from from onward. When follow is true Log must keep calling fn as records
// appear and return only when ctx is canceled or the stream ends. Stdin writes
// data and, when eof is true, closes stdin. When note is true Stdin persists
// data in the trajectory without forwarding it to the guest's stdin. When
// after is non-zero the write only succeeds if the offset of the most recent
// stdin or note record in the trajectory is still exactly after; this
// compare-and-append serializes several gateway replicas. Stdin returns the
// offset at which it appended the write.
type Backend interface {
	Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error
	Stdin(ctx context.Context, namespace, name string, data []byte, eof, note bool, after uint64) (uint64, error)
}

// Options configures a Server.
type Options struct {
	Backend Backend
	// Client is used for delegated SubjectAccessReview and token review. When
	// nil, resource requests are denied unless Insecure is set.
	Client kubernetes.Interface
	// ClientCA verifies TLS client certificates. It is normally the
	// kube-apiserver front proxy's client CA.
	ClientCA *x509.CertPool
	// TrustProxyHeaders accepts the kube-apiserver front-proxy identity
	// headers (X-Remote-User, X-Remote-Group) when no verifiable certificate
	// is available. Only enable it when direct network access to the listener
	// is restricted to the API server.
	TrustProxyHeaders bool
	// Insecure accepts requests without credentials and, when no Authorizer
	// is available, allows them. It exists for tests only.
	Insecure bool
	// Authorizer overrides the delegated Subject Access Review authorizer.
	// Tests can supply a fake to avoid a cluster.
	Authorizer authorizer.Authorizer
}

// Server is the stream API HTTP handler.
type Server struct {
	backend   Backend
	client    kubernetes.Interface
	clientCA  *x509.CertPool
	insecure  bool
	proxyAuth bool

	// Authorizer decides resource access. New sets it to a delegated
	// SubjectAccessReview authorizer when Client is non-nil. A nil Authorizer
	// denies access unless Insecure is set.
	Authorizer authorizer.Authorizer
}

// New returns a stream API server.
func New(opts Options) *Server {
	s := &Server{
		backend:    opts.Backend,
		client:     opts.Client,
		clientCA:   opts.ClientCA,
		insecure:   opts.Insecure,
		proxyAuth:  opts.TrustProxyHeaders,
		Authorizer: opts.Authorizer,
	}
	if s.Authorizer == nil && s.client != nil {
		s.Authorizer = sarAuthorizer{client: s.client}
	}
	return s
}

// Handler returns the HTTP handler. It implements group discovery, log reads
// and stdin writes.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	seg := pathSegments(r.URL.Path)

	switch {
	case len(seg) == 1 && seg[0] == "apis":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, groupList())
		return

	case len(seg) == 2 && seg[0] == "apis" && seg[1] == GroupName:
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, group())
		return

	case len(seg) == 3 && seg[0] == "apis" && seg[1] == GroupName && seg[2] == Version:
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		// Discovery is public; the aggregated API server's availability check
		// does not carry a user token. Log and stdin requests still require
		// authentication and authorization.
		writeJSON(w, http.StatusOK, resourceList())
		return

	case len(seg) == 8 && seg[0] == "apis" && seg[1] == GroupName && seg[2] == Version &&
		seg[3] == "namespaces" && seg[5] == Resource:
		namespace, name, subresource := seg[4], seg[6], seg[7]
		switch subresource {
		case "log":
			if !requireMethod(w, r, http.MethodGet) {
				return
			}
			s.serveLog(w, r, namespace, name)
			return
		case "stdin":
			if !requireMethod(w, r, http.MethodPost) {
				return
			}
			s.serveStdin(w, r, namespace, name)
			return
		}
	}

	writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, "the server could not find the requested resource")
}

func (s *Server) serveLog(w http.ResponseWriter, r *http.Request, namespace, name string) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.authorize(w, r, u, "get", "log", namespace, name) {
		return
	}

	q := r.URL.Query()
	var from uint64
	if v := q.Get("offset"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "offset must be an unsigned integer")
			return
		}
		from = n
	}
	follow, err := boolParam(q.Get("follow"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "follow must be true or false")
		return
	}
	raw, err := boolParam(q.Get("raw"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "raw must be true or false")
		return
	}
	if s.backend == nil {
		s.writeBackendError(w, ErrNotReady)
		return
	}

	if raw {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	enc := &recordWriter{w: w, raw: raw}
	if f, ok := w.(http.Flusher); ok {
		enc.flusher = f
	}
	err = s.backend.Log(r.Context(), namespace, name, from, follow, enc.write)
	if err != nil {
		if !enc.wrote {
			s.writeBackendError(w, err)
		}
		return
	}
	if !enc.wrote {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) serveStdin(w http.ResponseWriter, r *http.Request, namespace, name string) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.authorize(w, r, u, "create", "stdin", namespace, name) {
		return
	}
	eof, err := boolParam(r.URL.Query().Get("eof"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "eof must be true or false")
		return
	}
	note, err := boolParam(r.URL.Query().Get("note"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "note must be true or false")
		return
	}
	var after uint64
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "after must be an unsigned integer")
			return
		}
		after = n
	}
	if s.backend == nil {
		s.writeBackendError(w, ErrNotReady)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, "could not read request body")
		return
	}
	offset, err := s.backend.Stdin(r.Context(), namespace, name, data, eof, note, after)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Offset uint64 `json:"offset"`
	}{Offset: offset})
}

// recordWriter owns the framing of the log response. It delays the response
// header until the first record (or a successful empty read), so a backend that
// fails immediately can still produce a proper status code.
type recordWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	raw     bool
	wrote   bool
}

type recordJSON struct {
	Offset uint64 `json:"o"`
	Gen    uint64 `json:"g"`
	Type   string `json:"t"`
	Data   string `json:"d"`
}
type gapJSON struct {
	Type   string `json:"t"`
	Offset uint64 `json:"o"`
}

func (rw *recordWriter) write(rec stream.Record) error {
	if rw.raw {
		if rec.Type != stream.TypeOut {
			return nil
		}
		rw.start()
		if _, err := rw.w.Write(rec.Data); err != nil {
			return err
		}
		rw.flush()
		return nil
	}

	var (
		line []byte
		err  error
	)
	if rec.Type == stream.TypeGap {
		line, err = json.Marshal(gapJSON{Type: "gap", Offset: rec.Offset})
	} else {
		typ, ok := recordType(rec.Type)
		if !ok {
			return fmt.Errorf("streamapi: unknown record type %d", rec.Type)
		}
		line, err = json.Marshal(recordJSON{
			Offset: rec.Offset,
			Gen:    rec.Gen,
			Type:   typ,
			Data:   base64.StdEncoding.EncodeToString(rec.Data),
		})
	}
	if err != nil {
		return err
	}
	line = append(line, '\n')
	rw.start()
	if _, err := rw.w.Write(line); err != nil {
		return err
	}
	rw.flush()
	return nil
}

func (rw *recordWriter) start() {
	if !rw.wrote {
		rw.wrote = true
		rw.w.WriteHeader(http.StatusOK)
	}
}

func (rw *recordWriter) flush() {
	if rw.flusher != nil {
		rw.flusher.Flush()
	}
}

func recordType(t stream.RecordType) (string, bool) {
	switch t {
	case stream.TypeOut:
		return "out", true
	case stream.TypeErr:
		return "err", true
	case stream.TypeIn:
		return "in", true
	case stream.TypeStart:
		return "start", true
	case stream.TypeEnd:
		return "end", true
	case stream.TypeNote:
		return "note", true
	default:
		return "", false
	}
}

func (s *Server) writeBackendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, err.Error())
	case errors.Is(err, ErrNotRunning):
		writeStatus(w, http.StatusConflict, metav1.StatusReasonConflict, err.Error())
	case errors.Is(err, ErrClosed):
		writeStatus(w, http.StatusConflict, metav1.StatusReasonConflict, err.Error())
	case errors.Is(err, ErrNotReady):
		writeStatus(w, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, err.Error())
	case errors.Is(err, ErrPrecondition):
		writeStatus(w, http.StatusPreconditionFailed, statusReasonPreconditionFailed, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The client is gone; there is nobody to answer.
		return
	default:
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError, err.Error())
	}
}

// ServeTLS listens on addr and serves the API until ctx is canceled. Client
// certificates are requested, then verified against ClientCA by the handler;
// bearer tokens are verified with Client when configured.
func (s *Server) ServeTLS(ctx context.Context, addr, certFile, keyFile string, log *slog.Logger) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ClientCAs:    s.clientCA,
			// Certificates are verified by authenticate so a bearer-only
			// client can still connect.
			ClientAuth: tls.RequestClientCert,
		},
	}
	if ctx != nil {
		stop := context.AfterFunc(ctx, func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		})
		defer stop()
	}
	if log != nil {
		log.Info("stream API listening", "addr", ln.Addr().String())
	}
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func pathSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func boolParam(v string) (bool, error) {
	if v == "" {
		return false, nil
	}
	return strconv.ParseBool(v)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeStatus(w, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed,
		fmt.Sprintf("method %s is not allowed", r.Method))
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeStatus(w http.ResponseWriter, code int, reason metav1.StatusReason, message string) {
	writeJSON(w, code, metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Message:  message,
		Reason:   reason,
		Code:     int32(code),
	})
}

func groupList() *metav1.APIGroupList {
	return &metav1.APIGroupList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"},
		Groups:   []metav1.APIGroup{*group()},
	}
}

func group() *metav1.APIGroup {
	gv := metav1.GroupVersionForDiscovery{GroupVersion: GroupVersion, Version: Version}
	return &metav1.APIGroup{
		TypeMeta:         metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroup"},
		Name:             GroupName,
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	}
}

func resourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: GroupVersion,
		APIResources: []metav1.APIResource{
			{
				Name:         Resource,
				SingularName: "blipstream",
				Namespaced:   true,
				Kind:         "BlipStream",
				Verbs:        []string{"get", "create"},
			},
			{
				Name:       Resource + "/log",
				Namespaced: true,
				Kind:       "BlipStream",
				Verbs:      []string{"get"},
			},
			{
				Name:       Resource + "/stdin",
				Namespaced: true,
				Kind:       "BlipStream",
				Verbs:      []string{"create"},
			},
		},
	}
}
