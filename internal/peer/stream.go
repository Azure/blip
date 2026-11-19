package peer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/blip/internal/stream"
)

// StreamTarget is the local trajectory/stdio source the stream routes use.
// The node agent implements it; keeping the interface here leaves this package
// free of node imports.
type StreamTarget interface {
	StreamLog(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error
	StreamStdin(ctx context.Context, namespace, name string, data []byte, eof bool) error
}

// StreamGap is the record type the log stream uses to report records trimmed
// before the reported offset.
const StreamGap = 255

// streamRecord is one NDJSON line of a log response. Data is base64 so a
// record can be split on newlines.
type streamRecord struct {
	Offset uint64 `json:"o"`
	Gen    uint64 `json:"g,omitempty"`
	Type   uint8  `json:"t"`
	Data   string `json:"d,omitempty"`
}

// streamStatus lets a StreamTarget map its own errors to HTTP status codes
// without this package importing the target's sentinel errors.
type streamStatus interface {
	StreamHTTPStatus() int
}

func streamHTTPStatus(err error) int {
	var s streamStatus
	if errors.As(err, &s) {
		if code := s.StreamHTTPStatus(); code != 0 {
			return code
		}
	}
	return http.StatusInternalServerError
}

func streamTextError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, msg+"\n")
}

// handleStreamLog streams a state's trajectory as NDJSON. The response starts
// with the first record so an early failure can still be reported as an HTTP
// status.
func (s *Server) handleStreamLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.caller(w, r); !ok {
		return
	}
	q := r.URL.Query()
	namespace, name := q.Get("namespace"), q.Get("name")
	if namespace == "" || name == "" {
		streamTextError(w, http.StatusBadRequest, "namespace and name are required")
		return
	}
	from, err := strconv.ParseUint(q.Get("offset"), 10, 64)
	if q.Get("offset") != "" && err != nil {
		streamTextError(w, http.StatusBadRequest, "offset must be a uint64")
		return
	}
	follow, err := streamBool(q.Get("follow"))
	if err != nil {
		streamTextError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.cfg.Stream == nil {
		streamTextError(w, http.StatusServiceUnavailable, "stream service is not configured")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	flush, _ := w.(http.Flusher)
	started := false
	write := func(rec stream.Record) error {
		line := streamRecord{Offset: rec.Offset, Gen: rec.Gen, Type: uint8(rec.Type)}
		if len(rec.Data) > 0 {
			line.Data = base64.StdEncoding.EncodeToString(rec.Data)
		}
		b, err := json.Marshal(line)
		if err != nil {
			return err
		}
		if !started {
			w.WriteHeader(http.StatusOK)
			started = true
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
		if flush != nil {
			flush.Flush()
		}
		return nil
	}
	if err := s.cfg.Stream.StreamLog(r.Context(), namespace, name, from, follow, write); err != nil {
		if !started {
			streamTextError(w, streamHTTPStatus(err), err.Error())
		}
		return
	}
	if !started {
		w.WriteHeader(http.StatusOK)
	}
}

// handleStreamStdin forwards raw stdin bytes to the state's guest.
func (s *Server) handleStreamStdin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.caller(w, r); !ok {
		return
	}
	q := r.URL.Query()
	namespace, name := q.Get("namespace"), q.Get("name")
	if namespace == "" || name == "" {
		streamTextError(w, http.StatusBadRequest, "namespace and name are required")
		return
	}
	eof := false
	if v := q.Get("eof"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			streamTextError(w, http.StatusBadRequest, "eof must be a boolean")
			return
		}
		eof = b
	}
	if s.cfg.Stream == nil {
		streamTextError(w, http.StatusServiceUnavailable, "stream service is not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		streamTextError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Stream.StreamStdin(r.Context(), namespace, name, body, eof); err != nil {
		streamTextError(w, streamHTTPStatus(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func streamBool(v string) (bool, error) {
	switch v {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, errors.New("follow must be a boolean")
}

// streamRequest performs an authenticated peer request whose response may be
// read incrementally. The returned cleanup must run when the body is done.
func (c *Client) streamRequest(ctx context.Context, node, method, path string, body io.Reader, contentType string) (*http.Response, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	fail := func(err error) (*http.Response, func(), error) {
		stop()
		cancel()
		return nil, nil, err
	}
	if err := c.waitReady(ctx); err != nil {
		return fail(err)
	}
	p, ok := c.peers.Lookup(node)
	if !ok {
		return fail(fmt.Errorf("peer: unknown node %q", node))
	}
	endpoint := "https://" + net.JoinHostPort(p.Endpoint, strconv.Itoa(ExportPort)) + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fail(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Each request gets a fresh TLS handshake and a current registry key pin,
	// just like the export control requests.
	transport := &http.Transport{
		TLSClientConfig:     c.identity.clientTLS(c.peers, node),
		DisableKeepAlives:   true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	var roundTripper http.RoundTripper = transport
	if c.transport != nil {
		roundTripper = c.transport(transport)
	}
	client := &http.Client{
		Transport:     roundTripper,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		return fail(fmt.Errorf("peer: %w", err))
	}
	cleanup := func() {
		resp.Body.Close()
		transport.CloseIdleConnections()
		stop()
		cancel()
	}
	return resp, cleanup, nil
}

// StreamLog reads a state's trajectory from node. The callback is called once
// per record, including StreamGap records for trimmed history.
func (c *Client) StreamLog(ctx context.Context, node, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	if fn == nil {
		return errors.New("peer: nil stream callback")
	}
	q := url.Values{}
	q.Set("namespace", namespace)
	q.Set("name", name)
	q.Set("offset", strconv.FormatUint(from, 10))
	q.Set("follow", strconv.FormatBool(follow))
	resp, done, err := c.streamRequest(ctx, node, http.MethodGet, "/v1/stream/log?"+q.Encode(), nil, "")
	if err != nil {
		return err
	}
	defer done()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &responseError{status: resp.StatusCode,
			message: fmt.Sprintf("peer: %s /v1/stream/log: %s: %s", node, resp.Status, strings.TrimSpace(string(data)))}
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var line streamRecord
		if err := dec.Decode(&line); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		rec := stream.Record{Offset: line.Offset, Gen: line.Gen, Type: stream.RecordType(line.Type)}
		if line.Data != "" {
			rec.Data, err = base64.StdEncoding.DecodeString(line.Data)
			if err != nil {
				return fmt.Errorf("peer: bad stream record: %w", err)
			}
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

// StreamStdin writes raw bytes to a state's guest. eof closes the guest's
// stdin after the bytes are delivered.
func (c *Client) StreamStdin(ctx context.Context, node, namespace, name string, data []byte, eof bool) error {
	q := url.Values{}
	q.Set("namespace", namespace)
	q.Set("name", name)
	if eof {
		q.Set("eof", "true")
	}
	resp, done, err := c.streamRequest(ctx, node, http.MethodPost, "/v1/stream/stdin?"+q.Encode(), bytes.NewReader(data), "application/octet-stream")
	if err != nil {
		return err
	}
	defer done()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &responseError{status: resp.StatusCode,
			message: fmt.Sprintf("peer: %s /v1/stream/stdin: %s: %s", node, resp.Status, strings.TrimSpace(string(b)))}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
