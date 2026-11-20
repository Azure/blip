// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/stream"
)

type fakeStreamTarget struct {
	records   []stream.Record
	logErr    error
	from      uint64
	follow    bool
	logCalls  int
	stdin     []byte
	eof       bool
	note      bool
	after     uint64
	offset    uint64
	stdinErr  error
	stdinCall int
}

func (f *fakeStreamTarget) StreamLog(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	f.logCalls++
	f.from, f.follow = from, follow
	for _, rec := range f.records {
		if err := fn(rec); err != nil {
			return err
		}
	}
	return f.logErr
}

func (f *fakeStreamTarget) StreamStdin(ctx context.Context, namespace, name string, data []byte, eof, note bool, after uint64) (uint64, error) {
	f.stdinCall++
	f.stdin = append([]byte(nil), data...)
	f.eof = eof
	f.note = note
	f.after = after
	return f.offset, f.stdinErr
}

type testStreamStatusError struct {
	code int
	msg  string
}

func (e testStreamStatusError) Error() string         { return e.msg }
func (e testStreamStatusError) StreamHTTPStatus() int { return e.code }

func newStreamTestServer(t *testing.T, target StreamTarget) (*Server, map[string]*x509.Certificate) {
	t.Helper()
	peers := NewRegistry()
	certs := map[string]*x509.Certificate{}
	var registered []Peer
	for _, node := range []string{"n1", "n2"} {
		identity := testIdentity(t)
		cert, err := identity.certificate()
		if err != nil {
			t.Fatal(err)
		}
		certs[node] = cert.Leaf
		registered = append(registered, Peer{Node: node, PublicKey: identity.PublicKey(), Endpoint: "127.0.0.1"})
	}
	peers.SetPeers(registered)
	return &Server{cfg: ServerConfig{Peers: peers, Stream: target}}, certs
}

func streamRequest(t *testing.T, s *Server, method, target string, body io.Reader, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestStreamLogNDJSON(t *testing.T) {
	target := &fakeStreamTarget{records: []stream.Record{
		{Offset: 10, Gen: 2, Type: stream.TypeOut, Data: []byte("hi\n")},
		{Offset: 1, Type: stream.TypeGap},
	}}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodGet, "/v1/stream/log?namespace=default&name=root&offset=10&follow=true", nil, certs["n1"])
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Fatalf("content type = %q", got)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", rec.Body.String())
	}
	var first streamRecord
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Offset != 10 || first.Gen != 2 || first.Type != uint8(stream.TypeOut) {
		t.Fatalf("first = %+v", first)
	}
	if data, err := base64.StdEncoding.DecodeString(first.Data); err != nil || string(data) != "hi\n" {
		t.Fatalf("data = %q (%v)", first.Data, err)
	}
	var gap streamRecord
	if err := json.Unmarshal([]byte(lines[1]), &gap); err != nil {
		t.Fatal(err)
	}
	if gap.Type != uint8(stream.TypeGap) || gap.Offset != 1 || gap.Gen != 0 || gap.Data != "" {
		t.Fatalf("gap = %+v", gap)
	}
	if target.from != 10 || !target.follow {
		t.Fatalf("target got from=%d follow=%v", target.from, target.follow)
	}
}

func TestStreamLogErrorBeforeFirstRecord(t *testing.T) {
	target := &fakeStreamTarget{logErr: testStreamStatusError{code: 409, msg: "not running"}}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodGet, "/v1/stream/log?namespace=default&name=root", nil, certs["n1"])
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "not running") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestStreamLogRequiresAuthAndNames(t *testing.T) {
	s, certs := newStreamTestServer(t, &fakeStreamTarget{})
	req := httptest.NewRequest(http.MethodGet, "/v1/stream/log?namespace=default&name=root", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated status = %d", rec.Code)
	}
	rec = streamRequest(t, s, http.MethodGet, "/v1/stream/log?namespace=default", nil, certs["n1"])
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name status = %d", rec.Code)
	}
}

func TestStreamStdinForwardsBody(t *testing.T) {
	target := &fakeStreamTarget{offset: 11}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodPost, "/v1/stream/stdin?namespace=default&name=root&eof=true", strings.NewReader("ls\n"), certs["n1"])
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if target.stdinCall != 1 || string(target.stdin) != "ls\n" || !target.eof {
		t.Fatalf("target = %+v", target)
	}
	var out struct {
		Offset uint64 `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Offset != 11 {
		t.Fatalf("body = %q (%v)", rec.Body, err)
	}
}

func TestStreamStdinNoteAndAfter(t *testing.T) {
	target := &fakeStreamTarget{offset: 12}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodPost, "/v1/stream/stdin?namespace=default&name=root&note=true&after=11", strings.NewReader("note"), certs["n1"])
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if !target.note || target.after != 11 || target.eof || string(target.stdin) != "note" {
		t.Fatalf("target = %+v", target)
	}
	var out struct {
		Offset uint64 `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Offset != 12 {
		t.Fatalf("body = %q (%v)", rec.Body, err)
	}
}

func TestStreamStdinPreconditionPassthrough(t *testing.T) {
	target := &fakeStreamTarget{stdinErr: testStreamStatusError{code: http.StatusPreconditionFailed, msg: "stream: stdin precondition failed"}}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodPost, "/v1/stream/stdin?namespace=default&name=root&after=7", strings.NewReader("x"), certs["n1"])
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "precondition") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestStreamStdinMapsErrors(t *testing.T) {
	target := &fakeStreamTarget{stdinErr: testStreamStatusError{code: 503, msg: "not ready"}}
	s, certs := newStreamTestServer(t, target)
	rec := streamRequest(t, s, http.MethodPost, "/v1/stream/stdin?namespace=default&name=root", strings.NewReader("x"), certs["n1"])
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "not ready") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestClientStreamLog(t *testing.T) {
	want := []stream.Record{
		{Offset: 7, Gen: 3, Type: stream.TypeErr, Data: []byte("boom")},
		{Offset: 20, Type: stream.TypeGap},
	}
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/stream/log" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("namespace") != "default" || q.Get("name") != "root" || q.Get("offset") != "7" || q.Get("follow") != "true" {
			t.Errorf("query = %v", q)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, rec := range want {
			line := streamRecord{Offset: rec.Offset, Gen: rec.Gen, Type: uint8(rec.Type)}
			if len(rec.Data) > 0 {
				line.Data = base64.StdEncoding.EncodeToString(rec.Data)
			}
			b, _ := json.Marshal(line)
			w.Write(append(b, '\n'))
		}
	}))
	var got []stream.Record
	if err := c.StreamLog(context.Background(), "exporter", "default", "root", 7, true, func(rec stream.Record) error {
		got = append(got, rec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Offset != 7 || got[0].Type != stream.TypeErr || string(got[0].Data) != "boom" || got[1].Type != stream.TypeGap {
		t.Fatalf("records = %+v", got)
	}
}

func TestClientStreamStdin(t *testing.T) {
	var gotBody string
	var gotEOF bool
	var gotNote bool
	var gotAfter string
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/stream/stdin" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("namespace") != "default" || q.Get("name") != "root" {
			t.Errorf("query = %v", q)
		}
		gotEOF = q.Get("eof") == "true"
		gotNote = q.Get("note") == "true"
		gotAfter = q.Get("after")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"offset":21}`)
	}))
	off, err := c.StreamStdin(context.Background(), "exporter", "default", "root", []byte("hello"), true, true, 21)
	if err != nil {
		t.Fatal(err)
	}
	if gotBody != "hello" || !gotEOF || !gotNote || gotAfter != "21" {
		t.Fatalf("body = %q eof = %v note = %v after = %q", gotBody, gotEOF, gotNote, gotAfter)
	}
	if off != 21 {
		t.Fatalf("offset = %d, want 21", off)
	}
}

func TestClientStreamStdinErrorStatus(t *testing.T) {
	c := newLifecycleTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blip is not running", http.StatusConflict)
	}))
	_, err := c.StreamStdin(context.Background(), "exporter", "default", "root", []byte("x"), false, false, 0)
	var re *responseError
	if !errors.As(err, &re) || re.status != http.StatusConflict {
		t.Fatalf("error = %v", err)
	}
}
