// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/stream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeBackend struct {
	mu sync.Mutex

	records  []stream.Record
	logErr   error
	stdinErr error

	gotNamespace string
	gotName      string
	gotFrom      uint64
	gotFollow    bool
	gotData      []byte
	gotEOF       bool
	gotNote      bool
	gotAfter     uint64
	offset       uint64
}

func (f *fakeBackend) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	f.mu.Lock()
	f.gotNamespace, f.gotName, f.gotFrom, f.gotFollow = namespace, name, from, follow
	records, err := f.records, f.logErr
	f.mu.Unlock()
	for _, rec := range records {
		if err := fn(rec); err != nil {
			return err
		}
	}
	return err
}

func (f *fakeBackend) Stdin(ctx context.Context, namespace, name string, data []byte, eof, note bool, after uint64) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotNamespace, f.gotName = namespace, name
	f.gotData = append([]byte(nil), data...)
	f.gotEOF = eof
	f.gotNote = note
	f.gotAfter = after
	return f.offset, f.stdinErr
}

func serve(s *Server, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder) metav1.Status {
	t.Helper()
	var st metav1.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v\n%s", err, rec.Body.String())
	}
	return st
}

func TestDiscovery(t *testing.T) {
	s := New(Options{Insecure: true})
	h := s.Handler()
	cases := []struct {
		path   string
		into   any
		verify func(*testing.T, any)
	}{
		{
			path: "/apis",
			into: &metav1.APIGroupList{},
			verify: func(t *testing.T, v any) {
				list := v.(*metav1.APIGroupList)
				if len(list.Groups) != 1 || list.Groups[0].Name != GroupName {
					t.Fatalf("unexpected groups: %+v", list.Groups)
				}
				if got := list.Groups[0].PreferredVersion.Version; got != Version {
					t.Fatalf("preferred version = %q", got)
				}
			},
		},
		{
			path: "/apis/" + GroupName,
			into: &metav1.APIGroup{},
			verify: func(t *testing.T, v any) {
				g := v.(*metav1.APIGroup)
				if g.Name != GroupName || len(g.Versions) != 1 || g.Versions[0].GroupVersion != GroupVersion {
					t.Fatalf("unexpected group: %+v", g)
				}
			},
		},
		{
			path: "/apis/" + GroupVersion,
			into: &metav1.APIResourceList{},
			verify: func(t *testing.T, v any) {
				list := v.(*metav1.APIResourceList)
				if list.GroupVersion != GroupVersion {
					t.Fatalf("group version = %q", list.GroupVersion)
				}
				byName := map[string]metav1.APIResource{}
				for _, r := range list.APIResources {
					byName[r.Name] = r
				}
				main, ok := byName[Resource]
				if !ok || !main.Namespaced || strings.Join(main.Verbs, ",") != "get,create" {
					t.Fatalf("unexpected main resource: %+v", main)
				}
				if got := strings.Join(byName[Resource+"/log"].Verbs, ","); got != "get" {
					t.Fatalf("log verbs = %q", got)
				}
				if got := strings.Join(byName[Resource+"/stdin"].Verbs, ","); got != "create" {
					t.Fatalf("stdin verbs = %q", got)
				}
			},
		},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", c.path, rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s: content type %q", c.path, ct)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), c.into); err != nil {
			t.Fatalf("%s: decode: %v", c.path, err)
		}
		c.verify(t, c.into)
	}
}

func TestLogNDJSON(t *testing.T) {
	fb := &fakeBackend{records: []stream.Record{
		{Offset: 10, Gen: 1, Type: stream.TypeOut, Data: []byte("hello")},
		{Offset: 15, Gen: 1, Type: stream.TypeErr, Data: []byte("bad")},
		{Offset: 18, Gen: 2, Type: stream.TypeIn, Data: []byte{0, 1}},
		{Offset: 20, Gen: 2, Type: stream.TypeStart},
		{Offset: 20, Gen: 2, Type: stream.TypeEnd},
		{Offset: 40, Gen: 0, Type: stream.TypeGap},
	}}
	s := New(Options{Backend: fb, Insecure: true})
	rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log?offset=7")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content type = %q", ct)
	}
	if fb.gotNamespace != "ns" || fb.gotName != "demo" || fb.gotFrom != 7 || fb.gotFollow {
		t.Fatalf("backend call = %q %q %d %v", fb.gotNamespace, fb.gotName, fb.gotFrom, fb.gotFollow)
	}

	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("got %d lines: %q", len(lines), lines)
	}
	wantTypes := []string{"out", "err", "in", "start", "end", "gap"}
	wantData := []string{
		base64.StdEncoding.EncodeToString([]byte("hello")),
		base64.StdEncoding.EncodeToString([]byte("bad")),
		base64.StdEncoding.EncodeToString([]byte{0, 1}),
		"", "", "",
	}
	wantOffsets := []uint64{10, 15, 18, 20, 20, 40}
	for i, line := range lines {
		var obj struct {
			O uint64 `json:"o"`
			G uint64 `json:"g"`
			T string `json:"t"`
			D string `json:"d"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if obj.T != wantTypes[i] || obj.O != wantOffsets[i] || obj.D != wantData[i] {
			t.Fatalf("line %d = %+v", i, obj)
		}
		if i == 5 && obj.G != 0 {
			t.Fatalf("gap gen = %d, want omitted", obj.G)
		}
	}
	// A gap carries only t and o.
	var gap map[string]any
	if err := json.Unmarshal([]byte(lines[5]), &gap); err != nil {
		t.Fatal(err)
	}
	if len(gap) != 2 || gap["t"] != "gap" || gap["o"] != float64(40) {
		t.Fatalf("gap = %#v", gap)
	}
}

func TestLogRawOnlyOut(t *testing.T) {
	fb := &fakeBackend{records: []stream.Record{
		{Offset: 0, Type: stream.TypeOut, Data: []byte("a")},
		{Offset: 1, Type: stream.TypeErr, Data: []byte("b")},
		{Offset: 2, Type: stream.TypeOut, Data: []byte("c")},
		{Offset: 3, Type: stream.TypeGap},
	}}
	s := New(Options{Backend: fb, Insecure: true})
	rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log?raw=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content type = %q", got)
	}
	if got := rec.Body.String(); got != "ac" {
		t.Fatalf("body = %q", got)
	}
}

func TestLogFollowStreamsUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	stopped := make(chan struct{})

	fb := fakeLogFunc(func(ctx context.Context, from uint64, follow bool, fn func(stream.Record) error) error {
		if !follow {
			return errors.New("follow was not requested")
		}
		if err := fn(stream.Record{Offset: 3, Gen: 1, Type: stream.TypeOut, Data: []byte("one")}); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	})
	s := New(Options{Backend: fb, Insecure: true})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log?offset=3&follow=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never started following")
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"t":"out"`) || !strings.Contains(line, `"o":3`) {
		t.Fatalf("line = %q", line)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("request context did not reach the backend")
	}
}

type fakeLogFunc func(ctx context.Context, from uint64, follow bool, fn func(stream.Record) error) error

func (f fakeLogFunc) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	return f(ctx, from, follow, fn)
}

func (fakeLogFunc) Stdin(context.Context, string, string, []byte, bool, bool, uint64) (uint64, error) {
	return 0, nil
}

func TestLogErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		reason metav1.StatusReason
	}{
		{ErrNotFound, http.StatusNotFound, metav1.StatusReasonNotFound},
		{fmt.Errorf("backend: %w", ErrNotRunning), http.StatusConflict, metav1.StatusReasonConflict},
		{ErrClosed, http.StatusConflict, metav1.StatusReasonConflict},
		{ErrNotReady, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable},
		{errors.New("broken"), http.StatusInternalServerError, metav1.StatusReasonInternalError},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%d", c.reason, c.status), func(t *testing.T) {
			s := New(Options{Backend: &fakeBackend{logErr: c.err}, Insecure: true})
			rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log")
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content type = %q", ct)
			}
			st := decodeStatus(t, rec)
			if st.Code != int32(c.status) || st.Reason != c.reason || st.Status != metav1.StatusFailure {
				t.Fatalf("status = %+v", st)
			}
		})
	}
}

func TestBadLogParams(t *testing.T) {
	s := New(Options{Backend: &fakeBackend{}, Insecure: true})
	for _, q := range []string{"offset=-1", "offset=x", "follow=maybe", "raw=maybe"} {
		rec := serve(s, http.MethodGet, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/log?"+q)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", q, rec.Code)
		}
		if st := decodeStatus(t, rec); st.Reason != metav1.StatusReasonBadRequest {
			t.Fatalf("%s: %+v", q, st)
		}
	}
}

func TestStdin(t *testing.T) {
	fb := &fakeBackend{}
	s := New(Options{Backend: fb, Insecure: true})
	req := httptest.NewRequest(http.MethodPost,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/stdin?eof=true", strings.NewReader("hello\n"))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if string(fb.gotData) != "hello\n" || !fb.gotEOF || fb.gotNamespace != "ns" || fb.gotName != "demo" {
		t.Fatalf("backend got %q eof=%v %q/%q", fb.gotData, fb.gotEOF, fb.gotNamespace, fb.gotName)
	}

	// EOF alone closes stdin.
	rec = serve(s, http.MethodPost, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/stdin?eof=true")
	if rec.Code != http.StatusOK || !fb.gotEOF || len(fb.gotData) != 0 {
		t.Fatalf("empty eof: status %d, eof=%v data=%q", rec.Code, fb.gotEOF, fb.gotData)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
	var out struct {
		Offset uint64 `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Offset != 0 {
		t.Fatalf("body = %q (%v)", rec.Body, err)
	}
}

func TestStdinNoteAndAfter(t *testing.T) {
	fb := &fakeBackend{offset: 42}
	s := New(Options{Backend: fb, Insecure: true})
	req := httptest.NewRequest(http.MethodPost,
		"/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/stdin?note=true&after=7", strings.NewReader("a note"))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
	var out struct {
		Offset uint64 `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body: %v\n%s", err, rec.Body)
	}
	if out.Offset != 42 {
		t.Fatalf("offset = %d, want 42", out.Offset)
	}
	if !fb.gotNote || fb.gotAfter != 7 || string(fb.gotData) != "a note" {
		t.Fatalf("backend got note=%v after=%d data=%q", fb.gotNote, fb.gotAfter, fb.gotData)
	}
}

func TestStdinPrecondition(t *testing.T) {
	s := New(Options{Backend: &fakeBackend{stdinErr: ErrPrecondition}, Insecure: true})
	rec := serve(s, http.MethodPost, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/stdin?after=7")
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if st := decodeStatus(t, rec); st.Reason != statusReasonPreconditionFailed || st.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %+v", st)
	}
}

func TestBadStdinParams(t *testing.T) {
	s := New(Options{Backend: &fakeBackend{}, Insecure: true})
	for _, q := range []string{"eof=maybe", "note=maybe", "after=-1", "after=x"} {
		rec := serve(s, http.MethodPost, "/apis/"+GroupVersion+"/namespaces/ns/blipstreams/demo/stdin?"+q)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", q, rec.Code)
		}
		if st := decodeStatus(t, rec); st.Reason != metav1.StatusReasonBadRequest {
			t.Fatalf("%s: %+v", q, st)
		}
	}
}

func TestMethodNotAllowedAndNotFound(t *testing.T) {
	s := New(Options{Insecure: true})
	rec := serve(s, http.MethodPost, "/apis")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST /apis: %d %v", rec.Code, rec.Header())
	}
	rec = serve(s, http.MethodGet, "/apis/other.example/v1")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: %d", rec.Code)
	}
	if st := decodeStatus(t, rec); st.Reason != metav1.StatusReasonNotFound {
		t.Fatalf("status: %+v", st)
	}
}
