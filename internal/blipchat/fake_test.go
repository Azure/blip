package blipchat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

type fakeCluster struct {
	mu         sync.Mutex
	states     map[string]*v1.BlipState
	blips      map[string]*v1.Blip
	blipOrder  []string
	createBlip int
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{states: map[string]*v1.BlipState{}, blips: map[string]*v1.Blip{}}
}

func key(ns, name string) string { return ns + "/" + name }

func copyState(s *v1.BlipState) *v1.BlipState {
	c := s.DeepCopy()
	return c
}

func copyBlip(b *v1.Blip) *v1.Blip { return b.DeepCopy() }

func (f *fakeCluster) ListSessions(_ context.Context, ns string) ([]v1.BlipState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.BlipState
	for _, s := range f.states {
		if s.Namespace == ns && s.Labels[LabelSession] == "true" {
			out = append(out, *copyState(s))
		}
	}
	return out, nil
}

func (f *fakeCluster) GetSession(_ context.Context, ns, name string) (*v1.BlipState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.states[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name)
	}
	return copyState(s), nil
}

func (f *fakeCluster) CreateSession(_ context.Context, ns string, s *v1.BlipState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.states[key(ns, s.Name)]; ok {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, s.Name)
	}
	c := copyState(s)
	c.Namespace = ns
	if c.CreationTimestamp.IsZero() {
		c.CreationTimestamp = metav1.Now()
	}
	f.states[key(ns, s.Name)] = c
	return nil
}

func (f *fakeCluster) PatchSession(_ context.Context, ns, name string, labels, annotations map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.states[key(ns, name)]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name)
	}
	if s.Labels == nil && len(labels) > 0 {
		s.Labels = map[string]string{}
	}
	for k, v := range labels {
		s.Labels[k] = v
	}
	if s.Annotations == nil && len(annotations) > 0 {
		s.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		s.Annotations[k] = v
	}
	return nil
}

func (f *fakeCluster) ListSessionBlips(_ context.Context, ns string) ([]v1.Blip, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.Blip
	for _, b := range f.blips {
		if b.Namespace == ns && b.Labels[LabelSession] != "" {
			out = append(out, *copyBlip(b))
		}
	}
	return out, nil
}

func (f *fakeCluster) ListStateBlips(_ context.Context, ns, state string) ([]v1.Blip, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.Blip
	for _, b := range f.blips {
		if b.Namespace == ns && b.Labels[LabelSession] == state {
			out = append(out, *copyBlip(b))
		}
	}
	return out, nil
}

func (f *fakeCluster) CreateBlip(_ context.Context, ns string, b *v1.Blip) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(ns, b.Name)
	if _, ok := f.blips[k]; ok {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, b.Name)
	}
	c := copyBlip(b)
	c.Namespace = ns
	c.Status.Phase = v1.BlipRunning
	f.blips[k] = c
	f.blipOrder = append(f.blipOrder, b.Name)
	f.createBlip++
	return nil
}

func (f *fakeCluster) GetBlip(_ context.Context, ns, name string) (*v1.Blip, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blips[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, name)
	}
	return copyBlip(b), nil
}

func (f *fakeCluster) StopBlip(_ context.Context, ns, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blips[key(ns, name)]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, name)
	}
	b.Spec.Stop = true
	return nil
}

func (f *fakeCluster) blipNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.blipOrder...)
}

type sentMessage struct {
	raw    []byte
	method string
	id     string
	eof    bool
}

type fakeWire struct {
	mu        sync.Mutex
	lines     chan []byte
	sent      []sentMessage
	offset    uint64
	failFirst bool
	closed    bool
}

func newFakeWire() *fakeWire {
	return &fakeWire{lines: make(chan []byte, 128)}
}

func (f *fakeWire) Send(ctx context.Context, namespace, state string, data []byte, eof bool) error {
	if eof {
		f.mu.Lock()
		f.sent = append(f.sent, sentMessage{eof: true})
		f.mu.Unlock()
		f.emitACP(map[string]any{"jsonrpc": "2.0", "method": "blip/output", "params": map[string]string{"stream": "eof"}})
		return nil
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}
	method, _ := msg["method"].(string)
	id, _ := msg["id"].(string)
	f.mu.Lock()
	f.sent = append(f.sent, sentMessage{raw: append([]byte(nil), data...), method: method, id: id})
	fail := f.failFirst && method == "session/prompt"
	if fail {
		f.failFirst = false
	}
	f.mu.Unlock()
	if fail {
		return ErrNotRunning
	}
	switch method {
	case "initialize":
		f.emitRPC(id, map[string]any{
			"agentCapabilities": map[string]any{"loadSession": true},
		})
	case "session/new":
		f.emitRPC(id, map[string]any{"sessionId": "acp-session-1"})
	case "session/load", "session/resume":
		f.emitRPC(id, map[string]any{})
	}
	return nil
}

func (f *fakeWire) OpenLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error) {
	return &chanReader{ctx: ctx, ch: f.lines}, nil
}

func (f *fakeWire) emitRPC(id string, result any) {
	f.emitACP(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (f *fakeWire) emitACP(msg any) {
	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	off := f.offset
	f.offset += uint64(streamRecordHeader + len(data))
	ch := f.lines
	f.mu.Unlock()
	rec := map[string]any{"o": off, "g": 1, "t": 1, "d": base64.StdEncoding.EncodeToString(data)}
	line, _ := json.Marshal(rec)
	select {
	case ch <- append(line, '\n'):
	default:
	}
}

func (f *fakeWire) closeLog() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (f *fakeWire) messages() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMessage(nil), f.sent...)
}

func (f *fakeWire) promptIDs() []string {
	var ids []string
	for _, m := range f.messages() {
		if m.method == "session/prompt" {
			ids = append(ids, m.id)
		}
	}
	return ids
}

type chanReader struct {
	ctx context.Context
	ch  <-chan []byte
	buf []byte
}

func (r *chanReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		select {
		case <-r.ctx.Done():
			return 0, io.EOF
		case b, ok := <-r.ch:
			if !ok {
				return 0, io.EOF
			}
			r.buf = b
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *chanReader) Close() error { return nil }

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
