// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

type fakeCluster struct {
	mu                sync.Mutex
	states            map[string]*v1.BlipState
	blips             map[string]*v1.Blip
	pods              map[string]*corev1.Pod
	endpoints         []string
	blipOrder         []string
	createBlip        int
	createBlipAttempt int
	createBlipErr     error
	pendingBlips      bool
	createSessionErr  error
	onCreateBlip      func(*v1.Blip)
	stopBlipStarted   chan struct{}
	stopBlipGate      chan struct{}
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{states: map[string]*v1.BlipState{}, blips: map[string]*v1.Blip{}, pods: map[string]*corev1.Pod{}}
}

func key(ns, name string) string { return ns + "/" + name }

func copyState(s *v1.BlipState) *v1.BlipState { return s.DeepCopy() }
func copyBlip(b *v1.Blip) *v1.Blip            { return b.DeepCopy() }

func (f *fakeCluster) ListSessions(_ context.Context, ns string) ([]v1.BlipState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.BlipState
	for _, s := range f.states {
		if s.DeletionTimestamp != nil {
			continue
		}
		if s.Namespace == ns && s.Labels[LabelSession] == "true" && isChatState(s) {
			out = append(out, *copyState(s))
		}
	}
	return out, nil
}

func (f *fakeCluster) ListStates(_ context.Context, ns string, selector labels.Selector) ([]v1.BlipState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.BlipState
	for _, s := range f.states {
		if s.Namespace == ns && selector.Matches(labels.Set(s.Labels)) {
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

func (f *fakeCluster) DeleteSession(_ context.Context, ns, name string, uid types.UID, resourceVersion ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[key(ns, name)]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name)
	}
	if uid != "" && st.UID != "" && st.UID != uid {
		return apierrors.NewConflict(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name,
			fmt.Errorf("the UID in the precondition (%s) does not match the UID in record (%s)", uid, st.UID))
	}
	for _, version := range resourceVersion {
		if version == "" {
			continue
		}
		if st.ResourceVersion != version {
			return apierrors.NewConflict(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name,
				fmt.Errorf("the resource version in the precondition (%s) does not match the resource version in record (%s)", version, st.ResourceVersion))
		}
		break
	}
	delete(f.states, key(ns, name))
	return nil
}

func (f *fakeCluster) CreateSession(_ context.Context, ns string, s *v1.BlipState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createSessionErr != nil {
		return f.createSessionErr
	}
	if _, ok := f.states[key(ns, s.Name)]; ok {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, s.Name)
	}
	c := copyState(s)
	c.Namespace = ns
	if c.Status.Phase == "" {
		c.Status.Phase = v1.StateReady
	}
	if c.CreationTimestamp.IsZero() {
		c.CreationTimestamp = metav1.Now()
	}
	f.states[key(ns, s.Name)] = c
	return nil
}

func (f *fakeCluster) ForkSession(_ context.Context, ns string, source, dest *v1.BlipState, owner *metav1.OwnerReference) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.states[key(ns, dest.Name)]; ok {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, dest.Name)
	}
	c := copyState(dest)
	c.Namespace = ns
	c.Spec.CopyFrom = source.Name
	if c.Status.Phase == "" {
		c.Status.Phase = v1.StateReady
	}
	if owner != nil {
		c.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	if c.CreationTimestamp.IsZero() {
		c.CreationTimestamp = metav1.Now()
	}
	f.states[key(ns, dest.Name)] = c
	return nil
}

func (f *fakeCluster) ListChildSessions(_ context.Context, ns, parent string) ([]v1.BlipState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []v1.BlipState
	for _, s := range f.states {
		if s.Namespace == ns && s.Labels[LabelParent] == parent && isChatState(s) {
			out = append(out, *copyState(s))
		}
	}
	return out, nil
}

func (f *fakeCluster) GetPod(_ context.Context, ns, name string) (*corev1.Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pods[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, name)
	}
	return p.DeepCopy(), nil
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
	version, _ := strconv.ParseUint(s.ResourceVersion, 10, 64)
	s.ResourceVersion = strconv.FormatUint(version+1, 10)
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

func (f *fakeCluster) RecordStop(_ context.Context, ns, name string, before uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[key(ns, name)]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blipstates"}, name)
	}
	if before > stopBefore(st) {
		if st.Annotations == nil {
			st.Annotations = map[string]string{}
		}
		st.Annotations[AnnotationStopBefore] = strconv.FormatUint(before, 10)
	}
	return nil
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
	f.createBlipAttempt++
	if f.createBlipErr != nil {
		err := f.createBlipErr
		f.mu.Unlock()
		return err
	}
	k := key(ns, b.Name)
	if _, ok := f.blips[k]; ok {
		f.mu.Unlock()
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, b.Name)
	}
	c := copyBlip(b)
	c.Namespace = ns
	if c.UID == "" {
		c.UID = types.UID(c.Name + "-uid")
	}
	if c.Status.RootAttachmentID == "" {
		c.Status.RootAttachmentID = c.Name + "-root"
	}
	c.Status.Phase = v1.BlipRunning
	if f.pendingBlips {
		c.Status.Phase = v1.BlipPending
	}
	if st := f.states[key(ns, c.Spec.State)]; st != nil {
		st.Status.Writer = &v1.Writer{
			BlipName: c.Name, BlipUID: string(c.UID), AttachmentID: c.Status.RootAttachmentID,
		}
		if st.Status.Committed != nil {
			st.Status.Writer.BaseCommit = st.Status.Committed.ID
		}
	}
	f.blips[k] = c
	f.blipOrder = append(f.blipOrder, b.Name)
	f.createBlip++
	hook := f.onCreateBlip
	f.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	return nil
}

func (f *fakeCluster) PatchBlip(_ context.Context, ns, name string, labels, annotations map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blips[key(ns, name)]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, name)
	}
	if b.Labels == nil && len(labels) > 0 {
		b.Labels = map[string]string{}
	}
	for k, v := range labels {
		b.Labels[k] = v
	}
	if b.Annotations == nil && len(annotations) > 0 {
		b.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		b.Annotations[k] = v
	}
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
	b, ok := f.blips[key(ns, name)]
	if !ok {
		f.mu.Unlock()
		return apierrors.NewNotFound(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, name)
	}
	b.Spec.Stop = true
	started, gate := f.stopBlipStarted, f.stopBlipGate
	f.stopBlipStarted = nil
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	b.Status.Phase = v1.BlipSucceeded
	f.mu.Unlock()
	return nil
}

func (f *fakeCluster) ListEndpointMembers(_ context.Context, ns, service string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.endpoints...), nil
}

// setActive marks every blip of the state as terminal, as a controller would
// after the guest exits.
func (f *fakeCluster) setActive(ns, state, phase string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.blips {
		if b.Namespace == ns && b.Labels[LabelSession] == state {
			b.Status.Phase = phase
		}
	}
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
	note   bool
	after  uint64
	offset uint64
}

// fakeWire emulates the node's ring plus its stdin endpoint: appends are
// serialized, conditional appends are checked against the generation's last
// input offset, and agent replies are recorded as ordinary log records.
type fakeWire struct {
	mu             sync.Mutex
	cond           *sync.Cond
	records        []streamLogRecord
	offset         uint64
	gen            uint64
	lastSeq        uint64
	sent           []sentMessage
	failFirst      bool
	failInitialize error
	autoRespond    bool
	closed         bool
	// onPrompt, when set, runs after a prompt is recorded and may append
	// records (for example a permission request) before the auto reply.
	onPrompt func(gen uint64, text string)
}

func newFakeWire() *fakeWire {
	f := &fakeWire{}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *fakeWire) Send(_ context.Context, _, _ string, data []byte, eof, note bool, after uint64) (uint64, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, ErrNotRunning
	}
	if after != 0 && after != f.lastSeq {
		f.mu.Unlock()
		return 0, ErrPrecondition
	}
	if eof {
		seq := f.lastSeq
		f.sent = append(f.sent, sentMessage{eof: true})
		gen := f.gen
		f.sent[len(f.sent)-1].after = gen
		f.mu.Unlock()
		return seq, nil
	}
	typ := recordIn
	var msg map[string]any
	if note {
		typ = recordNote
	} else if err := json.Unmarshal(data, &msg); err != nil {
		f.mu.Unlock()
		return 0, err
	}
	method, _ := msg["method"].(string)
	id, _ := msg["id"].(string)
	if f.failFirst && method == "session/prompt" {
		f.failFirst = false
		f.mu.Unlock()
		return 0, ErrNotRunning
	}
	off := f.appendLocked(f.gen, typ, data)
	f.sent = append(f.sent, sentMessage{raw: append([]byte(nil), data...), method: method, id: id, note: note, after: after, offset: off})
	f.lastSeq = off
	f.mu.Unlock()

	if note {
		return off, nil
	}
	switch method {
	case "initialize":
		f.mu.Lock()
		failure := f.failInitialize
		f.mu.Unlock()
		if failure != nil {
			f.emitACP(f.gen, map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]any{"code": -32603, "message": failure.Error()},
			})
			break
		}
		f.emitACP(f.gen, map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  map[string]any{"agentCapabilities": map[string]any{"loadSession": true}},
		})
	case "session/new":
		f.emitACP(f.gen, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"sessionId": "acp-session-1"}})
	case "session/load", "session/resume":
		f.emitACP(f.gen, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{}})
	case "session/prompt":
		f.respondPrompt(f.gen, id, promptText(data))
	}
	return off, nil
}

func (f *fakeWire) respondPrompt(gen uint64, id, text string) {
	f.mu.Lock()
	hook := f.onPrompt
	auto := f.autoRespond
	f.mu.Unlock()
	if hook != nil {
		hook(gen, text)
	}
	if !auto {
		return
	}
	f.emitACP(gen, map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params": map[string]any{
			"sessionId": "acp-session-1",
			"update": map[string]any{
				"sessionUpdate": "agent_message_chunk",
				"content":       map[string]string{"type": "text", "text": "done: " + text},
			},
		},
	})
	f.emitACP(gen, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"stopReason": "end_turn"}})
}

// start records the guest connection for a generation. Like the node, it resets
// the generation's conditional-append sequence.
func (f *fakeWire) start(gen uint64) {
	f.mu.Lock()
	f.gen = gen
	f.lastSeq = 0
	f.mu.Unlock()
	f.appendRecord(gen, recordStart, nil)
}

func (f *fakeWire) end(gen uint64) {
	f.appendRecord(gen, recordEnd, mustJSON(map[string]any{"code": 0, "reason": "exit"}))
}

func (f *fakeWire) note(note noteRecord) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	off := f.appendLocked(f.gen, recordNote, mustJSON(note))
	f.lastSeq = off
	return off
}

// MarshalJSON encodes a ring record in the same {o,g,t,d} shape UnmarshalJSON
// reads. fake_test.go serializes streamLogRecord values with json.Marshal to
// emulate the log endpoint; without this method the fields are capitalized and
// decode as empty records, so the engine never sees a generation or a note.
// This lives in a test file because only the fake ever marshals a record.
func (r streamLogRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		O uint64 `json:"o"`
		G uint64 `json:"g"`
		T int    `json:"t"`
		D string `json:"d"`
	}{
		O: r.Offset,
		G: r.Gen,
		T: int(r.Type),
		D: base64.StdEncoding.EncodeToString(r.Data),
	})
}
func (f *fakeWire) appendRecord(gen uint64, typ streamRecordType, data []byte) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appendLocked(gen, typ, data)
}

func (f *fakeWire) appendLocked(gen uint64, typ streamRecordType, data []byte) uint64 {
	off := f.offset
	f.records = append(f.records, streamLogRecord{Offset: off, Gen: gen, Type: typ, Data: append([]byte(nil), data...)})
	f.offset = off + streamRecordHeader + uint64(len(data))
	f.cond.Broadcast()
	return off
}

func (f *fakeWire) emitACP(gen uint64, msg any) {
	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	f.appendRecord(gen, recordOut, data)
}

func (f *fakeWire) OpenLog(ctx context.Context, _, _ string, offset uint64) (io.ReadCloser, error) {
	return &fakeLogReader{wire: f, ctx: ctx, after: offset}, nil
}

func (f *fakeWire) ReadLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error) {
	f.mu.Lock()
	var buf bytes.Buffer
	for _, rec := range f.records {
		if rec.Offset < offset {
			continue
		}
		line, _ := json.Marshal(rec)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	f.mu.Unlock()
	return io.NopCloser(&buf), nil
}

func (f *fakeWire) LogEnd(context.Context, string, string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) == 0 {
		return 0, nil
	}
	// Like the real ring, LogEnd returns a cursor just past the newest
	// record, not the record's own start offset.
	return f.offset, nil
}

func (f *fakeWire) closeLog() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
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

func (f *fakeWire) notes() []noteRecord {
	var out []noteRecord
	for _, m := range f.messages() {
		if !m.note {
			continue
		}
		var note noteRecord
		if json.Unmarshal(m.raw, &note) == nil {
			out = append(out, note)
		}
	}
	return out
}

// fakeLogReader replays recorded lines from the requested offset and then
// follows new ones until the context ends.
type fakeLogReader struct {
	wire  *fakeWire
	ctx   context.Context
	after uint64
	idx   int
	buf   []byte
}

func (r *fakeLogReader) Read(p []byte) (int, error) {
	for {
		if len(r.buf) > 0 {
			n := copy(p, r.buf)
			r.buf = r.buf[n:]
			return n, nil
		}
		if r.ctx.Err() != nil {
			return 0, io.EOF
		}
		r.wire.mu.Lock()
		if r.idx >= len(r.wire.records) {
			r.wire.mu.Unlock()
			select {
			case <-r.ctx.Done():
				return 0, io.EOF
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		rec := r.wire.records[r.idx]
		r.idx++
		r.wire.mu.Unlock()
		if rec.Offset < r.after {
			continue
		}
		line, _ := json.Marshal(rec)
		r.buf = append(line, '\n')
	}
}

func (r *fakeLogReader) Close() error { return nil }

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

func promptText(data []byte) string {
	var msg struct {
		Params struct {
			Prompt []struct {
				Text string `json:"text"`
			} `json:"prompt"`
		} `json:"params"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return ""
	}
	var out bytes.Buffer
	for _, part := range msg.Params.Prompt {
		out.WriteString(part.Text)
	}
	return out.String()
}

// newChat creates a chat state with the minimal annotations the handlers need.
func newChat(cluster *fakeCluster, name, profile string) *v1.BlipState {
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              name,
			Labels:            map[string]string{LabelSession: "true", v1.LabelOwner: name},
			Annotations:       map[string]string{AnnotationProfile: profile, AnnotationRoot: name, AnnotationDepth: "0"},
			CreationTimestamp: metav1.Now(),
		},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	cluster.mu.Lock()
	cluster.states[key(st.Namespace, name)] = st
	cluster.mu.Unlock()
	return st
}

// markDeleting persists a deletion timestamp on a stored state, as the API
// server does once a delete request has been accepted.
func (f *fakeCluster) markDeleting(t *testing.T, ns, name string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[key(ns, name)]
	if !ok {
		t.Fatalf("state %s/%s not found", ns, name)
	}
	now := metav1.Now()
	st.DeletionTimestamp = &now
	st.Finalizers = append(st.Finalizers, "blip.dev/test")
}

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

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
