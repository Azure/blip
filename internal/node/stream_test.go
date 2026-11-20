// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
	"github.com/Azure/blip/internal/stream"
	"github.com/Azure/blip/internal/wire"
)

// ringStore maps volume IDs and view IDs to real files so the manager can open
// rings in a test.
type ringStore struct {
	*fakeStore
	files  map[string]string
	views  map[string]string
	closed []string
}

func newRingStore() *ringStore {
	return &ringStore{fakeStore: newFakeStore(), files: map[string]string{}, views: map[string]string{}}
}

func (r *ringStore) Device(id string) (string, error) {
	if p, ok := r.files[id]; ok {
		return p, nil
	}
	return "", storage.ErrNotFound
}

func (r *ringStore) OpenView(ctx context.Context, stateUID, commitID, viewID string) (string, error) {
	if p, ok := r.views[viewID]; ok {
		return p, nil
	}
	return "", storage.ErrNotFound
}

func (r *ringStore) CloseView(viewID string) error {
	r.closed = append(r.closed, viewID)
	return nil
}

func ringFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ring")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func collect(t *testing.T, m *streamManager, want int) []stream.Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last []stream.Record
	for time.Now().Before(deadline) {
		last = nil
		err := m.Log(context.Background(), "default", "root", 0, false, func(rec stream.Record) error {
			last = append(last, rec)
			return nil
		})
		if err == nil && len(last) >= want {
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("records = %+v", last)
	return nil
}

func TestStreamWriterAppendsGuestFrames(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 2)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	m.readyTimeout = 50 * time.Millisecond
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 2); err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	conns <- host
	g := wire.NewConn(guest)

	if err := g.Write(wire.TStdout, wire.EncodeData(0, []byte("hello"))); err != nil {
		t.Fatal(err)
	}
	recs := collect(t, m, 2)
	if recs[0].Type != stream.TypeStart || recs[0].Gen != 2 {
		t.Fatalf("start = %+v", recs[0])
	}
	if recs[1].Type != stream.TypeOut || string(recs[1].Data) != "hello" {
		t.Fatalf("out = %+v", recs[1])
	}

	if err := g.Write(wire.TStderr, wire.EncodeData(0, []byte("oops"))); err != nil {
		t.Fatal(err)
	}
	exit, _ := json.Marshal(wire.Exit{Code: 3, Reason: wire.ReasonCompleted})
	if err := g.Write(wire.TExited, exit); err != nil {
		t.Fatal(err)
	}
	recs = collect(t, m, 4)
	if recs[2].Type != stream.TypeErr || string(recs[2].Data) != "oops" {
		t.Fatalf("err = %+v", recs[2])
	}
	if recs[3].Type != stream.TypeEnd {
		t.Fatalf("end = %+v", recs[3])
	}
	var end struct {
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(recs[3].Data, &end); err != nil || end.Code != 3 || end.Reason != wire.ReasonCompleted {
		t.Fatalf("end data = %s (%v)", recs[3].Data, err)
	}
	if _, err := m.Stdin(ctx, "default", "root", []byte("x"), false, false, 0); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("stdin after exit = %v", err)
	}
	if err := m.closeWriter("a1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Log(ctx, "default", "root", 0, false, func(stream.Record) error { return nil }); !errors.Is(err, ErrStreamNotFound) {
		t.Fatalf("log after close = %v", err)
	}
}

func TestStreamWriterResumesAfterDrop(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 2)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	conns <- host
	g := wire.NewConn(guest)
	if err := g.Write(wire.TStdout, wire.EncodeData(0, []byte("abc"))); err != nil {
		t.Fatal(err)
	}
	collect(t, m, 2)
	guest.Close()

	// The guest replays its retained buffer from the beginning on a new
	// connection; the agent drops records it already stored.
	host2, guest2 := net.Pipe()
	conns <- host2
	g2 := wire.NewConn(guest2)
	if err := g2.Write(wire.TStdout, wire.EncodeData(0, []byte("abc"))); err != nil {
		t.Fatal(err)
	}
	if err := g2.Write(wire.TStdout, wire.EncodeData(3, []byte("def"))); err != nil {
		t.Fatal(err)
	}
	recs := collect(t, m, 3)
	if len(recs) != 3 || string(recs[1].Data) != "abc" || string(recs[2].Data) != "def" {
		t.Fatalf("records = %+v", recs)
	}
}

func TestStreamStdinWaitsAndForwards(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return nil, errors.New("no guest") }
	m.readyTimeout = 20 * time.Millisecond
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stdin(ctx, "default", "root", []byte("x"), false, false, 0); !errors.Is(err, ErrStreamNotReady) {
		t.Fatalf("stdin before connect = %v", err)
	}
	if _, err := m.Stdin(ctx, "default", "other", []byte("x"), false, false, 0); !errors.Is(err, ErrStreamNotRunning) {
		t.Fatalf("stdin unknown state = %v", err)
	}
}

func TestStreamStdinAndEOF(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 1)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	conns <- host
	g := wire.NewConn(guest)

	done := make(chan error, 1)
	go func() {
		_, err := m.Stdin(ctx, "default", "root", []byte("ls\n"), false, false, 0)
		done <- err
	}()
	typ, payload, err := g.Read()
	if err != nil {
		t.Fatal(err)
	}
	if typ != wire.TStdin || string(payload) != "ls\n" {
		t.Fatalf("stdin frame = %d %q", typ, payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	recs := collect(t, m, 2)
	if recs[1].Type != stream.TypeIn || string(recs[1].Data) != "ls\n" {
		t.Fatalf("in = %+v", recs[1])
	}

	go func() {
		_, err := m.Stdin(ctx, "default", "root", nil, true, false, 0)
		done <- err
	}()
	typ, _, err = g.Read()
	if err != nil {
		t.Fatal(err)
	}
	if typ != wire.TStdinEOF {
		t.Fatalf("eof frame = %d", typ)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stdin(ctx, "default", "root", []byte("more"), false, false, 0); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("stdin after eof = %v", err)
	}
	// Notes never reach the guest, so they are still recorded after EOF.
	off, err := m.Stdin(ctx, "default", "root", []byte("note"), false, true, 0)
	if err != nil {
		t.Fatalf("note after eof = %v", err)
	}
	if off == 0 {
		t.Fatal("note after eof returned no offset")
	}
}

type stdinResult struct {
	off uint64
	err error
}

// goStdin runs a manager Stdin call that may block writing to the guest, so the
// test can read the frame on the other side of the pipe.
func goStdin(ctx context.Context, m *streamManager, data []byte, eof, note bool, after uint64) <-chan stdinResult {
	ch := make(chan stdinResult, 1)
	go func() {
		off, err := m.Stdin(ctx, "default", "root", data, eof, note, after)
		ch <- stdinResult{off: off, err: err}
	}()
	return ch
}

func TestStreamNoteStaysOutOfGuest(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 1)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	conns <- host
	g := wire.NewConn(guest)
	select {
	case <-m.pods[pkey("p")].ready:
	case <-time.After(time.Second):
		t.Fatal("writer did not become ready")
	}

	off, err := m.Stdin(ctx, "default", "root", []byte("note text"), false, true, 0)
	if err != nil || off == 0 {
		t.Fatalf("note = %d, %v", off, err)
	}
	// The guest must never see a note.
	_ = guest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := g.Read(); err == nil {
		t.Fatal("guest received a note frame")
	}
	_ = guest.SetReadDeadline(time.Time{})

	recs := collect(t, m, 2)
	if recs[1].Type != stream.TypeNote || string(recs[1].Data) != "note text" {
		t.Fatalf("note record = %+v", recs[1])
	}

	// A note advances the conditional-write cursor like stdin does.
	if _, err := m.Stdin(ctx, "default", "root", []byte("stale"), false, true, off+1); !errors.Is(err, ErrStreamPrecondition) {
		t.Fatalf("stale note after = %v", err)
	}
	next, err := m.Stdin(ctx, "default", "root", []byte("second"), false, true, off)
	if err != nil || next <= off {
		t.Fatalf("conditional note = %d, %v", next, err)
	}
	if got := collect(t, m, 3); got[2].Type != stream.TypeNote || string(got[2].Data) != "second" {
		t.Fatalf("second note = %+v", got[2])
	}
}

func TestStreamStdinPrecondition(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 1)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	t.Cleanup(m.closeAll)
	ctx := context.Background()
	if err := m.Open(ctx, "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	conns <- host
	g := wire.NewConn(guest)

	ch := goStdin(ctx, m, []byte("one"), false, false, 0)
	if typ, payload, err := g.Read(); err != nil || typ != wire.TStdin || string(payload) != "one" {
		t.Fatalf("stdin frame = %d %q (%v)", typ, payload, err)
	}
	first := <-ch
	if first.err != nil || first.off == 0 {
		t.Fatalf("first write = %d, %v", first.off, first.err)
	}

	if _, err := m.Stdin(ctx, "default", "root", []byte("x"), false, false, first.off+1); !errors.Is(err, ErrStreamPrecondition) {
		t.Fatalf("stale after = %v", err)
	}
	// The rejected write reached neither the ring nor the guest.
	_ = guest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := g.Read(); err == nil {
		t.Fatal("guest received a rejected write")
	}
	_ = guest.SetReadDeadline(time.Time{})
	if recs := collect(t, m, 2); len(recs) != 2 {
		t.Fatalf("records after rejected write = %+v", recs)
	}

	ch = goStdin(ctx, m, []byte("two"), false, false, first.off)
	if typ, payload, err := g.Read(); err != nil || typ != wire.TStdin || string(payload) != "two" {
		t.Fatalf("stdin frame = %d %q (%v)", typ, payload, err)
	}
	second := <-ch
	if second.err != nil || second.off <= first.off {
		t.Fatalf("second write = %d, %v", second.off, second.err)
	}
}

func TestStreamReadStoppedUsesView(t *testing.T) {
	f, err := os.OpenFile(ringFile(t), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := stream.NewWriter(f, stream.Offset, stream.MinSize, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(stream.TypeOut, []byte("saved")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rs := newRingStore()
	rs.views["stream-c1"] = f.Name()
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	s := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "root", UID: types.UID("uid-root")},
		Spec:       v1alpha1.BlipStateSpec{StreamSize: nil},
		Status: v1alpha1.BlipStateStatus{
			StreamSize: v1alpha1.DefaultStreamSize,
			Committed:  &v1alpha1.Commit{ID: "c1", Generation: 2},
			Placements: []string{self},
		},
	}
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	m.states = fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

	var got []stream.Record
	if err := m.Log(context.Background(), "default", "root", 0, false, func(rec stream.Record) error {
		got = append(got, rec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Data) != "saved" {
		t.Fatalf("records = %+v", got)
	}
	if len(rs.closed) != 1 || rs.closed[0] != "stream-c1" {
		t.Fatalf("closed views = %v", rs.closed)
	}

	// A state without a committed version has nothing to read.
	none := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nostream", UID: types.UID("uid-none")},
		Status:     v1alpha1.BlipStateStatus{Placements: []string{self}},
	}
	m.states = fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, none).Build()
	if err := m.Log(context.Background(), "default", "nostream", 0, false, func(stream.Record) error { return nil }); !errors.Is(err, ErrStreamNotFound) {
		t.Fatalf("log without commit = %v", err)
	}
}

func TestStreamReadTrimmedHistoryEmitsGap(t *testing.T) {
	f, err := os.OpenFile(ringFile(t), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := stream.NewWriter(f, stream.Offset, stream.MinSize, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Overflow the ring so the oldest records are trimmed.
	for range 5 {
		if _, err := w.Append(stream.TypeOut, bytes.Repeat([]byte("x"), stream.MaxRecord)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rs := newRingStore()
	rs.views["stream-c1"] = f.Name()
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	s := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "root", UID: types.UID("uid-root")},
		Status: v1alpha1.BlipStateStatus{
			StreamSize: stream.MinSize,
			Committed:  &v1alpha1.Commit{ID: "c1", Generation: 2},
			Placements: []string{self},
		},
	}
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	m.states = fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

	var got []stream.Record
	if err := m.Log(context.Background(), "default", "root", 0, false, func(rec stream.Record) error {
		got = append(got, rec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Type != stream.TypeGap || got[0].Offset == 0 {
		t.Fatalf("first record = %+v, want a gap at a trimmed offset", got)
	}
}

func TestStreamIdleIgnoresUnstartedWriters(t *testing.T) {
	rs := newRingStore()
	rs.files["a1"] = ringFile(t)
	conns := make(chan net.Conn, 1)
	m := newStreamManager(rs, nil, self, func(string) string { return t.TempDir() }, nil)
	m.dial = func(string) (net.Conn, error) { return <-conns, nil }
	t.Cleanup(m.closeAll)
	if err := m.Open(context.Background(), "default", "root", pkey("p"), "a1", stream.MinSize, 1); err != nil {
		t.Fatal(err)
	}
	if m.idle(pkey("p"), 0) {
		t.Fatal("idle before the guest connects")
	}
	host, guest := net.Pipe()
	conns <- host
	_ = wire.NewConn(guest)
	select {
	case <-m.pods[pkey("p")].ready:
	case <-time.After(time.Second):
		t.Fatal("writer did not become ready")
	}
	att := m.pods[pkey("p")]
	att.mu.Lock()
	att.lastActivity = time.Now().Add(-time.Minute)
	att.mu.Unlock()
	if !m.idle(pkey("p"), time.Second) {
		t.Fatal("idle after the timeout")
	}
}

func TestApplyIdleSetsStopReason(t *testing.T) {
	v := newView()
	b, d := durableBlip(v)
	readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)
	d.observed = &podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: "r1"}
	timeout := int64(30)
	b.Spec.IdleTimeoutSeconds = &timeout
	d.desired = &podapi.Desired{Claim: &podapi.Claim{
		BlipName: b.Name,
		BlipUID:  string(b.UID),
		Root:     podapi.Disk{ID: "r1"},
	}}
	m := newStreamManager(newRingStore(), nil, self, func(string) string { return t.TempDir() }, nil)
	att := &streamAttachment{pod: pkey("p"), ready: make(chan struct{}), stop: make(chan struct{}),
		lastActivity: time.Now().Add(-time.Minute)}
	close(att.ready)
	m.pods[pkey("p")] = att
	a := &Agent{streams: m}
	p := &plan{desired: map[string]podapi.Desired{}}
	v.index()
	a.applyIdle(v, p)
	got, ok := p.desired[pkey("p")]
	if !ok || !got.Stop || got.StopReason != wire.ReasonIdle {
		t.Fatalf("desired = %+v", got)
	}
}

func TestStateStreamSize(t *testing.T) {
	cases := []struct {
		name string
		s    *v1alpha1.BlipState
		want int64
	}{
		{"default", &v1alpha1.BlipState{}, v1alpha1.DefaultStreamSize},
		{"zero", &v1alpha1.BlipState{Status: v1alpha1.BlipStateStatus{StreamSize: 0}}, v1alpha1.DefaultStreamSize},
		{"clamp low", &v1alpha1.BlipState{Status: v1alpha1.BlipStateStatus{StreamSize: 4096}}, stream.MinSize},
		{"clamp high", &v1alpha1.BlipState{Status: v1alpha1.BlipStateStatus{StreamSize: 2 << 30}}, stream.MaxSize},
		{"align", &v1alpha1.BlipState{Status: v1alpha1.BlipStateStatus{StreamSize: stream.MinSize + 1}}, stream.MinSize + 4096},
	}
	for _, tc := range cases {
		if got := stateStreamSize(tc.s); got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}
}
