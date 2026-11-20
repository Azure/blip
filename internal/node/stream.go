// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/stream"
	"github.com/Azure/blip/internal/wire"
)

const (
	// streamReadyTimeout bounds how long a writer waits for the guest stdio
	// connection before reporting that the stream is not ready.
	streamReadyTimeout = 5 * time.Second
	// streamPollInterval is how often a follower re-reads the ring.
	streamPollInterval = 100 * time.Millisecond
	// streamReconnectInterval is the backoff between guest connection tries.
	streamReconnectInterval = 200 * time.Millisecond
	// streamReadBatch bounds one ring read.
	streamReadBatch = 256
	// streamWriteTimeout bounds a blocked frame write so sealing a writer can
	// never wait on an unresponsive guest forever.
	streamWriteTimeout = 10 * time.Second
	// streamGap is the record type the log stream uses for trimmed history.
	streamGap = stream.TypeGap
)

// streamError is a sentinel with the downstream HTTP status it maps to.
type streamError struct {
	msg    string
	status int
}

func (e *streamError) Error() string { return e.msg }

// StreamHTTPStatus lets the peer server map this error without importing the
// node package.
func (e *streamError) StreamHTTPStatus() int { return e.status }

var (
	// ErrStreamNotFound reports that the state has no readable trajectory
	// (it does not exist or has never been committed).
	ErrStreamNotFound = &streamError{msg: "stream: state has no trajectory", status: 404}
	// ErrStreamNotRunning reports stdin for a state with no running blip.
	ErrStreamNotRunning = &streamError{msg: "stream: blip is not running", status: 409}
	// ErrStreamClosed reports stdin after the command's stdin was closed.
	ErrStreamClosed = &streamError{msg: "stream: stdin is closed", status: 409}
	// ErrStreamNotReady reports that the guest stdio connection is not open
	// yet. The caller may retry.
	ErrStreamNotReady = &streamError{msg: "stream: guest stdio is not connected", status: 503}
	// ErrStreamPrecondition reports that a conditional stdin write lost its
	// race: the last stdin/note offset is no longer the expected one.
	ErrStreamPrecondition = &streamError{msg: "stream: stdin precondition failed", status: 412}
)

// streamManager owns every running blip's stdio on this node. It keeps the
// trajectory ring open per pod and serves reads and writes from it.
type streamManager struct {
	store  Store
	peer   *peer.Client
	node   string
	podDir func(podKey string) string
	states client.Reader

	// dial and readyTimeout are replaceable in tests.
	dial         func(podKey string) (net.Conn, error)
	readyTimeout time.Duration

	mu    sync.Mutex
	pods  map[string]*streamAttachment // podKey -> attachment
	names map[string]*streamAttachment // namespace/state -> attachment
	ids   map[string]*streamAttachment // attachment ID -> attachment
	// retired remembers attachments a seal closed, so a lagging view cannot
	// reopen a writer the seal now needs exclusive access to.
	retired map[string]string // attachment ID -> podKey

	closed bool
}

func newStreamManager(store Store, pc *peer.Client, node string, podDir func(string) string, states client.Reader) *streamManager {
	m := &streamManager{
		store:        store,
		peer:         pc,
		node:         node,
		podDir:       podDir,
		states:       states,
		readyTimeout: streamReadyTimeout,
		pods:         map[string]*streamAttachment{},
		names:        map[string]*streamAttachment{},
		ids:          map[string]*streamAttachment{},
		retired:      map[string]string{},
	}
	m.dial = func(podKey string) (net.Conn, error) {
		return wire.DialVsock(filepath.Join(podDir(podKey), podapi.VsockSocket), wire.StdioPort, 10*time.Second)
	}
	return m
}

// streamAttachment is one pod's open trajectory ring and guest connection.
type streamAttachment struct {
	m            *streamManager
	key          string // namespace/state
	pod          string // podKey
	attachmentID string
	size         int64

	mu     sync.Mutex
	file   *os.File
	writer *stream.Writer
	conn   *wire.Conn
	net    net.Conn
	// closed reports that the command exited or the writer was closed.
	closed bool
	// eof reports that a caller already sent stdin EOF.
	eof bool
	// lastSeq is the ring offset of the most recently appended stdin or note
	// record, used for conditional writes.
	lastSeq uint64
	// outNext and errNext are the next guest byte offsets to accept, used to
	// resume after a dropped connection and to drop replayed frames.
	outNext, errNext uint64
	lastActivity     time.Time

	ready     chan struct{}
	readyOnce sync.Once
	stop      chan struct{}
	stopOnce  sync.Once
}

// Open acquires the plaintext working volume and starts the writer for a pod
// whose claim the guest accepted. It is idempotent for the same pod and
// attachment.
func (m *streamManager) Open(ctx context.Context, namespace, name, pod, attachmentID string, size int64, gen uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := namespace + "/" + name
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("stream: manager is closed")
	}
	if att := m.pods[pod]; att != nil {
		m.mu.Unlock()
		if att.key == key && att.attachmentID == attachmentID {
			return nil
		}
		return fmt.Errorf("stream: pod %s already has attachment %s", pod, att.attachmentID)
	}
	if att := m.names[key]; att != nil {
		m.mu.Unlock()
		if att.pod == pod && att.attachmentID == attachmentID {
			return nil
		}
		return fmt.Errorf("stream: state %s is already open in pod %s", key, att.pod)
	}
	if _, gone := m.retired[attachmentID]; gone {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	dev, err := m.store.Device(attachmentID)
	if err != nil {
		return fmt.Errorf("stream: open device %s: %w", attachmentID, err)
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("stream: open %s: %w", dev, err)
	}
	w, err := stream.NewWriter(f, stream.Offset, size, gen)
	if err != nil {
		f.Close()
		return fmt.Errorf("stream: writer %s: %w", attachmentID, err)
	}
	att := &streamAttachment{
		m: m, key: key, pod: pod,
		attachmentID: attachmentID, size: size,
		file: f, writer: w, lastActivity: time.Now(),
		ready: make(chan struct{}), stop: make(chan struct{}),
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		att.close()
		return errors.New("stream: manager is closed")
	}
	if _, gone := m.retired[attachmentID]; gone {
		m.mu.Unlock()
		att.close()
		return nil
	}
	if cur := m.pods[pod]; cur != nil {
		m.mu.Unlock()
		att.close()
		if cur.key == key && cur.attachmentID == attachmentID {
			return nil
		}
		return fmt.Errorf("stream: pod %s already has attachment %s", pod, cur.attachmentID)
	}
	if cur := m.names[key]; cur != nil {
		m.mu.Unlock()
		att.close()
		if cur.pod == pod && cur.attachmentID == attachmentID {
			return nil
		}
		return fmt.Errorf("stream: state %s is already open in pod %s", key, cur.pod)
	}
	m.pods[pod] = att
	m.names[key] = att
	m.ids[attachmentID] = att
	m.mu.Unlock()
	go att.run()
	slog.Info("stream writer opened", "pod", pod, "state", key, "attachment", attachmentID, "gen", gen)
	return nil
}

// closeStale closes writers for pods that no longer have an accepted claim.
func (m *streamManager) closeStale(wanted map[string]bool) {
	m.mu.Lock()
	var stale []*streamAttachment
	for pod, att := range m.pods {
		if !wanted[pod] {
			stale = append(stale, att)
		}
	}
	m.mu.Unlock()
	for _, att := range stale {
		if err := m.closeWriter(att.attachmentID); err != nil {
			slog.Error("close stream writer", "attachment", att.attachmentID, "err", err)
		}
	}
}

// pruneRetired forgets seal markers for pods that are gone for good.
func (m *streamManager) pruneRetired(pods map[string]*corev1.Pod) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, pod := range m.retired {
		if _, ok := pods[pod]; !ok {
			delete(m.retired, id)
		}
	}
}

// closeWriter stops the guest connection and closes the ring's device. Sealing
// requires it: an open block device makes storage.Seal fail with ErrInUse.
func (m *streamManager) closeWriter(attachmentID string) error {
	m.mu.Lock()
	att := m.ids[attachmentID]
	if att != nil {
		delete(m.ids, attachmentID)
		if m.pods[att.pod] == att {
			delete(m.pods, att.pod)
		}
		if m.names[att.key] == att {
			delete(m.names, att.key)
		}
		m.retired[attachmentID] = att.pod
	}
	m.mu.Unlock()
	if att == nil {
		return nil
	}
	return att.close()
}

// flushWriter persists the ring before a live snapshot.
func (m *streamManager) flushWriter(attachmentID string) error {
	m.mu.Lock()
	att := m.ids[attachmentID]
	m.mu.Unlock()
	if att == nil {
		return nil
	}
	att.mu.Lock()
	defer att.mu.Unlock()
	if att.file == nil {
		return nil
	}
	return att.file.Sync()
}

// closeAll closes every writer, for agent shutdown.
func (m *streamManager) closeAll() {
	m.mu.Lock()
	m.closed = true
	atts := make([]*streamAttachment, 0, len(m.ids))
	for id, att := range m.ids {
		atts = append(atts, att)
		delete(m.ids, id)
	}
	m.pods = map[string]*streamAttachment{}
	m.names = map[string]*streamAttachment{}
	m.mu.Unlock()
	for _, att := range atts {
		if err := att.close(); err != nil {
			slog.Error("close stream writer", "attachment", att.attachmentID, "err", err)
		}
	}
}

// idle reports whether a running pod has been quiet past timeout.
func (m *streamManager) idle(podKey string, timeout time.Duration) bool {
	m.mu.Lock()
	att := m.pods[podKey]
	m.mu.Unlock()
	if att == nil {
		return false
	}
	select {
	case <-att.ready:
	default:
		// The command has not started yet; its idle clock starts at the
		// TypeStart record.
		return false
	}
	att.mu.Lock()
	defer att.mu.Unlock()
	return !att.closed && time.Since(att.lastActivity) > timeout
}

// Log serves a state's trajectory. A local writer is read directly; a stopped
// state is read through a committed view, local or on a placement peer.
func (m *streamManager) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	key := namespace + "/" + name
	m.mu.Lock()
	att := m.names[key]
	m.mu.Unlock()
	if att != nil {
		return att.read(ctx, from, follow, fn)
	}
	s, err := m.state(ctx, namespace, name)
	if err != nil {
		return err
	}
	if s == nil {
		return ErrStreamNotFound
	}
	if w := s.Status.Writer; w != nil {
		if w.Node != m.node && m.peer != nil {
			return m.peer.StreamLog(ctx, w.Node, namespace, name, from, follow, fn)
		}
		// The writer is local but its attachment has not opened yet (or was
		// just sealed). There is no trajectory to serve from this pass.
		return ErrStreamNotFound
	}
	return m.readStopped(ctx, s, from, follow, fn)
}

// Stdin routes raw bytes to a running state's guest, forwarding to the
// writer's node when it is not this one. A note is persisted in the trajectory
// without reaching the guest. A non-zero after makes the write conditional on
// the last stdin/note offset. It returns the offset the write was appended at.
func (m *streamManager) Stdin(ctx context.Context, namespace, name string, data []byte, eof, note bool, after uint64) (uint64, error) {
	key := namespace + "/" + name
	m.mu.Lock()
	att := m.names[key]
	m.mu.Unlock()
	if att == nil {
		s, err := m.state(ctx, namespace, name)
		if err != nil {
			return 0, err
		}
		if s == nil {
			return 0, ErrStreamNotRunning
		}
		if w := s.Status.Writer; w != nil {
			if w.Node != m.node && m.peer != nil {
				return m.peer.StreamStdin(ctx, w.Node, namespace, name, data, eof, note, after)
			}
			return 0, ErrStreamNotReady
		}
		return 0, ErrStreamNotRunning
	}

	timer := time.NewTimer(m.readyTimeout)
	defer timer.Stop()
	select {
	case <-att.ready:
	case <-att.stop:
		return 0, ErrStreamClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return 0, ErrStreamNotReady
	}

	att.mu.Lock()
	defer att.mu.Unlock()
	if att.closed {
		return 0, ErrStreamClosed
	}
	if att.eof && !note {
		// The guest has its EOF, but notes never reach the guest and the ring
		// is still writable. Recording one is how a new turn begins.
		return 0, ErrStreamClosed
	}
	if after != 0 && after != att.lastSeq {
		return 0, ErrStreamPrecondition
	}
	if !note && (att.conn == nil || att.net == nil) {
		return 0, ErrStreamNotReady
	}
	off := att.lastSeq
	for len(data) > 0 {
		n := min(len(data), stream.MaxRecord)
		chunk := data[:n]
		typ := stream.TypeIn
		if note {
			typ = stream.TypeNote
		}
		pos, err := att.writer.Append(typ, chunk)
		if err != nil {
			return 0, err
		}
		att.lastSeq, off = pos, pos
		if !note {
			if err := att.send(wire.TStdin, chunk); err != nil {
				return 0, err
			}
		}
		att.lastActivity = time.Now()
		data = data[n:]
	}
	if eof {
		if err := att.send(wire.TStdinEOF, nil); err != nil {
			return 0, err
		}
		att.eof = true
		att.lastActivity = time.Now()
	}
	return off, nil
}

func (m *streamManager) state(ctx context.Context, namespace, name string) (*v1alpha1.BlipState, error) {
	if m.states == nil {
		return nil, nil
	}
	var s v1alpha1.BlipState
	err := m.states.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// readStopped streams a committed version through a read-only view.
func (m *streamManager) readStopped(ctx context.Context, s *v1alpha1.BlipState, from uint64, follow bool, fn func(stream.Record) error) error {
	c := s.Status.Committed
	if c == nil {
		return ErrStreamNotFound
	}
	if !slices.Contains(s.Status.Placements, m.node) {
		if m.peer == nil || len(s.Status.Placements) == 0 {
			return ErrStreamNotFound
		}
		placements := slices.Clone(s.Status.Placements)
		slices.Sort(placements)
		return m.peer.StreamLog(ctx, placements[0], s.Namespace, s.Name, from, follow, fn)
	}
	viewID := "stream-" + c.ID
	dev, err := m.store.OpenView(ctx, string(s.UID), c.ID, viewID)
	if err != nil {
		return err
	}
	defer func() {
		if err := m.store.CloseView(viewID); err != nil {
			slog.Error("close stream view", "view", viewID, "err", err)
		}
	}()
	f, err := os.Open(dev)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := stream.NewReader(f, stream.Offset, stateStreamSize(s))
	if err != nil {
		return err
	}
	pos := from
	for {
		recs, head, err := r.Read(pos, streamReadBatch)
		if errors.Is(err, stream.ErrGap) {
			if err := fn(stream.Record{Offset: head, Type: streamGap}); err != nil {
				return err
			}
			pos = head
			continue
		}
		if err != nil {
			return err
		}
		for _, rec := range recs {
			if rec.Offset < pos {
				continue
			}
			if err := fn(rec); err != nil {
				return err
			}
			pos = rec.Offset + uint64(stream.RecordHeader+len(rec.Data))
		}
		if len(recs) == 0 {
			// A stopped state produces no more records. follow still ends the
			// response after the retained history.
			return nil
		}
	}
}

// read streams the live ring. follow polls until the writer closes or the
// context ends.
func (a *streamAttachment) read(ctx context.Context, from uint64, follow bool, fn func(stream.Record) error) error {
	a.mu.Lock()
	f := a.file
	a.mu.Unlock()
	if f == nil {
		return ErrStreamNotFound
	}
	r, err := stream.NewReader(f, stream.Offset, a.size)
	if err != nil {
		return err
	}
	pos := from
	for {
		recs, head, err := r.Read(pos, streamReadBatch)
		if errors.Is(err, stream.ErrGap) {
			if err := fn(stream.Record{Offset: head, Type: streamGap}); err != nil {
				return err
			}
			pos = head
			continue
		}
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		for _, rec := range recs {
			if rec.Offset < pos {
				continue
			}
			if err := fn(rec); err != nil {
				return err
			}
			pos = rec.Offset + uint64(stream.RecordHeader+len(rec.Data))
		}
		if len(recs) > 0 {
			continue
		}
		if !follow {
			return nil
		}
		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			// Drain records appended before the close, then end.
			follow = false
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(streamPollInterval):
		}
	}
}

// run connects to the guest and reads frames until the command ends or the
// writer is closed. It reconnects while the guest is still running.
func (a *streamAttachment) run() {
	connected := false
	for {
		select {
		case <-a.stop:
			return
		default:
		}
		conn, err := a.m.dial(a.pod)
		if err != nil {
			if !a.wait() {
				return
			}
			continue
		}
		c := wire.NewConn(conn)
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			conn.Close()
			return
		}
		a.conn, a.net = c, conn
		if !connected {
			if _, err := a.writer.Append(stream.TypeStart, nil); err != nil {
				a.closed = true
				a.mu.Unlock()
				conn.Close()
				slog.Error("append stream start", "state", a.key, "err", err)
				_ = a.close()
				return
			}
			a.lastActivity = time.Now()
		}
		a.readyOnce.Do(func() { close(a.ready) })
		a.mu.Unlock()
		connected = true
		a.pump(c)
		conn.Close()
		a.mu.Lock()
		if a.conn == c {
			a.conn, a.net = nil, nil
		}
		ended := a.closed
		a.mu.Unlock()
		if ended {
			return
		}
		if !a.wait() {
			return
		}
	}
}

// wait pauses before another connection attempt. It reports false when the
// attachment is closing.
func (a *streamAttachment) wait() bool {
	t := time.NewTimer(streamReconnectInterval)
	defer t.Stop()
	select {
	case <-a.stop:
		return false
	case <-t.C:
		return true
	}
}

// pump reads guest frames and appends them to the ring.
func (a *streamAttachment) pump(c *wire.Conn) {
	for {
		typ, payload, err := c.Read()
		if err != nil {
			return
		}
		switch typ {
		case wire.TStdioHello:
			// The guest replays any buffered output and then TExited; the
			// hello's exit status only tells us the command already ended.
			var hello wire.StdioHello
			if wire.Decode(payload, &hello) != nil {
				return
			}
		case wire.TStdout:
			off, data, err := wire.DecodeData(payload)
			if err != nil {
				return
			}
			a.output(stream.TypeOut, &a.outNext, off, data)
		case wire.TStderr:
			off, data, err := wire.DecodeData(payload)
			if err != nil {
				return
			}
			a.output(stream.TypeErr, &a.errNext, off, data)
		case wire.TExited:
			var exit wire.Exit
			if wire.Decode(payload, &exit) != nil {
				return
			}
			a.end(exit)
			return
		}
	}
}

// output appends one stdout/stderr frame, trimming replay after a reconnect.
func (a *streamAttachment) output(typ stream.RecordType, next *uint64, off uint64, data []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	end := off + uint64(len(data))
	if end <= *next {
		return
	}
	if off < *next {
		data = data[*next-off:]
		off = *next
	} else if off > *next {
		// The guest trimmed output this agent never saw.
		if _, err := a.writer.Append(stream.TypeGap, nil); err != nil {
			slog.Error("append stream gap", "state", a.key, "err", err)
		}
		*next = off
	}
	pos := off
	for len(data) > 0 {
		n := min(len(data), stream.MaxRecord)
		if _, err := a.writer.Append(typ, data[:n]); err != nil {
			slog.Error("append stream record", "state", a.key, "err", err)
			return
		}
		pos += uint64(n)
		*next = pos
		data = data[n:]
	}
	a.lastActivity = time.Now()
}

// end appends the command's exit record and stops accepting frames.
func (a *streamAttachment) end(exit wire.Exit) {
	data, _ := json.Marshal(struct {
		Code   int    `json:"code"`
		Signal string `json:"signal,omitempty"`
		Reason string `json:"reason,omitempty"`
	}{exit.Code, exit.Signal, exit.Reason})
	a.mu.Lock()
	if !a.closed {
		if _, err := a.writer.Append(stream.TypeEnd, data); err != nil {
			slog.Error("append stream end", "state", a.key, "err", err)
		}
		a.lastActivity = time.Now()
		a.closed = true
		if a.net != nil {
			a.net.Close()
		}
	}
	a.mu.Unlock()
}

// send writes one frame to the guest. Callers hold a.mu.
func (a *streamAttachment) send(t wire.Type, payload []byte) error {
	if a.conn == nil || a.net == nil {
		return ErrStreamNotReady
	}
	return a.writeLocked(t, payload)
}

func (a *streamAttachment) writeLocked(t wire.Type, payload []byte) error {
	if a.net != nil {
		_ = a.net.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
		defer a.net.SetWriteDeadline(time.Time{})
	}
	if err := a.conn.Write(t, payload); err != nil {
		return fmt.Errorf("stream: guest write: %w", err)
	}
	return nil
}

// close stops the reader and closes the device. The writer persists its header
// before the file closes.
func (a *streamAttachment) close() error {
	a.stopOnce.Do(func() { close(a.stop) })
	a.mu.Lock()
	a.closed = true
	netConn := a.net
	a.conn, a.net = nil, nil
	w, f := a.writer, a.file
	a.writer, a.file = nil, nil
	a.mu.Unlock()
	var errs []error
	if netConn != nil {
		errs = append(errs, netConn.Close())
	}
	if w != nil {
		errs = append(errs, w.Close())
	}
	if f != nil {
		errs = append(errs, f.Sync(), f.Close())
	}
	return errors.Join(errs...)
}

// stateStreamSize returns the ring size for a state, clamped to the bounds the
// ring supports and aligned to a ring slot.
func stateStreamSize(s *v1alpha1.BlipState) int64 {
	size := v1alpha1.DefaultStreamSize
	if s != nil && s.Status.StreamSize > 0 {
		size = s.Status.StreamSize
	}
	const align = int64(stream.SlotSize)
	if rem := size % align; rem != 0 {
		size += align - rem
	}
	if size < stream.MinSize {
		size = stream.MinSize
	}
	if size > stream.MaxSize {
		size = stream.MaxSize
	}
	return size
}

// StreamLog serves the trajectory of a BlipState by name.
func (a *Agent) StreamLog(ctx context.Context, namespace, state string, from uint64, follow bool, fn func(stream.Record) error) error {
	if a.streams == nil {
		return ErrStreamNotFound
	}
	return a.streams.Log(ctx, namespace, state, from, follow, fn)
}

// StreamStdin writes to a BlipState's guest by name. A note stays in the
// trajectory, and after makes the write conditional on the last stdin/note
// offset. It returns the offset the write was appended at.
func (a *Agent) StreamStdin(ctx context.Context, namespace, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	if a.streams == nil {
		return 0, ErrStreamNotRunning
	}
	return a.streams.Stdin(ctx, namespace, state, data, eof, note, after)
}

// reconcileStreams opens writers for pods whose claims the guest accepted and
// closes writers whose claims are gone.
func (a *Agent) reconcileStreams(ctx context.Context, v *view) {
	if a.streams == nil {
		return
	}
	wanted := map[string]bool{}
	for _, key := range sortedKeys(v.pods) {
		pod := v.pods[key]
		d := v.dirs[key]
		if d == nil || d.observed == nil || d.desired == nil || d.desired.Claim == nil {
			continue
		}
		claim := d.desired.Claim
		if d.observed.ClaimID == "" || d.observed.ClaimID != claim.Root.ID {
			continue
		}
		if podDone(pod, d) || v.fenced(key, string(pod.UID), claim.Root.ID) {
			continue
		}
		b := v.blipByUID[claim.BlipUID]
		if b == nil {
			continue
		}
		s := v.stateByName[b.Namespace+"/"+b.Spec.State]
		if s == nil {
			continue
		}
		gen := uint64(1)
		if c := s.Status.Committed; c != nil {
			gen = uint64(c.Generation) + 1
		}
		if err := a.streams.Open(ctx, s.Namespace, s.Name, key, claim.Root.ID, stateStreamSize(s), gen); err != nil {
			slog.Error("open stream writer", "pod", key, "state", s.Name, "err", err)
			continue
		}
		wanted[key] = true
	}
	a.streams.closeStale(wanted)
	a.streams.pruneRetired(v.pods)
}

// applyIdle sets Stop for a running blip whose command has been idle past its
// configured timeout. The planner stays pure; this uses the stream manager's
// activity state.
func (a *Agent) applyIdle(v *view, p *plan) {
	if a.streams == nil {
		return
	}
	for _, key := range sortedKeys(v.pods) {
		pod := v.pods[key]
		d := v.dirs[key]
		if d == nil || d.observed == nil || d.desired == nil || d.desired.Claim == nil {
			continue
		}
		claim := d.desired.Claim
		if d.observed.ClaimID == "" || d.observed.ClaimID != claim.Root.ID || podDone(pod, d) {
			continue
		}
		b := v.blipByUID[claim.BlipUID]
		if b == nil || b.Spec.IdleTimeoutSeconds == nil {
			continue
		}
		timeout := time.Duration(*b.Spec.IdleTimeoutSeconds) * time.Second
		if timeout <= 0 || !a.streams.idle(key, timeout) {
			continue
		}
		cur, ok := p.desired[key]
		if !ok {
			cur = *d.desired
		}
		if cur.Claim == nil || cur.Stop {
			continue
		}
		cur.Stop = true
		cur.StopReason = wire.ReasonIdle
		p.desired[key] = cur
		slog.Info("stopping idle blip", "pod", key, "blip", b.Name, "timeout", timeout)
	}
}
