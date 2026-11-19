// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Labels and annotations blipchat puts on the states and blips it owns. A
// state's conversation is its trajectory ring; these annotations only record
// presentation and client state.
const (
	LabelSession         = "chat.blip.dev/session"
	AnnotationTitle      = "chat.blip.dev/title"
	AnnotationProfile    = "chat.blip.dev/profile"
	AnnotationACPSession = "chat.blip.dev/acp-session"
	AnnotationOffset     = "chat.blip.dev/offset"
	AnnotationGeneration = "chat.blip.dev/generation"
)

const (
	maxTranscriptMessages = 600
	maxTranscriptBytes    = 2 << 20
	startTimeout          = 120 * time.Second
	statusPoll            = 250 * time.Millisecond
)

type opKind int

const (
	opEnsure opKind = iota
	opPrompt
	opCancel
	opStop
)

type operation struct {
	kind opKind
	text string
}

type driverOptions struct {
	Cluster     Cluster
	Wire        Wire
	Hub         *Hub
	Log         *slog.Logger
	Namespace   string
	State       string
	Profile     Profile
	AutoApprove string
	SessionID   string
	Offset      uint64
	HaveOffset  bool
}

// driver is the goroutine for one active chat state. It reads the state's
// trajectory log from a persisted offset, speaks ACP to the agent, and fans
// updates out through its hub.
type driver struct {
	cluster   Cluster
	wire      Wire
	hub       *Hub
	log       *slog.Logger
	namespace string
	state     string
	profile   Profile

	ctx    context.Context
	cancel context.CancelFunc
	ops    chan operation

	advanceMu   sync.Mutex
	mu          sync.Mutex
	queue       []string
	inflight    bool
	initialized bool
	ended       bool
	agent       *acpAgent
	offset      uint64
	haveOffset  bool
	persisted   uint64
	havePersist bool
	generation  uint64
	transcript  []json.RawMessage
	txBytes     int
	lastStatus  Status
	haveStatus  bool
}

func newDriver(opts driverOptions) *driver {
	ctx, cancel := context.WithCancel(context.Background())
	d := &driver{
		cluster:    opts.Cluster,
		wire:       opts.Wire,
		hub:        opts.Hub,
		log:        opts.Log.With("namespace", opts.Namespace, "session", opts.State),
		namespace:  opts.Namespace,
		state:      opts.State,
		profile:    opts.Profile,
		ctx:        ctx,
		cancel:     cancel,
		ops:        make(chan operation, 32),
		offset:     opts.Offset,
		haveOffset: opts.HaveOffset,
	}
	d.agent = newACPAgent(d.sendACP, d.acpMessage, d.promptDone, d.patchACPSession, opts.AutoApprove)
	d.agent.SetSessionID(opts.SessionID)
	return d
}

func (d *driver) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	d.ctx = ctx
	d.cancel = cancel
	go d.run()
}

func (d *driver) Close() {
	d.cancel()
}

func (d *driver) enqueue(op operation) bool {
	select {
	case d.ops <- op:
		return true
	case <-d.ctx.Done():
		return false
	default:
		return false
	}
}

func (d *driver) Submit(text string) bool { return d.enqueue(operation{kind: opPrompt, text: text}) }
func (d *driver) Cancel() bool            { return d.enqueue(operation{kind: opCancel}) }
func (d *driver) Stop() bool              { return d.enqueue(operation{kind: opStop}) }
func (d *driver) Ensure() bool            { return d.enqueue(operation{kind: opEnsure}) }

func (d *driver) Snapshot() ([]json.RawMessage, uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]json.RawMessage, len(d.transcript))
	copy(out, d.transcript)
	return out, d.hub.Seq()
}

func (d *driver) run() {
	defer d.persistOffset()
	go d.readLog()
	d.refreshStatus()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case op := <-d.ops:
			d.handleOp(op)
		case <-ticker.C:
			d.persistOffset()
		}
	}
}

func (d *driver) handleOp(op operation) {
	switch op.kind {
	case opEnsure:
		if _, err := d.ensureRunning(d.ctx, false); err != nil {
			d.setStatus("Error", false, err.Error())
			return
		}
		d.setStatus("Running", true, "agent ready")
	case opPrompt:
		d.mu.Lock()
		d.queue = append(d.queue, op.text)
		d.mu.Unlock()
		d.advance()
	case opCancel:
		if err := d.agent.Cancel(d.ctx); err != nil {
			d.setStatus("Error", false, "cancel: "+err.Error())
		} else {
			d.setStatus("Cancelling", true, "cancel requested")
		}
	case opStop:
		if err := d.stopBlip(d.ctx); err != nil {
			d.setStatus("Error", false, "stop: "+err.Error())
		}
	}
}

func (d *driver) refreshStatus() {
	blips, err := d.cluster.ListStateBlips(d.ctx, d.namespace, d.state)
	if err != nil {
		return
	}
	b := latestBlip(blips)
	if b == nil {
		d.setStatus("Stopped", false, "no agent")
		return
	}
	d.setStatus(b.Status.Phase, b.Status.Phase == v1.BlipRunning, "")
}

func latestBlip(blips []v1.Blip) *v1.Blip {
	var latest *v1.Blip
	var max int64 = -1
	for i := range blips {
		g := generationOf(&blips[i])
		if g > max {
			max = g
			latest = &blips[i]
		}
	}
	return latest
}

func runningBlip(blips []v1.Blip) *v1.Blip {
	var best *v1.Blip
	var max int64 = -1
	for i := range blips {
		if blips[i].Status.Phase != v1.BlipRunning {
			continue
		}
		if g := generationOf(&blips[i]); g > max {
			max = g
			best = &blips[i]
		}
	}
	return best
}

func generationOf(b *v1.Blip) int64 {
	if b.Annotations[AnnotationGeneration] != "" {
		if n, err := strconv.ParseInt(b.Annotations[AnnotationGeneration], 10, 64); err == nil {
			return n
		}
	}
	for i := len(b.Name) - 1; i >= 1; i-- {
		if b.Name[i-1] == '-' && b.Name[i] == 'g' {
			if n, err := strconv.ParseInt(b.Name[i+1:], 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func (d *driver) ensureRunning(ctx context.Context, forceNew bool) (*v1.Blip, error) {
	blips, err := d.cluster.ListStateBlips(ctx, d.namespace, d.state)
	if err != nil {
		return nil, err
	}
	if !forceNew {
		if b := runningBlip(blips); b != nil {
			d.noteGeneration(b)
			return b, nil
		}
		if b := latestBlip(blips); b != nil && b.Status.Phase == v1.BlipPending {
			running, err := d.waitRunning(ctx, b.Name)
			if err != nil {
				return nil, err
			}
			d.noteGeneration(running)
			return running, nil
		}
	}
	var maxGen int64
	for i := range blips {
		if g := generationOf(&blips[i]); g > maxGen {
			maxGen = g
		}
	}
	idle := d.profile.IdleTimeoutSeconds
	for attempt := 0; attempt < 3; attempt++ {
		gen := maxGen + 1
		name := fmt.Sprintf("%s-g%d", d.state, gen)
		b := &v1.Blip{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: d.namespace,
				Labels:    map[string]string{LabelSession: d.state},
				Annotations: map[string]string{
					AnnotationGeneration: strconv.FormatInt(gen, 10),
				},
			},
			Spec: v1.BlipSpec{
				Pool:               d.profile.Pool,
				State:              d.state,
				Command:            append([]string(nil), d.profile.Command...),
				Env:                d.profile.envVars(),
				IdleTimeoutSeconds: &idle,
			},
		}
		d.setStatus("Starting", false, "starting "+name)
		if err := d.cluster.CreateBlip(ctx, d.namespace, b); err != nil {
			if apierrors.IsAlreadyExists(err) {
				blips, err = d.cluster.ListStateBlips(ctx, d.namespace, d.state)
				if err != nil {
					return nil, err
				}
				maxGen = 0
				for i := range blips {
					if g := generationOf(&blips[i]); g > maxGen {
						maxGen = g
					}
				}
				continue
			}
			return nil, err
		}
		running, err := d.waitRunning(ctx, name)
		if err != nil {
			return nil, err
		}
		d.noteGeneration(running)
		d.setStatus("Running", true, "agent running")
		return running, nil
	}
	return nil, fmt.Errorf("could not allocate a blip generation")
}

func (d *driver) noteGeneration(b *v1.Blip) {
	if g := generationOf(b); g > 0 {
		d.mu.Lock()
		d.generation = uint64(g)
		d.mu.Unlock()
	}
}

func (d *driver) waitRunning(ctx context.Context, name string) (*v1.Blip, error) {
	deadline := time.Now().Add(startTimeout)
	for {
		b, err := d.cluster.GetBlip(ctx, d.namespace, name)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
		if b != nil {
			switch b.Status.Phase {
			case v1.BlipRunning:
				return b, nil
			case v1.BlipSucceeded, v1.BlipFailed:
				reason := b.Status.Message
				if reason == "" {
					reason = b.Status.Reason
				}
				return nil, fmt.Errorf("%s %s: %s", name, b.Status.Phase, reason)
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", name)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(statusPoll):
		}
	}
}

func (d *driver) stopBlip(ctx context.Context) error {
	blips, err := d.cluster.ListStateBlips(ctx, d.namespace, d.state)
	if err != nil {
		return err
	}
	var target *v1.Blip
	for i := range blips {
		switch blips[i].Status.Phase {
		case v1.BlipRunning, v1.BlipPending:
			if target == nil || generationOf(&blips[i]) > generationOf(target) {
				target = &blips[i]
			}
		}
	}
	if target == nil {
		d.setStatus("Stopped", false, "no running agent")
		return nil
	}
	if err := d.cluster.StopBlip(ctx, d.namespace, target.Name); err != nil {
		return err
	}
	d.setStatus("Stopping", true, "stop requested")
	return nil
}

func (d *driver) advance() {
	d.advanceMu.Lock()
	defer d.advanceMu.Unlock()
	d.mu.Lock()
	if d.inflight || len(d.queue) == 0 {
		d.mu.Unlock()
		return
	}
	text := d.queue[0]
	d.queue = d.queue[1:]
	d.mu.Unlock()

	if err := d.sendPrompt(d.ctx, text); err != nil {
		d.mu.Lock()
		d.inflight = false
		d.mu.Unlock()
		d.log.Warn("prompt failed", "err", err)
		d.setStatus("Error", false, err.Error())
		return
	}
	// The response may already have arrived and cleared the turn. Trust the
	// agent's pending set rather than blindly marking the turn in flight.
	d.mu.Lock()
	d.inflight = d.agent.Pending() > 0
	d.mu.Unlock()
}

func (d *driver) sendPrompt(ctx context.Context, text string) error {
	for attempt := 0; attempt < 3; attempt++ {
		d.mu.Lock()
		initialized := d.initialized
		d.mu.Unlock()
		if !initialized {
			if err := d.startAgent(ctx); err != nil {
				if errors.Is(err, ErrNotRunning) {
					d.markEnded()
					continue
				}
				return err
			}
		}
		if err := d.agent.Prompt(ctx, text); err != nil {
			if errors.Is(err, ErrNotRunning) {
				d.markEnded()
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("agent exited before accepting the prompt")
}

func (d *driver) startAgent(ctx context.Context) error {
	d.mu.Lock()
	force := d.ended
	d.mu.Unlock()
	_, err := d.ensureRunning(ctx, force)
	if err != nil {
		return err
	}
	d.agent.Reset()
	sessionID, err := d.agent.Start(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.initialized = true
	d.ended = false
	d.inflight = false
	d.mu.Unlock()
	d.patchACPSession(sessionID)
	d.setStatus("Running", true, "session "+shortID(sessionID))
	return nil
}

func (d *driver) markEnded() {
	d.mu.Lock()
	d.initialized = false
	d.ended = true
	d.inflight = false
	d.mu.Unlock()
	d.agent.Reset()
}

func (d *driver) promptDone() {
	d.mu.Lock()
	d.inflight = false
	empty := len(d.queue) == 0
	initialized := d.initialized
	d.mu.Unlock()
	if !empty {
		d.advance()
		return
	}
	if initialized && d.agent.Pending() == 0 {
		d.endTurn()
	}
}

// endTurn closes the agent's stdin. ACP agents exit on EOF, which lets the
// blip stop and save its state (including the trajectory ring).
func (d *driver) endTurn() {
	d.advanceMu.Lock()
	defer d.advanceMu.Unlock()
	d.mu.Lock()
	if d.inflight || len(d.queue) > 0 || !d.initialized {
		d.mu.Unlock()
		return
	}
	d.initialized = false
	d.ended = true
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.wire.Send(ctx, d.namespace, d.state, nil, true); err != nil && !errors.Is(err, ErrNotRunning) {
		d.log.Warn("stdin eof", "err", err)
	}
	d.persistOffset()
	d.setStatus("Idle", false, "turn complete")
}

func (d *driver) sendACP(ctx context.Context, data []byte, eof bool) error {
	var err error
	for attempt := 0; attempt < 15; attempt++ {
		err = d.wire.Send(ctx, d.namespace, d.state, data, eof)
		if err == nil || !errors.Is(err, ErrUnavailable) {
			return err
		}
		sleepCtx(ctx, time.Duration(min(attempt+1, 5))*200*time.Millisecond)
	}
	return err
}

func (d *driver) acpMessage(raw json.RawMessage) {
	d.mu.Lock()
	d.transcript = append(d.transcript, raw)
	d.txBytes += len(raw)
	for len(d.transcript) > maxTranscriptMessages || (d.txBytes > maxTranscriptBytes && len(d.transcript) > 1) {
		d.txBytes -= len(d.transcript[0])
		d.transcript = d.transcript[1:]
	}
	d.mu.Unlock()
	d.hub.Publish(Event{Type: "acp", Message: raw})
}

func (d *driver) emitOutput(stream string, data []byte) {
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "blip/output",
		"params":  map[string]string{"stream": stream, "text": string(data)},
	})
	if err != nil {
		return
	}
	d.acpMessage(raw)
}

func (d *driver) setStatus(phase string, running bool, detail string) {
	st := Status{Phase: phase, Running: running, Detail: detail}
	d.mu.Lock()
	if d.haveStatus && d.lastStatus == st {
		d.mu.Unlock()
		return
	}
	d.lastStatus = st
	d.haveStatus = true
	d.mu.Unlock()
	d.hub.Publish(Event{Type: "status", Status: &st})
}

func (d *driver) patchACPSession(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.cluster.PatchSession(ctx, d.namespace, d.state, nil, map[string]string{AnnotationACPSession: id}); err != nil {
		d.log.Warn("save acp session", "err", err)
	}
}

func (d *driver) persistOffset() {
	d.mu.Lock()
	if !d.haveOffset || (d.havePersist && d.persisted == d.offset) {
		d.mu.Unlock()
		return
	}
	off := d.offset
	d.persisted = off
	d.havePersist = true
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.cluster.PatchSession(ctx, d.namespace, d.state, nil, map[string]string{AnnotationOffset: strconv.FormatUint(off, 10)}); err != nil {
		d.mu.Lock()
		if d.persisted == off {
			d.havePersist = false
		}
		d.mu.Unlock()
		d.log.Debug("save log offset", "err", err)
	}
}

func (d *driver) readLog() {
	for d.ctx.Err() == nil {
		d.mu.Lock()
		offset := d.offset
		d.mu.Unlock()
		rc, err := d.wire.OpenLog(d.ctx, d.namespace, d.state, offset)
		if err != nil {
			if errors.Is(err, ErrNotRunning) {
				d.setStatus("Stopped", false, "waiting for agent")
			} else if !errors.Is(err, ErrUnavailable) {
				d.log.Debug("open log", "err", err)
			}
			sleepCtx(d.ctx, 750*time.Millisecond)
			continue
		}
		scanner := bufio.NewScanner(rc)
		scanner.Buffer(make([]byte, 64<<10), acpMaxLine)
		records := 0
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}
			var rec streamLogRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				d.log.Debug("bad log record", "err", err)
				continue
			}
			records++
			d.handleRecord(rec)
		}
		rc.Close()
		if d.ctx.Err() != nil {
			return
		}
		if records == 0 {
			// A stopped state returns its retained history and ends. Wait
			// before polling again so a quiet chat is not a busy loop.
			sleepCtx(d.ctx, time.Second)
		} else {
			sleepCtx(d.ctx, 100*time.Millisecond)
		}
	}
}

func (d *driver) handleRecord(rec streamLogRecord) {
	d.mu.Lock()
	if rec.Type == recordGap {
		duplicate := d.haveOffset && rec.Offset <= d.offset
		d.mu.Unlock()
		if duplicate {
			return
		}
		// A gap's offset is the first retained record, not a record that was
		// consumed. Leave the requested offset alone so that record is read.
		d.hub.Publish(Event{Type: "gap"})
		return
	}
	if d.haveOffset && rec.Offset <= d.offset {
		d.mu.Unlock()
		return
	}
	d.offset = rec.Offset
	d.haveOffset = true
	d.mu.Unlock()

	switch rec.Type {
	case recordOut:
		d.agent.Feed(rec.Data)
	case recordErr:
		d.emitOutput("stderr", rec.Data)
	case recordEnd:
		d.mu.Lock()
		current := d.generation
		queued := len(d.queue) > 0
		d.mu.Unlock()
		if current != 0 && (rec.Gen == 0 || rec.Gen >= current) {
			d.markEnded()
			d.setStatus("Stopped", false, "agent exited")
			if queued {
				d.advance()
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
