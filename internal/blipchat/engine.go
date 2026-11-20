// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// An engine drives one chat: it follows the state's trajectory ring, derives
// the chat view from it, and appends the next ACP frame or note with a
// compare-and-append check so exactly one replica wins each step. Engines hold
// no durable state; any replica can rebuild one by replaying the ring.
const (
	startTimeout         = 120 * time.Second
	statusPoll           = 250 * time.Millisecond
	engineTick           = time.Second
	actionCooloff        = 250 * time.Millisecond
	readRetry            = time.Second
	retryMinDelay        = 15 * time.Second
	retryMaxDelay        = 60 * time.Second
	initRetry            = 10 * time.Second
	cancelTimeout        = 5 * time.Second
	promptTimeout        = 10 * time.Minute
	idleBlipWait         = 5 * time.Second
	chatAdmissionTimeout = 30 * time.Second
)

// errEngineIdle tells the engine loop that the chat needs no driver and the
// engine can stop. Another request starts a fresh one.
var errEngineIdle = errors.New("chat engine idle")

// chatEngine follows one chat's ring and converges it toward the next action.
type chatEngine struct {
	s      *Server
	name   string
	ctx    context.Context
	cancel context.CancelFunc

	view       *chatView
	profile    Profile
	start      uint64
	sessionID  string
	savedACP   string
	savedTitle uint64

	records      <-chan recordResult
	stopReading  context.CancelFunc
	reconnectAt  time.Time
	lastAction   time.Time
	initSentAt   time.Time
	cancelSentAt time.Time
	eofSent      bool
	sessionTries int
	attemptGen   uint64
	permissionID string
	cancelSeq    uint64

	awaitSeq   uint64
	awaitSince time.Time

	lastRecord uint64
	haveRecord bool
	lostWrites int
	progressAt time.Time
	stalled    bool

	cachedST    *v1.BlipState
	cachedBlips []v1.Blip
	lastCheck   time.Time

	delay       time.Duration
	nextAttempt time.Time
	doneCount   int
}

// recordResult is one log record or a read error from a follow stream.
type recordResult struct {
	rec streamLogRecord
	err error
}

// streamRecords decodes an NDJSON log stream in the background. The channel
// closes after a read error so the engine can reconnect.
func streamRecords(ctx context.Context, rc io.ReadCloser) <-chan recordResult {
	out := make(chan recordResult)
	go func() {
		defer close(out)
		defer rc.Close()
		dec := json.NewDecoder(rc)
		for {
			var rec streamLogRecord
			if err := dec.Decode(&rec); err != nil {
				if ctx.Err() == nil {
					select {
					case out <- recordResult{err: err}:
					case <-ctx.Done():
					}
				}
				return
			}
			select {
			case out <- recordResult{rec: rec}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ensureEngine starts the engine for a chat unless the shard assigns the chat
// to another replica. It never blocks on the engine itself.
func (s *Server) ensureEngine(name string) *chatEngine {
	if s.shards != nil && !s.shards.owns(name) {
		return nil
	}
	s.mu.Lock()
	if e := s.engines[name]; e != nil {
		s.mu.Unlock()
		return e
	}
	ctx, cancel := context.WithCancel(s.ctx)
	e := &chatEngine{s: s, name: name, ctx: ctx, cancel: cancel}
	s.engines[name] = e
	s.mu.Unlock()
	go e.run()
	return e
}

func (s *Server) finishEngine(e *chatEngine) {
	s.mu.Lock()
	if s.engines[e.name] == e {
		delete(s.engines, e.name)
	}
	s.mu.Unlock()
	e.cancel()
}

func (s *Server) lookupEngine(name string) *chatEngine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.engines[name]
}

func (e *chatEngine) run() {
	defer e.s.finishEngine(e)
	ctx := e.ctx
	st, err := e.s.chatState(ctx, e.s.namespace, e.name)
	if err != nil {
		e.s.log.Debug("start chat engine", "session", e.name, "err", err)
		return
	}
	e.applyState(st)
	e.view = newChatView(e.sessionID)
	e.attach(e.start)
	ticker := time.NewTicker(engineTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case res, ok := <-e.records:
			if !ok {
				e.readFailed()
				continue
			}
			if res.err != nil {
				e.readFailed()
				continue
			}
			if e.haveRecord && res.rec.Offset <= e.lastRecord {
				continue
			}
			e.view.observe(res.rec)
			e.lastRecord, e.haveRecord = res.rec.Offset, true
			e.lostWrites = 0
			e.progressAt = time.Now()
			e.stalled = false
			if err := e.converge(ctx); err != nil {
				if errors.Is(err, errEngineIdle) {
					return
				}
				e.s.log.Debug("chat engine", "session", e.name, "err", err)
			}
		case <-ticker.C:
			if e.records == nil && time.Now().After(e.reconnectAt) {
				e.attach(e.view.Newest)
			}
			if err := e.converge(ctx); err != nil {
				if errors.Is(err, errEngineIdle) {
					return
				}
				e.s.log.Debug("chat engine", "session", e.name, "err", err)
			}
		}
	}
}

func (e *chatEngine) applyState(st *v1.BlipState) {
	if e.view != nil {
		e.view.applyStopBefore(stopBefore(st))
	}
	if session := st.Annotations[AnnotationACPSession]; session != "" {
		e.sessionID = session
		e.savedACP = session
	}
	if start := st.Annotations[AnnotationStart]; start != "" {
		if n, err := strconv.ParseUint(start, 10, 64); err == nil {
			e.start = n
		}
	}
	if e.savedTitle == 0 && st.Annotations[AnnotationTitle] != "" {
		e.savedTitle = 1
	}
}

// attach follows the log from the given logical offset.
func (e *chatEngine) attach(from uint64) {
	e.progressAt = time.Now()
	if e.stopReading != nil {
		e.stopReading()
		e.stopReading = nil
	}
	ctx, cancel := context.WithCancel(e.ctx)
	rc, err := e.s.wire.OpenLog(ctx, e.s.namespace, e.name, from)
	if err != nil {
		cancel()
		e.records = nil
		e.reconnectAt = time.Now().Add(readRetry)
		e.s.log.Debug("open chat log", "session", e.name, "err", err)
		return
	}
	e.stopReading = cancel
	e.records = streamRecords(ctx, rc)
}

func (e *chatEngine) readFailed() {
	if e.stopReading != nil {
		e.stopReading()
		e.stopReading = nil
	}
	e.records = nil
	e.reconnectAt = time.Now().Add(readRetry)
}

// converge performs at most one write. Every write carries an explicit
// compare-and-append offset when the chat has seen input in this generation, so
// two replicas that briefly believe they own the chat cannot both advance it.
func (e *chatEngine) converge(ctx context.Context) error {
	if time.Since(e.lastAction) < actionCooloff {
		return nil
	}
	// Wait until the log has caught up with our own write. Records are
	// ordered, so nothing else can be decided correctly before then, and
	// this window is where a second engine would otherwise duplicate work.
	if e.awaitSeq != 0 {
		if e.view.Newest >= e.awaitSeq {
			e.awaitSeq = 0
		} else if time.Since(e.awaitSince) < 5*time.Second {
			return nil
		} else {
			// The record is gone (the ring wrapped and dropped it). Carry on
			// from the truncated view; deterministic ids still prevent a
			// duplicate prompt.
			e.awaitSeq = 0
		}
	}
	if e.s.shards != nil && !e.s.shards.owns(e.name) {
		return errEngineIdle
	}
	if e.cachedST == nil || time.Since(e.lastCheck) >= engineTick {
		st, err := e.s.chatState(ctx, e.s.namespace, e.name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return errEngineIdle
			}
			return err
		}
		blips, err := e.s.cluster.ListStateBlips(ctx, e.s.namespace, e.name)
		if err != nil {
			return err
		}
		e.cachedST, e.cachedBlips, e.lastCheck = st, blips, time.Now()
	}
	st, blips := e.cachedST, e.cachedBlips
	e.applyState(st)
	profile, unavailable := e.s.profileFor(st)
	if unavailable != nil {
		// A chat whose profile was removed cannot run. Leave it idle instead
		// of retrying forever; fixing the profile revives it.
		return nil
	}
	if done := e.view.doneTotal(); done > e.doneCount {
		e.doneCount = done
		e.delay = 0
		e.nextAttempt = time.Time{}
	}
	active := activeBlip(blips)
	if active == nil {
		if !e.view.hasWork() {
			return errEngineIdle
		}
		if e.nextAttempt.IsZero() {
			e.delay = retryMinDelay
			e.nextAttempt = time.Now().Add(e.delay)
			return nil
		}
		if time.Now().Before(e.nextAttempt) {
			return nil
		}
		e.nextAttempt = time.Now().Add(e.delay)
		if e.delay < retryMaxDelay {
			e.delay *= 2
			if e.delay > retryMaxDelay {
				e.delay = retryMaxDelay
			}
		}
		if _, err := e.s.ensureRunning(ctx, st, profile); err != nil {
			return err
		}
		e.cachedST = nil
		e.lastAction = time.Now()
		return nil
	}
	gen := generationOf(active)
	if gen <= int64(e.view.Gen) && e.view.Started && e.view.StopSeq > e.view.StartSeq {
		return e.s.stopBlip(ctx, e.name)
	}
	switch {
	case gen > int64(e.view.Gen):
		// The log has not caught up with the blip yet.
		return nil
	case gen < int64(e.view.Gen):
		// An older generation is still winding down. Stop it so its state
		// lease does not keep this chat busy.
		return e.s.stopBlip(ctx, e.name)
	case active.Status.Phase == v1.BlipPending:
		return nil
	case active.Status.Phase != v1.BlipRunning:
		return nil
	}
	if e.view.Ended || !e.view.Started || e.view.Gen == 0 {
		return nil
	}
	if e.attemptGen != e.view.Gen {
		e.attemptGen = e.view.Gen
		e.sessionTries = 0
		e.eofSent = false
		e.cancelSentAt = time.Time{}
		e.permissionID = ""
	}
	// Setup can hang too. Check before the readiness gates below, otherwise
	// an agent that never answers session/new can never reach its watchdog.
	if !e.stalled && ((e.view.InitSent && !e.view.InitDone) ||
		(e.view.SessionSent && !e.view.SessionReady) || e.view.busy()) &&
		!e.progressAt.IsZero() && time.Since(e.progressAt) > promptTimeout {
		e.s.log.Warn("chat agent stopped responding", "session", e.name, "generation", e.view.Gen)
		if err := e.s.stopBlip(ctx, e.name); err != nil {
			return err
		}
		e.stalled = true
		return nil
	}

	if !e.view.InitDone {
		// A previous engine may have written initialize just before its
		// generation died. The request id is deterministic, so resending it
		// is safe; initRetry just avoids a hot loop.
		if e.initSentAt.IsZero() || time.Since(e.initSentAt) > initRetry {
			ok, err := e.send(ctx, initializeFrame(e.view.Gen), 0)
			if err != nil {
				return err
			}
			if ok {
				e.initSentAt = time.Now()
			}
		}
		return nil
	}

	if !e.view.SessionSent || e.view.SessionFailed {
		if e.view.SessionFailed && e.sessionTries > 1 {
			return e.s.stopBlip(ctx, e.name)
		}
		sessionID := e.view.SessionID
		if sessionID == "" {
			sessionID = e.sessionID
		}
		var frame []byte
		if !e.view.SessionFailed && sessionID != "" && e.view.CanResume {
			frame = sessionSetupFrame(e.view.Gen, "session/resume", sessionID, e.s.mcpServers())
		} else if !e.view.SessionFailed && sessionID != "" {
			frame = sessionSetupFrame(e.view.Gen, "session/load", sessionID, e.s.mcpServers())
		} else {
			frame = newSessionFrame(e.view.Gen, e.s.mcpServers())
		}
		ok, err := e.send(ctx, frame, e.appendSeq())
		if err != nil {
			return err
		}
		if ok {
			e.sessionTries++
			e.lastAction = time.Now()
		}
		return nil
	}
	if !e.view.SessionReady {
		return nil
	}
	if e.view.SessionID != "" && e.view.SessionID != e.savedACP {
		if err := e.s.cluster.PatchSession(ctx, e.s.namespace, e.name, nil, map[string]string{AnnotationACPSession: e.view.SessionID}); err != nil {
			return err
		}
		e.savedACP = e.view.SessionID
		e.sessionID = e.view.SessionID
	}
	if e.view.HasTitle && e.view.TitleSeq > e.savedTitle {
		if err := e.s.cluster.PatchSession(ctx, e.s.namespace, e.name, nil, map[string]string{AnnotationTitle: e.view.Title}); err != nil {
			return err
		}
		e.savedTitle = e.view.TitleSeq
	}
	if e.view.Permission != nil && rawID(e.view.Permission.ID) != e.permissionID {
		frame := permissionReply(e.view.Permission.ID, e.view.Permission.Method, e.view.Permission.Params, e.s.autoApprove)
		ok, err := e.send(ctx, frame, e.appendSeq())
		if err != nil {
			return err
		}
		if ok {
			e.permissionID = rawID(e.view.Permission.ID)
			e.lastAction = time.Now()
		}
		return nil
	}
	if e.view.Inflight != nil && e.view.Inflight.Sent != 0 && e.view.CancelSeq >= e.view.Inflight.Sent &&
		e.view.LastCancelIn < e.view.CancelSeq && e.view.CancelSeq > e.cancelSeq {
		sessionID := e.view.SessionID
		if sessionID == "" {
			sessionID = e.sessionID
		}
		ok, err := e.send(ctx, cancelFrame(sessionID), e.appendSeq())
		if err != nil {
			return err
		}
		if ok {
			e.cancelSeq = e.view.CancelSeq
			e.cancelSentAt = time.Now()
			e.lastAction = time.Now()
		}
		return nil
	}
	if !e.cancelSentAt.IsZero() {
		if !e.view.busy() {
			e.cancelSentAt = time.Time{}
		} else if time.Since(e.cancelSentAt) > cancelTimeout {
			e.cancelSentAt = time.Time{}
			return e.s.stopBlip(ctx, e.name)
		} else {
			// Give the agent time to finish the cancelled turn.
			return nil
		}
	}
	if e.view.busy() {
		return nil
	}
	if prompt, ok := e.view.nextTurn(); ok {
		sessionID := e.view.SessionID
		if sessionID == "" {
			sessionID = e.sessionID
		}
		frame := promptFrame(prompt.ID, sessionID, prompt.Text, prompt.Original, prompt.Sender)
		ok, err := e.send(ctx, frame, e.appendSeq())
		if err != nil {
			return err
		}
		if ok {
			e.lastAction = time.Now()
		}
		return nil
	}
	if !e.eofSent {
		after := e.appendSeq()
		ok, err := e.sendEOF(ctx, after)
		if err != nil {
			return err
		}
		if ok || errors.Is(err, ErrNotRunning) {
			e.eofSent = true
			e.lastAction = time.Now()
		}
	}
	return nil
}

// appendSeq is the conditional-append offset for this generation, or zero when
// the node has not seen input in it yet (lastSeq restarts per attachment).
func (e *chatEngine) appendSeq() uint64 {
	if n, ok := e.view.canWrite(); ok {
		return n
	}
	return 0
}

// send writes one ACP frame. ok is false when the write lost a race or the
// generation is ending; both are retried after the view catches up.
func (e *chatEngine) send(ctx context.Context, data []byte, after uint64) (bool, error) {
	for attempt := 0; attempt < 5; attempt++ {
		offset, err := e.s.wire.Send(ctx, e.s.namespace, e.name, data, false, false, after)
		switch {
		case err == nil:
			if offset != 0 {
				e.awaitSeq, e.awaitSince = offset, time.Now()
			}
			return true, nil
		case errors.Is(err, ErrPrecondition), errors.Is(err, ErrNotRunning):
			// We lost the compare-and-append race, or the generation ended.
			// If the view never catches up (for example, a node restart lost
			// its cursor), stop the blip so a fresh generation retries with an
			// unconditioned write.
			e.lostWrites++
			if e.lostWrites >= 40 {
				e.lostWrites = 0
				return false, e.s.stopBlip(ctx, e.name)
			}
			return false, nil
		case errors.Is(err, ErrUnavailable):
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 200 * time.Millisecond):
			}
		default:
			return false, err
		}
	}
	return false, ErrUnavailable
}

func (e *chatEngine) sendEOF(ctx context.Context, after uint64) (bool, error) {
	_, err := e.s.wire.Send(ctx, e.s.namespace, e.name, nil, true, false, after)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrPrecondition), errors.Is(err, ErrNotRunning):
		return false, nil
	default:
		return false, err
	}
}

// profileFor returns the chat's profile, or an error when the profile is gone.
func (s *Server) profileFor(st *v1.BlipState) (Profile, error) {
	name := st.Annotations[AnnotationProfile]
	if name == "" {
		name = DefaultProfileName
	}
	profile, ok := s.profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("%w: profile %q", errProfileUnavailable, name)
	}
	return profile.normalized(s.defaultPool), nil
}

// touchChat fences a reaper holding an older resource version before new work
// starts. A patch can succeed on a terminating state, so reread its identity and
// deletion status before proceeding.
func (s *Server) touchChat(ctx context.Context, st *v1.BlipState) error {
	if s.chatRetention <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, chatAdmissionTimeout)
	defer cancel()
	if err := s.cluster.PatchSession(ctx, s.namespace, st.Name, nil, map[string]string{
		annotationActivityAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return err
	}
	current, err := s.cluster.GetSession(ctx, s.namespace, st.Name)
	if err != nil {
		return err
	}
	if current.DeletionTimestamp != nil || current.UID != st.UID {
		return fmt.Errorf("chat %s was deleted or replaced before new work could start", st.Name)
	}
	return nil
}

// ensureRunning returns a running blip for the state, creating the next
// generation when none is active.
func (s *Server) ensureRunning(ctx context.Context, st *v1.BlipState, profile Profile) (*v1.Blip, error) {
	blips, err := s.cluster.ListStateBlips(ctx, s.namespace, st.Name)
	if err != nil {
		return nil, err
	}
	if running := runningBlip(blips); running != nil {
		return running, nil
	}
	if latest := latestBlip(blips); latest != nil && latest.Status.Phase == v1.BlipPending {
		return s.waitRunning(ctx, latest.Name)
	}
	var maxGen int64
	for i := range blips {
		if g := generationOf(&blips[i]); g > maxGen {
			maxGen = g
		}
	}
	labels := map[string]string{LabelSession: st.Name}
	if owner := st.Labels[v1.LabelOwner]; owner != "" {
		labels[v1.LabelOwner] = owner
	}
	idle := profile.IdleTimeoutSeconds
	for attempt := 0; attempt < 3; attempt++ {
		gen := maxGen + 1
		name := fmt.Sprintf("%s-g%d", st.Name, gen)
		blip := &v1.Blip{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   s.namespace,
				Labels:      labels,
				Annotations: map[string]string{AnnotationGeneration: strconv.FormatInt(gen, 10)},
			},
			Spec: v1.BlipSpec{
				Pool:               profile.Pool,
				State:              st.Name,
				Command:            append([]string(nil), profile.Command...),
				Env:                profile.envVars(),
				IdleTimeoutSeconds: &idle,
			},
		}
		if err := s.touchChat(ctx, st); err != nil {
			return nil, err
		}
		createCtx, cancel := context.WithTimeout(ctx, chatAdmissionTimeout)
		err := s.cluster.CreateBlip(createCtx, s.namespace, blip)
		cancel()
		if err != nil {
			if apierrors.IsAlreadyExists(err) {
				blips, err = s.cluster.ListStateBlips(ctx, s.namespace, st.Name)
				if err != nil {
					return nil, err
				}
				if running := runningBlip(blips); running != nil {
					return running, nil
				}
				if active := activeBlip(blips); active != nil {
					return s.waitRunning(ctx, active.Name)
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
		return s.waitRunning(ctx, name)
	}
	return nil, fmt.Errorf("could not allocate a blip generation for %s", st.Name)
}

func (s *Server) waitRunning(ctx context.Context, name string) (*v1.Blip, error) {
	deadline := time.Now().Add(startTimeout)
	for {
		blip, err := s.cluster.GetBlip(ctx, s.namespace, name)
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%s disappeared before it started", name)
		}
		if err != nil {
			return nil, err
		}
		switch blip.Status.Phase {
		case v1.BlipRunning:
			return blip, nil
		case v1.BlipSucceeded, v1.BlipFailed:
			reason := blip.Status.Message
			if reason == "" {
				reason = blip.Status.Reason
			}
			return nil, fmt.Errorf("%s %s: %s", name, blip.Status.Phase, reason)
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

// chatStart is the first ring offset that belongs to this chat. A fork begins
// after its base's records.
func chatStart(st *v1.BlipState) uint64 {
	if raw := st.Annotations[AnnotationStart]; raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

// stopBlip asks every active generation to stop and waits briefly for them to
// leave Running so a follow-up message does not race the state lease.
func (s *Server) stopBlip(ctx context.Context, state string) error {
	blips, err := s.cluster.ListStateBlips(ctx, s.namespace, state)
	if err != nil {
		return err
	}
	var targets []*v1.Blip
	for i := range blips {
		switch blips[i].Status.Phase {
		case v1.BlipRunning, v1.BlipPending:
			targets = append(targets, &blips[i])
		}
	}
	if len(targets) == 0 {
		return nil
	}
	for _, target := range targets {
		if err := s.cluster.StopBlip(ctx, s.namespace, target.Name); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		blips, err := s.cluster.ListStateBlips(ctx, s.namespace, state)
		if err != nil {
			break
		}
		active := 0
		for i := range blips {
			if blips[i].Status.Phase == v1.BlipRunning || blips[i].Status.Phase == v1.BlipPending {
				active++
			}
		}
		if active == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

func (v *chatView) doneTotal() int { return len(v.Done) }

// activeBlip returns the newest blip that may still be running.
func activeBlip(blips []v1.Blip) *v1.Blip {
	var best *v1.Blip
	var max int64 = -1
	for i := range blips {
		switch blips[i].Status.Phase {
		case v1.BlipRunning, v1.BlipPending:
		default:
			continue
		}
		if g := generationOf(&blips[i]); g > max {
			max = g
			best = &blips[i]
		}
	}
	return best
}

// readView replays a chat's whole ring. Handlers use it for details, event
// backfill, and MCP calls; the engine keeps its own incremental view.
// viewCacheTTL bounds how often the same chat's ring is replayed for read-only
// views. The UI lists chats every couple of seconds and MCP long-polls much
// faster; without the cache each poll would re-read 16 MiB of history.
const viewCacheTTL = time.Second

type cachedChatView struct {
	view *chatView
	at   time.Time
}

// invalidateView drops a cached view after this replica writes to the chat, so
// its own writes are immediately visible.
func (s *Server) invalidateView(name string) {
	s.viewsMu.Lock()
	delete(s.views, name)
	s.viewsMu.Unlock()
}

func (s *Server) readView(ctx context.Context, st *v1.BlipState) *chatView {
	if v := s.cachedView(st.Name); v != nil && v.stopBefore >= stopBefore(st) {
		return v
	}
	v := newChatView(st.Annotations[AnnotationACPSession])
	rc, err := s.wire.ReadLog(ctx, s.namespace, st.Name, chatStart(st))
	if err != nil {
		s.log.Debug("read chat log", "session", st.Name, "err", err)
		return v
	}
	defer rc.Close()
	dec := json.NewDecoder(rc)
	for {
		var rec streamLogRecord
		if err := dec.Decode(&rec); err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Debug("read chat log", "session", st.Name, "err", err)
			}
			break
		}
		v.observe(rec)
	}
	v.applyStopBefore(stopBefore(st))
	s.viewsMu.Lock()
	if len(s.views) > 512 {
		clear(s.views)
	}
	s.views[st.Name] = cachedChatView{view: v, at: time.Now()}
	s.viewsMu.Unlock()
	return v
}

func (s *Server) cachedView(name string) *chatView {
	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()
	if c, ok := s.views[name]; ok && time.Since(c.at) < viewCacheTTL {
		return c.view
	}
	return nil
}

// writeNote appends a note to a running chat.
func (s *Server) writeNote(ctx context.Context, state string, note noteRecord) (uint64, error) {
	data, err := json.Marshal(note)
	if err != nil {
		return 0, err
	}
	off, err := s.wire.Send(ctx, s.namespace, state, data, false, true, 0)
	if err == nil {
		s.invalidateView(state)
	}
	return off, err
}

// appendNote ensures a running agent and then appends the note. A generation
// that is ending rejects the write; wait for it to leave Running and retry on
// the next one.
func (s *Server) appendNote(ctx context.Context, st *v1.BlipState, profile Profile, note noteRecord) error {
	for attempt := 0; attempt < 3; attempt++ {
		_, err := s.writeNote(ctx, st.Name, note)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrNotRunning) {
			return err
		}
		waitNoActive(ctx, s, st.Name)
		if _, err := s.ensureRunning(ctx, st, profile); err != nil {
			return err
		}
	}
	return errSessionBusy
}

// waitNoActive waits for a stopping generation to leave Running so the next
// create does not run two VMs against the same state.
func waitNoActive(ctx context.Context, s *Server, state string) {
	deadline := time.Now().Add(idleBlipWait)
	for time.Now().Before(deadline) {
		blips, err := s.cluster.ListStateBlips(ctx, s.namespace, state)
		if err != nil {
			return
		}
		if activeBlip(blips) == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(statusPoll):
		}
	}
}

// messageData builds the template data for a chat. The rendered text is what
// the agent sees; the original is what the transcript shows.
func (s *Server) messageData(st *v1.BlipState, profile Profile, text string) MessageData {
	profileName := st.Annotations[AnnotationProfile]
	if profileName == "" {
		profileName = DefaultProfileName
	}
	return MessageData{
		Text:        text,
		Session:     st.Name,
		Namespace:   s.namespace,
		Profile:     profileName,
		Title:       st.Annotations[AnnotationTitle],
		Description: profile.Description,
		Base:        st.Annotations[AnnotationBase],
		Parent:      st.Annotations[AnnotationParent],
		Root:        st.Annotations[AnnotationRoot],
		Depth:       sessionDepth(st),
		Created:     sessionCreated(st),
	}
}

// promptNote renders a user's message and wraps it as a note.
func (s *Server) promptNote(st *v1.BlipState, profile Profile, sender, text string) (noteRecord, error) {
	rendered, err := profile.renderMessage(s.messageData(st, profile, text))
	if err != nil {
		return noteRecord{}, fmt.Errorf("render message: %w", err)
	}
	if len(rendered) > maxPromptBytes {
		return noteRecord{}, errMessageTooLong
	}
	id := "n" + strconv.FormatInt(time.Now().UnixNano(), 36) + randomSuffix()
	return noteRecord{Type: notePrompt, ID: id, Text: rendered, Original: text, Sender: sender}, nil
}

func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}
