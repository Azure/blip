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
// presentation and client state. The tree fields are shared with the
// admission policies, so they are defined in the API package.
const (
	LabelSession = v1.LabelChatSession

	AnnotationTitle      = "chat.blip.dev/title"
	AnnotationScope      = "chat.blip.dev/scope"
	AnnotationUser       = "chat.blip.dev/user"
	AnnotationProfile    = v1.AnnotationChatProfile
	AnnotationBase       = "chat.blip.dev/base"
	AnnotationACPSession = "chat.blip.dev/acp-session"
	AnnotationOffset     = "chat.blip.dev/offset"
	AnnotationGeneration = "chat.blip.dev/generation"

	// LabelParent names the chat state that spawned this one. The tree in the
	// UI and the admission policies both use it.
	LabelParent      = v1.AnnotationChatParent
	AnnotationParent = v1.AnnotationChatParent

	// AnnotationRoot is the top chat of the tree and AnnotationDepth is the
	// distance from it.
	AnnotationRoot          = v1.AnnotationChatRoot
	AnnotationDepth         = v1.AnnotationChatDepth
	AnnotationParentProfile = v1.AnnotationChatParentProfile
	AnnotationParentDepth   = v1.AnnotationChatParentDepth
)

const maxQueue = 32

var (
	errSessionBusy        = errors.New("session is busy")
	errMessageTooLong     = errors.New("message is too long")
	errProfileUnavailable = errors.New("profile is not configured")
	errStopRequested      = errors.New("stop requested while starting")
)

const (
	maxTranscriptMessages = 10000
	maxTranscriptBytes    = 16 << 20
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
	user string
	// at is when the request reached the API. Stop uses it to distinguish
	// prompts the user sent before clicking Stop from prompts accepted after
	// the click but processed before the stop operation.
	at time.Time
}

type queuedPrompt struct {
	id         string
	text       string
	original   string
	user       string
	recorded   bool
	attempts   int
	acceptedAt time.Time
	// keepOnStop marks a prompt accepted after the stop request. Stop drops
	// prompts queued for the agent being stopped, but a prompt the user sent
	// during the stop window was accepted with HTTP 202 and must still run.
	keepOnStop bool
}

// defaultStartRetryDelay spaces out retries after an agent fails to start.
// Without this, a burst of queued messages would allocate a fresh Blip
// generation for each one against the same unavailable pool.
const defaultStartRetryDelay = 15 * time.Second

// maxStartRetryDelay caps the exponential backoff between start attempts.
const maxStartRetryDelay = 60 * time.Second

// maxStartAttempts bounds automatic retries for one prompt. A permanent agent
// failure (bad command, missing runtime) must not allocate a fresh generation
// forever; after this many attempts the prompt stays in the transcript and the
// chat reports an error until the user sends again.
const maxStartAttempts = 4

type driverOptions struct {
	Cluster     Cluster
	Wire        Wire
	Hub         *Hub
	Log         *slog.Logger
	Namespace   string
	State       string
	ProfileName string
	Profile     Profile
	Base        string
	Parent      string
	Root        string
	Depth       int
	Created     string
	AutoApprove string
	SessionID   string
	Title       string
	Offset      uint64
	HaveOffset  bool
	MCPServers  []any
	Transcript  []json.RawMessage

	// TranscriptTruncated records that Transcript was already capped while
	// replaying the durable log, so the UI can say older history is omitted.
	TranscriptTruncated bool

	// Unavailable disables new turns when the chat's profile is no longer
	// configured. The driver still serves history; SubmitAs returns this
	// error instead of silently running a different profile.
	Unavailable error

	// Pending is optional. When set, accepted but undelivered prompts are
	// persisted outside the process so a blipchat restart can resume them.
	Pending        PendingStore
	PendingPrompts []PendingPrompt
}

// PendingPrompt is one accepted prompt that has not reached the agent yet.
type PendingPrompt struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Original string `json:"original"`
	User     string `json:"user,omitempty"`
}

// PendingStore persists the small window between accepting a prompt and
// writing it to the agent's stdin. Implementations may return an error; the
// driver treats that as a failed submit rather than silently losing the turn.
type PendingStore interface {
	LoadPending(ctx context.Context, namespace, session string) ([]PendingPrompt, error)
	SavePending(ctx context.Context, namespace, session string, prompts []PendingPrompt) error
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
	// profileName, base, parent, root, depth, and created are stable chat
	// identity used by the profile's message template.
	profileName string
	base        string
	parent      string
	root        string
	depth       int
	created     string

	ctx    context.Context
	cancel context.CancelFunc
	ops    chan operation

	advanceMu   sync.Mutex
	persistMu   sync.Mutex
	mu          sync.Mutex
	queue       []queuedPrompt
	inflight    bool
	current     *queuedPrompt
	reading     bool
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
	txTruncated bool
	lastStatus  Status
	haveStatus  bool
	title       string
	haveTitle   bool
	reply       string
	submitted   int
	completed   int

	retryAfter   time.Time
	retryPending bool
	retryDelay   time.Duration

	// unavailable is set when the chat's profile no longer exists. History
	// stays readable, but new prompts fail instead of switching profiles.
	unavailable error

	pendingStore PendingStore
	pending      map[string]queuedPrompt
	promptSeq    uint64

	startCancel   context.CancelFunc
	stopRequested bool
	cancelStart   bool
	cancelledTurn bool
	cancelSeq     uint64
}

func newDriver(opts driverOptions) *driver {
	ctx, cancel := context.WithCancel(context.Background())
	d := &driver{
		cluster:      opts.Cluster,
		wire:         opts.Wire,
		hub:          opts.Hub,
		log:          opts.Log.With("namespace", opts.Namespace, "session", opts.State),
		namespace:    opts.Namespace,
		state:        opts.State,
		profile:      opts.Profile,
		profileName:  opts.ProfileName,
		base:         opts.Base,
		parent:       opts.Parent,
		root:         opts.Root,
		depth:        opts.Depth,
		created:      opts.Created,
		ctx:          ctx,
		cancel:       cancel,
		ops:          make(chan operation, maxQueue+8),
		ended:        true,
		offset:       opts.Offset,
		haveOffset:   opts.HaveOffset,
		title:        opts.Title,
		haveTitle:    true,
		transcript:   append([]json.RawMessage(nil), opts.Transcript...),
		txTruncated:  opts.TranscriptTruncated,
		retryDelay:   defaultStartRetryDelay,
		pendingStore: opts.Pending,
		pending:      make(map[string]queuedPrompt),
		unavailable:  opts.Unavailable,
	}
	for _, raw := range d.transcript {
		d.txBytes += len(raw)
	}
	// A prompt accepted just before blipchat restarted may be in the durable
	// pending ConfigMap but not yet in the trajectory log. Record any such
	// prompt now so reopening the chat shows every accepted user turn, not
	// just the ones that happened to reach the log before the restart. Prompts
	// already present are left alone to avoid duplicate transcript rows.
	recordedPrompts := transcriptPromptIDs(d.transcript)
	for _, p := range opts.PendingPrompts {
		if p.ID == "" || strings.TrimSpace(p.Original) == "" {
			continue
		}
		if !recordedPrompts[p.ID] {
			d.recordUser(p.User, p.Original, p.ID)
			recordedPrompts[p.ID] = true
		}
		q := queuedPrompt{id: p.ID, text: p.Text, original: p.Original, user: p.User, recorded: true}
		d.queue = append(d.queue, q)
		d.pending[p.ID] = q
		d.submitted++
	}
	d.agent = newACPAgent(d.sendACP, d.acpMessage, d.promptDone, d.patchACPSession, opts.AutoApprove)
	d.agent.SetSessionID(opts.SessionID)
	d.agent.SetMCPServers(opts.MCPServers)
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

func (d *driver) Submit(text string) error { return d.SubmitAs("", text) }

// SubmitAs queues a prompt and remembers who sent it so the transcript can
// show a sender on each user message. The profile's message template is
// applied to the prompt but not to the transcript.
func (d *driver) SubmitAs(user, text string) error {
	if d.unavailable != nil {
		return d.unavailable
	}
	d.mu.Lock()
	title := d.title
	d.mu.Unlock()
	rendered, err := d.profile.renderMessage(MessageData{
		Text:        text,
		Session:     d.state,
		Namespace:   d.namespace,
		Profile:     d.profileName,
		Title:       title,
		Description: d.profile.Description,
		Base:        d.base,
		Parent:      d.parent,
		Root:        d.root,
		Depth:       d.depth,
		Created:     d.created,
	})
	if err != nil {
		return fmt.Errorf("render message: %w", err)
	}
	if len(rendered) > maxPromptBytes {
		return errMessageTooLong
	}
	d.mu.Lock()
	if len(d.queue) >= maxQueue {
		d.mu.Unlock()
		return errSessionBusy
	}
	id := d.nextPromptIDLocked()
	q := queuedPrompt{
		id:         id,
		text:       rendered,
		original:   text,
		user:       user,
		recorded:   true,
		acceptedAt: time.Now(),
		keepOnStop: d.stopRequested,
	}
	d.queue = append(d.queue, q)
	d.pending[id] = q
	d.submitted++
	d.mu.Unlock()
	if err := d.persistPending(); err != nil {
		d.mu.Lock()
		d.removeQueuedLocked(id)
		d.mu.Unlock()
		return fmt.Errorf("persist prompt: %w", err)
	}
	if !d.enqueue(operation{kind: opPrompt}) {
		d.mu.Lock()
		d.removeQueuedLocked(id)
		d.mu.Unlock()
		_ = d.persistPending()
		return errSessionBusy
	}
	// Record the turn at submit time, not when it is dequeued. A message sent
	// while the previous turn runs must be visible in every open transcript
	// immediately instead of appearing minutes later or after a reload.
	d.recordUser(user, text, id)
	return nil
}

func (d *driver) nextPromptIDLocked() string {
	d.promptSeq++
	return fmt.Sprintf("%s-%d-%d", d.state, time.Now().UnixNano(), d.promptSeq)
}

func (d *driver) removeQueuedLocked(id string) {
	if id == "" {
		return
	}
	for i := range d.queue {
		if d.queue[i].id == id {
			d.queue = append(d.queue[:i], d.queue[i+1:]...)
			delete(d.pending, id)
			if d.submitted > 0 {
				d.submitted--
			}
			return
		}
	}
	delete(d.pending, id)
}

func (d *driver) pendingPromptsLocked() []PendingPrompt {
	out := make([]PendingPrompt, 0, len(d.pending))
	seen := make(map[string]bool, len(d.pending))
	// Persist in queue order. Iterating the map directly would shuffle the
	// order every time a prompt is queued, so a restart could run accepted
	// prompts in a different order than the user sent them.
	for _, q := range d.queue {
		if _, ok := d.pending[q.id]; !ok || seen[q.id] {
			continue
		}
		if d.current != nil && q.id == d.current.id {
			continue
		}
		out = append(out, PendingPrompt{ID: q.id, Text: q.text, Original: q.original, User: q.user})
		seen[q.id] = true
	}
	for id, q := range d.pending {
		if seen[id] {
			continue
		}
		if d.current != nil && id == d.current.id {
			continue
		}
		out = append(out, PendingPrompt{ID: q.id, Text: q.text, Original: q.original, User: q.user})
	}
	return out
}

// transcriptPromptIDs returns the prompt IDs already present as user turns in
// a replayed transcript.
func transcriptPromptIDs(transcript []json.RawMessage) map[string]bool {
	ids := make(map[string]bool)
	for _, raw := range transcript {
		var msg struct {
			Params struct {
				Update struct {
					Kind     string `json:"sessionUpdate"`
					PromptID string `json:"promptID"`
				} `json:"update"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}
		if msg.Params.Update.Kind == "user_message_chunk" && msg.Params.Update.PromptID != "" {
			ids[msg.Params.Update.PromptID] = true
		}
	}
	return ids
}

func (d *driver) persistPending() error {
	if d.pendingStore == nil {
		return nil
	}
	// Serialize snapshot-and-save. Two concurrent submits otherwise write
	// snapshots out of order and a later snapshot can be overwritten by an
	// older one.
	d.persistMu.Lock()
	defer d.persistMu.Unlock()
	d.mu.Lock()
	prompts := d.pendingPromptsLocked()
	d.mu.Unlock()
	return d.pendingStore.SavePending(d.ctx, d.namespace, d.state, prompts)
}

// resume starts queued prompts restored from the pending store after a
// restart. The driver records each user turn only when it actually dequeues
// it, so the replayed transcript does not show duplicates.
func (d *driver) resume() {
	if d.unavailable != nil {
		return
	}
	d.mu.Lock()
	queued := len(d.queue) > 0
	d.mu.Unlock()
	if queued {
		go d.advance()
	}
}

func (d *driver) Cancel() bool {
	d.mu.Lock()
	cancel := d.startCancel
	if cancel != nil {
		// Abort a pending start, but keep prompts that were accepted while
		// it was starting. The aborted advance drops only its own prompt and
		// runs the queued ones on a fresh agent. Do not enqueue opCancel:
		// it would arrive after the next queued prompt started and cancel
		// that turn instead.
		d.cancelStart = true
		d.cancelledTurn = true
		d.mu.Unlock()
		cancel()
		return true
	}
	d.mu.Unlock()
	if d.enqueue(operation{kind: opCancel}) {
		return true
	}
	return false
}

func (d *driver) Stop() bool {
	at := time.Now()
	d.mu.Lock()
	d.stopRequested = true
	cancel := d.startCancel
	d.mu.Unlock()
	if cancel != nil {
		// Abort a blocked ensureRunning/waitRunning immediately. The queued
		// opStop then closes the turn and clears any prompts accepted for it.
		cancel()
	}
	if d.enqueue(operation{kind: opStop, at: at}) {
		return true
	}
	d.mu.Lock()
	d.stopRequested = false
	d.mu.Unlock()
	return false
}
func (d *driver) Ensure() bool { return d.enqueue(operation{kind: opEnsure}) }

// Busy reports whether a turn is queued, in flight, or waiting for the agent's
// response. An MCP caller uses it to know when a child's answer is final.
func (d *driver) Busy() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.submitted > d.completed || d.inflight
}

// Reply is the text of the agent's last turn.
func (d *driver) Reply() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reply
}

// WaitIdle blocks until no turn is outstanding, the timeout passes, or ctx is
// done. It reports whether the chat is idle.
func (d *driver) WaitIdle(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !d.Busy() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return !d.Busy()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (d *driver) Snapshot() ([]json.RawMessage, uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]json.RawMessage, len(d.transcript))
	copy(out, d.transcript)
	// ended is set once the driver has closed the turn and has no queued or
	// pending prompts. Callers use it to avoid pairing a terminal transcript
	// offset with a stale Blip phase that is still Running.
	idle := d.ended && !d.inflight && len(d.queue) == 0 && len(d.pending) == 0
	return out, d.hub.Seq(), idle
}

// TranscriptTruncated reports whether older transcript records were dropped
// from the in-memory view. The durable log still contains them.
func (d *driver) TranscriptTruncated() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.txTruncated
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
			d.watchRunning()
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
		if op.text != "" {
			d.mu.Lock()
			if len(d.queue) < maxQueue {
				d.queue = append(d.queue, queuedPrompt{text: op.text, original: op.text, user: op.user})
				d.submitted++
			}
			d.mu.Unlock()
		}
		d.advance()
	case opCancel:
		// Cancel means cancel the current turn. If no turn is in flight the
		// start was aborted before it delivered a prompt; run the next queued
		// prompt instead of stranding the queue.
		if !d.inflight {
			d.mu.Lock()
			aborted := d.cancelStart || d.cancelledTurn
			d.cancelStart = false
			d.cancelledTurn = false
			if aborted {
				// The start was aborted, so the partially initialized agent
				// must not be reused for the queued prompt.
				d.initialized = false
				d.ended = true
			}
			d.mu.Unlock()
			if aborted {
				d.agent.Reset()
			}
			d.advance()
			return
		}
		d.mu.Lock()
		d.cancelSeq++
		seq := d.cancelSeq
		d.mu.Unlock()
		if err := d.agent.Cancel(d.ctx); err != nil {
			d.setStatus("Error", false, "cancel: "+err.Error())
		} else {
			d.mu.Lock()
			d.cancelledTurn = true
			d.mu.Unlock()
			d.setStatus("Cancelling", true, "cancel requested")
			// Some agents stop the prompt without completing its RPC when a
			// turn is cancelled. That leaves the turn in flight and any
			// prompts queued behind it stranded forever. Close the turn if
			// the normal promptDone path has not done so shortly.
			time.AfterFunc(5*time.Second, func() {
				d.mu.Lock()
				stale := d.cancelSeq != seq || !d.inflight
				d.mu.Unlock()
				if stale {
					return
				}
				_ = d.stopBlip(d.ctx)
				d.markEnded()
				d.setStatus("Stopped", false, "cancel timed out")
				d.advance()
			})
		}
	case opStop:
		d.mu.Lock()
		// Keep stopRequested set while the old generation winds down so a
		// prompt response arriving during the stop cannot start new work.
		d.cancelStart = false
		d.cancelledTurn = false
		d.mu.Unlock()
		if err := d.stopBlip(d.ctx); err != nil {
			d.mu.Lock()
			d.stopRequested = false
			d.mu.Unlock()
			d.setStatus("Error", false, "stop: "+err.Error())
			return
		}
		// Stopping a blip kills the agent without writing an end record for
		// the current turn. Close the turn here, or the next prompt queues
		// behind a dead in-flight request and never runs. Stop also means
		// drop prompts that were accepted for the stopped agent; otherwise
		// the next turn would replay the whole stale queue.
		d.mu.Lock()
		d.stopRequested = false
		d.dropQueuedOnStopLocked(op.at)
		d.mu.Unlock()
		d.markEnded()
		d.setStatus("Stopped", false, "agent stopped")
		d.advance()
	}
}

// dropQueuedOnStopLocked removes prompts that were queued before the user
// clicked Stop. Prompts accepted after the stop request survive even when the
// message POST was processed before the stop operation. d.mu must be held.
func (d *driver) dropQueuedOnStopLocked(stopAt time.Time) int {
	kept := d.queue[:0]
	dropped := 0
	for _, q := range d.queue {
		if q.keepOnStop || (!stopAt.IsZero() && q.acceptedAt.After(stopAt)) {
			kept = append(kept, q)
			continue
		}
		delete(d.pending, q.id)
		dropped++
	}
	d.queue = kept
	d.submitted -= dropped
	if d.submitted < 0 {
		d.submitted = 0
	}
	return dropped
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

// watchRunning notices when the blip that owns the current turn is gone
// without a recordEnd. A VM can be evicted, fail, or be stopped by another
// client; without this the driver keeps waiting for an agent that no longer
// exists and queued prompts never run.
func (d *driver) watchRunning() {
	blips, err := d.cluster.ListStateBlips(d.ctx, d.namespace, d.state)
	if err != nil {
		return
	}
	d.mu.Lock()
	inflight := d.inflight
	starting := d.startCancel != nil
	initialized := d.initialized
	queued := len(d.queue)
	d.mu.Unlock()
	if !inflight {
		if starting || initialized || queued > 0 {
			return
		}
		// A blip can still be Running after blipchat restarts mid-turn. The
		// ACP request that owned it is gone, so no end record will ever arrive;
		// without this the chat reports Running forever and Cancel does
		// nothing. Only adopt this branch when no turn is starting, active, or
		// queued, so a warm agent is not stopped while its first prompt is
		// still being delivered. Check every generation, not just the newest:
		// a timed-out start can leave an older Running generation behind a
		// newer Succeeded one.
		b := latestBlip(blips)
		if runningBlip(blips) == nil {
			// An interruption can publish Failed while the controller later
			// records the generation as Succeeded. Reconcile that stale failure
			// on the next poll so a reopened or still-open tab settles to idle.
			d.mu.Lock()
			staleFailure := d.haveStatus && d.lastStatus.Phase == "Failed"
			d.mu.Unlock()
			if staleFailure && b != nil && b.Status.Phase == v1.BlipSucceeded {
				d.setStatus("Stopped", false, "agent exited")
			}
			return
		}
		if err := d.stopBlip(d.ctx); err != nil {
			d.log.Warn("stop orphaned agent", "session", d.state, "err", err)
			return
		}
		d.markEnded()
		d.setStatus("Stopped", false, "agent interrupted")
		return
	}
	phase, detail := "", ""
	b := latestBlip(blips)
	if b == nil {
		phase, detail = "Stopped", "agent stopped"
	} else {
		switch b.Status.Phase {
		case v1.BlipFailed:
			phase, detail = "Failed", b.Status.Message
			if detail == "" {
				detail = b.Status.Reason
			}
		case v1.BlipSaving:
			// Saving means the VM has already exited. If the driver still
			// thinks a turn is in flight, no end record will arrive.
			phase, detail = "Failed", b.Status.Message
			if detail == "" {
				detail = b.Status.Reason
			}
			if detail == "" {
				detail = "agent exited before the turn completed"
			}
		case v1.BlipSucceeded:
			phase, detail = "Succeeded", "agent exited"
		default:
			return
		}
	}
	d.markEnded()
	d.setStatus(phase, false, detail)
	d.advance()
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
	// The owner label scopes the agent's Kubernetes writes. Carry it from the
	// chat state, which owns this blip's tree.
	labels := map[string]string{LabelSession: d.state}
	if st, err := d.cluster.GetSession(ctx, d.namespace, d.state); err == nil {
		if owner := st.Labels[v1.LabelOwner]; owner != "" {
			labels[v1.LabelOwner] = owner
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
				Labels:    labels,
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
		if apierrors.IsNotFound(err) {
			// The blip was deleted while we waited for its VM. Treat it like a
			// failed start instead of blocking the driver for the full start
			// timeout; a queued prompt can then retry on a fresh generation.
			return nil, fmt.Errorf("%s disappeared before it started", name)
		}
		if err != nil {
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
	var targets []*v1.Blip
	for i := range blips {
		switch blips[i].Status.Phase {
		case v1.BlipRunning, v1.BlipPending:
			targets = append(targets, &blips[i])
		}
	}
	if len(targets) == 0 {
		d.setStatus("Stopped", false, "no running agent")
		return nil
	}
	// Stop every active generation, not just the newest. A retry after an
	// initialize timeout can leave an older generation Running while a newer
	// one finishes; stopping only the newest leaves the old VM holding the
	// session open and every detail request reporting running forever.
	for _, target := range targets {
		if err := d.cluster.StopBlip(ctx, d.namespace, target.Name); err != nil {
			return err
		}
	}
	d.mu.Lock()
	alreadyEnded := d.ended && d.haveStatus &&
		(d.lastStatus.Phase == "Stopped" || d.lastStatus.Phase == "Failed" || d.lastStatus.Phase == "Error")
	d.mu.Unlock()
	if !alreadyEnded {
		d.setStatus("Stopping", true, "stop requested")
	}
	// Wait briefly for the generations to leave Running/Pending before the
	// caller closes the turn. Otherwise the UI reports idle while the old VM
	// can still append output, and a queued follow-up races the state lease.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		blips, err := d.cluster.ListStateBlips(ctx, d.namespace, d.state)
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

func (d *driver) advance() {
	if d.unavailable != nil {
		return
	}
	d.advanceMu.Lock()
	defer d.advanceMu.Unlock()
	d.mu.Lock()
	if d.stopRequested || d.inflight || len(d.queue) == 0 || (!d.retryAfter.IsZero() && time.Now().Before(d.retryAfter)) {
		d.mu.Unlock()
		return
	}
	q := d.queue[0]
	d.queue = d.queue[1:]
	d.current = &q
	d.reply = ""
	d.mu.Unlock()

	// Record the user turn before the agent answers so every viewer sees the
	// message and its sender in order. A retry must not append it twice.
	if !q.recorded {
		d.recordUser(q.user, q.original, q.id)
		q.recorded = true
	}

	if err := d.sendPrompt(d.ctx, q.text, q.original, q.user, q.id); err != nil {
		d.mu.Lock()
		d.inflight = false
		d.current = nil
		cancelled := d.cancelStart
		if cancelled {
			d.cancelStart = false
			d.cancelledTurn = false
			d.initialized = false
			d.ended = true
		}
		stopped := d.stopRequested
		gaveUp := false
		if !cancelled && !stopped {
			q.attempts++
			if q.attempts >= maxStartAttempts {
				gaveUp = true
				if d.submitted > 0 {
					d.submitted--
				}
				delete(d.pending, q.id)
			} else {
				d.queue = append([]queuedPrompt{q}, d.queue...)
			}
		} else {
			delete(d.pending, q.id)
		}
		d.mu.Unlock()
		if cancelled || stopped || gaveUp {
			_ = d.persistPending()
		}
		if stopped {
			// opStop is queued behind this attempt. It closes the turn and
			// drops the prompts accepted for the agent we are stopping.
			return
		}
		if cancelled {
			// The user cancelled this turn while it was starting. Drop only
			// this prompt and run the prompts queued behind it on a fresh
			// agent/generation. Stop the aborted Blip first: it still holds
			// the state lease and blocks the next generation.
			if err := d.stopBlip(d.ctx); err != nil {
				d.log.Warn("cancel stop", "session", d.state, "err", err)
			}
			d.agent.Reset()
			d.setStatus("Cancelled", false, "cancel requested")
			go d.advance()
			return
		}
		// A failed start can leave the generation Running: ensureRunning may
		// have created the Blip before initialize/session-new timed out. That
		// old generation still holds the state lease, so a retry would create
		// a new generation stuck Pending on StateBusy forever. Stop it before
		// requeueing or giving up, and reset the agent so the next attempt
		// starts from a clean session.
		if err := d.stopBlip(d.ctx); err != nil {
			d.log.Warn("retry stop", "session", d.state, "err", err)
		}
		d.agent.Reset()
		d.mu.Lock()
		d.initialized = false
		d.ended = true
		d.mu.Unlock()

		d.log.Warn("prompt failed", "session", d.state, "attempts", q.attempts, "err", err)
		if gaveUp {
			// A permanent start failure applies to every prompt accepted for
			// this agent. Drop the rest of the queue too; otherwise those
			// messages remain visible but no retry or advance is scheduled and
			// they would sit unanswered until an unrelated send wakes the
			// driver.
			d.mu.Lock()
			dropped := len(d.queue)
			d.queue = nil
			if dropped > 0 {
				if d.submitted >= dropped {
					d.submitted -= dropped
				} else {
					d.submitted = 0
				}
			}
			d.pending = make(map[string]queuedPrompt)
			d.initialized = false
			d.ended = true
			d.mu.Unlock()
			d.agent.Reset()
			_ = d.persistPending()
			d.setStatus("Error", false, fmt.Sprintf("agent failed to start after %d attempts: %v", maxStartAttempts, err))
			return
		}
		d.setStatus("Error", false, err.Error())
		d.scheduleRetry(q.attempts)
		return
	}
	// The response may already have arrived and cleared the turn. Trust the
	// agent's pending set rather than blindly marking the turn in flight.
	pending := d.agent.Pending() > 0
	d.mu.Lock()
	d.inflight = pending
	d.mu.Unlock()
}

// scheduleRetry wakes the driver after a failed start. The delay keeps a
// queue of already accepted messages from turning into a generation storm
// while the pool is exhausted.
func (d *driver) scheduleRetry(attempt int) {
	d.mu.Lock()
	if d.ctx.Err() != nil || d.retryPending {
		d.mu.Unlock()
		return
	}
	delay := d.retryDelay
	if delay <= 0 {
		delay = defaultStartRetryDelay
	}
	if delay > maxStartRetryDelay {
		delay = maxStartRetryDelay
	}
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= maxStartRetryDelay {
			delay = maxStartRetryDelay
			break
		}
	}
	d.retryPending = true
	d.retryAfter = time.Now().Add(delay)
	d.mu.Unlock()
	time.AfterFunc(delay, func() {
		d.mu.Lock()
		d.retryPending = false
		d.retryAfter = time.Time{}
		d.mu.Unlock()
		if d.ctx.Err() != nil {
			return
		}
		if _, err := d.cluster.GetSession(d.ctx, d.namespace, d.state); apierrors.IsNotFound(err) {
			// The chat was deleted while a prompt was waiting to retry. Do
			// not keep creating blips for a state that no longer exists.
			d.markEnded()
			d.setStatus("Stopped", false, "chat removed")
			return
		}
		d.advance()
	})
}

func (d *driver) sendPrompt(ctx context.Context, text, original, sender, id string) error {
	meta := map[string]any{}
	if sender != "" {
		meta["blip.dev/sender"] = sender
	}
	if original != "" {
		// Keep the user's original text in the durable trajectory log so a
		// restarted blipchat can render it even when the profile wraps prompts.
		meta["blip.dev/text"] = original
	}
	if id != "" {
		meta["blip.dev/promptID"] = id
	}
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
		d.mu.Lock()
		stopped := d.stopRequested
		cancelled := d.cancelStart
		d.mu.Unlock()
		if stopped {
			return errStopRequested
		}
		if cancelled {
			return errStopRequested
		}
		if err := d.agent.Prompt(ctx, text, meta); err != nil {
			if errors.Is(err, ErrNotRunning) {
				d.markEnded()
				continue
			}
			return err
		}
		// Keep the prompt in the pending store until the agent actually
		// completes it. A transport-level success only means the request was
		// written; the agent can still reject it asynchronously (for example
		// "session already has an active prompt" after a restart). Keeping it
		// pending makes that case retryable instead of silently losing it.
		return nil
	}
	return errors.New("agent exited before accepting the prompt")
}

func (d *driver) startAgent(ctx context.Context) error {
	d.mu.Lock()
	if d.stopRequested {
		d.mu.Unlock()
		return errStopRequested
	}
	force := d.ended
	startCtx, cancel := context.WithCancel(ctx)
	d.startCancel = cancel
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.startCancel = nil
		d.mu.Unlock()
		cancel()
	}()
	_, err := d.ensureRunning(startCtx, force)
	if err != nil {
		return err
	}
	d.mu.Lock()
	stopped := d.stopRequested
	cancelled := d.cancelStart
	d.mu.Unlock()
	if stopped || cancelled {
		return errStopRequested
	}
	d.agent.Reset()
	sessionID, err := d.agent.Start(startCtx)
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
	// The in-flight prompt is over (completed, stopped, cancelled, or its
	// chat disappeared). Drop it from the pending map now: some callers clear
	// the turn before promptDone runs, and a later persist would otherwise
	// resurrect the answered/stopped prompt in the pending ConfigMap.
	if d.current != nil {
		delete(d.pending, d.current.id)
	}
	d.current = nil
	d.cancelStart = false
	d.cancelledTurn = false
	d.completed = d.submitted
	d.cancelSeq++
	d.mu.Unlock()
	d.agent.Reset()
	// Persist the removal so Stop and process-exit paths cannot leave a stale
	// blipchat-pending ConfigMap after the chat is idle.
	_ = d.persistPending()
}

func (d *driver) promptDone(promptErr error) {
	d.mu.Lock()
	d.inflight = false
	cur := d.current
	d.current = nil
	reading := d.reading
	if promptErr == nil && cur != nil {
		delete(d.pending, cur.id)
	}
	d.mu.Unlock()
	if promptErr != nil {
		if reading {
			go d.promptFailed(cur, promptErr)
		} else {
			d.promptFailed(cur, promptErr)
		}
		return
	}
	_ = d.persistPending()

	d.mu.Lock()
	d.completed++
	d.cancelSeq++
	cancelled := d.cancelledTurn
	d.cancelledTurn = false
	empty := len(d.queue) == 0
	initialized := d.initialized
	d.mu.Unlock()
	if !empty {
		if cancelled {
			// A cancelled turn can leave the ACP session unable to accept
			// another prompt. Start a fresh agent/generation for the queue.
			// Stop the old generation first: it still holds the state lease,
			// so a new generation created while it runs stays Pending on
			// StateBusy forever.
			d.mu.Lock()
			d.initialized = false
			d.ended = true
			d.mu.Unlock()
			d.agent.Reset()
			if err := d.stopBlip(d.ctx); err != nil {
				d.log.Warn("cancel stop", "session", d.state, "err", err)
			}
		}
		// Prompt completion is normally handled on the stream reader
		// goroutine. Starting an agent from there waits for the initialize
		// response, which only the reader can deliver, so move that advance to
		// a separate goroutine. Other callers (the simulation and tests) can
		// advance synchronously and keep deterministic ordering.
		if reading {
			go d.advance()
		} else {
			d.advance()
		}
		return
	}
	if initialized && d.agent.Pending() == 0 {
		d.endTurn()
	}
}

// promptFailed handles an asynchronous session/prompt error response. The
// agent originally accepted the request at the transport layer, but later
// rejected it (most commonly because a restarted driver reused an ACP session
// that still had an active prompt). Stop the old generation, requeue the
// prompt, and retry on a fresh generation instead of reporting the turn as
// complete and deleting the pending prompt.
func (d *driver) promptFailed(cur *queuedPrompt, promptErr error) {
	d.mu.Lock()
	cancelled := d.cancelStart || d.cancelledTurn || d.stopRequested
	gaveUp := false
	if cur != nil && !cancelled {
		cur.attempts++
		if cur.attempts >= maxStartAttempts {
			gaveUp = true
			if d.submitted > 0 {
				d.submitted--
			}
			delete(d.pending, cur.id)
		} else {
			d.queue = append([]queuedPrompt{*cur}, d.queue...)
		}
	} else if cur != nil {
		delete(d.pending, cur.id)
	}
	d.mu.Unlock()
	if cancelled {
		_ = d.persistPending()
		return
	}
	if err := d.stopBlip(d.ctx); err != nil {
		d.log.Warn("retry stop", "session", d.state, "err", err)
	}
	d.agent.Reset()
	d.mu.Lock()
	d.initialized = false
	d.ended = true
	d.mu.Unlock()
	_ = d.persistPending()
	d.log.Warn("prompt rejected", "session", d.state, "attempts", curAttempts(cur), "err", promptErr)
	if gaveUp {
		d.mu.Lock()
		dropped := len(d.queue)
		d.queue = nil
		if dropped > 0 {
			if d.submitted >= dropped {
				d.submitted -= dropped
			} else {
				d.submitted = 0
			}
		}
		d.pending = make(map[string]queuedPrompt)
		d.mu.Unlock()
		_ = d.persistPending()
		d.setStatus("Error", false, fmt.Sprintf("agent failed to start after %d attempts: %v", maxStartAttempts, promptErr))
		return
	}
	d.setStatus("Error", false, promptErr.Error())
	d.scheduleRetry(curAttempts(cur))
}

func curAttempts(q *queuedPrompt) int {
	if q == nil {
		return 0
	}
	return q.attempts
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

// recordUser appends a user turn to the transcript. The synthetic
// session/update carries the sender so every client can label the message
// with the identity the gateway forwarded.
func (d *driver) recordUser(user, text, id string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	update := map[string]any{
		"sessionUpdate": "user_message_chunk",
		"content":       []map[string]string{{"type": "text", "text": text}},
		"blipUser":      true,
	}
	if user != "" {
		update["sender"] = user
	}
	if id != "" {
		update["promptID"] = id
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params":  map[string]any{"update": update},
	})
	if err != nil {
		d.log.Warn("record user message", "err", err)
		return
	}
	d.acpMessage(raw)
}

func (d *driver) acpMessage(raw json.RawMessage) {
	d.mu.Lock()
	d.transcript = append(d.transcript, raw)
	d.txBytes += len(raw)
	for len(d.transcript) > maxTranscriptMessages || (d.txBytes > maxTranscriptBytes && len(d.transcript) > 1) {
		d.txBytes -= len(d.transcript[0])
		d.transcript = d.transcript[1:]
		d.txTruncated = true
	}
	d.mu.Unlock()
	d.hub.Publish(Event{Type: "acp", Message: raw})
	d.noteSessionInfo(raw)
	d.noteReply(raw)
}

// noteReply keeps the agent's latest answer so an MCP parent can read it
// without parsing the transcript.
func (d *driver) noteReply(raw json.RawMessage) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				Kind    string          `json:"sessionUpdate"`
				Content json.RawMessage `json:"content"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	if msg.Method != "session/update" || msg.Params.Update.Kind != "agent_message_chunk" {
		return
	}
	text := contentText(msg.Params.Update.Content)
	if text == "" {
		return
	}
	d.mu.Lock()
	if len(d.reply) < 64<<10 {
		d.reply += text
	}
	d.mu.Unlock()
}

// contentText accepts the shapes ACP uses for content: a string, a text
// object, or a list of either.
func contentText(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var one struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &one); err == nil {
		return one.Text
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err == nil {
		var b strings.Builder
		for _, item := range list {
			b.WriteString(contentText(item))
		}
		return b.String()
	}
	return ""
}

// noteSessionInfo saves the title an agent sets with ACP session_info_update.
// Agents may send it on any turn, so the last title wins. Updates replayed
// while loading a session never reach this point.
func (d *driver) noteSessionInfo(raw json.RawMessage) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				Kind  string          `json:"sessionUpdate"`
				Title json.RawMessage `json:"title"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	if msg.Method != "session/update" || msg.Params.Update.Kind != "session_info_update" || len(msg.Params.Update.Title) == 0 {
		return
	}
	// A null title clears the name, so an absent field and a null field mean
	// different things here.
	var title string
	if string(msg.Params.Update.Title) != "null" {
		if err := json.Unmarshal(msg.Params.Update.Title, &title); err != nil {
			return
		}
	}
	title = strings.TrimSpace(title)
	if runes := []rune(title); len(runes) > 200 {
		title = string(runes[:200])
	}
	d.mu.Lock()
	if d.haveTitle && d.title == title {
		d.mu.Unlock()
		return
	}
	d.title, d.haveTitle = title, true
	d.mu.Unlock()
	if err := d.patchAnnotations(map[string]string{AnnotationTitle: title}); err != nil {
		d.log.Warn("save title", "err", err)
	}
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

func (d *driver) patchAnnotations(annotations map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.cluster.PatchSession(ctx, d.namespace, d.state, nil, annotations)
}

func (d *driver) patchACPSession(id string) {
	if id == "" {
		return
	}
	if err := d.patchAnnotations(map[string]string{AnnotationACPSession: id}); err != nil {
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
		d.mu.Lock()
		d.reading = true
		d.mu.Unlock()
		d.agent.Feed(rec.Data)
		d.mu.Lock()
		d.reading = false
		d.mu.Unlock()
	case recordErr:
		d.emitOutput("stderr", rec.Data)
	case recordEnd:
		d.mu.Lock()
		current := d.generation
		queued := len(d.queue) > 0
		// A permanent start failure already published a terminal Error. The
		// agent process exits immediately afterwards and writes a recordEnd;
		// do not replace that actionable error with a generic Stopped status.
		keepError := d.haveStatus && (d.lastStatus.Phase == "Error" || d.lastStatus.Phase == "Failed")
		d.mu.Unlock()
		if current != 0 && (rec.Gen == 0 || rec.Gen >= current) {
			d.markEnded()
			if !keepError {
				d.setStatus("Stopped", false, "agent exited")
			}
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
