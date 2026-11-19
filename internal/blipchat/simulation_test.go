// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simtest"
)

// This file drives the production Hub, driver, and server teardown code through
// internal/sim. It deliberately does not run the driver's goroutine: every
// action calls the same production method the goroutine would call, but
// synchronously, so the exploration has no wall clock or scheduler in it.
//
// Hub model:
//
//	The initial world is a Hub whose ring has already wrapped and whose first
//	subscriber has overflowed its channel, drained the overflow, and received a
//	gap marker followed by the event that triggered it. Actions publish,
//	subscribe at exact replay boundaries, receive, and cancel. The model keeps
//	an oracle for channel occupancy and replay contents; production remains the
//	only implementation of publishing, dropping, gap insertion, replay, and
//	channel closure.
//
// Driver model:
//
//	A prompt starts a generation through the real ensureRunning/startAgent path;
//	outputs and end records go through readLog's handleRecord; a crash fails the
//	blip and ends the driver; the next prompt allocates the next generation and
//	loads the retained ACP session. A close action models session teardown. The
//	model verifies that transcript and Hub history are retained across restart,
//	that generation names and annotations are consistent, and that no event is
//	published after teardown.

const (
	hubSimMaxSubs = 2
	hubSimBudget  = 4

	driverSimNamespace = "team"
	driverSimState     = "chat-sim"
	driverSimBudget    = 4
)

// hashEvents canonically digests events for model keys. Payloads are small, but
// keys are built often during exploration, so hashing keeps them compact.
func hashEvents(events []Event) string {
	h := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(h, "%d,%s,%d,", ev.Offset, ev.Type, len(ev.Message))
		_, _ = h.Write(ev.Message)
		if ev.Status == nil {
			_, _ = h.Write([]byte("-,-;"))
			continue
		}
		fmt.Fprintf(h, "%s,%t,%s;", ev.Status.Phase, ev.Status.Running, ev.Status.Detail)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func equalEvents(a, b []Event) bool { return reflect.DeepEqual(a, b) }

// wantHubReplay is the oracle for Hub.Subscribe's replay cursor. It mirrors the
// public contract, not the production implementation: events after the cursor,
// from the retained ring, preceded by a gap marker only when the cursor is too
// old. after == 0 intentionally means "from the start of the retained ring"
// and therefore does not produce a gap.
func wantHubReplay(published []Event, after uint64) []Event {
	if len(published) == 0 {
		return nil
	}
	base := published[0].Offset
	if len(published) >= hubHistory {
		base = published[len(published)-hubHistory].Offset
	}
	var out []Event
	if after > 0 && after+1 < base {
		out = append(out, Event{Offset: base, Type: "gap"})
	}
	for _, ev := range published {
		if ev.Offset >= base && ev.Offset > after {
			out = append(out, ev)
		}
	}
	return out
}

type hubSimSub struct {
	id        string
	after     uint64
	at        int // number of events published when this subscriber appeared
	replay    []Event
	received  []Event
	queued    []Event // oracle for the buffered channel contents
	dropped   bool
	canceled  bool
	cancelSeq uint64
	closed    bool
	ch        <-chan Event
	cancel    func()
}

type hubSimulation struct {
	hub       *Hub
	published []Event
	subs      []*hubSimSub
	actions   []string
	budget    int
	nextEvent int
}

func buildHubSimulation(actions []string, budget int) *hubSimulation {
	m := &hubSimulation{hub: NewHub(), budget: budget}
	m.applySubscribe(0)
	// Wrap the ring and overflow the first subscriber's 256-slot channel.
	for i := 0; i < hubHistory+8; i++ {
		m.publishOne()
	}
	// Drain the overflowed channel. The subscriber remains marked as dropped,
	// which is exactly the state in which the next publish inserts a gap.
	for len(m.subs[0].queued) > 0 {
		if err := m.receive(m.subs[0].id); err != nil {
			panic("hub simulation setup: " + err.Error())
		}
	}
	// The next publish inserts a gap marker and then the triggering event.
	m.publishOne()
	for _, action := range actions {
		if err := m.apply(action); err != nil {
			panic("hub simulation replay: " + err.Error())
		}
	}
	m.actions = slices.Clone(actions)
	return m
}

func newHubSimulation() *hubSimulation { return buildHubSimulation(nil, hubSimBudget) }

func (m *hubSimulation) Clone() sim.Model { return buildHubSimulation(m.actions, m.budget) }

func (m *hubSimulation) Key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pub=%d/%s;next=%d;budget=%d;", len(m.published), hashEvents(m.published), m.nextEvent, m.budget)
	for _, sub := range m.subs {
		fmt.Fprintf(&b, "%s|after=%d|at=%d|replay=%d|recv=%s|queue=%s|drop=%t|cancel=%t/%d|closed=%t;",
			sub.id, sub.after, sub.at, len(sub.replay), hashEvents(sub.received), hashEvents(sub.queued),
			sub.dropped, sub.canceled, sub.cancelSeq, sub.closed)
	}
	return b.String()
}

func (m *hubSimulation) baseOffset() uint64 {
	if len(m.published) == 0 {
		return 0
	}
	if len(m.published) >= hubHistory {
		return m.published[len(m.published)-hubHistory].Offset
	}
	return m.published[0].Offset
}

func (m *hubSimulation) Enabled() []string {
	if m.budget == 0 {
		return nil
	}
	actions := []string{"publish"}
	if len(m.subs) < hubSimMaxSubs {
		seq := m.hub.Seq()
		actions = append(actions, "subscribe/live", "subscribe/start", "subscribe/one")
		if seq > uint64(hubHistory)+2 {
			actions = append(actions, "subscribe/old")
		}
		if base := m.baseOffset(); base > 1 {
			actions = append(actions, "subscribe/base", "subscribe/before-base")
		}
	}
	for _, sub := range m.subs {
		if !sub.canceled {
			if len(sub.queued) > 0 {
				actions = append(actions, "receive/"+sub.id)
			}
			actions = append(actions, "cancel/"+sub.id)
			continue
		}
		if !sub.closed {
			actions = append(actions, "receive/"+sub.id)
		}
	}
	return actions
}

func (m *hubSimulation) publishOne() {
	index := m.nextEvent
	m.nextEvent++
	raw := json.RawMessage(fmt.Sprintf(`{"n":%d}`, index))
	ev := Event{Type: "acp", Message: raw}
	m.hub.Publish(ev)
	ev.Offset = m.hub.Seq()
	m.published = append(m.published, ev)
	for _, sub := range m.subs {
		m.enqueue(sub, ev)
	}
}

// enqueue updates the channel oracle using the Hub's documented drop policy.
func (m *hubSimulation) enqueue(sub *hubSimSub, ev Event) {
	if sub.canceled {
		return
	}
	if sub.dropped {
		if len(sub.queued) == hubBuffer {
			return
		}
		sub.queued = append(sub.queued, Event{Offset: ev.Offset, Type: "gap"})
		sub.dropped = false
	}
	if len(sub.queued) == hubBuffer {
		sub.dropped = true
		return
	}
	sub.queued = append(sub.queued, ev)
}

func (m *hubSimulation) applySubscribe(after uint64) error {
	if len(m.subs) >= hubSimMaxSubs {
		return errors.New("too many subscribers")
	}
	replay, ch, cancel := m.hub.Subscribe(after)
	sub := &hubSimSub{
		id:       fmt.Sprintf("s%d", len(m.subs)),
		after:    after,
		at:       len(m.published),
		replay:   slices.Clone(replay),
		received: slices.Clone(replay),
		ch:       ch,
		cancel:   cancel,
	}
	m.subs = append(m.subs, sub)
	return nil
}

func (m *hubSimulation) subscribeCursor(action string) (uint64, error) {
	seq := m.hub.Seq()
	switch action {
	case "subscribe/live":
		return seq, nil
	case "subscribe/start":
		return 0, nil
	case "subscribe/one":
		return 1, nil
	case "subscribe/old":
		if seq <= uint64(hubHistory)+2 {
			return 0, errors.New("ring is not old enough for a gap")
		}
		return seq - uint64(hubHistory) - 2, nil
	case "subscribe/base":
		base := m.baseOffset()
		if base <= 1 {
			return 0, errors.New("ring is not trimmed")
		}
		return base, nil
	case "subscribe/before-base":
		base := m.baseOffset()
		if base <= 1 {
			return 0, errors.New("ring is not trimmed")
		}
		return base - 1, nil
	default:
		return 0, fmt.Errorf("unknown subscribe action %q", action)
	}
}

func (m *hubSimulation) receive(id string) error {
	var sub *hubSimSub
	for _, candidate := range m.subs {
		if candidate.id == id {
			sub = candidate
			break
		}
	}
	if sub == nil {
		return fmt.Errorf("unknown subscriber %q", id)
	}
	if len(sub.queued) > 0 {
		want := sub.queued[0]
		got, ok := <-sub.ch
		if !ok {
			return fmt.Errorf("%s: channel closed with %d buffered events", id, len(sub.queued))
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("%s: got %+v, want %+v", id, got, want)
		}
		sub.queued = sub.queued[1:]
		sub.received = append(sub.received, got)
		return nil
	}
	if !sub.canceled {
		return fmt.Errorf("%s: receive with an empty channel", id)
	}
	if ev, ok := <-sub.ch; ok {
		return fmt.Errorf("%s: unexpected event %+v after drain", id, ev)
	}
	sub.closed = true
	return nil
}

func (m *hubSimulation) apply(action string) error {
	switch action {
	case "publish":
		m.publishOne()
		return nil
	}
	if strings.HasPrefix(action, "subscribe/") {
		after, err := m.subscribeCursor(action)
		if err != nil {
			return err
		}
		return m.applySubscribe(after)
	}
	if id, ok := strings.CutPrefix(action, "receive/"); ok {
		return m.receive(id)
	}
	if id, ok := strings.CutPrefix(action, "cancel/"); ok {
		for _, sub := range m.subs {
			if sub.id != id {
				continue
			}
			if sub.canceled {
				return fmt.Errorf("%s: already canceled", id)
			}
			sub.canceled = true
			sub.cancelSeq = m.hub.Seq()
			sub.cancel()
			return nil
		}
		return fmt.Errorf("unknown subscriber %q", id)
	}
	return fmt.Errorf("unknown hub action %q", action)
}

func (m *hubSimulation) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond hub model budget")
	}
	if err := m.apply(action); err != nil {
		return err
	}
	m.actions = append(m.actions, action)
	m.budget--
	return nil
}

func (m *hubSimulation) Check() error {
	if len(m.subs) == 0 {
		return errors.New("model has no subscribers")
	}
	published := make(map[uint64]Event, len(m.published))
	for _, ev := range m.published {
		published[ev.Offset] = ev
	}
	for _, sub := range m.subs {
		if got := len(sub.ch); got != len(sub.queued) {
			return fmt.Errorf("%s: channel holds %d events, oracle holds %d", sub.id, got, len(sub.queued))
		}
		if sub.closed && !sub.canceled {
			return fmt.Errorf("%s: an uncanceled channel closed", sub.id)
		}
		if want := wantHubReplay(m.published[:sub.at], sub.after); !equalEvents(sub.replay, want) {
			return fmt.Errorf("%s: replay after %d = %+v, want %+v", sub.id, sub.after, sub.replay, want)
		}
		if len(sub.received) < len(sub.replay) {
			return fmt.Errorf("%s: received history shorter than its replay", sub.id)
		}
		live := sub.received[len(sub.replay):]
		last := sub.after
		if len(sub.replay) > 0 {
			last = sub.replay[len(sub.replay)-1].Offset
		}
		gapOffset := uint64(0)
		inGap := false
		seen := map[uint64]bool{}
		for _, ev := range live {
			if ev.Offset > m.hub.Seq() {
				return fmt.Errorf("%s: received unpublished offset %d", sub.id, ev.Offset)
			}
			if sub.canceled && ev.Offset > sub.cancelSeq {
				return fmt.Errorf("%s: received offset %d after cancel at %d", sub.id, ev.Offset, sub.cancelSeq)
			}
			if ev.Type == "gap" {
				if _, ok := published[ev.Offset]; !ok {
					return fmt.Errorf("%s: gap offset %d is not a published event", sub.id, ev.Offset)
				}
				inGap = true
				gapOffset = ev.Offset
				continue
			}
			want, ok := published[ev.Offset]
			if !ok {
				return fmt.Errorf("%s: event offset %d was never published", sub.id, ev.Offset)
			}
			if ev.Type != want.Type || !bytes.Equal(ev.Message, want.Message) {
				return fmt.Errorf("%s: offset %d payload %+v, want %+v", sub.id, ev.Offset, ev, want)
			}
			if seen[ev.Offset] {
				return fmt.Errorf("%s: duplicate event offset %d", sub.id, ev.Offset)
			}
			seen[ev.Offset] = true
			if inGap {
				if ev.Offset != gapOffset {
					return fmt.Errorf("%s: event %d after gap at %d", sub.id, ev.Offset, gapOffset)
				}
				inGap = false
			} else if ev.Offset != last+1 {
				return fmt.Errorf("%s: lost or duplicated event: %d after %d", sub.id, ev.Offset, last)
			}
			last = ev.Offset
		}
	}
	return nil
}

func TestHubSimulation(t *testing.T) {
	initial := newHubSimulation()
	report := simtest.Explore(t, initial, sim.Limits{States: 20000, Depth: hubSimBudget})
	if !report.Complete {
		t.Fatalf("incomplete hub exploration: %+v", report)
	}
	t.Logf("hub: %d states, %d transitions", report.States, report.Transitions)

	simtest.Run(t, initial, simtest.Seeds(0, 16), hubSimBudget)
}

// TestHubReplayBoundaryScript names the exact replay boundaries used by the
// exploration: the last retained offset (no gap), the first retained offset
// (no gap), and one offset older than the ring (gap at the first retained
// offset). A cursor of zero intentionally reads the retained ring without a
// gap.
func TestHubReplayBoundaryScript(t *testing.T) {
	for _, action := range []string{
		"subscribe/before-base",
		"subscribe/base",
		"subscribe/start",
		"subscribe/old",
		"subscribe/live",
	} {
		t.Run(action, func(t *testing.T) {
			model := newHubSimulation()
			if err := model.Step(action); err != nil {
				t.Fatal(err)
			}
			if err := model.Check(); err != nil {
				t.Fatal(err)
			}
			if len(model.subs) != 2 {
				t.Fatalf("got %d subscribers", len(model.subs))
			}
			sub := model.subs[1]
			want := wantHubReplay(model.published[:sub.at], sub.after)
			if !equalEvents(sub.replay, want) {
				t.Fatalf("replay after %d = %+v, want %+v", sub.after, sub.replay, want)
			}
			base := model.baseOffset()
			switch action {
			case "subscribe/before-base":
				if sub.after != base-1 || len(sub.replay) == 0 || sub.replay[0].Offset != base || sub.replay[0].Type == "gap" {
					t.Fatalf("before-base replay = %+v (base %d)", sub.replay, base)
				}
			case "subscribe/base":
				if sub.after != base || len(sub.replay) == 0 || sub.replay[0].Offset != base+1 {
					t.Fatalf("base replay = %+v (base %d)", sub.replay, base)
				}
			case "subscribe/start":
				if sub.after != 0 || len(sub.replay) == 0 || sub.replay[0].Offset != base || sub.replay[0].Type == "gap" {
					t.Fatalf("start replay = %+v (base %d)", sub.replay, base)
				}
			case "subscribe/old":
				if len(sub.replay) < 2 || sub.replay[0].Type != "gap" || sub.replay[0].Offset != base || sub.replay[1].Offset != base {
					t.Fatalf("old replay = %+v (base %d)", sub.replay, base)
				}
			case "subscribe/live":
				if len(sub.replay) != 0 {
					t.Fatalf("live replay = %+v", sub.replay)
				}
			}
		})
	}
}

// TestHubSimulationNegativeControl proves that Check catches a missing gap
// marker instead of accepting any received sequence.
func TestHubSimulationNegativeControl(t *testing.T) {
	model := newHubSimulation()
	if err := model.Step("receive/s0"); err != nil {
		t.Fatal(err)
	}
	if err := model.Step("receive/s0"); err != nil {
		t.Fatal(err)
	}
	if err := model.Check(); err != nil {
		t.Fatalf("baseline model: %v", err)
	}
	broken := model.Clone().(*hubSimulation)
	for _, sub := range broken.subs {
		for i, ev := range sub.received {
			if ev.Type == "gap" {
				sub.received = append(slices.Clone(sub.received[:i]), sub.received[i+1:]...)
				if err := broken.Check(); err == nil {
					t.Fatal("Check accepted a skipped event without a gap")
				}
				return
			}
		}
	}
	t.Fatal("initial model has no gap marker to remove")
}

// ---------------------------------------------------------------------------
// Driver simulation
// ---------------------------------------------------------------------------

type simPrompt struct {
	ID   json.RawMessage
	Text string
}

type simDriverWire struct {
	mu           sync.Mutex
	agent        *acpAgent
	methods      []string
	prompts      []simPrompt
	eofs         int
	lastPromptID json.RawMessage
}

func newSimDriverWire() *simDriverWire { return &simDriverWire{} }

func (w *simDriverWire) Send(_ context.Context, _, _ string, data []byte, eof bool) error {
	if eof {
		w.mu.Lock()
		w.eofs++
		w.mu.Unlock()
		return nil
	}
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Prompt []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"prompt"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}
	w.mu.Lock()
	if req.Method != "" {
		w.methods = append(w.methods, req.Method)
	}
	var result any
	switch req.Method {
	case "initialize":
		result = map[string]any{"agentCapabilities": map[string]any{"loadSession": true}}
	case "session/new":
		result = map[string]any{"sessionId": "acp-sim-session"}
	case "session/load", "session/resume":
		result = map[string]any{}
	case "session/prompt":
		text := ""
		if len(req.Params.Prompt) > 0 {
			text = req.Params.Prompt[0].Text
		}
		w.prompts = append(w.prompts, simPrompt{ID: slices.Clone(req.ID), Text: text})
		w.lastPromptID = slices.Clone(req.ID)
	}
	agent := w.agent
	w.mu.Unlock()
	if result != nil && agent != nil {
		line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if err != nil {
			return err
		}
		agent.Feed(append(line, '\n'))
	}
	return nil
}

func (w *simDriverWire) OpenLog(context.Context, string, string, uint64) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (w *simDriverWire) respond() error {
	w.mu.Lock()
	id := slices.Clone(w.lastPromptID)
	w.mu.Unlock()
	if len(id) == 0 {
		return errors.New("no pending prompt")
	}
	if w.agent == nil {
		return errors.New("wire has no agent")
	}
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"stopReason":"end_turn"}}`, id)
	w.agent.Feed([]byte(line + "\n"))
	return nil
}

func (w *simDriverWire) snapshot() (methods, prompts []string, eofs int, last string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	methods = slices.Clone(w.methods)
	for _, p := range w.prompts {
		prompts = append(prompts, p.Text)
	}
	return methods, prompts, w.eofs, string(w.lastPromptID)
}

func (w *simDriverWire) loadCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, m := range w.methods {
		if m == "session/load" || m == "session/resume" {
			n++
		}
	}
	return n
}

type driverSimulation struct {
	fc     *fakeCluster
	wire   *simDriverWire
	d      *driver
	action []string
	budget int

	nextLog  uint64
	promptNo int

	sawCrash            bool
	restartedAfterCrash bool
	crashGen            uint64
	crashTranscript     []json.RawMessage
	crashHub            []Event
	loadsAtCrash        int

	closed     bool
	seqAtClose uint64
}

func buildDriverSimulation(actions []string, budget int) *driverSimulation {
	ctx := context.Background()
	fc := newFakeCluster()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      driverSimState,
			Namespace: driverSimNamespace,
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationTitle:   "Simulation",
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, driverSimNamespace, state); err != nil {
		panic(err)
	}
	wire := newSimDriverWire()
	profile := Profiles{DefaultProfileName: {}}.get(DefaultProfileName, "default")
	d := newDriver(driverOptions{
		Cluster:     fc,
		Wire:        wire,
		Hub:         NewHub(),
		Log:         testLogger(),
		Namespace:   driverSimNamespace,
		State:       driverSimState,
		Profile:     profile,
		AutoApprove: "always",
	})
	// ACP request ids are the only random input in the driver path. Pinning the
	// prefix makes transcripts and hence model keys reproducible.
	d.agent.idPrefix = "sim"
	wire.agent = d.agent

	m := &driverSimulation{fc: fc, wire: wire, d: d, budget: budget, nextLog: 1}
	for _, action := range actions {
		if err := m.apply(action); err != nil {
			panic("driver simulation replay: " + err.Error())
		}
	}
	m.action = slices.Clone(actions)
	return m
}

func newDriverSimulation() *driverSimulation {
	return buildDriverSimulation(nil, driverSimBudget)
}

func (m *driverSimulation) Clone() sim.Model { return buildDriverSimulation(m.action, m.budget) }

func (m *driverSimulation) driverLocked() (gen uint64, offset uint64, haveOffset, initialized, ended, inflight bool, queue []string, persisted uint64, havePersist bool, status Status, haveStatus bool, transcriptHash string) {
	d := m.d
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.generation, d.offset, d.haveOffset, d.initialized, d.ended, d.inflight,
		slices.Clone(d.queue), d.persisted, d.havePersist, d.lastStatus, d.haveStatus, hashRaw(d.transcript)
}

func hashRaw(messages []json.RawMessage) string {
	h := sha256.New()
	for _, raw := range messages {
		fmt.Fprintf(h, "%d,", len(raw))
		_, _ = h.Write(raw)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func rawPrefix(got, want []json.RawMessage) bool {
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

func (m *driverSimulation) Key() string {
	d := m.d
	gen, offset, haveOffset, initialized, ended, inflight, queue, persisted, havePersist, status, haveStatus, txHash := m.driverLocked()
	d.agent.mu.Lock()
	idSeq := d.agent.idSeq
	sessionID := d.agent.sessionID
	replaying := d.agent.replaying
	loadSession := d.agent.loadSession
	resumeSession := d.agent.resumeSession
	pending := len(d.agent.pending)
	bufLen := len(d.agent.buf)
	d.agent.mu.Unlock()

	methods, prompts, eofs, lastPrompt := m.wire.snapshot()
	names := m.fc.blipNames()
	var blips strings.Builder
	for _, name := range names {
		b, err := m.fc.GetBlip(context.Background(), driverSimNamespace, name)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&blips, "%s:%s:%t:%s;", b.Name, b.Status.Phase, b.Spec.Stop, b.Annotations[AnnotationGeneration])
	}
	st, err := m.fc.GetSession(context.Background(), driverSimNamespace, driverSimState)
	if err != nil {
		panic(err)
	}
	hub := hubReplay(d.hub)

	var b strings.Builder
	fmt.Fprintf(&b, "gen=%d;off=%d/%t;init=%t;ended=%t;inflight=%t;queue=%s;persist=%d/%t;",
		gen, offset, haveOffset, initialized, ended, inflight, strings.Join(queue, "\x1f"), persisted, havePersist)
	if haveStatus {
		fmt.Fprintf(&b, "status=%s/%t/%s;", status.Phase, status.Running, status.Detail)
	} else {
		b.WriteString("status=none;")
	}
	fmt.Fprintf(&b, "tx=%s;hub=%s;seq=%d;", txHash, hashEvents(hub), d.hub.Seq())
	fmt.Fprintf(&b, "agent=%d/%s/%t/%t/%t/%d/%d;", idSeq, sessionID, replaying, loadSession, resumeSession, pending, bufLen)
	fmt.Fprintf(&b, "wire=%s/%s/%d/%s;", strings.Join(methods, ","), strings.Join(prompts, "\x1f"), eofs, lastPrompt)
	fmt.Fprintf(&b, "blips=%s;sess=%s/%s;next=%d;prompt=%d;budget=%d;",
		blips.String(), st.Annotations[AnnotationACPSession], st.Annotations[AnnotationOffset], m.nextLog, m.promptNo, m.budget)
	fmt.Fprintf(&b, "closed=%t/%d;crash=%t/%t/%d/%s/%s/%d;",
		m.closed, m.seqAtClose, m.sawCrash, m.restartedAfterCrash, m.crashGen,
		hashRaw(m.crashTranscript), hashEvents(m.crashHub), m.loadsAtCrash)
	return b.String()
}

func hubReplay(h *Hub) []Event {
	replay, _, cancel := h.Subscribe(0)
	cancel()
	return replay
}

func simBlipPhase(t *testing.T, fc *fakeCluster, name string) string {
	t.Helper()
	b, err := fc.GetBlip(context.Background(), driverSimNamespace, name)
	if err != nil {
		t.Fatal(err)
	}
	return b.Status.Phase
}

func (m *driverSimulation) anyStoppable() bool {
	m.fc.mu.Lock()
	defer m.fc.mu.Unlock()
	for _, b := range m.fc.blips {
		if b.Status.Phase == v1.BlipRunning || b.Status.Phase == v1.BlipPending {
			return true
		}
	}
	return false
}

func (m *driverSimulation) Enabled() []string {
	if m.budget == 0 || m.closed {
		return nil
	}
	d := m.d
	d.mu.Lock()
	initialized := d.initialized
	queueLen := len(d.queue)
	haveOffset := d.haveOffset
	d.mu.Unlock()
	pending := d.agent.Pending()

	set := map[string]bool{"prompt": true, "close": true}
	if initialized {
		set["output"] = true
		set["gap"] = true
		set["cancel"] = true
		if queueLen == 0 {
			set["crash"] = true
		}
	}
	if pending > 0 {
		set["respond"] = true
	}
	if haveOffset {
		set["gap"] = true
		set["persist"] = true
	}
	if m.anyStoppable() {
		set["stop"] = true
	}
	actions := make([]string, 0, len(set))
	for action := range set {
		actions = append(actions, action)
	}
	return actions
}

func (m *driverSimulation) applyPrompt() {
	m.promptNo++
	m.d.handleOp(operation{kind: opPrompt, text: fmt.Sprintf("message-%d", m.promptNo)})
	if m.sawCrash && !m.restartedAfterCrash && m.d.generation > m.crashGen {
		m.restartedAfterCrash = true
	}
}

func (m *driverSimulation) applyOutput() error {
	offset := m.nextLog
	m.nextLog++
	line := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"session/update","params":{"n":%d}}`+"\n", offset))
	m.d.handleRecord(streamLogRecord{Offset: offset, Gen: m.d.generation, Type: recordOut, Data: line})
	if !m.d.haveOffset || m.d.offset != offset {
		return fmt.Errorf("output offset = %d/%t, want %d", m.d.offset, m.d.haveOffset, offset)
	}
	return nil
}

func (m *driverSimulation) applyGap() error {
	offset := m.nextLog
	before := m.d.offset
	seq := m.d.hub.Seq()
	m.d.handleRecord(streamLogRecord{Offset: offset, Gen: m.d.generation, Type: recordGap})
	if m.d.offset != before {
		return fmt.Errorf("gap moved the consumed offset from %d to %d", before, m.d.offset)
	}
	if m.d.hub.Seq() != seq+1 {
		return fmt.Errorf("gap did not publish exactly one event")
	}
	return nil
}

func (m *driverSimulation) applyCrash() error {
	if m.d.generation == 0 {
		return errors.New("crash without a generation")
	}
	name := fmt.Sprintf("%s-g%d", driverSimState, m.d.generation)
	m.fc.mu.Lock()
	b, ok := m.fc.blips[driverSimNamespace+"/"+name]
	if !ok {
		m.fc.mu.Unlock()
		return fmt.Errorf("missing generation %s", name)
	}
	b.Status.Phase = v1.BlipFailed
	b.Status.Message = "simulated crash"
	m.fc.mu.Unlock()

	m.crashGen = m.d.generation
	m.crashTranscript = slices.Clone(m.d.transcript)
	m.crashHub = hubReplay(m.d.hub)
	m.loadsAtCrash = m.wire.loadCount()
	m.sawCrash = true
	m.restartedAfterCrash = false

	offset := m.nextLog
	m.nextLog++
	m.d.handleRecord(streamLogRecord{Offset: offset, Gen: m.crashGen, Type: recordEnd})
	if !m.d.ended {
		return errors.New("crash did not end the driver")
	}
	m.d.mu.Lock()
	status := m.d.lastStatus
	m.d.mu.Unlock()
	if status.Phase != "Stopped" {
		return fmt.Errorf("crash status = %q, want Stopped", status.Phase)
	}
	return nil
}

func (m *driverSimulation) apply(action string) error {
	switch action {
	case "prompt":
		m.applyPrompt()
		return nil
	case "output":
		return m.applyOutput()
	case "gap":
		return m.applyGap()
	case "respond":
		return m.wire.respond()
	case "crash":
		return m.applyCrash()
	case "cancel":
		m.d.handleOp(operation{kind: opCancel})
		return nil
	case "stop":
		m.d.handleOp(operation{kind: opStop})
		return nil
	case "persist":
		m.d.persistOffset()
		return nil
	case "close":
		m.seqAtClose = m.d.hub.Seq()
		m.d.Close()
		m.closed = true
		return nil
	default:
		return fmt.Errorf("unknown driver action %q", action)
	}
}

func (m *driverSimulation) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond driver model budget")
	}
	if m.closed {
		return errors.New("step after driver teardown")
	}
	if err := m.apply(action); err != nil {
		return err
	}
	m.action = append(m.action, action)
	m.budget--
	return nil
}

func (m *driverSimulation) Check() error {
	d := m.d
	gen, offset, haveOffset, _, _, _, _, persisted, havePersist, _, _, transcriptHash := m.driverLocked()
	_ = transcriptHash

	hub := hubReplay(d.hub)
	seq := d.hub.Seq()
	if len(hub) > hubHistory {
		return fmt.Errorf("hub retained %d events, more than its ring", len(hub))
	}
	for i, ev := range hub {
		if ev.Offset == 0 || (i > 0 && ev.Offset <= hub[i-1].Offset) {
			return fmt.Errorf("hub replay offsets not strictly increasing at %d: %+v", i, hub)
		}
	}
	if seq > 0 && (len(hub) == 0 || hub[len(hub)-1].Offset != seq) {
		return fmt.Errorf("hub seq %d does not match retained history", seq)
	}

	names := m.fc.blipNames()
	gens := map[int64]bool{}
	maxGen := int64(0)
	for _, name := range names {
		b, err := m.fc.GetBlip(context.Background(), driverSimNamespace, name)
		if err != nil {
			return err
		}
		g := generationOf(b)
		if g <= 0 {
			return fmt.Errorf("blip %q has generation %d", name, g)
		}
		if gens[g] {
			return fmt.Errorf("duplicate blip generation %d", g)
		}
		gens[g] = true
		if want := fmt.Sprintf("%s-g%d", driverSimState, g); name != want {
			return fmt.Errorf("generation %d is named %q, want %q", g, name, want)
		}
		if b.Annotations[AnnotationGeneration] != strconv.FormatInt(g, 10) {
			return fmt.Errorf("generation annotation on %q is %q", name, b.Annotations[AnnotationGeneration])
		}
		if g > maxGen {
			maxGen = g
		}
	}
	if gen > 0 && uint64(maxGen) != gen {
		return fmt.Errorf("driver generation %d, newest blip generation %d", gen, maxGen)
	}
	if gen == 0 && maxGen != 0 {
		return fmt.Errorf("driver has generation 0 but blips reach %d", maxGen)
	}

	sessionID := d.agent.SessionID()
	st, err := m.fc.GetSession(context.Background(), driverSimNamespace, driverSimState)
	if err != nil {
		return err
	}
	if sessionID != "" && st.Annotations[AnnotationACPSession] != sessionID {
		return fmt.Errorf("acp session annotation %q, driver has %q", st.Annotations[AnnotationACPSession], sessionID)
	}
	if havePersist {
		raw := st.Annotations[AnnotationOffset]
		persistedAnnotation, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("persisted offset annotation %q: %w", raw, err)
		}
		if persistedAnnotation != persisted {
			return fmt.Errorf("persisted offset annotation %d, driver persisted %d", persistedAnnotation, persisted)
		}
		if haveOffset && persisted > offset {
			return fmt.Errorf("persisted offset %d is ahead of consumed offset %d", persisted, offset)
		}
	}

	if m.restartedAfterCrash {
		if gen <= m.crashGen {
			return fmt.Errorf("restart did not advance generation past %d", m.crashGen)
		}
		d.mu.Lock()
		transcript := slices.Clone(d.transcript)
		d.mu.Unlock()
		if !rawPrefix(transcript, m.crashTranscript) {
			return errors.New("restart corrupted retained transcript history")
		}
		current := make(map[uint64]Event, len(hub))
		for _, ev := range hub {
			current[ev.Offset] = ev
		}
		for _, want := range m.crashHub {
			got, ok := current[want.Offset]
			if !ok {
				return fmt.Errorf("restart lost retained hub event %d", want.Offset)
			}
			if !reflect.DeepEqual(got, want) {
				return fmt.Errorf("restart changed retained hub event %d: %+v -> %+v", want.Offset, want, got)
			}
		}
		if m.wire.loadCount() <= m.loadsAtCrash {
			return errors.New("restart did not load the retained ACP session")
		}
	}

	if m.closed {
		if d.ctx.Err() == nil {
			return errors.New("teardown did not cancel the driver context")
		}
		if got := d.hub.Seq(); got != m.seqAtClose {
			return fmt.Errorf("teardown published %d events after close", got-m.seqAtClose)
		}
	}
	return nil
}

func TestDriverSimulation(t *testing.T) {
	initial := newDriverSimulation()
	report := simtest.Explore(t, initial, sim.Limits{States: 20000, Depth: driverSimBudget})
	if !report.Complete {
		t.Fatalf("incomplete driver exploration: %+v", report)
	}
	t.Logf("driver: %d states, %d transitions", report.States, report.Transitions)

	simtest.Run(t, initial, simtest.Seeds(0, 16), driverSimBudget)
}

// TestDriverCrashRestartScript follows one path past the exploration depth. It
// is the explicit statement of the crash/restart invariant: the failed
// generation stays visible, the next prompt allocates a new generation, the ACP
// session is loaded again, and the transcript and Hub history from before the
// crash survive unchanged.
func TestDriverCrashRestartScript(t *testing.T) {
	model := buildDriverSimulation(nil, 6)
	for _, action := range []string{"prompt", "output", "crash", "prompt", "output", "respond"} {
		if err := model.Step(action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if err := model.Check(); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if model.crashGen != 1 || !model.sawCrash {
		t.Fatalf("crash = %d/%t", model.crashGen, model.sawCrash)
	}
	if !model.restartedAfterCrash || model.d.generation != 2 {
		t.Fatalf("restart = %t, generation %d", model.restartedAfterCrash, model.d.generation)
	}
	if model.wire.loadCount() == 0 {
		t.Fatal("restart did not load the ACP session")
	}
	names := model.fc.blipNames()
	if len(names) != 2 || names[0] != driverSimState+"-g1" || names[1] != driverSimState+"-g2" {
		t.Fatalf("generations = %v", names)
	}
	if got := simBlipPhase(t, model.fc, driverSimState+"-g1"); got != v1.BlipFailed {
		t.Fatalf("crashed generation phase = %s", got)
	}
	d := model.d
	d.mu.Lock()
	transcript := slices.Clone(d.transcript)
	d.mu.Unlock()
	if !rawPrefix(transcript, model.crashTranscript) || len(transcript) <= len(model.crashTranscript) {
		t.Fatalf("transcript was not retained and extended: before %d, after %d", len(model.crashTranscript), len(transcript))
	}
}

// TestDriverSimulationNegativeControl proves Check notices a generation that was
// renamed behind the driver's back.
func TestDriverSimulationNegativeControl(t *testing.T) {
	model := newDriverSimulation()
	if err := model.Step("prompt"); err != nil {
		t.Fatal(err)
	}
	if err := model.Check(); err != nil {
		t.Fatalf("baseline model: %v", err)
	}
	broken := model.Clone().(*driverSimulation)
	broken.fc.mu.Lock()
	broken.fc.blipOrder[0] = "not-the-generation"
	broken.fc.mu.Unlock()
	if err := broken.Check(); err == nil {
		t.Fatal("Check accepted a renamed generation")
	}
	if err := model.Check(); err != nil {
		t.Fatalf("negative control mutated the original: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Server session teardown
// ---------------------------------------------------------------------------

type teardownWire struct {
	opened chan struct{}
	once   sync.Once
}

type teardownReader struct {
	ctx context.Context
	w   *teardownWire
}

func (r *teardownReader) Read([]byte) (int, error) {
	r.w.once.Do(func() { close(r.w.opened) })
	<-r.ctx.Done()
	return 0, io.EOF
}

func (r *teardownReader) Close() error { return nil }

func (w *teardownWire) Send(context.Context, string, string, []byte, bool) error { return nil }

func (w *teardownWire) OpenLog(ctx context.Context, _, _ string, _ uint64) (io.ReadCloser, error) {
	return &teardownReader{ctx: ctx, w: w}, nil
}

// TestSessionTeardownSimulation uses the real Server.driverFor and Server.Close
// path. It waits on the log reader rather than a timer to establish that the
// driver has started, then proves Close empties the registry and cancels the
// driver context. A subscriber created before teardown observes a closed
// channel and receives no event published after cancellation.
func TestSessionTeardownSimulation(t *testing.T) {
	fc := newFakeCluster()
	ctx := context.Background()
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-teardown",
			Namespace: driverSimNamespace,
			Labels:    map[string]string{LabelSession: "true"},
			Annotations: map[string]string{
				AnnotationTitle:   "Teardown",
				AnnotationProfile: DefaultProfileName,
			},
		},
	}
	if err := fc.CreateSession(ctx, driverSimNamespace, state); err != nil {
		t.Fatal(err)
	}
	wire := &teardownWire{opened: make(chan struct{})}
	s, err := New(Options{
		Namespace:   driverSimNamespace,
		Profiles:    Profiles{DefaultProfileName: {}},
		DefaultPool: "default",
		AutoApprove: "always",
		Cluster:     fc,
		Wire:        wire,
		Log:         testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	d, err := s.driverFor(ctx, driverSimNamespace, "chat-teardown")
	if err != nil {
		t.Fatal(err)
	}
	<-wire.opened // the driver's readLog is now attached

	_, ch, cancel := d.hub.Subscribe(d.hub.Seq())
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("canceled subscription is still open")
	}

	s.Close()
	if got := s.lookupDriver(driverSimNamespace, "chat-teardown"); got != nil {
		t.Fatalf("teardown retained driver %p", got)
	}
	if d.ctx.Err() == nil {
		t.Fatal("teardown did not cancel the driver context")
	}
	d.hub.Publish(Event{Type: "acp", Message: json.RawMessage(`{"after":"close"}`)})
	if ev, ok := <-ch; ok {
		t.Fatalf("canceled subscription received %+v", ev)
	}
	s.Close() // repeated teardown is safe
}
