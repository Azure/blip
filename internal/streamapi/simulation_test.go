// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

// This file models the aggregated stream API server, not the node's trajectory
// ring. Every request below is executed by the production Handler (serveHTTP,
// authenticate/authorize, serveLog/serveStdin, recordWriter and
// writeBackendError). A simulated Backend stands in for the node agent and
// models only the boundary the server is documented to see:
//
//   - A bounded append-only record history with byte offsets, generations and
//     retained-head trimming. The backend is allowed to return retained records
//     at or after the requested offset, to emit a gap at the retained head for a
//     stale cursor, and to return the package's sentinel errors.
//   - A process-generation lifecycle: running, restarting (no ready stream) and
//     exited (stdin closed). Restart increments the generation; reconnect
//     appends a TypeStart for the new generation. The trajectory survives the
//     restart, so an old cursor continues to refer to the same history.
//   - EOF closes stdin. A later stdin request is rejected before any record is
//     appended or forwarded.
//   - A "lost reply" is modeled where the boundary can express it: stdin is
//     appended before forwarding, and the forward then fails; a log response
//     loses bytes after the status and part of a record. These are ambiguous
//     results, not a reimplementation of HTTP.
//
// The API has no generation query parameter. Generation staleness is therefore
// modeled where production can observe it: a request that arrives while the
// node attachment is restarting is rejected by the backend with ErrNotReady,
// and stdin for an exited/closed generation is rejected with ErrClosed. The
// server is responsible for turning those into 503/409 without opening a
// stream, forwarding input, or writing more response status after streaming
// has started. The modeled client follows the real CLI/chat cursor convention:
// it asks for the last consumed record offset and drops the re-delivered
// overlap, so transcript offsets stay strictly increasing.
//
// Deliberately outside this model: discovery endpoints, TLS certificate and
// bearer-token authentication (covered by auth_test.go), raw=1 framing, bad
// query parameters, and the real node ring/peer transport.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simtest"
	"github.com/Azure/blip/internal/stream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const (
	// simLogBatch bounds one backend log read. A small batch forces reconnects
	// and overlap handling rather than draining everything in one request.
	simLogBatch = 2
	// simBudget bounds every explored path. The world always has another guest
	// or request action, so a finite action budget is what makes Explore
	// terminate with Complete instead of truncating at a depth limit.
	simBudget = 6
	// simStates bounds retained nodes for the exhaustive search.
	simStates = 40000
)

var (
	errSimLostFrame = errors.New("simulation: response frame lost")
	errSimLostReply = errors.New("simulation: stdin forward result lost")
)

type simPhase uint8

const (
	simRunning simPhase = iota + 1
	simRestarting
	simExited
)

func (p simPhase) String() string {
	switch p {
	case simRunning:
		return "running"
	case simRestarting:
		return "restarting"
	case simExited:
		return "exited"
	default:
		return "unknown"
	}
}

// simRecord is a trajectory record as the backend stores it. Offsets are byte
// offsets, matching stream.Record.
type simRecord struct {
	offset uint64
	gen    uint64
	typ    stream.RecordType
	data   []byte
}

func (r simRecord) size() uint64 { return uint64(stream.RecordHeader + len(r.data)) }

// simWorld is the independent external world: the retained ring, durable
// history, node generation and stdin state. It never implements API framing or
// authorization.
type simWorld struct {
	gen         uint64
	phase       simPhase
	head        uint64
	tail        uint64
	stdinClosed bool
	retained    []simRecord
	history     []simRecord

	// Counters are observation state for request invariants. They do not affect
	// future behavior, so Key omits them.
	openReaders int
	logCalls    int
	stdinCalls  int
	forwarded   []byte
	gaps        int
}

func (w *simWorld) clone() simWorld {
	c := *w
	c.retained = slices.Clone(w.retained)
	for i := range c.retained {
		c.retained[i].data = slices.Clone(c.retained[i].data)
	}
	c.history = slices.Clone(w.history)
	for i := range c.history {
		c.history[i].data = slices.Clone(c.history[i].data)
	}
	c.forwarded = slices.Clone(w.forwarded)
	return c
}

func (w *simWorld) appendRecord(gen uint64, typ stream.RecordType, data []byte) simRecord {
	rec := simRecord{offset: w.tail, gen: gen, typ: typ, data: slices.Clone(data)}
	w.retained = append(w.retained, rec)
	w.history = append(w.history, rec)
	w.tail += rec.size()
	return rec
}

// trim drops the oldest retained record, as the production ring does when it
// needs space. History is never trimmed: it is the monitor's durable ledger.
func (w *simWorld) trim() {
	if len(w.retained) <= 1 {
		return
	}
	w.retained = w.retained[1:]
	w.head = w.retained[0].offset
}

// simConsumer is the modeled client cursor. from is the offset sent on the next
// log request; last is the last fully consumed record. The production clients
// request last again on reconnect and skip the duplicate, which this model
// reproduces and checks.
type simConsumer struct {
	from       uint64
	last       uint64
	haveLast   bool
	endedGen   uint64
	transcript []simRecord
}

func (c simConsumer) clone() simConsumer {
	out := c
	out.transcript = slices.Clone(c.transcript)
	for i := range out.transcript {
		out.transcript[i].data = slices.Clone(out.transcript[i].data)
	}
	return out
}

type apiSimulation struct {
	world  simWorld
	client simConsumer
	budget int
}

func newAPISimulation() *apiSimulation {
	w := simWorld{gen: 1, phase: simRunning}
	w.appendRecord(1, stream.TypeStart, nil)
	w.appendRecord(1, stream.TypeOut, []byte("hello"))
	w.appendRecord(1, stream.TypeErr, []byte("warn"))
	return &apiSimulation{world: w, budget: simBudget}
}

func (m *apiSimulation) Clone() sim.Model {
	c := *m
	c.world = m.world.clone()
	c.client = m.client.clone()
	return &c
}

// Key includes the durable history as well as the retained window because the
// consumer transcript is checked against history after records are trimmed.
func (m *apiSimulation) Key() string {
	var b strings.Builder
	w := &m.world
	fmt.Fprintf(&b, "budget=%d;world=%d/%s/%d/%d/%t/%d;", m.budget, w.gen, w.phase, w.head, w.tail, w.stdinClosed, w.openReaders)
	b.WriteString("retained=")
	for _, rec := range w.retained {
		fmt.Fprintf(&b, "%d/%d/%d/%q;", rec.offset, rec.gen, rec.typ, rec.data)
	}
	b.WriteString("history=")
	for _, rec := range w.history {
		fmt.Fprintf(&b, "%d/%d/%d/%q;", rec.offset, rec.gen, rec.typ, rec.data)
	}
	c := &m.client
	fmt.Fprintf(&b, "client=%d/%d/%t/%d;", c.from, c.last, c.haveLast, c.endedGen)
	b.WriteString("transcript=")
	for _, rec := range c.transcript {
		fmt.Fprintf(&b, "%d/%d/%d/%q;", rec.offset, rec.gen, rec.typ, rec.data)
	}
	return b.String()
}

// simBackend is the only production-facing adapter. It implements Backend and
// records what the world did; it does not do authentication or HTTP framing.
type simBackend struct {
	sim    *apiSimulation
	op     string
	cancel context.CancelFunc
}

func (b *simBackend) Log(ctx context.Context, namespace, name string, from uint64, follow bool, fn func(stream.Record) error) error {
	w := &b.sim.world
	w.logCalls++
	w.openReaders++
	defer func() { w.openReaders-- }()

	if namespace != "ns" || name != "demo" {
		return ErrNotFound
	}
	if w.phase == simRestarting {
		return ErrNotReady
	}
	if from < w.head {
		// A stale cursor is not silently skipped: the first record the API emits
		// is a gap at the retained head.
		w.gaps++
		if err := fn(stream.Record{Offset: w.head, Type: stream.TypeGap}); err != nil {
			return err
		}
		from = w.head
	}
	if from > w.tail {
		from = w.tail
	}
	emitted := 0
	limit := simLogBatch
	if follow && b.op == "log/follow-eof" {
		// A follow stream that ends at EOF drains every remaining record; the
		// batch limit only models an intermediate live read.
		limit = -1
	}
	for _, rec := range w.retained {
		if rec.offset < from {
			continue
		}
		if limit >= 0 && emitted == limit {
			break
		}
		if err := fn(stream.Record{
			Offset: rec.offset,
			Gen:    rec.gen,
			Type:   rec.typ,
			Data:   slices.Clone(rec.data),
		}); err != nil {
			return err
		}
		emitted++
	}
	if !follow {
		return nil
	}
	switch b.op {
	case "log/follow-cancel":
		if b.cancel == nil {
			return errors.New("simulation: follow-cancel without a context cancel")
		}
		b.cancel()
		<-ctx.Done()
		return ctx.Err()
	case "log/follow-eof":
		if w.phase != simExited {
			return errors.New("simulation: follow ended before the stream exited")
		}
		return nil
	default:
		return fmt.Errorf("simulation: follow action %q has no end or cancellation", b.op)
	}
}

func (b *simBackend) Stdin(ctx context.Context, namespace, name string, data []byte, eof bool) error {
	w := &b.sim.world
	w.stdinCalls++
	if namespace != "ns" || name != "demo" {
		return ErrNotFound
	}
	if w.phase == simRestarting {
		return ErrNotReady
	}
	if w.phase == simExited || w.stdinClosed {
		return ErrClosed
	}
	if len(data) > 0 {
		w.appendRecord(w.gen, stream.TypeIn, data)
		w.forwarded = append(w.forwarded, data...)
	}
	if eof {
		w.stdinClosed = true
	}
	if b.op == "stdin/lost-reply" {
		// The node records stdin before forwarding it. A failed forward is an
		// ambiguous result: the record is durable but the API reports failure.
		return errSimLostReply
	}
	return nil
}

type simAuth uint8

const (
	simAuthAnonymous simAuth = iota
	simAuthDeny
	simAuthError
	simAuthAllow
)

func (m *apiSimulation) serverFor(auth simAuth, backend Backend) *Server {
	switch auth {
	case simAuthAnonymous:
		return New(Options{Backend: backend})
	case simAuthDeny:
		return New(Options{
			Backend:  backend,
			Insecure: true,
			Authorizer: authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionDeny, "simulation denied", nil
			}),
		})
	case simAuthError:
		return New(Options{
			Backend:  backend,
			Insecure: true,
			Authorizer: authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionNoOpinion, "", errors.New("simulation authorizer failure")
			}),
		})
	default:
		return New(Options{
			Backend:  backend,
			Insecure: true,
			Authorizer: authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionAllow, "", nil
			}),
		})
	}
}

// simLostWriter loses part of the first body frame after the status line, like
// a connection reset in the middle of a record.
type simLostWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
	wrote  bool
}

func (w *simLostWriter) Header() http.Header { return w.header }

func (w *simLostWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		w.code = code
	}
}

func (w *simLostWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n := len(p) / 2
	_, _ = w.body.Write(p[:n])
	return n, errSimLostFrame
}

func simLogPath() string   { return "/apis/" + GroupVersion + "/namespaces/ns/blipstreams/demo/log" }
func simStdinPath() string { return "/apis/" + GroupVersion + "/namespaces/ns/blipstreams/demo/stdin" }

type simRequest struct {
	op       string
	method   string
	target   string
	body     io.Reader
	auth     simAuth
	follow   bool
	lost     bool
	cancel   bool
	wantCode int
}

func (m *apiSimulation) serve(req simRequest) (int, []byte, error) {
	backend := &simBackend{sim: m, op: req.op}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if req.cancel {
		backend.cancel = cancel
	}
	httpReq := httptest.NewRequest(req.method, req.target, req.body).WithContext(ctx)
	server := m.serverFor(req.auth, backend)

	if req.lost {
		w := &simLostWriter{header: make(http.Header)}
		server.Handler().ServeHTTP(w, httpReq)
		return w.code, w.body.Bytes(), nil
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httpReq)
	return rec.Code, rec.Body.Bytes(), nil
}

func (m *apiSimulation) Enabled() []string {
	if m.budget == 0 {
		return nil
	}
	// Authentication and authorization actions leave the world untouched, so
	// they converge on the same next state and do not multiply exploration.
	actions := []string{
		"log/anonymous", "log/forbidden", "log/authorizer-error",
		"stdin/anonymous", "stdin/forbidden", "stdin/authorizer-error",
		"log/read",
	}
	switch m.world.phase {
	case simRunning:
		actions = append(actions,
			"log/follow-cancel", "log/lost-response",
			"node/restart", "guest/output", "guest/error", "guest/exit",
		)
		if !m.world.stdinClosed {
			actions = append(actions, "stdin/write", "stdin/write-eof", "stdin/eof", "stdin/lost-reply")
		}
	case simRestarting:
		actions = append(actions, "node/connect")
	case simExited:
		actions = append(actions, "log/follow-eof", "log/lost-response", "node/restart")
	}
	if m.world.phase != simRunning || m.world.stdinClosed {
		actions = append(actions, "stdin/stale")
	}
	if len(m.world.retained) > 1 {
		actions = append(actions, "ring/trim")
	}
	return actions
}

func (m *apiSimulation) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond the simulation budget")
	}
	m.budget--

	switch action {
	case "log/anonymous":
		return m.doLog(simRequest{op: action, auth: simAuthAnonymous, wantCode: http.StatusUnauthorized})
	case "log/forbidden":
		return m.doLog(simRequest{op: action, auth: simAuthDeny, wantCode: http.StatusForbidden})
	case "log/authorizer-error":
		return m.doLog(simRequest{op: action, auth: simAuthError, wantCode: http.StatusForbidden})
	case "stdin/anonymous":
		return m.doStdin(simRequest{op: action, auth: simAuthAnonymous, wantCode: http.StatusUnauthorized}, nil, false)
	case "stdin/forbidden":
		return m.doStdin(simRequest{op: action, auth: simAuthDeny, wantCode: http.StatusForbidden}, nil, false)
	case "stdin/authorizer-error":
		return m.doStdin(simRequest{op: action, auth: simAuthError, wantCode: http.StatusForbidden}, nil, false)

	case "log/read":
		return m.doLog(simRequest{op: action, auth: simAuthAllow})
	case "log/follow-cancel":
		return m.doLog(simRequest{op: action, auth: simAuthAllow, follow: true, cancel: true, wantCode: http.StatusOK})
	case "log/follow-eof":
		return m.doLog(simRequest{op: action, auth: simAuthAllow, follow: true, wantCode: http.StatusOK})
	case "log/lost-response":
		return m.doLog(simRequest{op: action, auth: simAuthAllow, lost: true, wantCode: http.StatusOK})

	case "stdin/write":
		data := []byte(fmt.Sprintf("in-%d", len(m.world.history)))
		return m.doStdin(simRequest{op: action, auth: simAuthAllow, wantCode: http.StatusOK}, data, false)
	case "stdin/write-eof":
		data := []byte(fmt.Sprintf("in-%d", len(m.world.history)))
		return m.doStdin(simRequest{op: action, auth: simAuthAllow, wantCode: http.StatusOK}, data, true)
	case "stdin/eof":
		return m.doStdin(simRequest{op: action, auth: simAuthAllow, wantCode: http.StatusOK}, nil, true)
	case "stdin/lost-reply":
		data := []byte(fmt.Sprintf("in-%d", len(m.world.history)))
		return m.doStdin(simRequest{op: action, auth: simAuthAllow, wantCode: http.StatusInternalServerError}, data, false)
	case "stdin/stale":
		code := http.StatusConflict
		if m.world.phase == simRestarting {
			code = http.StatusServiceUnavailable
		}
		return m.doStdin(simRequest{op: action, auth: simAuthAllow, wantCode: code}, []byte("stale"), false)

	case "guest/output":
		if m.world.phase != simRunning {
			return errors.New("guest output while not running")
		}
		m.world.appendRecord(m.world.gen, stream.TypeOut, []byte(fmt.Sprintf("out-%d", len(m.world.history))))
		return nil
	case "guest/error":
		if m.world.phase != simRunning {
			return errors.New("guest error while not running")
		}
		m.world.appendRecord(m.world.gen, stream.TypeErr, []byte(fmt.Sprintf("err-%d", len(m.world.history))))
		return nil
	case "guest/exit":
		if m.world.phase != simRunning {
			return errors.New("guest exit while not running")
		}
		m.world.appendRecord(m.world.gen, stream.TypeEnd, []byte(fmt.Sprintf("exit-%d", m.world.gen)))
		m.world.phase = simExited
		m.world.stdinClosed = true
		return nil
	case "node/restart":
		if m.world.phase == simRestarting {
			return errors.New("restart while already restarting")
		}
		m.world.phase = simRestarting
		m.world.gen++
		return nil
	case "node/connect":
		if m.world.phase != simRestarting {
			return errors.New("connect while not restarting")
		}
		m.world.phase = simRunning
		m.world.stdinClosed = false
		m.world.appendRecord(m.world.gen, stream.TypeStart, nil)
		return nil
	case "ring/trim":
		m.world.trim()
		return nil
	default:
		return fmt.Errorf("unknown simulation action %q", action)
	}
}

func (m *apiSimulation) doLog(req simRequest) error {
	target := simLogPath() + "?offset=" + fmt.Sprint(m.client.from)
	if req.follow {
		target += "&follow=true"
	}
	req.method = http.MethodGet
	req.target = target

	beforeLog, beforeStdin := m.world.logCalls, m.world.stdinCalls
	code, body, err := m.serve(req)
	if err != nil {
		return err
	}
	if req.auth != simAuthAllow {
		if m.world.logCalls != beforeLog || m.world.stdinCalls != beforeStdin || m.world.openReaders != 0 {
			return fmt.Errorf("%s: denied request reached the backend", req.op)
		}
		return m.checkStatus(req.op, code, body, req.wantCode)
	}

	if m.world.logCalls != beforeLog+1 {
		return fmt.Errorf("%s: log backend calls = %d, want %d", req.op, m.world.logCalls, beforeLog+1)
	}
	if m.world.stdinCalls != beforeStdin {
		return fmt.Errorf("%s: log request changed stdin calls", req.op)
	}
	if m.world.openReaders != 0 {
		return fmt.Errorf("%s: stream remained open after the request", req.op)
	}

	wantCode := http.StatusOK
	if m.world.phase == simRestarting {
		wantCode = http.StatusServiceUnavailable
	}
	if code != wantCode {
		return fmt.Errorf("%s: status = %d, want %d: %s", req.op, code, wantCode, body)
	}
	if code != http.StatusOK {
		return m.checkStatus(req.op, code, body, wantCode)
	}

	observed, partial, err := decodeSimLines(body)
	if err != nil {
		return fmt.Errorf("%s: decode response: %w", req.op, err)
	}
	if req.lost {
		if len(partial) == 0 {
			return fmt.Errorf("%s: lost response contained no partial frame", req.op)
		}
		// The incomplete frame is intentionally not consumed; the next read
		// from the same cursor must recover it exactly once.
	} else if len(partial) > 0 {
		return fmt.Errorf("%s: response ended with an incomplete record: %q", req.op, partial)
	}
	if err := m.consume(observed); err != nil {
		return fmt.Errorf("%s: %w", req.op, err)
	}
	if req.op == "log/follow-eof" {
		// A follow read may only end normally after the command's end record.
		if m.client.endedGen != m.world.gen {
			return fmt.Errorf("%s: follow ended without the current generation's end", req.op)
		}
		if len(observed) == 0 || observed[len(observed)-1].typ != "end" {
			return fmt.Errorf("%s: follow returned without a final end record", req.op)
		}
	}
	return nil
}

func (m *apiSimulation) doStdin(req simRequest, data []byte, eof bool) error {
	target := simStdinPath()
	if eof {
		target += "?eof=true"
	}
	req.method = http.MethodPost
	req.target = target
	req.body = bytes.NewReader(data)

	beforeLog, beforeStdin := m.world.logCalls, m.world.stdinCalls
	beforeRecords := len(m.world.history)
	beforeForwarded := len(m.world.forwarded)
	code, body, err := m.serve(req)
	if err != nil {
		return err
	}
	if req.auth != simAuthAllow {
		if m.world.logCalls != beforeLog || m.world.stdinCalls != beforeStdin || m.world.openReaders != 0 {
			return fmt.Errorf("%s: denied request reached the backend", req.op)
		}
		if len(m.world.history) != beforeRecords || len(m.world.forwarded) != beforeForwarded {
			return fmt.Errorf("%s: denied request changed the stream", req.op)
		}
		return m.checkStatus(req.op, code, body, req.wantCode)
	}

	if m.world.stdinCalls != beforeStdin+1 {
		return fmt.Errorf("%s: stdin backend calls = %d, want %d", req.op, m.world.stdinCalls, beforeStdin+1)
	}
	if m.world.logCalls != beforeLog {
		return fmt.Errorf("%s: stdin request changed log calls", req.op)
	}
	if m.world.openReaders != 0 {
		return fmt.Errorf("%s: stdin request left a stream open", req.op)
	}
	if code != req.wantCode {
		return fmt.Errorf("%s: status = %d, want %d: %s", req.op, code, req.wantCode, body)
	}
	if code != http.StatusOK {
		if err := m.checkStatus(req.op, code, body, req.wantCode); err != nil {
			return err
		}
		if req.op == "stdin/lost-reply" {
			// The ambiguous result is real: the stdin record is durable even
			// though the caller sees an error. It must be recorded exactly once.
			if len(m.world.history) != beforeRecords+1 {
				return fmt.Errorf("%s: lost reply recorded %d records, want 1", req.op, len(m.world.history)-beforeRecords)
			}
			last := m.world.history[len(m.world.history)-1]
			if last.typ != stream.TypeIn || last.gen != m.world.gen || !bytes.Equal(last.data, data) {
				return fmt.Errorf("%s: lost reply appended record = %+v", req.op, last)
			}
			if !bytes.Equal(m.world.forwarded, append(slices.Clone(m.world.forwarded[:beforeForwarded]), data...)) {
				return fmt.Errorf("%s: lost reply forwarded bytes were not recorded exactly once", req.op)
			}
			return nil
		}
		// Rejected stdin must not append or forward anything.
		if len(m.world.history) != beforeRecords || len(m.world.forwarded) != beforeForwarded {
			return fmt.Errorf("%s: rejected stdin changed the stream", req.op)
		}
		return nil
	}

	wantRecords := beforeRecords
	if len(data) > 0 {
		wantRecords++
	}
	if len(m.world.history) != wantRecords {
		return fmt.Errorf("%s: history has %d records, want %d", req.op, len(m.world.history), wantRecords)
	}
	if len(data) > 0 {
		last := m.world.history[len(m.world.history)-1]
		if last.typ != stream.TypeIn || last.gen != m.world.gen || !bytes.Equal(last.data, data) {
			return fmt.Errorf("%s: appended record = %+v", req.op, last)
		}
		if !bytes.Equal(m.world.forwarded, append(slices.Clone(m.world.forwarded[:beforeForwarded]), data...)) {
			return fmt.Errorf("%s: forwarded bytes were not recorded exactly once", req.op)
		}
	}
	if eof && !m.world.stdinClosed {
		return fmt.Errorf("%s: eof did not close stdin", req.op)
	}
	return nil
}

func (m *apiSimulation) checkStatus(op string, code int, body []byte, want int) error {
	if code != want {
		return fmt.Errorf("%s: status = %d, want %d: %s", op, code, want, body)
	}
	if code < 400 {
		return nil
	}
	var st metav1.Status
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("%s: decode status: %w", op, err)
	}
	if st.Code != int32(code) || st.Status != metav1.StatusFailure {
		return fmt.Errorf("%s: malformed status: %+v", op, st)
	}
	return nil
}

// simObserved is one complete NDJSON record decoded from the API response.
type simObserved struct {
	offset uint64
	gen    uint64
	typ    string
	data   []byte
	raw    map[string]any
}

func decodeSimLines(body []byte) ([]simObserved, []byte, error) {
	var out []simObserved
	for len(body) > 0 {
		i := bytes.IndexByte(body, '\n')
		if i < 0 {
			return out, slices.Clone(body), nil
		}
		line := body[:i]
		body = body[i+1:]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			return out, nil, fmt.Errorf("line %q: %w", line, err)
		}
		var rec struct {
			O uint64 `json:"o"`
			G uint64 `json:"g"`
			T string `json:"t"`
			D string `json:"d"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, nil, err
		}
		o := simObserved{offset: rec.O, gen: rec.G, typ: rec.T, raw: raw}
		if rec.T != "gap" {
			data, err := base64.StdEncoding.DecodeString(rec.D)
			if err != nil {
				return out, nil, fmt.Errorf("line %q: bad data: %w", line, err)
			}
			o.data = data
		}
		out = append(out, o)
	}
	return out, nil, nil
}

func (m *apiSimulation) consume(records []simObserved) error {
	for _, o := range records {
		if o.typ == "gap" {
			if len(o.raw) != 2 {
				return fmt.Errorf("gap record has extra fields: %v", o.raw)
			}
			if o.offset < m.world.head {
				return fmt.Errorf("gap at %d is below retained head %d", o.offset, m.world.head)
			}
			if o.offset < m.client.from {
				return fmt.Errorf("gap at %d went backwards from cursor %d", o.offset, m.client.from)
			}
			if m.client.haveLast && o.offset <= m.client.last {
				return fmt.Errorf("repeated gap at %d after consumed offset %d", o.offset, m.client.last)
			}
			// A gap names the first retained record. It is not a consumed record,
			// so the next request starts there without advancing last.
			m.client.from = o.offset
			continue
		}

		rec, ok := m.lookupHistory(o)
		if !ok {
			return fmt.Errorf("API emitted record %d/%d/%s that the world never appended", o.offset, o.gen, o.typ)
		}
		if m.client.haveLast && o.offset <= m.client.last {
			// The documented reconnect strategy re-delivers the last record.
			// It must be byte-identical and is not appended twice.
			if !m.transcriptHas(rec) {
				return fmt.Errorf("re-delivered record %d does not match the transcript", o.offset)
			}
			continue
		}
		if o.offset < m.client.from {
			return fmt.Errorf("record %d predates request cursor %d", o.offset, m.client.from)
		}

		if m.client.endedGen != 0 {
			if rec.gen <= m.client.endedGen {
				return fmt.Errorf("record %d/%d/%s follows the end of generation %d",
					rec.offset, rec.gen, simTypeName(rec.typ), m.client.endedGen)
			}
			if rec.typ != stream.TypeStart {
				return fmt.Errorf("generation %d began with %s at %d, not start",
					rec.gen, simTypeName(rec.typ), rec.offset)
			}
			m.client.endedGen = 0
		}
		if rec.typ == stream.TypeEnd {
			if m.client.endedGen != 0 && rec.gen <= m.client.endedGen {
				return fmt.Errorf("duplicate end for generation %d", rec.gen)
			}
			m.client.endedGen = rec.gen
		}

		m.client.from = rec.offset
		m.client.last = rec.offset
		m.client.haveLast = true
		m.client.transcript = append(m.client.transcript, simRecord{
			offset: rec.offset,
			gen:    rec.gen,
			typ:    rec.typ,
			data:   slices.Clone(rec.data),
		})
	}
	return nil
}

func (m *apiSimulation) lookupHistory(o simObserved) (simRecord, bool) {
	for _, rec := range m.world.history {
		if rec.offset != o.offset {
			continue
		}
		if rec.gen != o.gen || simTypeName(rec.typ) != o.typ || !bytes.Equal(rec.data, o.data) {
			return simRecord{}, false
		}
		return rec, true
	}
	return simRecord{}, false
}

func (m *apiSimulation) transcriptHas(rec simRecord) bool {
	for _, seen := range m.client.transcript {
		if seen.offset == rec.offset && seen.gen == rec.gen && seen.typ == rec.typ && bytes.Equal(seen.data, rec.data) {
			return true
		}
	}
	return false
}

func simTypeName(t stream.RecordType) string {
	switch t {
	case stream.TypeOut:
		return "out"
	case stream.TypeErr:
		return "err"
	case stream.TypeIn:
		return "in"
	case stream.TypeStart:
		return "start"
	case stream.TypeEnd:
		return "end"
	case stream.TypeGap:
		return "gap"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

func (m *apiSimulation) Check() error {
	if m.budget < 0 {
		return fmt.Errorf("negative budget %d", m.budget)
	}
	w := &m.world
	if w.openReaders != 0 {
		return fmt.Errorf("%d log stream(s) still open between steps", w.openReaders)
	}
	if w.head > w.tail {
		return fmt.Errorf("head %d > tail %d", w.head, w.tail)
	}
	if w.phase == simExited && !w.stdinClosed {
		return errors.New("exited stream accepts stdin")
	}
	if err := checkWorldRecords("retained", w.retained, w.head, w.tail, true); err != nil {
		return err
	}
	if err := checkWorldRecords("history", w.history, 0, w.tail, false); err != nil {
		return err
	}
	if len(w.retained) == 0 {
		if w.head != w.tail {
			return fmt.Errorf("empty retained window has head %d tail %d", w.head, w.tail)
		}
	} else if w.retained[0].offset != w.head {
		return fmt.Errorf("retained head %d has first record %d", w.head, w.retained[0].offset)
	}
	if len(w.history) > 0 {
		last := w.history[len(w.history)-1]
		if last.offset+last.size() != w.tail {
			return fmt.Errorf("history tail %d does not follow record at %d", w.tail, last.offset)
		}
	}
	if err := checkGenerationOrder(w.history); err != nil {
		return err
	}
	if err := checkConsumer(&m.client, w); err != nil {
		return err
	}
	return nil
}

func checkWorldRecords(name string, records []simRecord, lower, upper uint64, bounded bool) error {
	var prev, prevEnd uint64
	for i, rec := range records {
		if rec.typ < stream.TypeOut || rec.typ > stream.TypeGap {
			return fmt.Errorf("%s record %d has invalid type %d", name, rec.offset, rec.typ)
		}
		if len(rec.data) > stream.MaxRecord {
			return fmt.Errorf("%s record %d is too large: %d", name, rec.offset, len(rec.data))
		}
		if bounded && rec.offset < lower {
			return fmt.Errorf("%s record %d is below head %d", name, rec.offset, lower)
		}
		if rec.offset+rec.size() > upper {
			return fmt.Errorf("%s record at %d ends past tail %d", name, rec.offset, upper)
		}
		if i > 0 {
			if rec.offset <= prev {
				return fmt.Errorf("%s offsets not strictly increasing: %d after %d", name, rec.offset, prev)
			}
			if rec.offset != prevEnd {
				return fmt.Errorf("%s record at %d does not follow the previous end %d", name, rec.offset, prevEnd)
			}
		}
		prev = rec.offset
		prevEnd = rec.offset + rec.size()
	}
	if len(records) > 0 && prevEnd != upper {
		return fmt.Errorf("%s ends at %d, want tail %d", name, prevEnd, upper)
	}
	return nil
}

func checkGenerationOrder(records []simRecord) error {
	var ended uint64
	for _, rec := range records {
		if ended != 0 {
			if rec.gen <= ended {
				return fmt.Errorf("record %d/%d/%s follows end of generation %d", rec.offset, rec.gen, simTypeName(rec.typ), ended)
			}
			if rec.typ != stream.TypeStart {
				return fmt.Errorf("generation %d begins with %s at %d, not start", rec.gen, simTypeName(rec.typ), rec.offset)
			}
			ended = 0
		}
		if rec.typ == stream.TypeEnd {
			ended = rec.gen
		}
	}
	return nil
}

func checkConsumer(c *simConsumer, w *simWorld) error {
	if c.haveLast {
		if len(c.transcript) == 0 {
			return errors.New("consumer has a last offset but no transcript")
		}
		last := c.transcript[len(c.transcript)-1]
		if last.offset != c.last {
			return fmt.Errorf("consumer cursor %d differs from transcript end %d", c.last, last.offset)
		}
		if c.from < c.last {
			return fmt.Errorf("consumer request offset %d went behind consumed offset %d", c.from, c.last)
		}
	}
	var prev uint64
	for i, rec := range c.transcript {
		if i > 0 && rec.offset <= prev {
			return fmt.Errorf("transcript offsets not strictly increasing: %d after %d", rec.offset, prev)
		}
		prev = rec.offset
		if !recordIn(rec, w.history) {
			return fmt.Errorf("transcript record %d/%d/%s was never appended", rec.offset, rec.gen, simTypeName(rec.typ))
		}
	}
	if c.endedGen != 0 {
		if len(c.transcript) == 0 {
			return errors.New("consumer ended without a transcript")
		}
		last := c.transcript[len(c.transcript)-1]
		if last.typ != stream.TypeEnd || last.gen != c.endedGen {
			return fmt.Errorf("consumer ended generation %d but transcript ends at %d/%d/%s",
				c.endedGen, last.offset, last.gen, simTypeName(last.typ))
		}
	}
	// A stale cursor is a legitimate intermediate state. If it is still
	// pending, the next request uses the consumed offset and the backend must
	// answer with a gap; if a gap was already consumed, from has advanced to the
	// retained head while last still names the last real record.
	if c.haveLast && c.last < w.head && c.from != c.last && c.from != w.head {
		return fmt.Errorf("stale cursor %d/%d is neither the consumed offset nor the retained head", c.from, c.last)
	}
	return nil
}

func recordIn(rec simRecord, records []simRecord) bool {
	for _, other := range records {
		if other.offset == rec.offset && other.gen == rec.gen && other.typ == rec.typ &&
			bytes.Equal(other.data, rec.data) {
			return true
		}
	}
	return false
}

// TestStreamAPISimulation exhaustively explores the bounded model and replays
// seeded longer paths. Complete means every state reachable within simBudget was
// visited; it is not an unbounded liveness proof.
func TestStreamAPISimulation(t *testing.T) {
	initial := newAPISimulation()
	report := simtest.Explore(t, initial, sim.Limits{States: simStates, Depth: simBudget})
	if !report.Complete {
		t.Fatalf("incomplete exploration: %+v", report)
	}
	t.Logf("explored %d states, %d transitions at depth %d", report.States, report.Transitions, simBudget)

	simtest.Run(t, initial, simtest.Seeds(0, 8), simBudget)
}

// TestStreamAPISimulationScenarios pins the named obligations to short,
// reproducible request sequences. Every Step still runs the production handler.
func TestStreamAPISimulationScenarios(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		check   func(*testing.T, *apiSimulation)
	}{
		{
			name:    "unauthorized never reaches backend",
			actions: []string{"log/anonymous", "stdin/forbidden", "log/read"},
			check: func(t *testing.T, m *apiSimulation) {
				if m.world.logCalls != 1 || m.world.stdinCalls != 0 {
					t.Fatalf("backend calls = log %d stdin %d", m.world.logCalls, m.world.stdinCalls)
				}
				if len(m.client.transcript) == 0 {
					t.Fatal("authorized read consumed no records")
				}
			},
		},
		{
			name:    "follow cancellation releases the stream",
			actions: []string{"log/follow-cancel", "log/read"},
			check: func(t *testing.T, m *apiSimulation) {
				if m.world.openReaders != 0 {
					t.Fatalf("open readers = %d", m.world.openReaders)
				}
				if m.world.logCalls != 2 {
					t.Fatalf("log calls = %d", m.world.logCalls)
				}
			},
		},
		{
			name:    "stale cursor produces a gap then advances monotonically",
			actions: []string{"log/read", "ring/trim", "ring/trim", "log/read"},
			check: func(t *testing.T, m *apiSimulation) {
				if m.world.gaps != 1 {
					t.Fatalf("gaps = %d, want 1", m.world.gaps)
				}
				if !m.client.haveLast || m.client.last < m.world.head {
					t.Fatalf("cursor %d did not reach head %d", m.client.last, m.world.head)
				}
				if len(m.client.transcript) < 3 {
					t.Fatalf("transcript = %+v", m.client.transcript)
				}
			},
		},
		{
			name:    "lost frame is not consumed and is recovered once",
			actions: []string{"log/lost-response", "log/read"},
			check: func(t *testing.T, m *apiSimulation) {
				if len(m.client.transcript) == 0 {
					t.Fatal("no records consumed after recovery")
				}
				first := m.client.transcript[0]
				if first.offset != m.world.history[0].offset || first.typ != stream.TypeStart {
					t.Fatalf("first transcript record = %+v", first)
				}
			},
		},
		{
			name: "restart rejects stale stdin and resumes the old cursor",
			actions: []string{
				"log/read", "log/read",
				"node/restart", "stdin/stale", "log/read",
				"node/connect", "log/read",
				"stdin/write", "log/read",
				"guest/exit", "log/follow-eof",
			},
			check: func(t *testing.T, m *apiSimulation) {
				if m.world.phase != simExited || !m.world.stdinClosed {
					t.Fatalf("phase=%s stdinClosed=%t", m.world.phase, m.world.stdinClosed)
				}
				if m.client.endedGen != 2 {
					t.Fatalf("ended generation = %d", m.client.endedGen)
				}
				var sawStart, sawIn, sawEnd bool
				for _, rec := range m.client.transcript {
					switch {
					case rec.gen == 2 && rec.typ == stream.TypeStart:
						sawStart = true
					case rec.gen == 2 && rec.typ == stream.TypeIn:
						sawIn = true
					case rec.gen == 2 && rec.typ == stream.TypeEnd:
						sawEnd = true
					}
				}
				if !sawStart || !sawIn || !sawEnd {
					t.Fatalf("generation 2 records: start=%t in=%t end=%t", sawStart, sawIn, sawEnd)
				}
			},
		},
		{
			name:    "stdin eof closes before later writes",
			actions: []string{"stdin/write", "stdin/eof", "stdin/stale"},
			check: func(t *testing.T, m *apiSimulation) {
				if !m.world.stdinClosed {
					t.Fatal("stdin was not closed")
				}
				if len(m.world.forwarded) == 0 || string(m.world.forwarded) != "in-3" {
					t.Fatalf("forwarded = %q", m.world.forwarded)
				}
				if len(m.world.history) != 4 {
					t.Fatalf("history length = %d, want 4", len(m.world.history))
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newAPISimulation()
			m.budget = len(tc.actions) + 4
			for i, action := range tc.actions {
				if !slices.Contains(m.Enabled(), action) {
					t.Fatalf("step %d: action %q is disabled; enabled=%v", i+1, action, m.Enabled())
				}
				if err := m.Step(action); err != nil {
					t.Fatalf("step %d (%s): %v", i+1, action, err)
				}
				if err := m.Check(); err != nil {
					t.Fatalf("step %d (%s): invariant: %v", i+1, action, err)
				}
			}
			tc.check(t, m)
		})
	}
}
