// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package apiproxy

// Deterministic simulations for the API proxy's decision core.
//
// Scope and assumptions:
//
//   - The credential model drives the real caPool, caTransport, tokenTransport
//     and projectedTokenFrom over an in-memory projected-credential filesystem.
//     It models token rotation, CA rotation/revocation, missing or malformed
//     projected files, and a base RoundTripper that can complete, fail, or
//     commit a request whose reply is then lost. It does not model TLS
//     handshakes or the kubernetes API server: a successful CA bundle read is
//     represented by the generation and root subjects the production pool
//     returns. Requests are synchronous, so "in flight" means a dispatch that
//     has already been recorded by the upstream and whose result cannot be
//     changed by a later rotation.
//
//   - The session model drives the real requestLimiter, trackedListener and
//     trackedConn. It models accepting connections,
//     admitting and completing requests on a connection, watch/upgrade
//     connections that stay tracked after hijack, connection close (which is
//     how a client cancellation reaches the proxy), and shutdown. The
//     http.Server goroutines and ConnContext wiring are out of scope; the
//     model sets the lifetime cancellation through the same trackedConn method
//     ConnContext uses. Releasing a slot when a connection closes models the
//     handler returning after its context is cancelled.
//
// Both models are finite: an explicit action budget makes exhaustive
// exploration terminate with Complete. State keys include the remaining budget,
// so histories are not collapsed into a future-equivalent state.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simtest"
)

const (
	simTokenPath = "/projected/token"
	simCAPath    = "/projected/ca.crt"

	simTokenVersions = 3
	simCAEpochLimit  = 3

	simCredentialBudget = 5
	simSessionBudget    = 7
	simSessionLimit     = 2
	simSessionMaxConns  = 3
)

var (
	errSimTransport = errors.New("simulation upstream transport failure")
	errSimLostReply = errors.New("simulation upstream reply lost after commit")
)

// simTokenMode models the projected token file's observable state.
type simTokenMode uint8

const (
	simTokenOK simTokenMode = iota
	simTokenMissing
	simTokenEmpty
	simTokenInvalid
)

func (m simTokenMode) String() string {
	switch m {
	case simTokenOK:
		return "ok"
	case simTokenMissing:
		return "missing"
	case simTokenEmpty:
		return "empty"
	case simTokenInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

func simTokenValue(version int) string { return fmt.Sprintf("token-%d", version) }

// simCAMode models the projected CA bundle file's observable state.
type simCAMode uint8

const (
	simCAOK simCAMode = iota
	simCAMissing
	simCAEmpty
	simCAInvalid
	simCAUnreadable
)

func (m simCAMode) String() string {
	switch m {
	case simCAOK:
		return "ok"
	case simCAMissing:
		return "missing"
	case simCAEmpty:
		return "empty"
	case simCAInvalid:
		return "invalid"
	case simCAUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}

// simFileInfo is the stat view of an in-memory projected file.
type simFileInfo struct {
	name string
	size int64
	mod  time.Time
}

func (i simFileInfo) Name() string       { return i.name }
func (i simFileInfo) Size() int64        { return i.size }
func (i simFileInfo) Mode() os.FileMode  { return 0600 }
func (i simFileInfo) ModTime() time.Time { return i.mod }
func (i simFileInfo) IsDir() bool        { return false }
func (i simFileInfo) Sys() any           { return nil }

// simCredentialFS is the in-memory projected volume. Its state is derived only
// from the credential model fields, so it is isolated by Clone.
type simCredentialFS struct {
	tokenMode    simTokenMode
	tokenVersion int
	caMode       simCAMode
	caVersion    int
	caEpoch      uint64
	caPEMs       [][]byte
}

func (fs simCredentialFS) tokenData() []byte {
	switch fs.tokenMode {
	case simTokenMissing:
		return nil
	case simTokenEmpty:
		return []byte(" \n")
	case simTokenInvalid:
		return []byte("token-0\nnot-a-token")
	default:
		return []byte(simTokenValue(fs.tokenVersion) + "\n")
	}
}

func (fs simCredentialFS) caData() []byte {
	switch fs.caMode {
	case simCAOK:
		return fs.caPEMs[fs.caVersion]
	case simCAInvalid:
		return []byte("this is not a certificate\n")
	default:
		return nil
	}
}

func (fs simCredentialFS) Stat(name string) (os.FileInfo, error) {
	switch name {
	case simTokenPath:
		if fs.tokenMode == simTokenMissing {
			return nil, os.ErrNotExist
		}
		return simFileInfo{name: name, size: int64(len(fs.tokenData()))}, nil
	case simCAPath:
		if fs.caMode == simCAMissing {
			return nil, os.ErrNotExist
		}
		return simFileInfo{
			name: name,
			size: int64(len(fs.caData())),
			mod:  time.Unix(0, int64(fs.caEpoch)),
		}, nil
	default:
		return nil, os.ErrNotExist
	}
}

func (fs simCredentialFS) ReadFile(name string) ([]byte, error) {
	switch name {
	case simTokenPath:
		if fs.tokenMode == simTokenMissing {
			return nil, os.ErrNotExist
		}
		return fs.tokenData(), nil
	case simCAPath:
		switch fs.caMode {
		case simCAMissing:
			return nil, os.ErrNotExist
		case simCAUnreadable:
			return nil, errors.New("simulated permission denied")
		default:
			return fs.caData(), nil
		}
	default:
		return nil, os.ErrNotExist
	}
}

// simFault is the upstream outcome selected for one dispatch.
type simFault uint8

const (
	simFaultNone simFault = iota
	simFaultTransport
	simFaultLostReply
)

func (f simFault) String() string {
	switch f {
	case simFaultNone:
		return "ok"
	case simFaultTransport:
		return "transport"
	case simFaultLostReply:
		return "lost-reply"
	default:
		return "unknown"
	}
}

// simCall is what the in-memory upstream actually observed.
type simCall struct {
	auth  string
	safe  string
	fault simFault
}

// simBase is the in-memory upstream. It records every request that reached it
// and implements CloseIdleConnections so it can stand in for *http.Transport in
// caTransport.
type simBase struct {
	nextFault  simFault
	idleClosed int
	calls      []simCall
}

func (b *simBase) RoundTrip(r *http.Request) (*http.Response, error) {
	fault := b.nextFault
	b.nextFault = simFaultNone
	b.calls = append(b.calls, simCall{
		auth:  r.Header.Get("Authorization"),
		safe:  r.Header.Get("X-Safe"),
		fault: fault,
	})
	switch fault {
	case simFaultTransport:
		return nil, errSimTransport
	case simFaultLostReply:
		return nil, errSimLostReply
	default:
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	}
}

func (b *simBase) CloseIdleConnections() { b.idleClosed++ }

func (b simBase) clone() simBase {
	b.calls = slices.Clone(b.calls)
	return b
}

// simDispatch records one request through the production transport chain.
type simDispatch struct {
	id            int
	approved      bool
	approvedTok   int
	approvedCA    int
	approvedEpoch uint64
	tokenMode     simTokenMode
	tokenVer      int
	caMode        simCAMode
	caVer         int
	caEpoch       uint64
	fault         simFault
	tokenRead     bool
	baseCalled    bool
	callCount     int
	callAuth      string
	callSafe      string
	err           string
	idleBefore    int
	idleAfter     int
	poolBefore    uint64
	poolAfter     uint64
	caGenBefore   uint64
	caGenAfter    uint64
	rootsFP       string
	corrupted     bool
}

// credentialModel exercises the production credential rotation and dispatch
// decisions. All production state that persists between requests (the CA
// pool's generation/mtime/size and the CA transport's generation) is carried in
// the model and handed back to a freshly built production chain for each step.
type credentialModel struct {
	tokenMode    simTokenMode
	tokenVersion int
	caMode       simCAMode
	caVersion    int
	caEpoch      uint64

	caPEMs        [][]byte
	caFingerprint []string

	poolGen      uint64
	poolPEM      []byte
	poolPEMFP    string
	poolRoots    *x509.CertPool
	poolRootsFP  string
	caTransport  uint64
	base         simBase
	dispatches   []simDispatch
	nextRequest  int
	requestCount int
	corrupted    bool
	budget       int

	// approved models a request that passed admission before a credential
	// rotation but has not reached tokenTransport yet.
	approved        bool
	approvedID      int
	approvedTok     int
	approvedCAVer   int
	approvedCAEpoch uint64
}

func newCredentialModel(caPEMs [][]byte) *credentialModel {
	fingerprints := make([]string, len(caPEMs))
	for i, pemBytes := range caPEMs {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			panic("simulation CA bundle is not valid PEM")
		}
		fingerprints[i] = rootsFingerprint(pool)
	}
	return &credentialModel{
		tokenMode:     simTokenOK,
		caMode:        simCAOK,
		caEpoch:       1,
		caPEMs:        caPEMs,
		caFingerprint: fingerprints,
		poolRootsFP:   "nil",
		budget:        simCredentialBudget,
	}
}

func (m *credentialModel) fs() simCredentialFS {
	return simCredentialFS{
		tokenMode:    m.tokenMode,
		tokenVersion: m.tokenVersion,
		caMode:       m.caMode,
		caVersion:    m.caVersion,
		caEpoch:      m.caEpoch,
		caPEMs:       m.caPEMs,
	}
}

func (m *credentialModel) Clone() sim.Model {
	c := *m
	c.caPEMs = slices.Clone(m.caPEMs)
	c.caFingerprint = slices.Clone(m.caFingerprint)
	c.poolPEM = slices.Clone(m.poolPEM)
	c.base = m.base.clone()
	c.dispatches = slices.Clone(m.dispatches)
	return &c
}

func (m *credentialModel) Key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "budget=%d;token=%s/%d;ca=%s/%d/%d;pool=%d/%s/%s;caGen=%d;idle=%d;next=%d;count=%d;corrupt=%t;approved=%t/%d/%d/%d/%d;",
		m.budget, m.tokenMode, m.tokenVersion, m.caMode, m.caVersion, m.caEpoch,
		m.poolGen, m.poolPEMFP, m.poolRootsFP, m.caTransport,
		m.base.idleClosed, m.nextRequest, m.requestCount, m.corrupted,
		m.approved, m.approvedID, m.approvedTok, m.approvedCAVer, m.approvedCAEpoch)
	for _, d := range m.dispatches {
		fmt.Fprintf(&b, "d=%d/%t/%d/%d/%d/%s/%d/%s/%d/%d/%s/%t/%t/%d/%s/%s/%s/%d/%d/%d/%d/%d/%d/%s/%t;",
			d.id, d.approved, d.approvedTok, d.approvedCA, d.approvedEpoch,
			d.tokenMode, d.tokenVer, d.caMode, d.caVer, d.caEpoch, d.fault,
			d.tokenRead, d.baseCalled, d.callCount, d.callAuth, d.callSafe, d.err,
			d.idleBefore, d.idleAfter, d.poolBefore, d.poolAfter,
			d.caGenBefore, d.caGenAfter, d.rootsFP, d.corrupted)
	}
	return b.String()
}

func (m *credentialModel) Enabled() []string {
	if m.budget == 0 {
		return nil
	}
	var actions []string
	if m.tokenMode == simTokenOK && m.tokenVersion+1 < simTokenVersions {
		actions = append(actions, "token/rotate")
	}
	if m.tokenMode != simTokenOK {
		actions = append(actions, "token/ok")
	}
	if m.tokenMode != simTokenMissing {
		actions = append(actions, "token/missing")
	}
	if m.tokenMode != simTokenEmpty {
		actions = append(actions, "token/empty")
	}
	if m.tokenMode != simTokenInvalid {
		actions = append(actions, "token/invalid")
	}
	if m.caEpoch < simCAEpochLimit {
		if m.caMode == simCAOK && len(m.caPEMs) > 1 {
			actions = append(actions, "ca/rotate")
		}
		if m.caMode != simCAOK {
			actions = append(actions, "ca/ok")
		}
		if m.caMode != simCAMissing {
			actions = append(actions, "ca/missing")
		}
		if m.caMode != simCAEmpty {
			actions = append(actions, "ca/empty")
		}
		if m.caMode != simCAInvalid {
			actions = append(actions, "ca/invalid")
		}
		if m.caMode != simCAUnreadable {
			actions = append(actions, "ca/unreadable")
		}
	}
	if !m.approved {
		actions = append(actions, "request/approve")
	}
	actions = append(actions, "request/ok", "request/transport", "request/lost-reply")
	return actions
}

func (m *credentialModel) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond credential model budget")
	}
	m.budget--
	switch action {
	case "token/rotate":
		if m.tokenMode != simTokenOK || m.tokenVersion+1 >= simTokenVersions {
			return fmt.Errorf("token/rotate is disabled")
		}
		m.tokenVersion++
		return nil
	case "token/ok":
		m.tokenMode = simTokenOK
		return nil
	case "token/missing":
		m.tokenMode = simTokenMissing
		return nil
	case "token/empty":
		m.tokenMode = simTokenEmpty
		return nil
	case "token/invalid":
		m.tokenMode = simTokenInvalid
		return nil
	case "ca/rotate":
		if m.caEpoch >= simCAEpochLimit || m.caMode != simCAOK || len(m.caPEMs) == 0 {
			return fmt.Errorf("ca/rotate is disabled")
		}
		m.caVersion = (m.caVersion + 1) % len(m.caPEMs)
		m.caEpoch++
		return nil
	case "ca/ok", "ca/missing", "ca/empty", "ca/invalid", "ca/unreadable":
		if m.caEpoch >= simCAEpochLimit {
			return fmt.Errorf("%s is disabled", action)
		}
		switch action {
		case "ca/ok":
			m.caMode = simCAOK
		case "ca/missing":
			m.caMode = simCAMissing
		case "ca/empty":
			m.caMode = simCAEmpty
		case "ca/invalid":
			m.caMode = simCAInvalid
		case "ca/unreadable":
			m.caMode = simCAUnreadable
		}
		m.caEpoch++
		return nil
	case "request/approve":
		if m.approved {
			return errors.New("a request is already approved")
		}
		m.nextRequest++
		m.approved = true
		m.approvedID = m.nextRequest
		m.approvedTok = m.tokenVersion
		m.approvedCAVer = m.caVersion
		m.approvedCAEpoch = m.caEpoch
		return nil
	case "request/ok":
		return m.dispatch(simFaultNone)
	case "request/transport":
		return m.dispatch(simFaultTransport)
	case "request/lost-reply":
		return m.dispatch(simFaultLostReply)
	default:
		return fmt.Errorf("unknown credential action %q", action)
	}
}

// dispatch sends one request through tokenTransport -> caTransport -> simBase,
// using a freshly built production chain with the model's carried state.
func (m *credentialModel) dispatch(fault simFault) error {
	id := 0
	approved := m.approved
	approvedTok, approvedCA, approvedEpoch := m.tokenVersion, m.caVersion, m.caEpoch
	if approved {
		id = m.approvedID
		approvedTok, approvedCA, approvedEpoch = m.approvedTok, m.approvedCAVer, m.approvedCAEpoch
	} else {
		m.nextRequest++
		id = m.nextRequest
	}
	m.requestCount++

	fs := m.fs()
	// Read the token up front only to know whether tokenTransport will reach
	// caTransport. This is the same production reader and has no side effect.
	_, tokenErr := projectedTokenFrom(fs, simTokenPath)

	pool := &caPool{
		caFile: simCAPath,
		label:  "simulation CA",
		files:  fs,
		gen:    m.poolGen,
		roots:  m.poolRoots,
		pem:    m.poolPEM,
	}
	ca := &caTransport{base: &m.base, pool: pool, gen: m.caTransport}
	transport := tokenTransport{base: ca, tokenFile: simTokenPath, files: fs}

	req, err := http.NewRequest(http.MethodGet, "https://kube-apiserver/api/v1/pods", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "caller-secret")
	req.Header.Set("X-Safe", "kept")

	d := simDispatch{
		id:            id,
		approved:      approved,
		approvedTok:   approvedTok,
		approvedCA:    approvedCA,
		approvedEpoch: approvedEpoch,
		tokenMode:     m.tokenMode,
		tokenVer:      m.tokenVersion,
		caMode:        m.caMode,
		caVer:         m.caVersion,
		caEpoch:       m.caEpoch,
		fault:         fault,
		tokenRead:     tokenErr == nil,
		idleBefore:    m.base.idleClosed,
		poolBefore:    pool.gen,
		caGenBefore:   ca.gen,
	}
	callsBefore := len(m.base.calls)
	m.base.nextFault = fault
	response, dispatchErr := transport.RoundTrip(req)
	m.base.nextFault = simFaultNone
	if response != nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}

	d.idleAfter = m.base.idleClosed
	d.poolAfter = pool.gen
	d.caGenAfter = ca.gen
	d.callCount = len(m.base.calls) - callsBefore
	if d.callCount > 0 {
		d.baseCalled = true
		call := m.base.calls[len(m.base.calls)-1]
		d.callAuth, d.callSafe = call.auth, call.safe
	}
	if dispatchErr != nil {
		d.err = dispatchErr.Error()
	}
	// The caller's request is the approved request. tokenTransport must clone
	// it before applying sidecar credentials.
	d.corrupted = req.Header.Get("Authorization") != "caller-secret" ||
		req.Header.Get("X-Safe") != "kept"
	m.corrupted = m.corrupted || d.corrupted

	m.poolGen = pool.gen
	m.poolPEM = slices.Clone(pool.pem)
	m.poolPEMFP = ""
	if pool.roots == nil {
		m.poolPEM = nil
	} else {
		m.poolPEMFP = fmt.Sprintf("%x", sha256.Sum256(pool.pem))
	}
	m.poolRoots = pool.roots
	m.poolRootsFP = rootsFingerprint(pool.roots)
	m.caTransport = ca.gen
	d.rootsFP = m.poolRootsFP
	m.dispatches = append(m.dispatches, d)
	m.approved = false
	return nil
}

func (m *credentialModel) Check() error {
	if m.budget < 0 {
		return fmt.Errorf("negative budget %d", m.budget)
	}
	if m.corrupted {
		return errors.New("a dispatch mutated the approved caller request")
	}
	previousToken := -1
	for _, d := range m.dispatches {
		if d.corrupted {
			return fmt.Errorf("dispatch %d corrupted the caller request", d.id)
		}
		if d.tokenMode == simTokenOK {
			if d.tokenVer < previousToken {
				return fmt.Errorf("dispatch %d reused stale token version %d after %d", d.id, d.tokenVer, previousToken)
			}
			previousToken = d.tokenVer
		}
		if d.approved {
			// A request admitted before a rotation must not pin the old
			// credential or move the CA generation backwards.
			if d.tokenMode == simTokenOK && d.tokenVer < d.approvedTok {
				return fmt.Errorf("approved dispatch %d used token version %d older than approval %d",
					d.id, d.tokenVer, d.approvedTok)
			}
			if d.caEpoch < d.approvedEpoch {
				return fmt.Errorf("approved dispatch %d used CA epoch %d older than approval %d",
					d.id, d.caEpoch, d.approvedEpoch)
			}
		}
		if d.baseCalled {
			if d.callCount != 1 {
				return fmt.Errorf("dispatch %d made %d upstream calls, want exactly 1", d.id, d.callCount)
			}
			if !d.tokenRead || d.tokenMode != simTokenOK {
				return fmt.Errorf("dispatch %d reached upstream without a readable token", d.id)
			}
			if want := "Bearer " + simTokenValue(d.tokenVer); d.callAuth != want {
				return fmt.Errorf("dispatch %d upstream authorization %q, want %q", d.id, d.callAuth, want)
			}
			if d.callSafe != "kept" {
				return fmt.Errorf("dispatch %d lost the caller's ordinary header", d.id)
			}
			if d.caMode != simCAOK {
				return fmt.Errorf("dispatch %d reached upstream with CA mode %s", d.id, d.caMode)
			}
			if want := m.caFingerprint[d.caVer]; d.rootsFP != want {
				return fmt.Errorf("dispatch %d used CA fingerprint %s, want %s", d.id, d.rootsFP, want)
			}
			switch d.fault {
			case simFaultNone:
				if d.err != "" {
					return fmt.Errorf("dispatch %d unexpectedly failed: %s", d.id, d.err)
				}
			default:
				if d.err == "" {
					return fmt.Errorf("dispatch %d did not report fault %s", d.id, d.fault)
				}
			}
			// A CA generation change must drop idle connections before the
			// request reaches the upstream.
			if d.caGenBefore != d.caGenAfter && d.idleAfter <= d.idleBefore {
				return fmt.Errorf("dispatch %d reused an idle connection across CA generation %d -> %d",
					d.id, d.caGenBefore, d.caGenAfter)
			}
			if d.poolAfter < d.poolBefore {
				return fmt.Errorf("dispatch %d CA generation moved backwards", d.id)
			}
		} else {
			if d.callCount != 0 {
				return fmt.Errorf("dispatch %d made %d upstream calls without reaching the base", d.id, d.callCount)
			}
			if d.err == "" {
				return fmt.Errorf("dispatch %d failed without reporting an error", d.id)
			}
			if d.tokenRead && d.caMode == simCAOK && d.fault == simFaultNone {
				return fmt.Errorf("dispatch %d did not reach a valid upstream", d.id)
			}
			if d.idleAfter != d.idleBefore {
				return fmt.Errorf("dispatch %d changed idle connections without reaching the CA transport", d.id)
			}
			if d.caGenAfter != d.caGenBefore {
				return fmt.Errorf("dispatch %d advanced the CA generation without reaching the CA transport", d.id)
			}
		}
	}
	return nil
}

// rootsFingerprint identifies a root bundle without retaining its mutable
// implementation. CertPool is immutable after construction.
func rootsFingerprint(pool *x509.CertPool) string {
	if pool == nil {
		return "nil"
	}
	subjects := pool.Subjects()
	slices.SortFunc(subjects, func(a, b []byte) int { return strings.Compare(string(a), string(b)) })
	sum := sha256.New()
	for _, subject := range subjects {
		_, _ = sum.Write(subject)
		_, _ = sum.Write([]byte{0})
	}
	return fmt.Sprintf("%x", sum.Sum(nil))
}

// --- Session admission and connection tracking -----------------------------

// simConn is a connection handed to the production tracked listener. It never
// carries bytes in the model: the point is connection identity, closure and
// lifetime cancellation.
type simConn struct {
	id     int
	closed bool
}

func (c *simConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *simConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *simConn) Close() error                     { c.closed = true; return nil }
func (c *simConn) LocalAddr() net.Addr              { return simAddr{} }
func (c *simConn) RemoteAddr() net.Addr             { return simAddr{} }
func (c *simConn) SetDeadline(time.Time) error      { return nil }
func (c *simConn) SetReadDeadline(time.Time) error  { return nil }
func (c *simConn) SetWriteDeadline(time.Time) error { return nil }
func (c *simConn) CloseWrite() error                { return nil }

type simAddr struct{}

func (simAddr) Network() string { return "sim" }
func (simAddr) String() string  { return "sim" }

// simListener supplies deterministic connections. Existing connections are
// re-registered by each rebuild; if the queue is empty a fresh connection is
// created with the model's next ID.
type simListener struct {
	queue  []*simConn
	nextID int
	closed bool
}

func (l *simListener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, net.ErrClosed
	}
	if len(l.queue) > 0 {
		c := l.queue[0]
		l.queue = l.queue[1:]
		return c, nil
	}
	c := &simConn{id: l.nextID}
	l.nextID++
	return c, nil
}

func (l *simListener) Close() error   { l.closed = true; return nil }
func (l *simListener) Addr() net.Addr { return simAddr{} }

// sessionConn is one tracked connection and the requests currently holding a
// limiter slot on it.
type sessionConn struct {
	id      int
	mode    string // plain, watch, or upgrade
	pending int
}

// sessionModel exercises admission, tracked connection release, hijacked
// watch/upgrade lifetime, cancellation, and shutdown.
type sessionModel struct {
	nextConn    int
	conns       []sessionConn
	pending     int
	limit       int
	maxAdmitted int
	admitted    int
	refused     int
	completed   int
	closed      int
	canceled    int
	shutdown    bool
	budget      int
}

func newSessionModel() *sessionModel {
	return &sessionModel{limit: simSessionLimit, budget: simSessionBudget}
}

func (m *sessionModel) Clone() sim.Model {
	c := *m
	c.conns = slices.Clone(m.conns)
	return &c
}

func (m *sessionModel) Key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "budget=%d;next=%d;pending=%d;limit=%d;max=%d;adm=%d;ref=%d;done=%d;closed=%d;cancel=%d;shutdown=%t;",
		m.budget, m.nextConn, m.pending, m.limit, m.maxAdmitted, m.admitted,
		m.refused, m.completed, m.closed, m.canceled, m.shutdown)
	for _, c := range m.conns {
		fmt.Fprintf(&b, "c=%d/%s/%d;", c.id, c.mode, c.pending)
	}
	return b.String()
}

func (m *sessionModel) Enabled() []string {
	if m.budget == 0 || m.shutdown {
		return nil
	}
	var actions []string
	if m.nextConn < simSessionMaxConns {
		actions = append(actions, "conn/accept")
	}
	for _, c := range m.conns {
		actions = append(actions, fmt.Sprintf("conn/close/%d", c.id))
		if c.mode == "plain" {
			actions = append(actions, fmt.Sprintf("request/admit/%d", c.id))
			if c.pending > 0 {
				actions = append(actions,
					fmt.Sprintf("conn/watch/%d", c.id),
					fmt.Sprintf("conn/upgrade/%d", c.id),
				)
			}
		}
		if c.pending > 0 {
			actions = append(actions, fmt.Sprintf("request/finish/%d", c.id))
		}
	}
	actions = append(actions, "shutdown")
	return actions
}

type sessionEnv struct {
	listener *simListener
	tracked  *trackedListener
	limiter  *requestLimiter
	conns    map[int]*trackedConn
	canceled map[int]bool
}

// build re-registers the model's open connections through the production
// tracked listener and primes the production limiter with the pending count.
func (m *sessionModel) build() (*sessionEnv, error) {
	listener := &simListener{nextID: m.nextConn}
	for _, c := range m.conns {
		listener.queue = append(listener.queue, &simConn{id: c.id})
	}
	tracked := &trackedListener{Listener: listener, connections: make(map[*trackedConn]struct{})}
	env := &sessionEnv{
		listener: listener,
		tracked:  tracked,
		conns:    make(map[int]*trackedConn),
		canceled: make(map[int]bool),
	}
	for range m.conns {
		conn, err := tracked.Accept()
		if err != nil {
			return nil, err
		}
		tc := conn.(*trackedConn)
		id := tc.Conn.(*simConn).id
		env.conns[id] = tc
		tc.setLifetimeCancel(func() { env.canceled[id] = true })
	}
	limiter := newRequestLimiter(m.limit)
	for i := 0; i < m.pending; i++ {
		if !limiter.acquire() {
			return nil, fmt.Errorf("pending requests %d exceed session limit %d", m.pending, m.limit)
		}
	}
	env.limiter = limiter
	return env, nil
}

func (m *sessionModel) Step(action string) error {
	if m.budget == 0 {
		return errors.New("step beyond session model budget")
	}
	m.budget--
	if action == "shutdown" {
		return m.doShutdown()
	}
	env, err := m.build()
	if err != nil {
		return err
	}
	switch {
	case action == "conn/accept":
		conn, err := env.tracked.Accept()
		if err != nil {
			return err
		}
		tc := conn.(*trackedConn)
		id := tc.Conn.(*simConn).id
		if id != m.nextConn {
			return fmt.Errorf("accepted connection id %d, want %d", id, m.nextConn)
		}
		tc.setLifetimeCancel(func() { env.canceled[id] = true })
		m.conns = append(m.conns, sessionConn{id: id, mode: "plain"})
		m.nextConn++
		return nil
	case strings.HasPrefix(action, "conn/watch/"):
		idx, id, err := m.connIndex(m.conns, strings.TrimPrefix(action, "conn/watch/"))
		if err != nil {
			return err
		}
		if m.conns[idx].mode != "plain" || m.conns[idx].pending == 0 {
			return fmt.Errorf("%s requires a plain connection with a held request", action)
		}
		if env.conns[id] == nil {
			return fmt.Errorf("%s: connection %d is not tracked", action, id)
		}
		m.conns[idx].mode = "watch"
		return nil
	case strings.HasPrefix(action, "conn/upgrade/"):
		idx, id, err := m.connIndex(m.conns, strings.TrimPrefix(action, "conn/upgrade/"))
		if err != nil {
			return err
		}
		if m.conns[idx].mode != "plain" || m.conns[idx].pending == 0 {
			return fmt.Errorf("%s requires a plain connection with a held request", action)
		}
		if env.conns[id] == nil {
			return fmt.Errorf("%s: connection %d is not tracked", action, id)
		}
		m.conns[idx].mode = "upgrade"
		return nil
	case strings.HasPrefix(action, "request/admit/"):
		idx, id, err := m.connIndex(m.conns, strings.TrimPrefix(action, "request/admit/"))
		if err != nil {
			return err
		}
		if m.conns[idx].mode != "plain" {
			return fmt.Errorf("%s: connection %d is not plain", action, id)
		}
		if env.limiter.acquire() {
			m.pending++
			m.conns[idx].pending++
			m.admitted++
			m.maxAdmitted = max(m.maxAdmitted, m.pending)
		} else {
			if m.pending != m.limit {
				return fmt.Errorf("admission refused at pending %d, limit %d", m.pending, m.limit)
			}
			m.refused++
		}
		return nil
	case strings.HasPrefix(action, "request/finish/"):
		idx, _, err := m.connIndex(m.conns, strings.TrimPrefix(action, "request/finish/"))
		if err != nil {
			return err
		}
		if m.conns[idx].pending == 0 {
			return fmt.Errorf("%s: connection has no held request", action)
		}
		env.limiter.release()
		m.conns[idx].pending--
		m.pending--
		m.completed++
		return nil
	case strings.HasPrefix(action, "conn/close/"):
		idx, id, err := m.connIndex(m.conns, strings.TrimPrefix(action, "conn/close/"))
		if err != nil {
			return err
		}
		tc := env.conns[id]
		if tc == nil {
			return fmt.Errorf("%s: connection %d is not tracked", action, id)
		}
		before := len(env.tracked.connections)
		if err := tc.Close(); err != nil {
			return err
		}
		if len(env.tracked.connections) != before-1 {
			return fmt.Errorf("%s: tracked connection was not released", action)
		}
		if !env.canceled[id] {
			return fmt.Errorf("%s: close did not cancel the connection lifetime", action)
		}
		held := m.conns[idx].pending
		for i := 0; i < held; i++ {
			env.limiter.release()
		}
		m.pending -= held
		m.completed += held
		m.conns = append(m.conns[:idx], m.conns[idx+1:]...)
		m.closed++
		m.canceled++
		return nil
	default:
		return fmt.Errorf("unknown session action %q", action)
	}
}

func (m *sessionModel) doShutdown() error {
	env, err := m.build()
	if err != nil {
		return err
	}
	held := m.pending
	open := len(env.tracked.connections)
	env.tracked.closeConnections()
	if len(env.tracked.connections) != 0 {
		return errors.New("shutdown left tracked connections")
	}
	for id := range env.conns {
		if !env.canceled[id] {
			return fmt.Errorf("shutdown did not cancel connection %d", id)
		}
	}
	// The closing flag is the listener-side admission gate: even if the
	// underlying listener would still yield a connection, Accept must reject
	// it and not add it to the tracked set.
	if _, err := env.tracked.Accept(); !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("accept after shutdown = %v, want net.ErrClosed", err)
	}
	if len(env.tracked.connections) != 0 {
		return errors.New("accept after shutdown added a tracked connection")
	}
	_ = env.listener.Close()
	for i := 0; i < held; i++ {
		env.limiter.release()
	}
	m.pending = 0
	m.completed += held
	m.closed += open
	m.canceled += open
	m.conns = nil
	m.shutdown = true
	return nil
}

func (m *sessionModel) connIndex(conns []sessionConn, text string) (int, int, error) {
	var id int
	if _, err := fmt.Sscanf(text, "%d", &id); err != nil {
		return 0, 0, fmt.Errorf("invalid connection id %q", text)
	}
	for i, c := range conns {
		if c.id == id {
			return i, id, nil
		}
	}
	return 0, 0, fmt.Errorf("unknown connection id %d", id)
}

func (m *sessionModel) Check() error {
	if m.budget < 0 {
		return fmt.Errorf("negative budget %d", m.budget)
	}
	if m.limit < 1 {
		return fmt.Errorf("invalid session limit %d", m.limit)
	}
	if m.pending < 0 || m.pending > m.limit {
		return fmt.Errorf("pending requests %d outside [0,%d]", m.pending, m.limit)
	}
	if m.maxAdmitted < m.pending || m.maxAdmitted > m.limit {
		return fmt.Errorf("max admitted %d inconsistent with pending %d and limit %d",
			m.maxAdmitted, m.pending, m.limit)
	}
	if m.shutdown && (len(m.conns) != 0 || m.pending != 0) {
		return fmt.Errorf("shutdown state retains %d connections and %d requests", len(m.conns), m.pending)
	}
	sum := 0
	lastID := -1
	for _, c := range m.conns {
		if c.id <= lastID || c.id >= m.nextConn {
			return fmt.Errorf("connection ids are not increasing below next id %d: %d after %d", m.nextConn, c.id, lastID)
		}
		lastID = c.id
		if c.mode != "plain" && c.mode != "watch" && c.mode != "upgrade" {
			return fmt.Errorf("connection %d has unknown mode %q", c.id, c.mode)
		}
		if c.pending < 0 || c.pending > m.pending {
			return fmt.Errorf("connection %d holds %d of %d pending requests", c.id, c.pending, m.pending)
		}
		sum += c.pending
	}
	if sum != m.pending {
		return fmt.Errorf("connection requests %d do not sum to pending %d", sum, m.pending)
	}

	// Rebuild the production listener and limiter, then release every tracked
	// connection to prove the production bookkeeping drops it.
	env, err := m.build()
	if err != nil {
		return err
	}
	if len(env.tracked.connections) != len(m.conns) {
		return fmt.Errorf("tracked connections %d, want %d", len(env.tracked.connections), len(m.conns))
	}
	if len(env.limiter.slots) != m.pending {
		return fmt.Errorf("limiter holds %d slots, want %d", len(env.limiter.slots), m.pending)
	}
	ids := make([]int, 0, len(env.conns))
	for id := range env.conns {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := env.conns[id].Close(); err != nil {
			return fmt.Errorf("close tracked connection %d: %w", id, err)
		}
		if !env.canceled[id] {
			return fmt.Errorf("close did not cancel tracked connection %d", id)
		}
	}
	if len(env.tracked.connections) != 0 {
		return fmt.Errorf("closing %d connections left %d tracked", len(ids), len(env.tracked.connections))
	}
	return nil
}

// TestAdmissionGateRejectsAndReleases drives the production admission wrapper
// without a listener. It complements the session model, which holds limiter
// slots across steps, by checking the 503 path and the connection-lifetime
// substitution.
func TestAdmissionGateRejectsAndReleases(t *testing.T) {
	limiter := newRequestLimiter(1)
	if !limiter.acquire() {
		t.Fatal("could not fill an empty limiter")
	}
	request := httptest.NewRequest(http.MethodGet, "http://kube-apiserver/api", nil)
	recorder := httptest.NewRecorder()
	ran := 0
	limiter.serve(recorder, request, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		ran++
	}))
	response := recorder.Result()
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if ran != 0 || response.StatusCode != http.StatusServiceUnavailable ||
		response.Header.Get("Retry-After") != "1" || len(body) > 64 {
		t.Fatalf("full-gate response: ran=%d status=%d retry=%q body=%q",
			ran, response.StatusCode, response.Header.Get("Retry-After"), body)
	}
	if len(limiter.slots) != 1 {
		t.Fatalf("rejected request changed held slots to %d", len(limiter.slots))
	}
	limiter.release()

	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	request = request.WithContext(context.WithValue(context.Background(), connectionLifetimeKey{}, lifetime))
	recorder = httptest.NewRecorder()
	limiter.serve(recorder, request, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context() != lifetime {
			t.Error("admitted request did not use the connection lifetime context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("admitted response status = %d, want 204", recorder.Code)
	}
	if len(limiter.slots) != 0 {
		t.Fatalf("returning handler left %d limiter slots", len(limiter.slots))
	}
}

func TestCredentialRotationSimulation(t *testing.T) {
	caA := newTestCA(t, "simulation CA A")
	caB := newTestCA(t, "simulation CA B")
	initial := newCredentialModel([][]byte{caA.pem, caB.pem})

	limits := sim.Limits{States: 250000, Depth: simCredentialBudget}
	report := simtest.Explore(t, initial, limits)
	if !report.Complete {
		t.Fatalf("incomplete credential exploration: %+v", report)
	}
	t.Logf("credential simulation: %d states, %d transitions", report.States, report.Transitions)

	simtest.Run(t, initial, simtest.Seeds(0, 8), simCredentialBudget)
}

func TestSessionAdmissionAndTrackingSimulation(t *testing.T) {
	initial := newSessionModel()

	limits := sim.Limits{States: 20000, Depth: simSessionBudget}
	report := simtest.Explore(t, initial, limits)
	if !report.Complete {
		t.Fatalf("incomplete session exploration: %+v", report)
	}
	t.Logf("session simulation: %d states, %d transitions", report.States, report.Transitions)

	simtest.Run(t, initial, simtest.Seeds(0, 8), simSessionBudget)
}
