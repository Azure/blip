// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package runtime

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

// Machine is the runtime lifecycle core used by Run. It has no clock, sockets,
// goroutines, or host operations. A caller supplies time to Apply and Reconcile,
// executes the returned effects, and delivers their results as events. Calls
// must be serialized. NewMachine owns a copy of every desired document.
type Machine struct {
	desired                                    podapi.Desired
	gen                                        int
	connected, helloReady                      bool
	hello                                      bool
	claimID                                    string
	claimWaiting                               bool
	claimSince, claimRetryAt                   time.Time
	rootInVM                                   bool
	rootDisk                                   *podapi.Disk
	rootAdding                                 uint64
	disks                                      map[string]*disk
	order                                      []string
	exit                                       *podapi.Exit
	errMsg                                     string
	sigterm, shutdownSent, shutdownDone        bool
	stopSince                                  time.Time
	exited, killSent                           bool
	frozen, freezeWaiting, thawing, freezeSkip map[string]bool
	freezeSince                                map[string]time.Time
	networkReady                               bool
	networkRevision, networkError, networkKey  string
	networkRetryAt                             time.Time
	networkApplying                            uint64
	skipNetwork                                bool
	nextToken                                  uint64
	pending                                    map[uint64]Effect
}

type disk struct {
	d                                podapi.Disk
	phase, message                   string
	inVM, mounted, waiting, removing bool
	detachPending                    bool // removal may have committed; must confirm before re-add
	waitType                         wire.Type
	waitSince, retryAt               time.Time
	adding, removal                  uint64
}

// EffectKind identifies an operation performed by the production runner.
type EffectKind string

const (
	EffectAddDisk    EffectKind = "add-disk"
	EffectRemoveDisk EffectKind = "remove-disk"
	EffectSend       EffectKind = "send"
	EffectConnect    EffectKind = "connect"
	EffectClose      EffectKind = "close"
	EffectKill       EffectKind = "kill"
	EffectNetwork    EffectKind = "network"
)

// Effect is a value describing an operation. AddDisk, RemoveDisk and Network
// require EventResult with the same Token. RemoveDisk success means confirmed
// absence from both CH config and device tree, not just remove-device acceptance.
// Send failures become EventDisconnected for Generation; successful sends are
// acknowledged by ordinary guest frames. Payload is encoded wire JSON.
type Effect struct {
	Kind             EffectKind
	Token            uint64
	Generation       int
	Disk             podapi.Disk
	Root, ClaimMount bool
	Type             wire.Type
	Payload          json.RawMessage
	Policy           *netpolicy.Policy
	Active           bool
	Key              string
}

type EventKind string

const (
	EventDesired      EventKind = "desired"
	EventConnected    EventKind = "connected"
	EventDisconnected EventKind = "disconnected"
	EventControl      EventKind = "control"
	EventResult       EventKind = "result"
	EventStop         EventKind = "stop"
	EventVMExited     EventKind = "vm-exited"
)

// Event contains an external observation. Error is a string so recorded traces
// can be replayed without preserving concrete Go error implementations.
type Event struct {
	Kind       EventKind
	Desired    podapi.Desired
	Generation int
	Type       wire.Type
	Payload    json.RawMessage
	Token      uint64
	Error      string
	Unsafe     bool // network runner could not enforce a deny-all fallback
}

func NewMachine(skipNetwork bool) *Machine {
	m := &Machine{skipNetwork: skipNetwork}
	m.init()
	return m
}

func (m *Machine) init() {
	if m.disks == nil {
		m.disks = map[string]*disk{}
	}
	if m.pending == nil {
		m.pending = map[uint64]Effect{}
	}
	if m.frozen == nil {
		m.resetFreeze()
	}
}

// Generation is the generation the next control connection must use.
func (m *Machine) Generation() int { return m.gen }

// Apply records one input without reconciling desired state. This lets the
// production loop coalesce a burst of frames before writing Observed. Effects
// returned here (close/connect/kill) must also be executed by the caller.
func (m *Machine) Apply(now time.Time, ev Event) []Effect {
	now = now.Round(0).UTC()
	m.init()
	if m.exited {
		return nil
	}
	switch ev.Kind {
	case EventDesired:
		m.desired = cloneDesired(ev.Desired)
		for _, e := range m.disks {
			e.retryAt = time.Time{}
		}
		m.claimRetryAt = time.Time{}
	case EventConnected:
		if ev.Generation == m.gen {
			m.connected, m.helloReady = true, false
		}
	case EventDisconnected:
		if ev.Generation == m.gen {
			return m.disconnect()
		}
	case EventControl:
		if ev.Generation == m.gen && m.connected {
			return m.control(now, ev.Type, ev.Payload)
		}
	case EventResult:
		return m.complete(now, ev)
	case EventStop:
		m.sigterm = true
	case EventVMExited:
		m.exited, m.connected, m.helloReady = true, false, false
		m.pending = map[uint64]Effect{}
		m.resetFreeze()
		if m.exit == nil {
			if m.stopRequested() {
				m.exit = &podapi.Exit{Reason: wire.ReasonStopped}
			} else {
				m.exit = &podapi.Exit{Code: 255, Reason: wire.ReasonGuestCrashed}
				if m.errMsg == "" {
					m.errMsg = fmt.Sprintf("VM exited unexpectedly (cloud-hypervisor: %s)", ev.Error)
				}
			}
		}
		for _, e := range m.disks {
			e.inVM, e.mounted, e.waiting, e.removing = false, false, false, false
			e.adding, e.removal = 0, 0
			e.phase = podapi.DiskDetached
		}
		return []Effect{{Kind: EffectClose, Generation: m.gen}}
	}
	return nil
}

func (m *Machine) disconnect() []Effect {
	old := m.gen
	m.connected, m.helloReady = false, false
	// Increment even during shutdown so queued old frames cannot resurrect state.
	m.gen++
	effects := []Effect{{Kind: EffectClose, Generation: old}}
	if !m.shutdownDone && !m.exited {
		effects = append(effects, Effect{Kind: EffectConnect, Generation: m.gen})
	}
	return effects
}

func (m *Machine) control(now time.Time, typ wire.Type, payload []byte) []Effect {
	if typ != wire.THello && !m.helloReady {
		return nil
	}
	switch typ {
	case wire.THello:
		var h wire.Hello
		if wire.Decode(payload, &h) != nil {
			return nil
		}
		if h.ClaimID == "" && m.claimID != "" {
			m.errMsg = "the VM guest crashed and restarted"
			return m.kill()
		}
		if h.ClaimID != "" && ((m.claimID != "" && h.ClaimID != m.claimID) ||
			(m.desired.Claim != nil && h.ClaimID != m.desired.Claim.Root.ID)) {
			m.errMsg = "guest reported a different claim"
			return m.kill()
		}
		m.hello, m.helloReady = true, true
		if h.Exit != nil {
			m.recordExit(now, *h.Exit)
		}
		if h.ClaimID != "" {
			m.claimID, m.rootInVM = h.ClaimID, true
		}
		m.claimWaiting, m.shutdownSent = false, false
		m.frozen, m.freezeWaiting, m.thawing = map[string]bool{}, map[string]bool{}, map[string]bool{}
		m.freezeSince = map[string]time.Time{}
		for _, id := range h.Frozen {
			m.frozen[id] = true
		}
		mounted := map[string]bool{}
		for _, id := range h.Mounts {
			mounted[id] = true
		}
		for _, e := range m.disks {
			e.waiting = false
			e.mounted = mounted[e.d.ID]
			if e.mounted && e.phase != podapi.DiskFailed {
				e.phase = podapi.DiskMounted
			}
		}
	case wire.TClaimResult:
		var res wire.Result
		if wire.Decode(payload, &res) != nil || !m.claimWaiting {
			return nil
		}
		if m.desired.Claim == nil || res.ID != m.desired.Claim.Root.ID {
			return nil
		}
		m.claimWaiting = false
		if res.Error != "" {
			for _, e := range m.disks {
				e.waiting = false
			}
			m.errMsg, m.claimRetryAt = "claim: "+res.Error, now.Add(retryInterval)
		} else {
			m.claimID, m.errMsg = res.ID, ""
		}
	case wire.TMountResult, wire.TUnmountResult:
		var res wire.Result
		if wire.Decode(payload, &res) != nil {
			return nil
		}
		e := m.disks[res.ID]
		if e == nil || !e.waiting || e.waitType != typ {
			return nil
		}
		e.waiting = false
		if res.Error != "" {
			delay := retryInterval
			if typ == wire.TUnmountResult {
				delay = unmountRetryInterval
			}
			e.phase, e.message, e.retryAt = podapi.DiskFailed, res.Error, now.Add(delay)
		} else if typ == wire.TMountResult {
			e.phase, e.message, e.mounted = podapi.DiskMounted, "", true
		} else {
			e.mounted, e.message = false, ""
			m.forgetFreeze(res.ID)
		}
	case wire.TFreezeResult:
		var res wire.FreezeResult
		if wire.Decode(payload, &res) != nil {
			return nil
		}
		// The guest can also report an unsolicited auto-thaw of a known freeze.
		if !m.freezeWaiting[res.ID] && !m.frozen[res.ID] {
			return nil
		}
		delete(m.freezeWaiting, res.ID)
		delete(m.freezeSince, res.ID)
		if m.thawing[res.ID] {
			delete(m.thawing, res.ID)
			break
		}
		if res.Frozen {
			m.frozen[res.ID] = true
		} else {
			delete(m.frozen, res.ID)
		}
		if res.Error != "" && !res.Frozen {
			m.freezeSkip[res.ID] = true
		}
	case wire.TExit:
		var ex wire.Exit
		if wire.Decode(payload, &ex) == nil {
			m.recordExit(now, ex)
		}
	case wire.TShutdownDone:
		var sd wire.ShutdownDone
		if wire.Decode(payload, &sd) != nil {
			return nil
		}
		if !sd.Clean {
			m.errMsg = "guest shutdown: " + sd.Error
		}
		m.shutdownDone = true
		return m.disconnect()
	}
	return nil
}

func (m *Machine) recordExit(now time.Time, ex wire.Exit) {
	if m.exit != nil {
		return
	}
	reason := ex.Reason
	if m.stopRequested() && reason == wire.ReasonCompleted {
		reason = wire.ReasonStopped
		if m.desired.StopReason != "" {
			reason = m.desired.StopReason
		}
	}
	m.exit = &podapi.Exit{Code: ex.Code, Signal: ex.Signal, Reason: reason, Output: ex.Output}
	if m.stopSince.IsZero() {
		m.stopSince = now
	}
}

func (m *Machine) issue(e Effect) Effect {
	m.nextToken++
	e.Token = m.nextToken
	m.pending[e.Token] = cloneEffect(e)
	return e
}

func (m *Machine) complete(now time.Time, ev Event) []Effect {
	effect, ok := m.pending[ev.Token]
	if !ok {
		return nil
	}
	delete(m.pending, ev.Token)
	switch effect.Kind {
	case EffectNetwork:
		m.networkApplying = 0
		if ev.Unsafe && ev.Error != "" {
			m.networkReady, m.networkRevision, m.networkError = false, "", ev.Error
			return m.kill()
		}
		// A newer desired policy must not inherit the old policy's readiness.
		if effect.Key != m.policyKey() {
			return nil
		}
		m.networkReady, m.networkRevision, m.networkError = false, "", ev.Error
		if ev.Error != "" {
			m.networkRetryAt = now.Add(retryInterval)
		} else if effect.Policy != nil {
			m.networkReady, m.networkRevision = true, effect.Policy.Revision
		}
	case EffectAddDisk:
		if effect.Root {
			if m.rootAdding != ev.Token {
				return nil
			}
			m.rootAdding = 0
			if ev.Error == "" {
				m.rootInVM = true
			} else {
				m.errMsg, m.claimRetryAt = "attach root: "+ev.Error, now.Add(retryInterval)
			}
			break
		}
		e := m.disks[effect.Disk.ID]
		if e == nil || e.adding != ev.Token {
			return nil
		}
		e.adding = 0
		if ev.Error == "" {
			e.inVM = true
		} else if effect.ClaimMount {
			m.errMsg, m.claimRetryAt = "attach "+effect.Disk.Path+": "+ev.Error, now.Add(retryInterval)
		} else {
			e.phase, e.message, e.retryAt = podapi.DiskFailed, "attach: "+ev.Error, now.Add(retryInterval)
		}
	case EffectRemoveDisk:
		e := m.disks[effect.Disk.ID]
		if e == nil || e.removal != ev.Token {
			return nil
		}
		e.removing, e.removal = false, 0
		if ev.Error != "" {
			e.phase, e.message, e.retryAt = podapi.DiskFailed, ev.Error, now.Add(retryInterval)
			break
		}
		e.inVM, e.mounted, e.waiting, e.message = false, false, false, ""
		e.detachPending = false
		m.forgetFreeze(e.d.ID)
		if m.wanted(e.d.ID) && !m.stopRequested() && m.exit == nil {
			e.phase, e.retryAt = podapi.DiskAttaching, time.Time{}
		} else {
			e.phase = podapi.DiskDetached
		}
	}
	return nil
}

func (m *Machine) wanted(id string) bool {
	for _, d := range m.desired.Mounts {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (m *Machine) stopRequested() bool { return m.desired.Stop || m.sigterm }

func (m *Machine) kill() []Effect {
	if m.killSent {
		return nil
	}
	m.killSent = true
	return []Effect{{Kind: EffectKill}}
}

// A lost reply is resolved by reconnecting and adopting Hello, never by
// guessing whether a mount/unmount/freeze took effect or blindly replaying it.
const controlResponseTimeout = 60 * time.Second

func (m *Machine) responseExpired(now time.Time) bool {
	if m.claimWaiting && now.Sub(m.claimSince) >= controlResponseTimeout {
		return true
	}
	for _, e := range m.disks {
		if e.waiting && now.Sub(e.waitSince) >= controlResponseTimeout {
			return true
		}
	}
	for _, since := range m.freezeSince {
		if now.Sub(since) >= controlResponseTimeout {
			return true
		}
	}
	return false
}

// Reconcile returns operations needed for the current state. Pending operations
// are never reissued. After synchronous results, call Reconcile again until no
// synchronous operation remains; asynchronous guest/removal results arrive later.
func (m *Machine) Reconcile(now time.Time) []Effect {
	now = now.Round(0).UTC()
	m.init()
	if m.exited || m.killSent {
		return nil
	}
	effects := m.reconcileNetwork(now)
	if m.stopRequested() && m.stopSince.IsZero() {
		m.stopSince = now
	}
	if !m.stopSince.IsZero() && now.Sub(m.stopSince) > stopTimeout {
		return append(effects, m.kill()...)
	}
	if !m.connected || !m.helloReady {
		return effects
	}
	if m.stopRequested() {
		if !m.shutdownSent && !m.shutdownDone {
			effects = append(effects, m.send(wire.TShutdown, wire.Shutdown{Reason: "Stop"}))
			m.shutdownSent = true
		}
		return effects
	}
	if m.exit != nil {
		return effects
	}
	if m.responseExpired(now) {
		return append(effects, m.disconnect()...)
	}
	c := m.desired.Claim
	if c == nil {
		return effects
	}
	// A VM's root attachment is immutable. A late attach/result or an
	// adopted Hello must never authorize a different root's claim.
	if (m.rootDisk != nil && !sameAttachment(*m.rootDisk, c.Root)) || (m.claimID != "" && m.claimID != c.Root.ID) {
		m.errMsg = "desired claim changed after root attachment"
		return append(effects, m.kill()...)
	}
	if m.claimID == "" {
		if !m.networkReady || m.claimWaiting || now.Before(m.claimRetryAt) {
			return effects
		}
		if !m.rootInVM {
			if m.rootAdding == 0 {
				e := m.issue(Effect{Kind: EffectAddDisk, Disk: c.Root, Root: true})
				root := c.Root
				m.rootDisk = &root
				m.rootAdding = e.Token
				effects = append(effects, e)
			}
			return effects
		}
		var mounts []wire.Mount
		for _, d := range m.desired.Mounts {
			e := m.ensureDisk(d)
			if !e.inVM {
				if e.adding == 0 {
					add := m.issue(Effect{Kind: EffectAddDisk, Disk: d, ClaimMount: true})
					e.adding = add.Token
					effects = append(effects, add)
				}
				return effects
			}
			mounts = append(mounts, wire.Mount{ID: d.ID, Serial: diskSerial(d), Path: d.Path, ReadOnly: d.ReadOnly})
		}
		for _, mount := range mounts {
			e := m.disks[mount.ID]
			e.waiting, e.waitType, e.waitSince = true, wire.TMountResult, now
		}
		effects = append(effects, m.send(wire.TClaim, wire.Claim{
			ID: c.Root.ID, Serial: diskSerial(c.Root), Hostname: c.BlipName,
			Command: append([]string(nil), c.Command...), Env: append([]string(nil), c.Env...), WorkingDir: c.WorkingDir,
			User: c.User, Mounts: mounts,
		}))
		m.claimWaiting, m.claimSince = true, now
		return effects
	}
	effects = append(effects, m.reconcileMounts(now)...)
	return append(effects, m.reconcileFreeze(now)...)
}

func (m *Machine) policyKey() string {
	data, _ := json.Marshal(struct {
		Policy *netpolicy.Policy
		Active bool
	}{m.desired.Network, m.desired.Claim != nil})
	return string(data)
}

func (m *Machine) reconcileNetwork(now time.Time) []Effect {
	p := m.desired.Network
	if m.skipNetwork {
		m.networkReady, m.networkError, m.networkRevision = true, "", ""
		if p != nil {
			m.networkRevision = p.Revision
		}
		return nil
	}
	key := m.policyKey()
	if key != m.networkKey {
		m.networkReady, m.networkRevision = false, ""
	}
	if m.networkApplying != 0 || (key == m.networkKey && (m.networkError == "" || now.Before(m.networkRetryAt))) {
		return nil
	}
	m.networkKey = key
	m.networkReady, m.networkRevision, m.networkError = false, "", ""
	policy := clonePolicy(p)
	e := m.issue(Effect{Kind: EffectNetwork, Policy: policy, Active: m.desired.Claim != nil, Key: key})
	m.networkApplying = e.Token
	return []Effect{e}
}

func (m *Machine) send(typ wire.Type, v any) Effect {
	data, _ := json.Marshal(v)
	return Effect{Kind: EffectSend, Generation: m.gen, Type: typ, Payload: data}
}

func (m *Machine) resetFreeze() {
	m.frozen, m.freezeWaiting, m.thawing, m.freezeSkip = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	m.freezeSince = map[string]time.Time{}
}

func (m *Machine) reconcileFreeze(now time.Time) []Effect {
	var effects []Effect
	want := map[string]bool{}
	for _, id := range m.desired.Freeze {
		want[id] = true
		if e := m.disks[id]; e != nil && (!e.mounted || e.waiting || e.removing) {
			continue
		}
		if m.frozen[id] || m.freezeWaiting[id] || m.freezeSkip[id] {
			continue
		}
		effects = append(effects, m.send(wire.TFreeze, wire.Freeze{ID: id}))
		m.freezeWaiting[id], m.freezeSince[id] = true, now
	}
	for id := range m.freezeSkip {
		if !want[id] {
			delete(m.freezeSkip, id)
		}
	}
	// A stable order is essential for deterministic traces with multiple thaws.
	var ids []string
	for id := range m.frozen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !want[id] && !m.freezeWaiting[id] {
			effects = append(effects, m.send(wire.TThaw, wire.Freeze{ID: id}))
			delete(m.frozen, id)
			m.freezeWaiting[id], m.thawing[id], m.freezeSince[id] = true, true, now
		}
	}
	return effects
}

func (m *Machine) ensureDisk(d podapi.Disk) *disk {
	e := m.disks[d.ID]
	if e == nil {
		e = &disk{d: d, phase: podapi.DiskAttaching}
		m.disks[d.ID] = e
		m.order = append(m.order, d.ID)
	} else if e.phase == podapi.DiskDetached {
		*e = disk{d: d, phase: podapi.DiskAttaching}
	}
	return e
}

func (m *Machine) reconcileMounts(now time.Time) []Effect {
	var effects []Effect
	want := map[string]bool{}
	for _, d := range m.desired.Mounts {
		want[d.ID] = true
		e := m.ensureDisk(d)
		if e.waiting || e.removing || e.adding != 0 || e.mounted || now.Before(e.retryAt) {
			continue
		}
		e.d = d
		if e.detachPending {
			// A failed remove response does not cancel a potentially committed
			// eject. Finish confirming it before attempting a re-add or mount.
			effects = append(effects, m.remove(e))
			continue
		}
		if !e.inVM {
			add := m.issue(Effect{Kind: EffectAddDisk, Disk: d})
			e.adding = add.Token
			effects = append(effects, add)
			continue
		}
		effects = append(effects, m.send(wire.TMount, wire.Mount{ID: d.ID, Serial: diskSerial(d), Path: d.Path, ReadOnly: d.ReadOnly}))
		e.waiting, e.waitType, e.waitSince = true, wire.TMountResult, now
		if e.phase != podapi.DiskFailed {
			e.phase = podapi.DiskAttaching
		}
	}
	var stale []string
	for _, id := range m.order {
		e := m.disks[id]
		if want[id] || e.waiting || e.removing || e.adding != 0 || now.Before(e.retryAt) {
			continue
		}
		if e.phase == podapi.DiskDetached {
			if e.d.ReadOnly {
				stale = append(stale, id)
			}
			continue
		}
		switch {
		case e.mounted:
			effects = append(effects, m.send(wire.TUnmount, wire.Unmount{ID: id}))
			e.waiting, e.waitType, e.waitSince = true, wire.TUnmountResult, now
			if e.phase != podapi.DiskFailed {
				e.phase = podapi.DiskUnmounting
			}
		case e.inVM:
			effects = append(effects, m.remove(e))
		default:
			e.phase = podapi.DiskDetached
		}
	}
	for _, id := range stale {
		m.dropDisk(id)
	}
	return effects
}

func (m *Machine) remove(e *disk) Effect {
	remove := m.issue(Effect{Kind: EffectRemoveDisk, Disk: e.d})
	e.removing, e.detachPending, e.removal, e.phase = true, true, remove.Token, podapi.DiskUnmounting
	return remove
}

func (m *Machine) dropDisk(id string) {
	delete(m.disks, id)
	m.forgetFreeze(id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

func (m *Machine) forgetFreeze(id string) {
	delete(m.frozen, id)
	delete(m.freezeSkip, id)
	delete(m.freezeWaiting, id)
	delete(m.freezeSince, id)
	delete(m.thawing, id)
}

func diskSerial(d podapi.Disk) string {
	if d.Serial != "" {
		return d.Serial
	}
	return d.ID
}

func sameAttachment(a, b podapi.Disk) bool {
	return a.ID == b.ID && a.Device == b.Device && diskSerial(a) == diskSerial(b) && a.ReadOnly == b.ReadOnly
}

func (m *Machine) phase() string {
	switch {
	case m.exited:
		return podapi.PhaseExited
	case m.shutdownSent || m.shutdownDone || m.exit != nil || (m.stopRequested() && m.hello):
		return podapi.PhaseStopping
	case m.claimID != "":
		return podapi.PhaseRunning
	case m.desired.Claim != nil && m.hello:
		return podapi.PhaseClaiming
	case m.hello:
		return podapi.PhaseWarm
	}
	return podapi.PhaseBooting
}

// Observed returns a detached snapshot suitable for the pod API or a trace.
func (m *Machine) Observed() podapi.Observed {
	o := podapi.Observed{Phase: m.phase(), ClaimID: m.claimID, Error: m.errMsg, NetworkRevision: m.networkRevision, NetworkError: m.networkError}
	if m.exit != nil {
		ex := *m.exit
		o.Exit = &ex
	}
	for _, id := range m.desired.Freeze {
		if m.frozen[id] {
			o.Frozen = append(o.Frozen, id)
		}
	}
	for _, id := range m.order {
		e := m.disks[id]
		o.Mounts = append(o.Mounts, podapi.DiskStatus{ID: id, State: e.d.State, Phase: e.phase, Message: e.message})
	}
	return o
}
