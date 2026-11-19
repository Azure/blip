package runtime

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/podapi"
)

// Clone returns an independent machine, including in-flight effects and retry
// deadlines. A simulator can branch here and deliver different future events.
func (m *Machine) Clone() *Machine {
	if m == nil {
		return nil
	}
	c := *m
	c.desired = cloneDesired(m.desired)
	if m.rootDisk != nil {
		root := *m.rootDisk
		c.rootDisk = &root
	}
	if m.exit != nil {
		exit := *m.exit
		c.exit = &exit
	}
	c.order = slices.Clone(m.order)
	c.disks = maps.Clone(m.disks)
	for id, d := range c.disks {
		copy := *d
		c.disks[id] = &copy
	}
	c.frozen = maps.Clone(m.frozen)
	c.freezeWaiting = maps.Clone(m.freezeWaiting)
	c.thawing = maps.Clone(m.thawing)
	c.freezeSkip = maps.Clone(m.freezeSkip)
	c.freezeSince = maps.Clone(m.freezeSince)
	c.pending = maps.Clone(m.pending)
	for token, e := range c.pending {
		c.pending[token] = cloneEffect(e)
	}
	return &c
}

func cloneDesired(d podapi.Desired) podapi.Desired {
	d.Network = clonePolicy(d.Network)
	if d.Claim != nil {
		claim := *d.Claim
		claim.Command = slices.Clone(claim.Command)
		claim.Env = slices.Clone(claim.Env)
		d.Claim = &claim
	}
	d.Mounts = slices.Clone(d.Mounts)
	d.Freeze = slices.Clone(d.Freeze)
	return d
}

func clonePolicy(p *netpolicy.Policy) *netpolicy.Policy {
	if p == nil {
		return nil
	}
	c := *p
	c.Layers = slices.Clone(p.Layers)
	for i, layer := range c.Layers {
		c.Layers[i] = slices.Clone(layer)
		for j := range c.Layers[i] {
			c.Layers[i][j].Except = slices.Clone(layer[j].Except)
		}
	}
	return &c
}

func cloneEffect(e Effect) Effect {
	e.Payload = slices.Clone(e.Payload)
	e.Policy = clonePolicy(e.Policy)
	return e
}

// Key returns canonical JSON for the complete machine state, not just Observed.
// Private pending operations, counters and deadlines determine future behavior
// and must participate in model-checker state deduplication. Map insertion order
// is immaterial; disk order is not. Apply/Reconcile normalize clocks to wall time.
func (m *Machine) Key() string {
	if m == nil {
		return "null"
	}
	disks := make(map[string]any, len(m.disks))
	for id, d := range m.disks {
		disks[id] = map[string]any{
			"disk": d.d, "phase": d.phase, "message": d.message,
			"inVM": d.inVM, "mounted": d.mounted, "waiting": d.waiting,
			"removing": d.removing, "detachPending": d.detachPending,
			"waitType": d.waitType, "waitSince": d.waitSince, "retryAt": d.retryAt,
			"adding": d.adding, "removal": d.removal,
		}
	}
	state := map[string]any{
		"desired": m.desired, "gen": m.gen,
		"connected": m.connected, "helloReady": m.helloReady, "hello": m.hello,
		"claimID": m.claimID, "claimWaiting": m.claimWaiting,
		"claimSince": m.claimSince, "claimRetryAt": m.claimRetryAt,
		"rootInVM": m.rootInVM, "rootDisk": m.rootDisk, "rootAdding": m.rootAdding,
		"disks": disks, "order": m.order, "exit": m.exit,
		"errMsg": m.errMsg, "sigterm": m.sigterm, "shutdownSent": m.shutdownSent,
		"shutdownDone": m.shutdownDone, "stopSince": m.stopSince,
		"exited": m.exited, "killSent": m.killSent,
		"frozen": m.frozen, "freezeWaiting": m.freezeWaiting,
		"thawing": m.thawing, "freezeSkip": m.freezeSkip, "freezeSince": m.freezeSince,
		"networkReady": m.networkReady, "networkRevision": m.networkRevision,
		"networkError": m.networkError, "networkKey": m.networkKey,
		"networkRetryAt": m.networkRetryAt, "networkApplying": m.networkApplying,
		"skipNetwork": m.skipNetwork, "nextToken": m.nextToken, "pending": m.pending,
	}
	data, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	return string(data)
}
