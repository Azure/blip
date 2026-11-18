package runtime

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

func TestMachineCloneOwnsMutableState(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewMachine(false)
	desired := simulationDesired()
	desired.Claim.Command = []string{"sleep", "1"}
	desired.Claim.Env = []string{"A=1"}
	desired.Freeze = []string{"data"}
	desired.Network = &network.Policy{Revision: "one", Layers: [][]network.Rule{{{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.1/32"}}}}}
	m.Apply(now, Event{Kind: EventDesired, Desired: desired})
	desired.Claim.Command[0] = "changed"
	desired.Claim.Env[0] = "changed"
	desired.Mounts[0].Path = "changed"
	desired.Freeze[0] = "changed"
	desired.Network.Layers[0][0].Except[0] = "changed"
	if m.desired.Claim.Command[0] != "sleep" || m.desired.Claim.Env[0] != "A=1" || m.desired.Mounts[0].Path != "/data" || m.desired.Freeze[0] != "data" || m.desired.Network.Layers[0][0].Except[0] != "10.0.0.1/32" {
		t.Fatal("desired aliases the input")
	}
	m.ensureDisk(m.desired.Mounts[0])
	m.rootDisk = &podapi.Disk{ID: "root"}
	m.exit = &podapi.Exit{Reason: "Completed"}
	m.frozen["data"], m.freezeWaiting["data"], m.thawing["data"], m.freezeSkip["data"] = true, true, true, true
	m.freezeSince["data"] = now
	effect := m.issue(Effect{Kind: EffectNetwork, Policy: clonePolicy(m.desired.Network), Payload: json.RawMessage(`{"test":1}`)})
	key := m.Key()
	effect.Policy.Revision = "caller mutation"
	effect.Policy.Layers[0][0].Except[0] = "caller mutation"
	effect.Payload[8] = '2'
	if m.Key() != key {
		t.Fatal("returned effect aliases pending state")
	}
	c := m.Clone()
	if c.Key() != key || !reflect.DeepEqual(c, m) {
		t.Fatal("clone lost private state")
	}
	c.desired.Claim.Command[0] = "changed"
	c.desired.Claim.Env[0] = "changed"
	c.desired.Mounts[0].Path = "changed"
	c.desired.Freeze[0] = "changed"
	c.desired.Network.Layers[0][0].Except[0] = "changed"
	c.rootDisk.ID = "changed"
	c.exit.Reason = "changed"
	c.order[0] = "changed"
	c.disks["data"].d.Path = "changed"
	delete(c.disks, "data")
	delete(c.frozen, "data")
	delete(c.freezeWaiting, "data")
	delete(c.thawing, "data")
	delete(c.freezeSkip, "data")
	c.freezeSince["data"] = now.Add(time.Second)
	e := c.pending[effect.Token]
	e.Policy.Layers[0][0].Except[0] = "changed"
	e.Payload[8] = '3'
	delete(c.pending, effect.Token)
	if m.Key() != key {
		t.Fatal("clone mutation reached the original")
	}
	if c.Key() == key {
		t.Fatal("changed clone retained its key")
	}
}

func TestMachineKeyDistinguishesFutureBehavior(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewMachine(false)
	m.Apply(now, Event{Kind: EventDesired, Desired: podapi.Desired{Network: &network.Policy{Revision: "one"}}})
	e := m.Reconcile(now)[0]
	c := m.Clone()
	// Same external observations, different pending completion semantics.
	changed := c.pending[e.Token]
	changed.Policy.Revision = "other"
	if !reflect.DeepEqual(m.Observed(), c.Observed()) || m.Key() == c.Key() {
		t.Fatal("key discarded pending policy state")
	}
	m.Apply(now, Event{Kind: EventResult, Token: e.Token})
	c.Apply(now, Event{Kind: EventResult, Token: e.Token})
	if m.Observed().NetworkRevision == c.Observed().NetworkRevision {
		t.Fatal("test did not distinguish completion behavior")
	}

	s := newLifecycleSimulation(t)
	s.claim(simulationDesired())
	s.m.desired.Mounts = nil
	s.settle()
	s.take(EffectSend, wire.TUnmount)
	fast := s.m.Clone()
	fast.disks["data"].waitSince = now.Add(-controlResponseTimeout)
	if !reflect.DeepEqual(s.m.Observed(), fast.Observed()) || s.m.Key() == fast.Key() {
		t.Fatal("key discarded control-response deadline")
	}
	if len(s.m.Reconcile(now)) != 0 || len(fast.Reconcile(now)) != 2 {
		t.Fatal("deadline did not distinguish future reconnect behavior")
	}
}

func TestMachineKeyCanonicalAndCloneReplay(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewMachine(true)
	m.Apply(now, Event{Kind: EventDesired, Desired: simulationDesired()})
	m.Apply(now, Event{Kind: EventConnected})
	m.Apply(now, Event{Kind: EventControl, Type: wire.THello, Payload: json.RawMessage(`{}`)})
	root := m.Reconcile(now)[0]
	m.freezeSkip["b"], m.freezeSkip["a"] = true, true
	c := m.Clone()
	c.freezeSkip = map[string]bool{}
	c.freezeSkip["a"], c.freezeSkip["b"] = true, true
	if m.Key() != c.Key() {
		t.Fatal("key depends on map insertion order")
	}
	// An equivalent wall clock in another location must replay identically.
	otherTime := now.In(time.FixedZone("offset", 3600))
	left := m.Apply(now, Event{Kind: EventResult, Token: root.Token, Error: "retry"})
	right := c.Apply(otherTime, Event{Kind: EventResult, Token: root.Token, Error: "retry"})
	if !reflect.DeepEqual(left, right) || m.Key() != c.Key() {
		t.Fatal("clone did not replay the pending root completion")
	}
	left, right = m.Reconcile(now.Add(retryInterval)), c.Reconcile(otherTime.Add(retryInterval))
	if !reflect.DeepEqual(left, right) || m.Key() != c.Key() {
		t.Fatal("clone did not replay the root retry")
	}
}
