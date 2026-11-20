// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simlive_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/blip/internal/podapi"
	vm "github.com/Azure/blip/internal/runtime"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simlive"
	"github.com/Azure/blip/internal/wire"
)

// claimWorld checks the production runtime's progress with a stable desired
// claim, functioning host/guest effects, and explicit weak scheduling fairness.
// Host execution and response delivery are separate transitions. Pausing the
// runtime is always possible, so progress cannot follow from safety exploration
// alone. This is a small protocol qualification, not a guest/kernel model.
type claimWorld struct {
	machine  *vm.Machine
	effects  []vm.Effect
	applied  bool
	attached bool
	claimed  bool
}

var claimTime = time.Unix(1000, 0).UTC()

func newClaimWorld() *claimWorld {
	m := vm.NewMachine(true)
	m.Apply(claimTime, vm.Event{Kind: vm.EventDesired, Desired: podapi.Desired{
		Claim: &podapi.Claim{Root: podapi.Disk{ID: "root", Device: "/dev/root"}},
	}})
	m.Apply(claimTime, vm.Event{Kind: vm.EventConnected, Generation: m.Generation()})
	hello, _ := json.Marshal(wire.Hello{Version: wire.Version})
	m.Apply(claimTime, vm.Event{Kind: vm.EventControl, Generation: m.Generation(), Type: wire.THello, Payload: hello})
	return &claimWorld{machine: m}
}

func (w *claimWorld) Clone() sim.Model {
	c := *w
	c.machine = w.machine.Clone()
	c.effects = append([]vm.Effect(nil), w.effects...)
	for i := range c.effects {
		c.effects[i].Payload = append(json.RawMessage(nil), c.effects[i].Payload...)
	}
	return &c
}

func (w *claimWorld) Key() string {
	b, err := json.Marshal(struct {
		Machine                    string
		Effects                    []vm.Effect
		Applied, Attached, Claimed bool
	}{w.machine.Key(), w.effects, w.applied, w.attached, w.claimed})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (w *claimWorld) Enabled() []string {
	actions := []string{"pause", "reconcile"}
	if len(w.effects) > 0 {
		if w.applied {
			actions = append(actions, "deliver")
		} else {
			actions = append(actions, "apply")
		}
	}
	return actions
}

func (w *claimWorld) Step(action string) error {
	switch action {
	case "pause":
	case "reconcile":
		w.effects = append(w.effects, w.machine.Reconcile(claimTime)...)
	case "apply":
		e := w.effects[0]
		switch e.Kind {
		case vm.EffectAddDisk:
			w.attached = true
		case vm.EffectSend:
			if e.Type != wire.TClaim || !w.attached {
				return fmt.Errorf("unexpected or unfenced guest request: %v", e)
			}
			w.claimed = true
		default:
			return fmt.Errorf("unexpected runtime effect: %v", e.Kind)
		}
		w.applied = true
	case "deliver":
		e := w.effects[0]
		w.effects = w.effects[1:]
		w.applied = false
		var result vm.Event
		if e.Kind == vm.EffectSend {
			payload, _ := json.Marshal(wire.Result{ID: "root"})
			result = vm.Event{Kind: vm.EventControl, Generation: e.Generation, Type: wire.TClaimResult, Payload: payload}
		} else {
			result = vm.Event{Kind: vm.EventResult, Token: e.Token}
		}
		w.effects = append(w.effects, w.machine.Apply(claimTime, result)...)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	return nil
}

func (w *claimWorld) Check() error {
	if w.machine.Observed().ClaimID != "" && (!w.attached || !w.claimed) {
		return fmt.Errorf("runtime acknowledged a claim before host and guest applied it")
	}
	return nil
}

func TestProductionRuntimeClaimProgress(t *testing.T) {
	goal := func(m sim.Model) bool { return m.(*claimWorld).machine.Observed().ClaimID == "root" }
	options := simlive.Options{
		Limits: sim.Limits{States: 1000, Depth: 30},
		Goal:   goal,
		WeakFairness: []simlive.Group{
			{Name: "runtime", Actions: []string{"reconcile"}},
			{Name: "host/guest", Actions: []string{"apply"}},
			{Name: "responses", Actions: []string{"deliver"}},
		},
	}
	report, err := simlive.Check(newClaimWorld(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || report.Witness != nil {
		t.Fatalf("fair host, guest, and runtime must finish the claim: %+v", report)
	}
	// The very same production machine has an infinite pause execution when
	// scheduler fairness is absent. Require an explicit counterexample rather
	// than accidentally treating an unexplored/paused execution as success.
	options.WeakFairness = nil
	report, err = simlive.Check(newClaimWorld(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || report.Witness == nil {
		t.Fatalf("missing unfair pause cycle: %+v", report)
	}
}
