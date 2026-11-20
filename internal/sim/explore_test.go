// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package sim

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// publication is a deliberately small harness qualification model. Application
// simulations live with their production components. The mutation publishes
// on a lost reply rather than waiting for durable evidence.
type publication struct {
	Requested bool
	Applied   bool
	Ack       bool
	Published bool
	Mutant    bool
}

func (m *publication) Clone() Model { n := *m; return &n }
func (m *publication) Key() string {
	b, _ := json.Marshal(m)
	return string(b)
}
func (m *publication) Enabled() []string {
	if !m.Requested {
		return []string{"request"}
	}
	if !m.Applied {
		return []string{"apply", "lose-reply"}
	}
	if !m.Ack {
		return []string{"ack", "lose-reply"}
	}
	if !m.Published {
		return []string{"publish"}
	}
	return nil
}
func (m *publication) Step(a string) error {
	switch a {
	case "request":
		m.Requested = true
	case "apply":
		m.Applied = true
	case "ack":
		m.Ack = true
	case "publish":
		m.Published = true
	case "lose-reply":
		m.Requested = false
		if m.Mutant {
			m.Published = true
		}
	default:
		return fmt.Errorf("unknown action %q", a)
	}
	return nil
}
func (m *publication) Check() error {
	if m.Published && !m.Applied {
		return fmt.Errorf("publication before persistence")
	}
	return nil
}

func TestExploreDetectsMutationAndReplaysShortestTrace(t *testing.T) {
	good, err := Explore(&publication{}, Limits{States: 100, Depth: 100})
	if err != nil || !good.Complete {
		t.Fatalf("valid model: %+v, %v", good, err)
	}
	initial := &publication{Mutant: true}
	bad, err := Explore(initial, Limits{States: 100, Depth: 100})
	if err == nil || !strings.Contains(err.Error(), "publication before persistence") {
		t.Fatalf("mutation escaped: %+v, %v", bad, err)
	}
	if bad.Complete || len(bad.Trace.Steps) != 2 {
		t.Fatalf("expected shortest two-step violation: %+v", bad)
	}
	data, err := json.Marshal(bad.Trace)
	if err != nil {
		t.Fatal(err)
	}
	var trace Trace
	if err := json.Unmarshal(data, &trace); err != nil {
		t.Fatal(err)
	}
	_, err = Replay(initial, trace)
	if err == nil || !strings.Contains(err.Error(), "publication before persistence") {
		t.Fatalf("replay did not reproduce violation: %v", err)
	}
	if initial.Requested || initial.Published {
		t.Fatal("exploration mutated initial state")
	}
}

func TestExplorationReportsTruncation(t *testing.T) {
	for _, limits := range []Limits{{States: 1, Depth: 100}, {States: 100, Depth: 1}} {
		r, err := Explore(&publication{}, limits)
		if err != nil || r.Complete {
			t.Fatalf("bounds mistaken for proof: %+v, %v", r, err)
		}
	}
}

func TestSeedReplayAndDrift(t *testing.T) {
	initial := &publication{}
	a, err := Run(initial, 42, 50)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(initial, 42, 50)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("seed is not reproducible: %v", err)
	}
	if _, err := Replay(initial, a); err != nil {
		t.Fatal(err)
	}
	a.Steps[0].After = "changed"
	if _, err := Replay(initial, a); err == nil {
		t.Fatal("replay accepted changed execution")
	}
}
