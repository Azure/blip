// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simtest

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Azure/blip/internal/sim"
)

// counter is a deliberately small model for qualifying the shared helpers.
type counter struct {
	Count   int
	Stopped bool
}

func (m *counter) Clone() sim.Model {
	n := *m
	return &n
}

func (m *counter) Key() string {
	return fmt.Sprintf("count=%d stopped=%t", m.Count, m.Stopped)
}

func (m *counter) Enabled() []string {
	if m.Stopped {
		return nil
	}
	if m.Count >= 2 {
		return []string{"reset", "stop"}
	}
	return []string{"inc", "reset", "stop"}
}

func (m *counter) Step(action string) error {
	switch action {
	case "inc":
		m.Count++
	case "reset":
		m.Count = 0
	case "stop":
		m.Stopped = true
	default:
		return fmt.Errorf("counter: unknown action %q", action)
	}
	return nil
}

func (m *counter) Check() error {
	if m.Count < 0 || m.Count > 2 {
		return fmt.Errorf("counter: count %d out of range", m.Count)
	}
	return nil
}

func TestSeedsDefaultAndEnvironmentOverride(t *testing.T) {
	t.Setenv("BLIP_SIM_SEED", "")
	t.Setenv("BLIP_SIM_RUNS", "")
	if got, want := Seeds(7, 3), []uint64{7, 8, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Seeds() = %v, want %v", got, want)
	}
	t.Setenv("BLIP_SIM_SEED", "1000")
	t.Setenv("BLIP_SIM_RUNS", "4")
	if got, want := Seeds(7, 3), []uint64{1000, 1001, 1002, 1003}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Seeds() = %v, want %v", got, want)
	}
	t.Setenv("BLIP_SIM_SEED", "bad")
	t.Setenv("BLIP_SIM_RUNS", "-1")
	if got, want := Seeds(7, 3), []uint64{7, 8, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("malformed environment changed Seeds() = %v, want %v", got, want)
	}
	if got := Seeds(0, 0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("Seeds(0, 0) = %v, want [0]", got)
	}
}

func TestRunReplaysEverySeedWithoutMutatingInitial(t *testing.T) {
	initial := &counter{}
	want := initial.Key()
	Run(t, initial, []uint64{1, 2, 3, 3, 42}, 100)
	if got := initial.Key(); got != want {
		t.Fatalf("initial changed: %s -> %s", want, got)
	}
}

func TestRunIsDeterministicAndReplayable(t *testing.T) {
	initial := &counter{}
	a, err := sim.Run(initial, 99, 50)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sim.Run(initial, 99, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same seed produced different traces:\n%+v\n%+v", a, b)
	}
	final, err := sim.Replay(initial, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := final.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestExploreReturnsCompleteReport(t *testing.T) {
	initial := &counter{}
	want := initial.Key()
	report := Explore(t, initial, sim.Limits{States: 100, Depth: 10})
	if !report.Complete {
		t.Fatalf("finite counter graph was truncated: %+v", report)
	}
	if report.States != 6 {
		t.Fatalf("states=%d, want 6", report.States)
	}
	if report.Trace.Initial != want {
		t.Fatalf("initial trace key=%q, want %q", report.Trace.Initial, want)
	}
	if got := initial.Key(); got != want {
		t.Fatalf("initial changed: %s -> %s", want, got)
	}
}

func TestExploreReturnsTruncatedReportWithoutRequiringComplete(t *testing.T) {
	initial := &counter{}
	want := initial.Key()
	for _, limits := range []sim.Limits{
		{States: 2, Depth: 10},
		{States: 100, Depth: 0},
	} {
		report := Explore(t, initial, limits)
		if report.Complete {
			t.Fatalf("limits %+v reported a complete search", limits)
		}
	}
	if got := initial.Key(); got != want {
		t.Fatalf("initial changed: %s -> %s", want, got)
	}
}
