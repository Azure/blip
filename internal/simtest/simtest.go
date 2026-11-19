// Package simtest provides conformance checks shared by component model tests.
//
// The helpers deliberately keep model construction and properties with the
// caller: they only check the replay and exploration contracts of internal/sim.
package simtest

import (
	"testing"

	"github.com/Azure/blip/internal/sim"
)

// Run executes a seeded simulation of initial for each seed and replays every
// trace, failing if either step errors or if replay does not reproduce the
// recorded transitions exactly. It also fails if the initial model's key
// changes before, during, or after a run, which would make exploration and
// replay unsound.
func Run(t *testing.T, initial sim.Model, seeds []uint64, steps int) {
	t.Helper()
	if len(seeds) == 0 {
		t.Fatal("simtest: no seeds")
	}
	want := initial.Key()
	for _, seed := range seeds {
		if got := initial.Key(); got != want {
			t.Fatalf("simtest: seed %d: initial key changed before run: %s -> %s", seed, want, got)
		}
		trace, err := sim.Run(initial, seed, steps)
		if err != nil {
			t.Fatalf("simtest: seed %d: run: %v", seed, err)
		}
		if got := initial.Key(); got != want {
			t.Fatalf("simtest: seed %d: run mutated initial: %s -> %s", seed, want, got)
		}
		if _, err := sim.Replay(initial, trace); err != nil {
			t.Fatalf("simtest: seed %d: replay: %v", seed, err)
		}
		if got := initial.Key(); got != want {
			t.Fatalf("simtest: seed %d: replay mutated initial: %s -> %s", seed, want, got)
		}
	}
}

// Explore explores initial within limits and returns the report. It fails only
// on exploration errors; callers decide whether a report must be Complete.
func Explore(t *testing.T, initial sim.Model, limits sim.Limits) sim.Report {
	t.Helper()
	want := initial.Key()
	report, err := sim.Explore(initial, limits)
	if err != nil {
		t.Fatalf("simtest: explore: %v", err)
	}
	if got := initial.Key(); got != want {
		t.Fatalf("simtest: explore mutated initial: %s -> %s", want, got)
	}
	if report.Trace.Initial != want {
		t.Fatalf("simtest: explore initial key %q differs from model key %q", report.Trace.Initial, want)
	}
	return report
}
