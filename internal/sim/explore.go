// Package sim explores production state machines against explicit models of
// their environment. It owns no goroutines, wall clocks, or global random state.
package sim

import (
	"fmt"
	"math/rand/v2"
	"slices"
)

// Model includes both application state and the external world's actual,
// observed and durable state. Enabled must enumerate all and only physically
// possible next actions in that modeled world. Step executes one such action,
// including fault injection.
//
// Clone must isolate all mutable state. Key must canonically encode everything
// that can affect future behavior, including timers, in-flight effects and
// monitors. Omitting any of these can make exhaustive exploration unsound.
// Clones must have the same key and behavior as their source. Key, Enabled and
// Check must be read-only, and Step must be deterministic for a state and action:
// represent random choices and external fault outcomes as separate actions.
// A Step error aborts the simulation; expected failures of modeled operations
// belong in the resulting state instead. Check must include terminal-state
// requirements when simply having no enabled actions would not mean success.
type Model interface {
	Clone() Model
	Key() string
	Enabled() []string
	Step(action string) error
	Check() error
}

// Transition records keys as well as actions so replay detects model drift.
type Transition struct {
	Action string `json:"action"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type Trace struct {
	Seed    uint64       `json:"seed"`
	Initial string       `json:"initial"`
	Steps   []Transition `json:"steps"`
}

// Run takes at most steps transitions, checking the initial state and every
// resulting state. It leaves initial untouched. Exhausting the step budget is
// not a liveness proof; scenarios must separately check their obligations.
func Run(initial Model, seed uint64, steps int) (Trace, error) {
	t := Trace{Seed: seed}
	if steps < 0 {
		return t, fmt.Errorf("negative step budget")
	}
	m := initial.Clone()
	t.Initial = m.Key()
	if err := m.Check(); err != nil {
		return t, fmt.Errorf("initial invariant: %w", err)
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for range steps {
		actions, err := enabled(m)
		if err != nil {
			return t, err
		}
		if len(actions) == 0 {
			break
		}
		a := actions[rng.IntN(len(actions))]
		x, err := advance(m, a)
		t.Steps = append(t.Steps, x)
		if err != nil {
			return t, fmt.Errorf("step %d (%s): %w", len(t.Steps), a, err)
		}
	}
	return t, nil
}

// Replay requires exactly the recorded states, not just the same seed. It
// returns the final (or failing) model without modifying initial.
// A failing transition must be the last recorded step; an unreachable suffix
// is a replay error, not reproduction of the model's failure.
func Replay(initial Model, trace Trace) (Model, error) {
	m := initial.Clone()
	if m.Key() != trace.Initial {
		return m, fmt.Errorf("replay initial state differs")
	}
	if err := m.Check(); err != nil {
		if len(trace.Steps) != 0 {
			return m, fmt.Errorf("replay has steps after a failed initial invariant")
		}
		return m, fmt.Errorf("initial invariant: %w", err)
	}
	for i, want := range trace.Steps {
		if m.Key() != want.Before {
			return m, fmt.Errorf("replay step %d: before state differs", i+1)
		}
		actions, err := enabled(m)
		if err != nil {
			return m, fmt.Errorf("replay step %d: %w", i+1, err)
		}
		if !slices.Contains(actions, want.Action) {
			return m, fmt.Errorf("replay step %d: action %q is disabled", i+1, want.Action)
		}
		got, stepErr := advance(m, want.Action)
		if got != want {
			return m, fmt.Errorf("replay step %d: state differs", i+1)
		}
		if stepErr != nil {
			if i+1 != len(trace.Steps) {
				return m, fmt.Errorf("replay has steps after failed step %d (%s)", i+1, want.Action)
			}
			return m, fmt.Errorf("step %d (%s): %w", i+1, want.Action, stepErr)
		}
	}
	return m, nil
}

type Limits struct {
	// States bounds the number of distinct states retained for expansion,
	// including the initial state. Outgoing transitions are still checked when
	// this bound is full, but new states are not retained for further expansion.
	States int
	// Depth is the maximum number of transitions in an explored path. Zero
	// checks only the initial state and whether it has enabled actions.
	Depth int
}

type Report struct {
	States      int  // distinct states retained, including the initial state
	Transitions int  // attempted Step calls, including failing transitions
	Complete    bool // true only after an error-free search without truncation
	// Trace records the path to a failure. Step/Check counterexamples are
	// shortest unless the state bound truncated the search.
	Trace Trace
}

// Explore breadth-first searches the reachable graph. Cycles are deduplicated
// by Key. A complete report proves safety only for this finite model; temporal
// fairness and unbounded system behavior require separate arguments.
func Explore(initial Model, limits Limits) (Report, error) {
	var r Report
	if limits.States < 1 || limits.Depth < 0 {
		return r, fmt.Errorf("invalid exploration limits")
	}
	root := initial.Clone()
	r.Trace.Initial = root.Key()
	r.States = 1
	if err := root.Check(); err != nil {
		return r, fmt.Errorf("initial invariant: %w", err)
	}
	type node struct {
		model  Model
		parent int
		depth  int
		via    Transition
	}
	queue := []node{{model: root, parent: -1}}
	seen := map[string]bool{r.Trace.Initial: true}
	path := func(at int) []Transition {
		steps := make([]Transition, queue[at].depth)
		for i := len(steps) - 1; i >= 0; i-- {
			steps[i] = queue[at].via
			at = queue[at].parent
		}
		return steps
	}
	r.Complete = true
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		// Only ancestry is needed after expansion; release the potentially large
		// model while retaining the information needed to reconstruct a trace.
		queue[head].model = nil
		actions, err := enabled(n.model)
		if err != nil {
			r.Complete = false
			r.Trace.Steps = path(head)
			return r, fmt.Errorf("enabled actions at depth %d: %w", n.depth, err)
		}
		if n.depth == limits.Depth {
			if len(actions) > 0 {
				r.Complete = false
			}
			continue
		}
		for _, a := range actions {
			m := n.model.Clone()
			x, err := advance(m, a)
			r.Transitions++
			if err != nil {
				r.Complete = false
				r.Trace.Steps = append(path(head), x)
				return r, fmt.Errorf("action %s at depth %d: %w", a, n.depth+1, err)
			}
			key := x.After
			if seen[key] {
				continue
			}
			if len(queue) >= limits.States {
				r.Complete = false
				continue
			}
			seen[key] = true
			queue = append(queue, node{model: m, parent: head, depth: n.depth + 1, via: x})
			r.States++
		}
	}
	return r, nil
}

func advance(m Model, action string) (Transition, error) {
	x := Transition{Action: action, Before: m.Key()}
	err := m.Step(action)
	x.After = m.Key()
	if err == nil {
		err = m.Check()
	}
	return x, err
}

func enabled(m Model) ([]string, error) {
	a := slices.Clone(m.Enabled())
	slices.Sort(a)
	for i, name := range a {
		if name == "" || (i > 0 && a[i-1] == name) {
			return nil, fmt.Errorf("empty or duplicate action %q", name)
		}
	}
	return a, nil
}

// Shrink removes chunks of a trace while the caller's predicate still
// reproduces the same violation. The predicate must reject invalid schedules
// and distinguish the original violation from unrelated errors. This makes
// shrinking usable with fault scripts as well as model actions.
// The predicate must be deterministic and must not mutate data referenced by
// the elements (slice storage is copied). The result is 1-minimal: removing any
// single remaining element no longer fails. It need not be the shortest failing
// subsequence. A trace that does not fail is returned unchanged.
func Shrink[T any](trace []T, fails func([]T) bool) []T {
	out := slices.Clone(trace)
	if len(out) == 0 || !fails(slices.Clone(out)) {
		return out
	}
	if empty := slices.Clone(out[:0]); fails(empty) {
		return empty
	}
	for size := max(1, len(out)/2); ; size = max(1, size/2) {
		for i := 0; i+size <= len(out); {
			candidate := append(slices.Clone(out[:i]), out[i+size:]...)
			if fails(slices.Clone(candidate)) {
				out = candidate
				// A later deletion may make an earlier event removable, especially
				// when the predicate also checks schedule validity.
				i = 0
			} else {
				i++
			}
		}
		if size == 1 {
			return out
		}
	}
}
