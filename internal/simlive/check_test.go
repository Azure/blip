package simlive_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simlive"
)

// Only at is mutable. The graph is immutable and shared by clones.
type graphModel struct {
	at    string
	graph map[string]map[string]string
}

func (m *graphModel) Clone() sim.Model { c := *m; return &c }
func (m *graphModel) Key() string      { return m.at }
func (m *graphModel) Check() error     { return nil }
func (m *graphModel) Enabled() []string {
	var actions []string
	for action := range m.graph[m.at] {
		actions = append(actions, action)
	}
	return actions
}
func (m *graphModel) Step(action string) error {
	to, ok := m.graph[m.at][action]
	if !ok {
		return fmt.Errorf("disabled action %q", action)
	}
	m.at = to
	return nil
}

func goal(m sim.Model) bool { return m.Key() == "goal" }

func options(groups ...simlive.Group) simlive.Options {
	return simlive.Options{Limits: sim.Limits{States: 100, Depth: 100}, Goal: goal, WeakFairness: groups}
}

func check(t *testing.T, m sim.Model, opts simlive.Options) simlive.Report {
	t.Helper()
	before := m.Key()
	r, err := simlive.Check(m, opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Key() != before {
		t.Fatal("checker mutated initial model")
	}
	if r.Witness != nil {
		verifyWitness(t, m, opts, *r.Witness)
	}
	return r
}

// Verify the serialized witness through the independent sim replay API and
// directly check weak fairness on the actual visited cycle states and actions.
func verifyWitness(t *testing.T, initial sim.Model, opts simlive.Options, witness simlive.Witness) {
	t.Helper()
	data, err := json.Marshal(witness)
	if err != nil {
		t.Fatal(err)
	}
	var w simlive.Witness
	if err := json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	m := initial.Clone()
	if opts.Goal(m) {
		t.Fatal("witness begins in goal")
	}
	for _, step := range w.Prefix.Steps {
		m, err = sim.Replay(m, sim.Trace{Initial: m.Key(), Steps: []sim.Transition{step}})
		if err != nil || opts.Goal(m) {
			t.Fatalf("invalid goal-avoiding prefix: %v", err)
		}
	}
	m, err = sim.Replay(initial, w.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Cycle) == 0 {
		if len(m.Enabled()) != 0 {
			t.Fatal("deadlock witness has enabled actions")
		}
		return
	}
	start := m.Key()
	disabled, taken := make([]bool, len(opts.WeakFairness)), make([]bool, len(opts.WeakFairness))
	for _, step := range w.Cycle {
		for i, group := range opts.WeakFairness {
			enabled := false
			for _, action := range group.Actions {
				enabled = enabled || slices.Contains(m.Enabled(), action)
				taken[i] = taken[i] || step.Action == action
			}
			disabled[i] = disabled[i] || !enabled
		}
		m, err = sim.Replay(m, sim.Trace{Initial: m.Key(), Steps: []sim.Transition{step}})
		if err != nil || opts.Goal(m) {
			t.Fatalf("invalid goal-avoiding cycle: %v", err)
		}
	}
	if m.Key() != start {
		t.Fatal("cycle does not close")
	}
	for i, group := range opts.WeakFairness {
		if !disabled[i] && !taken[i] {
			t.Fatalf("cycle starves continuously enabled group %q", group.Name)
		}
	}
	for range 3 {
		m, err = sim.Replay(m, sim.Trace{Initial: start, Steps: w.Cycle})
		if err != nil || m.Key() != start {
			t.Fatalf("cycle cannot repeat: %v", err)
		}
	}
}

func TestContinuouslyEnabledCompletionExcludesUnfairRetry(t *testing.T) {
	m := &graphModel{at: "pending", graph: map[string]map[string]string{
		"pending": {"retry": "pending", "complete": "goal"},
	}}
	for _, fairness := range [][]simlive.Group{nil, {{Name: "retry", Actions: []string{"retry"}}}} {
		r := check(t, m, options(fairness...))
		if !r.Complete || r.Witness == nil || len(r.Witness.Cycle) == 0 {
			t.Fatalf("retry negative control escaped: %+v", r)
		}
	}
	r := check(t, m, options(simlive.Group{Name: "completion", Actions: []string{"complete"}}))
	if !r.Complete || r.Witness != nil || r.States != 2 {
		t.Fatalf("unfair retry treated as violation: %+v", r)
	}
}

func TestIntermittentEnablingDoesNotEnsureProgress(t *testing.T) {
	m := &graphModel{at: "on", graph: map[string]map[string]string{
		"on":  {"complete": "goal", "off": "off", "idle": "on"},
		"off": {"on": "on"},
	}}
	r := check(t, m, options(simlive.Group{Name: "completion", Actions: []string{"complete"}}))
	if !r.Complete || r.Witness == nil || len(r.Witness.Cycle) == 0 {
		t.Fatalf("weak fairness mistaken for strong fairness: %+v", r)
	}
	// A cycle containing only the on/idle self-loop would be unfair.
	foundOff := false
	for _, step := range r.Witness.Cycle {
		foundOff = foundOff || step.Before == "off"
	}
	if !foundOff {
		t.Fatal("witness omitted the vertex that disables completion")
	}
}

func TestActionGroupEnablingIsUnionOfItsActions(t *testing.T) {
	m := &graphModel{at: "a", graph: map[string]map[string]string{
		"a": {"next": "b", "complete-a": "goal"},
		"b": {"next": "a", "complete-b": "goal"},
	}}
	grouped := options(simlive.Group{Name: "completion", Actions: []string{"complete-a", "complete-b"}})
	if r := check(t, m, grouped); !r.Complete || r.Witness != nil {
		t.Fatalf("continuously enabled group starved: %+v", r)
	}
	separate := options(
		simlive.Group{Name: "a", Actions: []string{"complete-a"}},
		simlive.Group{Name: "b", Actions: []string{"complete-b"}},
	)
	if r := check(t, m, separate); !r.Complete || r.Witness == nil {
		t.Fatalf("intermittently enabled individual groups forced progress: %+v", r)
	}
}

func TestWitnessTakesMultipleFairnessEdgesAndConnectsThem(t *testing.T) {
	m := &graphModel{at: "initial", graph: map[string]map[string]string{
		"initial": {"enter": "hub"},
		"hub":     {"idle": "hub", "left": "left", "right": "right", "finish": "goal"},
		"left":    {"back": "hub", "left": "left", "right": "left"},
		"right":   {"back": "hub", "left": "right", "right": "right"},
	}}
	opts := options(
		simlive.Group{Name: "left", Actions: []string{"left"}},
		simlive.Group{Name: "right", Actions: []string{"right"}},
		simlive.Group{Name: "either", Actions: []string{"left", "right"}},
		simlive.Group{Name: "finish", Actions: []string{"finish"}},
	)
	r := check(t, m, opts)
	if !r.Complete || r.Witness == nil || len(r.Witness.Prefix.Steps) != 1 {
		t.Fatalf("missing prefixed fair cycle: %+v", r)
	}
	for _, action := range []string{"left", "right", "back"} {
		if !slices.ContainsFunc(r.Witness.Cycle, func(x sim.Transition) bool { return x.Action == action }) {
			t.Fatalf("cycle omitted required action %q: %+v", action, r.Witness.Cycle)
		}
	}
	if again := check(t, m, opts); !reflect.DeepEqual(r, again) {
		t.Fatal("map iteration changed deterministic witness")
	}
}

func TestTerminalStatesAndGoalPruning(t *testing.T) {
	for _, at := range []string{"initial", "terminal"} {
		m := &graphModel{at: at, graph: map[string]map[string]string{"initial": {"stop": "terminal"}}}
		r := check(t, m, options(simlive.Group{Name: "absent", Actions: []string{"complete"}}))
		if !r.Complete || r.Witness == nil || len(r.Witness.Cycle) != 0 {
			t.Fatalf("unsatisfied terminal accepted: %+v", r)
		}
	}
	for _, at := range []string{"initial", "goal"} {
		m := &graphModel{at: at, graph: map[string]map[string]string{
			"initial": {"finish": "goal"}, "goal": {"leave": "terminal"},
		}}
		opts := options()
		opts.Limits.Depth = 1
		r := check(t, m, opts)
		if !r.Complete || r.Witness != nil || r.Transitions > 1 {
			t.Fatalf("goal state was not pruned: %+v", r)
		}
	}
	for _, at := range []string{"goal", "terminal", "pending"} {
		m := &graphModel{at: at, graph: map[string]map[string]string{"pending": {"finish": "goal"}}}
		opts := options()
		opts.Limits.Depth = 0
		r := check(t, m, opts)
		if r.Complete != (at != "pending") || (r.Witness != nil) != (at == "terminal") {
			t.Fatalf("zero-depth terminal handling for %s: %+v", at, r)
		}
	}
}

func TestBoundsDoNotProveEventualityOrManufactureDeadlocks(t *testing.T) {
	m := &graphModel{at: "a", graph: map[string]map[string]string{
		"a": {"next": "b"}, "b": {"next": "goal"},
	}}
	for _, limits := range []sim.Limits{{States: 1, Depth: 10}, {States: 10, Depth: 1}} {
		opts := options()
		opts.Limits = limits
		if r := check(t, m, opts); r.Complete || r.Witness != nil {
			t.Fatalf("truncation mistaken for conclusion: %+v", r)
		}
	}
	// The known self-loop remains a valid counterexample despite truncation.
	m.graph["a"]["retry"] = "a"
	opts := options()
	opts.Limits.States = 1
	if r := check(t, m, opts); r.Complete || r.Witness == nil {
		t.Fatalf("valid bounded cycle lost: %+v", r)
	}
	// Enabled fairness actions must include omitted outgoing edges too.
	opts.WeakFairness = []simlive.Group{{Name: "next", Actions: []string{"next"}}}
	if r := check(t, m, opts); r.Complete || r.Witness != nil {
		t.Fatalf("omitted edge made an unfair cycle fair: %+v", r)
	}
}

type brokenModel struct {
	stage int
	kind  string
}

func (m *brokenModel) Clone() sim.Model { c := *m; return &c }
func (m *brokenModel) Key() string      { return fmt.Sprint(m.stage) }
func (m *brokenModel) Enabled() []string {
	if m.kind == "duplicate" {
		return []string{"advance", "advance"}
	}
	if m.kind == "empty" {
		return []string{""}
	}
	return []string{"advance"}
}
func (m *brokenModel) Step(string) error {
	m.stage++
	if m.kind == "step" {
		return fmt.Errorf("broken step")
	}
	return nil
}
func (m *brokenModel) Check() error {
	if m.kind == "initial" || (m.kind == "invariant" && m.stage > 0) {
		return fmt.Errorf("broken invariant")
	}
	return nil
}

func TestModelAndConfigurationErrorsAreNotLivenessResults(t *testing.T) {
	for _, kind := range []string{"initial", "invariant", "step", "duplicate", "empty"} {
		r, err := simlive.Check(&brokenModel{kind: kind}, options())
		if err == nil || r.Complete || r.Witness != nil {
			t.Fatalf("%s: %+v, %v", kind, r, err)
		}
	}
	for _, groups := range [][]simlive.Group{
		{{Name: "empty"}},
		{{Actions: []string{"a"}}},
		{{Name: "a", Actions: []string{""}}},
		{{Name: "a", Actions: []string{"a", "a"}}},
		{{Name: "a", Actions: []string{"a"}}, {Name: "a", Actions: []string{"b"}}},
	} {
		if r, err := simlive.Check(&graphModel{at: "goal"}, options(groups...)); err == nil || r.Complete {
			t.Fatalf("invalid fairness accepted: %+v, %v", r, err)
		}
	}
	for _, mutate := range []func(*simlive.Options){
		func(o *simlive.Options) { o.Goal = nil },
		func(o *simlive.Options) { o.Limits.States = 0 },
		func(o *simlive.Options) { o.Limits.Depth = -1 },
	} {
		opts := options()
		mutate(&opts)
		if r, err := simlive.Check(&graphModel{at: "goal"}, opts); err == nil || r.Complete {
			t.Fatalf("invalid options accepted: %+v, %v", r, err)
		}
	}
	// Invariants still run on goal endpoints.
	opts := options()
	opts.Goal = func(sim.Model) bool { return true }
	if r, err := simlive.Check(&brokenModel{kind: "initial"}, opts); err == nil || !strings.Contains(err.Error(), "invariant") || r.Complete {
		t.Fatalf("goal hid model error: %+v, %v", r, err)
	}
}
