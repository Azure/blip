// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package sim

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// graphModel keeps immutable graph definitions separate from its mutable cursor.
// It qualifies search/replay behavior without relying on application models.
type graphModel struct {
	at    string
	edges map[string][]graphEdge
	bad   map[string]error
}

type graphEdge struct {
	action string
	to     string
	err    error
}

func (m *graphModel) Clone() Model { n := *m; return &n }
func (m *graphModel) Key() string  { return m.at }
func (m *graphModel) Check() error { return m.bad[m.at] }
func (m *graphModel) Enabled() []string {
	var actions []string
	for _, edge := range m.edges[m.at] {
		actions = append(actions, edge.action)
	}
	return actions
}
func (m *graphModel) Step(action string) error {
	for _, edge := range m.edges[m.at] {
		if edge.action == action {
			m.at = edge.to
			return edge.err
		}
	}
	return errors.New("disabled graph action")
}

func TestExploreErrorsNeverReportComplete(t *testing.T) {
	initialFailure := errors.New("initial failure")
	for _, tt := range []struct {
		name   string
		model  *graphModel
		limits Limits
		depth  int
	}{
		{"zero states", &graphModel{}, Limits{States: 0, Depth: 1}, 0},
		{"negative states", &graphModel{}, Limits{States: -1, Depth: 1}, 0},
		{"negative depth", &graphModel{}, Limits{States: 1, Depth: -1}, 0},
		{"initial invariant", &graphModel{bad: map[string]error{"": initialFailure}}, Limits{States: 1}, 0},
		{"empty action", &graphModel{edges: map[string][]graphEdge{"": {{action: ""}}}}, Limits{States: 1}, 0},
		{"duplicate actions", &graphModel{edges: map[string][]graphEdge{
			"":     {{action: "start", to: "next"}},
			"next": {{action: "again"}, {action: "again"}},
		}}, Limits{States: 2, Depth: 2}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Explore(tt.model, tt.limits)
			if err == nil || report.Complete {
				t.Fatalf("invalid exploration reported success: %+v, %v", report, err)
			}
			if len(report.Trace.Steps) != tt.depth {
				t.Fatalf("failure path has wrong depth: %+v", report.Trace)
			}
		})
	}
}

func TestExploreCyclesAndBounds(t *testing.T) {
	m := &graphModel{at: "root", edges: map[string][]graphEdge{
		"root": {{action: "a", to: "left"}, {action: "b", to: "right"}},
		"left": {{action: "join", to: "end"}},
		"right": {
			{action: "join", to: "end"},
			{action: "restart", to: "root"},
		},
	}}
	report, err := Explore(m, Limits{States: 4, Depth: 2})
	if err != nil || !report.Complete || report.States != 4 || report.Transitions != 5 {
		t.Fatalf("finite graph not fully explored: %+v, %v", report, err)
	}
	for _, limits := range []Limits{{States: 3, Depth: 2}, {States: 4, Depth: 1}, {States: 4, Depth: 0}} {
		report, err := Explore(m, limits)
		if err != nil || report.Complete || report.States > limits.States {
			t.Fatalf("truncated graph mistaken for a proof: %+v, %v", report, err)
		}
	}
	terminal, err := Explore(&graphModel{}, Limits{States: 1, Depth: 0})
	if err != nil || !terminal.Complete || terminal.States != 1 || terminal.Transitions != 0 {
		t.Fatalf("terminal initial state should be complete: %+v, %v", terminal, err)
	}
}

func TestExploreChecksEdgesBeforeStateDeduplicationAndAdmission(t *testing.T) {
	failure := errors.New("edge failed")
	for _, to := range []string{"root", "new state"} {
		t.Run(to, func(t *testing.T) {
			m := &graphModel{at: "root", edges: map[string][]graphEdge{
				"root": {{action: "fail", to: to, err: failure}},
			}}
			report, err := Explore(m, Limits{States: 1, Depth: 1})
			if !errors.Is(err, failure) || report.Complete || report.Transitions != 1 {
				t.Fatalf("failed edge was skipped: %+v, %v", report, err)
			}
			if _, err := Replay(m, report.Trace); !errors.Is(err, failure) {
				t.Fatalf("edge failure not replayable: %v", err)
			}
		})
	}
}

func TestExploreFindsShortestFailureAcrossBranches(t *testing.T) {
	failure := errors.New("bad state")
	m := &graphModel{at: "root", edges: map[string][]graphEdge{
		"root":  {{action: "a-long", to: "long1"}, {action: "z-short", to: "short"}},
		"long1": {{action: "continue", to: "long2"}},
		"long2": {{action: "fail", to: "bad"}},
		"short": {{action: "fail", to: "bad"}},
	}, bad: map[string]error{"bad": failure}}
	report, err := Explore(m, Limits{States: 10, Depth: 10})
	if !errors.Is(err, failure) || len(report.Trace.Steps) != 2 || report.Trace.Steps[0].Action != "z-short" {
		t.Fatalf("not the shortest failure: %+v, %v", report, err)
	}
	if final, err := Replay(m, report.Trace); !errors.Is(err, failure) || final.Key() != "bad" {
		t.Fatalf("shortest path did not replay: %s, %v", final.Key(), err)
	}
}

func TestReplayRejectsDriftBeforeExecutingAction(t *testing.T) {
	m := &graphModel{at: "root", edges: map[string][]graphEdge{
		"root": {{action: "start", to: "end"}},
	}}
	trace := Trace{Initial: "root", Steps: []Transition{{Action: "start", Before: "different", After: "end"}}}
	final, err := Replay(m, trace)
	if err == nil || !strings.Contains(err.Error(), "before state differs") || final.Key() != "root" {
		t.Fatalf("executed an action with the wrong precondition: %s, %v", final.Key(), err)
	}
}

func TestReplayRejectsUnreachableFailureSuffix(t *testing.T) {
	failure := errors.New("invariant failed")
	for _, initialFailure := range []bool{false, true} {
		m := &graphModel{at: "root", edges: map[string][]graphEdge{
			"root": {{action: "fail", to: "bad"}},
		}, bad: map[string]error{"bad": failure}}
		if initialFailure {
			m.at = "bad"
		}
		trace, err := Run(m, 1, 2)
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if _, err := Replay(m, trace); !errors.Is(err, failure) {
			t.Fatalf("valid failure trace did not reproduce: %v", err)
		}
		trace.Steps = append(trace.Steps, Transition{Action: "unreachable", Before: "bad", After: "bad"})
		if _, err := Replay(m, trace); err == nil || errors.Is(err, failure) || !strings.Contains(err.Error(), "after") {
			t.Fatalf("malformed trace accepted as the original failure: %v", err)
		}
	}
}

func TestRunIgnoresEnabledEnumerationOrder(t *testing.T) {
	forward := &graphModel{at: "root", edges: map[string][]graphEdge{
		"root":  {{action: "a", to: "root"}, {action: "b", to: "other"}},
		"other": {{action: "c", to: "root"}, {action: "d", to: "other"}},
	}}
	reverse := &graphModel{at: "root", edges: map[string][]graphEdge{}}
	for state, edges := range forward.edges {
		reverse.edges[state] = slices.Clone(edges)
		slices.Reverse(reverse.edges[state])
	}
	a, err := Run(forward, 42, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(reverse, 42, 100)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("enumeration order changed the seeded schedule: %v", err)
	}
	if _, err := Replay(reverse, a); err != nil {
		t.Fatal(err)
	}
	if forward.at != "root" || reverse.at != "root" {
		t.Fatal("run/replay mutated the initial model")
	}
}
