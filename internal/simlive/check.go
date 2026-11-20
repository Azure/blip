// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package simlive checks eventual reachability of a goal in a bounded, explicit
// finite-state model. It supports weak fairness of configured action groups,
// not strong fairness or claims about an unbounded implementation.
//
// The sim.Model contract applies: Clone isolates mutable state; Key preserves
// everything affecting future behavior; Enabled, Key and Check are read-only;
// and Step is deterministic. Goal must also be read-only and determined by Key.
// Random choices, faults and environmental progress belong in explicit actions.
package simlive

import (
	"fmt"
	"slices"

	"github.com/Azure/blip/internal/sim"
)

// Group gives a name to a nonempty set of action names. A group is enabled when
// any of its actions is enabled, and taken when any of its actions is taken.
// Groups may overlap. Group names must be unique, as must action names within
// each group. All names must be nonempty.
type Group struct {
	Name    string
	Actions []string
}

type Options struct {
	Limits sim.Limits
	Goal   func(sim.Model) bool
	// WeakFairness requires a group that stays continuously enabled to be
	// taken infinitely often on an infinite execution. Intermittent enabling
	// imposes no progress obligation. Nil means no fairness assumptions.
	WeakFairness []Group
}

// Witness describes a goal-avoiding execution. Prefix starts at the supplied
// initial model. A nonempty Cycle starts where Prefix ends and returns to that
// same key; repeating it forever satisfies every configured fairness group.
// An empty Cycle means Prefix ends in an unsatisfied terminal deadlock.
//
// Replay Prefix with sim.Replay, then replay Cycle using a sim.Trace whose
// Initial is the resulting model's Key. Neither a prefix nor cycle is promised
// to be shortest. The cycle can revisit states to meet all fairness obligations.
// Its length is not limited by the exploration depth bound.
type Witness struct {
	Prefix sim.Trace        `json:"prefix"`
	Cycle  []sim.Transition `json:"cycle,omitempty"`
}

type Report struct {
	States      int
	Transitions int
	// Complete means the goal-pruned reachable graph was fully explored,
	// without an error or truncation. Goal endpoints count toward States.
	// Complete && Witness == nil establishes eventual Goal only for this
	// finite model under exactly the configured weak fairness assumptions.
	Complete bool
	// A witness is a violation even if Complete is false. Conversely, no
	// witness in an incomplete report does not establish eventuality.
	Witness *Witness
}

type edge struct {
	to     int
	action string
}

type node struct {
	model   sim.Model
	key     string
	parent  int
	depth   int
	via     sim.Transition
	goal    bool
	enabled []bool
	edges   []edge
}

// Check enumerates reachable states breadth-first, pruning successors of Goal
// states. It checks model invariants before evaluating Goal. Model/configuration
// errors return an error; eventuality violations return Report.Witness instead.
// No enabled actions at a non-goal state is a violation, regardless of fairness.
// Bounds are never interpreted as deadlocks. Like sim.Explore, a depth-bound
// nonterminal state makes the search incomplete, even if its edges might only
// lead to known states. Initial and the options' slices are left untouched.
func Check(initial sim.Model, options Options) (Report, error) {
	var report Report
	if initial == nil || options.Goal == nil || options.Limits.States < 1 || options.Limits.Depth < 0 {
		return report, fmt.Errorf("invalid eventuality model, goal or limits")
	}
	membership := make(map[string][]int)
	names := make(map[string]bool)
	for i, group := range options.WeakFairness {
		if group.Name == "" || names[group.Name] || len(group.Actions) == 0 {
			return report, fmt.Errorf("empty or duplicate fairness group %q", group.Name)
		}
		names[group.Name] = true
		actions := make(map[string]bool)
		for _, action := range group.Actions {
			if action == "" || actions[action] {
				return report, fmt.Errorf("empty or duplicate action %q in fairness group %q", action, group.Name)
			}
			actions[action] = true
			membership[action] = append(membership[action], i)
		}
	}
	root := initial.Clone()
	report.States = 1
	if err := root.Check(); err != nil {
		return report, fmt.Errorf("initial invariant: %w", err)
	}
	nodes := []node{{model: root, key: root.Key(), parent: -1, goal: options.Goal(root)}}
	seen := map[string]int{nodes[0].key: 0}
	deadlock := -1
	report.Complete = true
	for head := 0; head < len(nodes); head++ {
		n := nodes[head]
		// Ancestry, outgoing edges and fairness enabling suffice after expansion.
		nodes[head].model = nil
		if n.goal {
			continue
		}
		actions := slices.Clone(n.model.Enabled())
		slices.Sort(actions)
		nodes[head].enabled = make([]bool, len(options.WeakFairness))
		for i, action := range actions {
			if action == "" || (i > 0 && actions[i-1] == action) {
				report.Complete = false
				return report, fmt.Errorf("empty or duplicate enabled action %q at key %q", action, n.key)
			}
			for _, group := range membership[action] {
				nodes[head].enabled[group] = true
			}
		}
		if len(actions) == 0 {
			if deadlock < 0 {
				deadlock = head
			}
			continue
		}
		if n.depth == options.Limits.Depth {
			report.Complete = false
			continue
		}
		for _, action := range actions {
			m := n.model.Clone()
			report.Transitions++
			err := m.Step(action)
			if err == nil {
				err = m.Check()
			}
			if err != nil {
				report.Complete = false
				return report, fmt.Errorf("action %q at key %q: %w", action, n.key, err)
			}
			key := m.Key()
			to, exists := seen[key]
			if !exists {
				if len(nodes) == options.Limits.States {
					report.Complete = false
					continue
				}
				to = len(nodes)
				seen[key] = to
				nodes = append(nodes, node{
					model: m, key: key, parent: head, depth: n.depth + 1,
					via:  sim.Transition{Action: action, Before: n.key, After: key},
					goal: options.Goal(m),
				})
				report.States++
			}
			if !nodes[to].goal {
				nodes[head].edges = append(nodes[head].edges, edge{to: to, action: action})
			}
		}
	}
	if deadlock >= 0 {
		report.Witness = &Witness{Prefix: prefix(nodes, deadlock)}
		return report, nil
	}
	for _, component := range components(nodes) {
		if cycle := fairCycle(nodes, component, membership, len(options.WeakFairness)); len(cycle) > 0 {
			report.Witness = &Witness{Prefix: prefix(nodes, component[0]), Cycle: cycle}
			break
		}
	}
	return report, nil
}

func prefix(nodes []node, at int) sim.Trace {
	trace := sim.Trace{Initial: nodes[0].key, Steps: make([]sim.Transition, nodes[at].depth)}
	for i := len(trace.Steps) - 1; i >= 0; i-- {
		trace.Steps[i] = nodes[at].via
		at = nodes[at].parent
	}
	return trace
}
