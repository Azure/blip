// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simlive

import (
	"slices"

	"github.com/Azure/blip/internal/sim"
)

// components uses Tarjan's algorithm on the non-goal graph. A maximal SCC
// fails weak fairness only when some group is enabled everywhere but has no
// internal edge. No subset of such an SCC could satisfy that group either.
func components(nodes []node) [][]int {
	index := make([]int, len(nodes))
	low := make([]int, len(nodes))
	onStack := make([]bool, len(nodes))
	var stack []int
	var result [][]int
	next := 0
	var visit func(int)
	visit = func(at int) {
		next++
		index[at], low[at] = next, next
		stack = append(stack, at)
		onStack[at] = true
		for _, e := range nodes[at].edges {
			if index[e.to] == 0 {
				visit(e.to)
				low[at] = min(low[at], low[e.to])
			} else if onStack[e.to] {
				low[at] = min(low[at], index[e.to])
			}
		}
		if low[at] == index[at] {
			var component []int
			for {
				last := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[last] = false
				component = append(component, last)
				if last == at {
					break
				}
			}
			slices.Sort(component)
			result = append(result, component)
		}
	}
	for at, n := range nodes {
		if !n.goal && index[at] == 0 {
			visit(at)
		}
	}
	return result
}

type requiredEdge struct {
	from int
	edge
}

func fairCycle(nodes []node, component []int, membership map[string][]int, groups int) []sim.Transition {
	inside := make(map[int]bool, len(component))
	for _, at := range component {
		inside[at] = true
	}
	// Each group needs either a disabled vertex or a taken internal edge.
	disabled := make([]bool, groups)
	taken := make([]*requiredEdge, groups)
	var anyEdge *requiredEdge
	for _, at := range component {
		for group, enabled := range nodes[at].enabled {
			disabled[group] = disabled[group] || !enabled
		}
		for _, e := range nodes[at].edges {
			if !inside[e.to] {
				continue
			}
			x := &requiredEdge{from: at, edge: e}
			if anyEdge == nil {
				anyEdge = x
			}
			for _, group := range membership[e.action] {
				if taken[group] == nil {
					taken[group] = x
				}
			}
		}
	}
	if anyEdge == nil {
		return nil // singleton without a self-loop is not an infinite execution
	}
	required := []*requiredEdge{anyEdge} // even a singleton needs a real edge
	for group := range groups {
		if disabled[group] {
			continue
		}
		if taken[group] == nil {
			return nil
		}
		required = append(required, taken[group])
	}

	// A simple DFS cycle may omit a required fairness edge or disabled vertex.
	// Instead construct a closed walk through all vertices and required edges.
	// Strong connectivity provides every connecting path. Repetition visits
	// every disabled vertex and takes every required edge infinitely often.
	at := component[0]
	var cycle []sim.Transition
	walkTo := func(to int) {
		cycle = append(cycle, pathWithin(nodes, inside, at, to)...)
		at = to
	}
	for _, to := range component {
		walkTo(to)
	}
	for _, e := range required {
		walkTo(e.from)
		cycle = append(cycle, sim.Transition{Action: e.action, Before: nodes[at].key, After: nodes[e.to].key})
		at = e.to
	}
	walkTo(component[0])
	return cycle
}

func pathWithin(nodes []node, inside map[int]bool, from, to int) []sim.Transition {
	if from == to {
		return nil
	}
	parents := make(map[int]requiredEdge)
	seen := map[int]bool{from: true}
	queue := []int{from}
	for head := 0; head < len(queue); head++ {
		at := queue[head]
		for _, e := range nodes[at].edges {
			if !inside[e.to] || seen[e.to] {
				continue
			}
			seen[e.to] = true
			parents[e.to] = requiredEdge{from: at, edge: e}
			if e.to == to {
				var path []sim.Transition
				for end := to; end != from; {
					p := parents[end]
					path = append(path, sim.Transition{Action: p.action, Before: nodes[p.from].key, After: nodes[end].key})
					end = p.from
				}
				slices.Reverse(path)
				return path
			}
			queue = append(queue, e.to)
		}
	}
	panic("simlive: no path within strongly connected component")
}
