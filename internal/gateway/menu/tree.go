package menu

import (
	"cmp"
	"slices"
	"strings"
)

type row struct {
	Entry
	prefix string
}

func compareEntries(a, b Entry) int {
	if order := cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); order != 0 {
		return order
	}
	return cmp.Compare(a.ID, b.ID)
}

// buildTree retains every resource, including worker-owned forks. Missing
// parents become roots. Cycles are broken at their alphabetically first member
// so the result remains deterministic even when List returns a different order.
func buildTree(entries []Entry) []row {
	ordered := slices.Clone(entries)
	ordered = slices.DeleteFunc(ordered, func(entry Entry) bool { return entry.ID == "" })
	slices.SortFunc(ordered, compareEntries)
	byID := make(map[string]Entry, len(ordered))
	for _, entry := range ordered {
		byID[entry.ID] = entry
	}
	parents := make(map[string]string, len(ordered))
	for _, entry := range ordered {
		if _, ok := byID[entry.Parent]; ok && entry.Parent != "" {
			parents[entry.ID] = entry.Parent
		}
	}
	visited := make(map[string]bool, len(ordered))
	for _, entry := range ordered {
		path := []string{}
		positions := map[string]int{}
		for id := entry.ID; id != "" && !visited[id]; id = parents[id] {
			if start, cycle := positions[id]; cycle {
				root := id
				for _, member := range path[start:] {
					if compareEntries(byID[member], byID[root]) < 0 {
						root = member
					}
				}
				delete(parents, root)
				break
			}
			positions[id] = len(path)
			path = append(path, id)
		}
		for _, id := range path {
			visited[id] = true
		}
	}

	children := make(map[string][]Entry, len(ordered))
	seen := make(map[string]bool, len(ordered))
	for _, entry := range ordered {
		if seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		children[parents[entry.ID]] = append(children[parents[entry.ID]], entry)
	}
	type frame struct {
		entry          Entry
		prefix, branch string
	}
	stack := make([]frame, 0, len(ordered))
	for _, entry := range slices.Backward(children[""]) {
		stack = append(stack, frame{entry: entry})
	}
	rows := make([]row, 0, len(ordered))
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		rows = append(rows, row{Entry: node.entry, prefix: node.prefix + node.branch})
		prefix := node.prefix
		switch node.branch {
		case "├─ ":
			prefix += "│  "
		case "└─ ":
			prefix += "   "
		}
		forks := children[node.entry.ID]
		for i := len(forks) - 1; i >= 0; i-- {
			branch := "├─ "
			if i == len(forks)-1 {
				branch = "└─ "
			}
			stack = append(stack, frame{entry: forks[i], prefix: prefix, branch: branch})
		}
	}
	return rows
}
