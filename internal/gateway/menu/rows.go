package menu

import (
	"cmp"
	"slices"
	"strings"
)

func compareEntries(a, b Entry) int {
	if order := cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); order != 0 {
		return order
	}
	return cmp.Compare(a.ID, b.ID)
}

// sortEntries drops empty IDs and orders the remaining root states by display
// name, then resource ID, so refreshes are deterministic.
func sortEntries(entries []Entry) []Entry {
	ordered := slices.Clone(entries)
	ordered = slices.DeleteFunc(ordered, func(entry Entry) bool { return entry.ID == "" })
	slices.SortFunc(ordered, compareEntries)
	return ordered
}
