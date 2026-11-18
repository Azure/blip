package sim

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// Obligations monitors individual progress after a scenario has established
// the required recovery/fairness conditions. Deadlines are explicit virtual
// times, not a claim of unconditional liveness during an indefinite outage.
type Obligations map[string]time.Duration

// Clone isolates the monitor when a model branches during exploration.
func (o Obligations) Clone() Obligations { return maps.Clone(o) }

func (o Obligations) Check(now time.Duration) error {
	var overdue []string
	for id, deadline := range o {
		if now >= deadline {
			overdue = append(overdue, id)
		}
	}
	if len(overdue) > 0 {
		slices.Sort(overdue)
		return fmt.Errorf("unresolved obligations at %s: %v", now, overdue)
	}
	return nil
}
