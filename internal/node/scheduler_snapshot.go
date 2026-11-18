package node

import (
	"encoding/json"
	"time"
)

// Clone isolates all mutable admission state for deterministic exploration.
func (s *Scheduler) Clone() *Scheduler {
	x := &Scheduler{limits: clone(s.limits), serial: s.serial}
	if s.jobs != nil {
		x.jobs = make(map[string]*scheduled, len(s.jobs))
		for key, job := range s.jobs {
			j := *job
			j.op = normalizeOperation(j.op)
			x.jobs[key] = &j
		}
	}
	return x
}

// Key includes reservations, queued priority, generations and retry state, not
// just the currently busy resources. Exploration supplies a logical clock.
func (s *Scheduler) Key() string {
	type jobState struct {
		Operation    Operation
		Order        uint64
		Failures     int
		Next         time.Time
		Running      uint64
		Wanted, Wake bool
	}
	state := struct {
		Limits map[string]int
		Serial uint64
		Jobs   map[string]jobState
	}{clone(s.limits), s.serial, make(map[string]jobState, len(s.jobs))}
	for key, j := range s.jobs {
		state.Jobs[key] = jobState{j.op, j.order, j.failures, j.next.UTC(), j.running, j.wanted, j.wake}
	}
	data, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	return string(data)
}
