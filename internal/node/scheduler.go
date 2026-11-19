// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"cmp"
	"slices"
	"time"
)

// Operation describes an idempotent job. Key identifies its retry history;
// writes are exclusive and reads are shared source reservations. Class names
// an optional concurrency limit. Empty resource names are ignored.
type Operation struct {
	Key    string
	Class  string
	Writes []string
	Reads  []string
}

// Attempt identifies one admitted generation, durable across forgotten work.
type Attempt struct {
	Operation  Operation
	Generation uint64
}

type Outcome uint8

const (
	Succeeded Outcome = iota
	Failed
	Canceled
)

type scheduled struct {
	op       Operation
	order    uint64
	failures int
	next     time.Time
	running  uint64
	wanted   bool
	wake     bool // last decision was to wait for next, rather than a resource
}

// Scheduler is the deterministic operation admission/retry machine used by
// Agent. It owns no clocks, goroutines, timers or callbacks. Callers serialize
// access, supply time, execute returned attempts and report their completion.
// Its zero value has unlimited concurrency.
type Scheduler struct {
	limits map[string]int
	jobs   map[string]*scheduled
	serial uint64
}

func NewScheduler(limits map[string]int) *Scheduler {
	return &Scheduler{limits: clone(limits)}
}

func normalizeOperation(op Operation) Operation {
	clean := func(in []string) []string {
		out := slices.Clone(in)
		slices.Sort(out)
		return slices.DeleteFunc(slices.Compact(out), func(k string) bool { return k == "" })
	}
	op.Writes = clean(append(slices.Clone(op.Writes), op.Key))
	op.Reads = slices.DeleteFunc(clean(op.Reads), func(k string) bool { return slices.Contains(op.Writes, k) })
	return op
}

func sameOperation(a, b Operation) bool {
	return a.Key == b.Key && a.Class == b.Class && slices.Equal(a.Writes, b.Writes) && slices.Equal(a.Reads, b.Reads)
}

// Schedule replaces queued work with wanted and admits all available jobs in
// first-waiting order. Running jobs retain reservations even when no longer
// wanted: cancellation is not completion. A blocked job does not block
// independent work, and later readers cannot starve an earlier writer.
func (s *Scheduler) Schedule(now time.Time, wanted []Operation) []Attempt {
	if s.jobs == nil {
		s.jobs = map[string]*scheduled{}
	}
	seen := map[string]bool{}
	for _, op := range wanted {
		if op.Key == "" || seen[op.Key] {
			continue
		}
		seen[op.Key] = true
		op = normalizeOperation(op)
		j := s.jobs[op.Key]
		if j == nil || j.running == 0 && !sameOperation(j.op, op) {
			s.serial++
			s.jobs[op.Key] = &scheduled{op: op, order: s.serial}
		}
	}
	var queue []*scheduled
	readers, writers, classes := map[string]bool{}, map[string]bool{}, map[string]int{}
	reserve := func(op Operation) {
		for _, k := range op.Writes {
			writers[k] = true
		}
		for _, k := range op.Reads {
			readers[k] = true
		}
	}
	for key, j := range s.jobs {
		if j.running != 0 {
			reserve(j.op)
			classes[j.op.Class]++
		} else if !seen[key] {
			// A snapshot may have omitted this job while it was running,
			// then raced its failed completion. Preserve the outstanding
			// backoff, but never start or arm timers for absent work. Expired
			// abandoned failures must not accumulate for the node's lifetime.
			j.wanted = false
			if j.failures == 0 || !now.Before(j.next) {
				delete(s.jobs, key)
			}
		} else {
			j.wanted = true
			queue = append(queue, j)
		}
	}
	slices.SortFunc(queue, func(a, b *scheduled) int {
		return cmp.Compare(a.order, b.order)
	})
	var started []Attempt
	for _, j := range queue {
		j.wake = false
		if now.Before(j.next) {
			j.wake = true
			continue // backoff holds no resources or queue priority
		}
		blocked := s.limits[j.op.Class] > 0 && classes[j.op.Class] >= s.limits[j.op.Class]
		for _, k := range j.op.Writes {
			blocked = blocked || writers[k] || readers[k]
		}
		for _, k := range j.op.Reads {
			blocked = blocked || writers[k]
		}
		reserve(j.op) // preserve priority against conflicting later arrivals
		if blocked {
			continue
		}
		s.serial++
		j.running = s.serial
		classes[j.op.Class]++
		started = append(started, Attempt{Operation: normalizeOperation(j.op), Generation: j.running})
	}
	return started
}

// Complete releases only the matching generation's reservations. Cancellation
// adds no failure; successful completion resets retry history. Failed attempts
// back off from completion time, starting at 2s and capped at 2m.
func (s *Scheduler) Complete(now time.Time, a Attempt, outcome Outcome) bool {
	j := s.jobs[a.Operation.Key]
	if j == nil || j.running == 0 || j.running != a.Generation {
		return false
	}
	j.running = 0
	if outcome != Failed {
		delete(s.jobs, a.Operation.Key)
		return true
	}
	j.failures++
	j.next = now.Add(min(time.Second<<min(j.failures, 7), 2*time.Minute))
	j.wake = true
	s.serial++
	j.order = s.serial
	return true
}

// Deadline is the next retry wake time, clamped to now if the deadline passed
// since the last Schedule. The adapter arms its timer using this absolute
// deadline and the same explicit now. Retries that Schedule found blocked on
// resources wait for completion or a new snapshot, avoiding a zero-delay spin.
func (s *Scheduler) Deadline(now time.Time) (time.Time, bool) {
	var next time.Time
	for _, j := range s.jobs {
		if j.wanted && j.wake && j.running == 0 && (next.IsZero() || j.next.Before(next)) {
			next = j.next
		}
	}
	if !next.IsZero() && next.Before(now) {
		return now, true
	}
	return next, !next.IsZero()
}

// Busy returns a detached snapshot of every running read/write reservation.
func (s *Scheduler) Busy() map[string]bool {
	out := map[string]bool{}
	for _, j := range s.jobs {
		if j.running != 0 {
			for _, k := range j.op.Writes {
				out[k] = true
			}
			for _, k := range j.op.Reads {
				out[k] = true
			}
		}
	}
	return out
}

func (s *Scheduler) Failures(key string) int {
	if j := s.jobs[key]; j != nil {
		return j.failures
	}
	return 0
}
