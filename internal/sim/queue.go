package sim

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// Event is data, not a callback into an untracked goroutine. Incarnation ties
// delivery to the receiving process; external effects may still have applied
// when that process crashed. Payload belongs to the scenario's typed protocol.
type Event[T any] struct {
	ID          uint64
	At          time.Duration
	Process     string
	Incarnation uint64
	Value       T
}

// Queue holds delivery events. A world separately models effect application,
// so dropping a completion never rolls back an applied operation. Events at
// the same time can be delivered in any order by choosing from Ready.
// The queue imposes no fairness among ready events. Models must include Now,
// NextID and Events in their state key, unless they use a proven equivalent
// canonical representation that preserves event identity and timing.
type Queue[T any] struct {
	Now    time.Duration
	NextID uint64
	Events []Event[T]
}

func (q *Queue[T]) Add(after time.Duration, process string, incarnation uint64, value T) uint64 {
	if after < 0 || q.Now+after < q.Now {
		panic("sim: invalid event delay")
	}
	if q.NextID == math.MaxUint64 {
		panic("sim: event identity overflow")
	}
	q.NextID++
	q.Events = append(q.Events, Event[T]{q.NextID, q.Now + after, process, incarnation, value})
	return q.NextID
}

func (q *Queue[T]) Ready() []uint64 {
	var ids []uint64
	for _, e := range q.Events {
		if e.At <= q.Now {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// Advance moves to the next deadline only when all currently ready events
// have been consumed or explicitly dropped. Delay is represented at enqueue
// time, so advancing cannot accidentally starve an already runnable event.
func (q *Queue[T]) Advance() bool {
	if len(q.Events) == 0 {
		return false
	}
	next := q.Events[0].At
	for _, e := range q.Events {
		if e.At <= q.Now {
			return false
		}
		next = min(next, e.At)
	}
	q.Now = next
	return true
}

func (q *Queue[T]) Take(id uint64) (Event[T], error) {
	for i, e := range q.Events {
		if e.ID == id {
			if e.At > q.Now {
				return Event[T]{}, fmt.Errorf("event %d is not ready", id)
			}
			q.Events = slices.Delete(q.Events, i, i+1)
			return e, nil
		}
	}
	return Event[T]{}, fmt.Errorf("unknown event %d", id)
}

// Drop loses or cancels a delivery, even while it is still in flight. It does
// not undo the effect that produced the event. Unknown IDs return an error so
// stale cancellation and duplicate loss actions cannot silently succeed.
func (q *Queue[T]) Drop(id uint64) error {
	for i, e := range q.Events {
		if e.ID == id {
			q.Events = slices.Delete(q.Events, i, i+1)
			return nil
		}
	}
	return fmt.Errorf("unknown event %d", id)
}

// Crash drops currently queued deliveries to one process incarnation. The
// world remains responsible for actual process death, child lifetimes, handle
// closure and persistence. It must also suppress any subsequently produced
// deliveries to that dead incarnation; Crash does not retain process state.
func (q *Queue[T]) Crash(process string, incarnation uint64) {
	q.Events = slices.DeleteFunc(q.Events, func(e Event[T]) bool {
		return e.Process == process && e.Incarnation == incarnation
	})
}

// Clone copies the event queue. A nil copyValue copies payloads by value and is
// suitable for immutable payloads; otherwise it must copy all mutable payload
// data. The source queue is not changed.
func (q Queue[T]) Clone(copyValue func(T) T) Queue[T] {
	q.Events = slices.Clone(q.Events)
	if copyValue != nil {
		for i := range q.Events {
			q.Events[i].Value = copyValue(q.Events[i].Value)
		}
	}
	return q
}
