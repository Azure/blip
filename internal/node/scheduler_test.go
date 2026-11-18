package node

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func attemptKeys(attempts []Attempt) []string {
	var keys []string
	for _, a := range attempts {
		keys = append(keys, a.Operation.Key)
	}
	return keys
}

func TestSchedulerSnapshotIsolationAndHiddenState(t *testing.T) {
	var zero Scheduler
	if zero.Clone().Key() != zero.Key() {
		t.Fatal("zero scheduler clone changed state")
	}
	s := NewScheduler(map[string]int{"fetch": 1})
	started := s.Schedule(testNow, []Operation{{Key: "a", Class: "fetch", Reads: []string{"base"}}, {Key: "b", Class: "fetch"}})
	x := s.Clone()
	before := s.Key()
	if x.Key() != before {
		t.Fatal("clone changed admission state")
	}
	x.jobs["a"].op.Reads[0] = "other"
	x.limits["fetch"] = 2
	if s.Key() != before {
		t.Fatal("clone aliases original reservations or limits")
	}
	x = s.Clone()
	x.Complete(testNow, started[0], Failed)
	if s.Key() != before || x.Key() == before || !s.Busy()["base"] {
		t.Fatal("completion did not isolate pending generation and retry state")
	}
	key := x.Key()
	x.jobs["a"].next = x.jobs["a"].next.Add(time.Second)
	if x.Key() == key {
		t.Fatal("key omitted retry deadline")
	}
}

func TestSchedulerSharedSourcesAndAtomicAdmission(t *testing.T) {
	s := NewScheduler(map[string]int{"image": 2})
	reads := []string{"base", "", "base"}
	ops := []Operation{
		{Key: "a", Class: "image", Reads: reads},
		{Key: "b", Class: "image", Reads: []string{"base"}},
		{Key: "delete", Writes: []string{"base", "other"}},
		{Key: "independent", Reads: []string{"unrelated"}},
	}
	got := s.Schedule(testNow, ops)
	if want := []string{"a", "b", "independent"}; !slices.Equal(attemptKeys(got), want) {
		t.Fatalf("admitted %v, want %v", attemptKeys(got), want)
	}
	// Neither caller-owned input nor returned reservations alias the machine.
	reads[0] = "mutated"
	got[0].Operation.Reads[0] = "mutated"
	busy := s.Busy()
	delete(busy, "base")
	if !s.Busy()["base"] || s.Busy()["other"] || s.Busy()["delete"] || s.Busy()["mutated"] {
		t.Fatalf("reservations are partial or aliased: %v", s.Busy())
	}
	if !s.Complete(testNow, got[1], Succeeded) || !s.Busy()["base"] {
		t.Fatal("one reader's completion released the other reader")
	}
	if started := s.Schedule(testNow, ops[2:]); len(started) != 0 {
		t.Fatalf("writer overtook reader: %v", started)
	}
	s.Complete(testNow, got[0], Succeeded)
	started := s.Schedule(testNow, ops[2:])
	if !slices.Equal(attemptKeys(started), []string{"delete"}) || !s.Busy()["other"] {
		t.Fatalf("writer not atomically admitted: %+v / %v", started, s.Busy())
	}
}

func TestSchedulerRetryBoundariesAndStaleSnapshot(t *testing.T) {
	var s Scheduler
	op := Operation{Key: "seal", Writes: []string{"attachment", "commit"}}
	now := testNow
	for i, delay := range []time.Duration{2, 4, 8, 16, 32, 64, 120, 120, 120} {
		started := s.Schedule(now, []Operation{op})
		if len(started) != 1 {
			t.Fatalf("retry %d not admitted at deadline: %+v", i, started)
		}
		// Operation duration must not shorten the retry delay.
		now = now.Add(17 * time.Second)
		if !s.Complete(now, started[0], Failed) || s.Failures(op.Key) != i+1 || len(s.Busy()) != 0 {
			t.Fatalf("failure %d did not release/reset correctly", i)
		}
		deadline := now.Add(delay * time.Second)
		if got, ok := s.Deadline(now); !ok || !got.Equal(deadline) {
			t.Fatalf("deadline %v/%v, want %v", got, ok, deadline)
		}
		// A pre-completion snapshot omitted this busy job. Its delayed plan
		// must not erase backoff, execute it, or keep a useless timer armed.
		if got := s.Schedule(now, nil); len(got) != 0 {
			t.Fatal("absent retry ran")
		}
		if _, ok := s.Deadline(now); ok {
			t.Fatal("timer armed for absent work")
		}
		if got := s.Schedule(deadline.Add(-time.Nanosecond), []Operation{op}); len(got) != 0 {
			t.Fatal("retry admitted before deadline")
		}
		if s.Complete(now, started[0], Failed) || s.Failures(op.Key) != i+1 {
			t.Fatal("duplicate failure changed retry history")
		}
		now = deadline
	}
	last := s.Schedule(now, []Operation{op})[0]
	s.Complete(now, last, Succeeded)
	if s.Failures(op.Key) != 0 {
		t.Fatal("success did not reset retry history")
	}
	if _, ok := s.Deadline(now); ok {
		t.Fatal("success left a timer")
	}
	// A changed source is a new operation, rather than the old retry.
	a := s.Schedule(now, []Operation{op})[0]
	s.Complete(now, a, Failed)
	op.Reads = []string{"replacement-source"}
	if got := s.Schedule(now, []Operation{op}); len(got) != 1 || s.Failures(op.Key) != 0 {
		t.Fatalf("replacement inherited old retry: %+v", got)
	}
}

func TestSchedulerCancellationRestartAndGeneration(t *testing.T) {
	var s Scheduler
	op := Operation{Key: "copy", Writes: []string{"destination"}, Reads: []string{"source"}}
	a := s.Schedule(testNow, []Operation{op, op, {}})[0]
	// Canceling demand while the adapter is still unwinding I/O cannot
	// release its source. Only acknowledged completion can do that.
	s.Schedule(testNow, nil)
	if !s.Busy()["source"] || !s.Busy()["destination"] {
		t.Fatal("cancellation released live I/O reservations")
	}
	wrong := a
	wrong.Generation++
	if s.Complete(testNow, wrong, Failed) {
		t.Fatal("accepted wrong generation")
	}
	if !s.Complete(testNow, a, Canceled) || len(s.Busy()) != 0 || s.Failures(op.Key) != 0 {
		t.Fatal("cancellation did not release cleanly")
	}
	b := s.Schedule(testNow, []Operation{op})[0]
	if a.Generation == b.Generation || s.Complete(testNow, a, Failed) || !s.Busy()["source"] {
		t.Fatal("stale completion released replacement")
	}
	s.Restart()
	c := s.Schedule(testNow, []Operation{op})[0]
	if c.Generation == b.Generation || s.Complete(testNow, b, Succeeded) || !s.Busy()["source"] {
		t.Fatal("pre-restart completion released restarted operation")
	}
	s.Complete(testNow, c, Canceled)
	if s.Complete(testNow, c, Succeeded) || len(s.Busy()) != 0 {
		t.Fatal("duplicate completion changed state")
	}
}

func TestSchedulerForgetsAbandonedFailuresAfterBackoff(t *testing.T) {
	var s Scheduler
	a := s.Schedule(testNow, []Operation{{Key: "deleted"}})[0]
	s.Complete(testNow, a, Failed)
	s.Schedule(testNow.Add(time.Second), nil)
	if s.Failures("deleted") != 1 {
		t.Fatal("stale snapshot erased an outstanding backoff")
	}
	s.Schedule(testNow.Add(2*time.Second), nil)
	if len(s.jobs) != 0 {
		t.Fatal("abandoned expired failure retained forever")
	}
}

func TestSchedulerTimerArmingTimeAndBlockedRetry(t *testing.T) {
	var s Scheduler
	op := Operation{Key: "retry", Writes: []string{"source"}}
	a := s.Schedule(testNow, []Operation{op})[0]
	s.Complete(testNow, a, Failed)
	s.Schedule(testNow.Add(time.Second), []Operation{op})
	// Status writes may delay timer creation past the retry deadline. Arming
	// at that later explicit time must wake now, not lose the retry wakeup.
	armed := testNow.Add(3 * time.Second)
	if next, ok := s.Deadline(armed); !ok || !next.Equal(armed) {
		t.Fatalf("overdue retry lost while arming timer: %v/%v", next, ok)
	}
	// A ready retry blocked on active I/O must not busy-loop the node.
	reader := Operation{Key: "reader", Reads: []string{"source"}}
	if got := s.Schedule(testNow.Add(time.Second), []Operation{op, reader}); !slices.Equal(attemptKeys(got), []string{"reader"}) {
		t.Fatalf("backoff reserved source: %+v", got)
	}
	if got := s.Schedule(armed, []Operation{op}); len(got) != 0 {
		t.Fatal("retry overtook source reader")
	}
	if next, ok := s.Deadline(armed); ok {
		t.Fatalf("blocked retry spins on timer %v", next)
	}
}

func TestSchedulerFairnessAndIndependentProgress(t *testing.T) {
	limits := map[string]int{"image": 1}
	s := NewScheduler(limits)
	limits["image"] = 99 // limits are owned by the machine
	ops := []Operation{{Key: "a", Class: "image"}, {Key: "b", Class: "image"}, {Key: "c", Class: "image"}}
	a := s.Schedule(testNow, ops)
	if !slices.Equal(attemptKeys(a), []string{"a"}) {
		t.Fatalf("class capacity: %v", attemptKeys(a))
	}
	s.Complete(testNow, a[0], Failed)
	// Newly eligible retries and reversed API list order cannot jump ahead
	// of jobs that have already waited for a class slot.
	reversed := slices.Clone(ops)
	slices.Reverse(reversed)
	b := s.Schedule(testNow.Add(2*time.Second), reversed)
	if !slices.Equal(attemptKeys(b), []string{"b"}) {
		t.Fatalf("waiting b starved: %v", attemptKeys(b))
	}
	s.Complete(testNow, b[0], Succeeded)
	c := s.Schedule(testNow.Add(2*time.Second), ops)
	if !slices.Equal(attemptKeys(c), []string{"c"}) {
		t.Fatalf("waiting c starved: %v", attemptKeys(c))
	}
	// Dropped queued work must not retain class priority or reservations.
	s.Schedule(testNow, nil)
	s.Complete(testNow, c[0], Canceled)
	if got := s.Schedule(testNow, []Operation{{Key: "fresh", Class: "image"}}); len(got) != 1 {
		t.Fatalf("dropped work blocked fresh job: %+v", got)
	}

	var writer Scheduler
	reader := Operation{Key: "reader", Reads: []string{"source"}}
	first := writer.Schedule(testNow, []Operation{reader})[0]
	wanted := []Operation{{Key: "delete", Writes: []string{"source"}}, {Key: "later-reader", Reads: []string{"source"}}, {Key: "unrelated"}}
	if got := writer.Schedule(testNow, wanted); !slices.Equal(attemptKeys(got), []string{"unrelated"}) {
		t.Fatalf("reader bypassed waiting writer or independent job stalled: %v", attemptKeys(got))
	}
	writer.Complete(testNow, first, Succeeded)
	slices.Reverse(wanted)
	if got := writer.Schedule(testNow, wanted); !slices.Equal(attemptKeys(got), []string{"delete"}) {
		t.Fatalf("writer starved: %v", attemptKeys(got))
	}
}

// Explore completion order, cancellation, duplicate delivery and restart with
// reproducible event streams. Check safety against actual in-flight work, not
// a second admission implementation, and compare complete replay transcripts.
func TestSchedulerAdversarialReplay(t *testing.T) {
	for seed := int64(0); seed < 24; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			run := func() string {
				rng := rand.New(rand.NewSource(seed))
				s := NewScheduler(map[string]int{"image": 2, "seal": 1})
				active := map[string]Attempt{}
				var stale []Attempt
				var transcript strings.Builder
				now := testNow
				for step := 0; step < 400; step++ {
					now = now.Add(time.Duration(rng.Intn(3000)) * time.Millisecond)
					if step%53 == 0 {
						for _, key := range sortedKeys(active) {
							stale = append(stale, active[key])
						}
						s.Restart()
						active = map[string]Attempt{}
					}
					keys := sortedKeys(active)
					if len(keys) != 0 && rng.Intn(3) != 0 {
						key := keys[rng.Intn(len(keys))]
						a := active[key]
						if !s.Complete(now, a, Outcome(rng.Intn(3))) {
							t.Fatal("current completion rejected")
						}
						delete(active, key)
						stale = append(stale, a)
					}
					if len(stale) != 0 && s.Complete(now, stale[rng.Intn(len(stale))], Failed) {
						t.Fatal("stale completion accepted")
					}
					var wanted []Operation
					for _, n := range rng.Perm(9) {
						if rng.Intn(4) == 0 {
							continue
						}
						op := Operation{Key: fmt.Sprint(n), Class: "image"}
						if n%3 == 0 {
							op.Class = "seal"
							op.Writes = []string{fmt.Sprint("source-", n%2)}
						} else {
							op.Reads = []string{fmt.Sprint("source-", n%2)}
						}
						wanted = append(wanted, op)
					}
					for _, a := range s.Schedule(now, wanted) {
						if _, ok := active[a.Operation.Key]; ok {
							t.Fatal("duplicate running key")
						}
						active[a.Operation.Key] = a
						fmt.Fprintf(&transcript, "%d:%s:%d;", step, a.Operation.Key, a.Generation)
					}
					readers, writers, classes := map[string]int{}, map[string]int{}, map[string]int{}
					busy := map[string]bool{}
					for _, a := range active {
						classes[a.Operation.Class]++
						for _, k := range a.Operation.Writes {
							writers[k]++
							busy[k] = true
						}
						for _, k := range a.Operation.Reads {
							readers[k]++
							busy[k] = true
						}
					}
					for k, n := range writers {
						if n > 1 || readers[k] != 0 {
							t.Fatalf("step %d conflicting reservation %s: writers=%d readers=%d", step, k, n, readers[k])
						}
					}
					if classes["image"] > 2 || classes["seal"] > 1 || !reflect.DeepEqual(busy, s.Busy()) {
						t.Fatalf("step %d capacity/reservation mismatch", step)
					}
				}
				s.Schedule(now, nil)
				for _, a := range active {
					s.Complete(now, a, Canceled)
				}
				if len(s.Busy()) != 0 {
					t.Fatal("shutdown leaked reservations")
				}
				return transcript.String()
			}
			if a, b := run(), run(); a != b {
				t.Fatal("same event stream produced different admissions")
			}
		})
	}
}

func TestAgentOperationAdapterCancellation(t *testing.T) {
	a := &Agent{operations: *NewScheduler(map[string]int{"image": 2}), wake: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 3)
	release := make(chan struct{})
	jobs := map[string]operationJob{}
	var ops []Operation
	for _, key := range []string{"a", "b", "c"} {
		ops = append(ops, Operation{Key: key, Class: "image", Reads: []string{"source"}})
		jobs[key] = operationJob{what: "test", run: func(ctx context.Context) error {
			started <- key
			<-release
			return ctx.Err()
		}}
	}
	a.runOperations(ctx, ops, jobs)
	seen := []string{<-started, <-started}
	slices.Sort(seen)
	if !slices.Equal(seen, []string{"a", "b"}) {
		t.Fatalf("adapter ignored admission: %v", seen)
	}
	cancel()
	a.runOperations(ctx, ops, jobs)
	a.mu.Lock()
	busy := a.operations.Busy()
	a.mu.Unlock()
	if !busy["source"] || busy["c"] {
		t.Fatalf("cancellation released I/O or admitted extra work: %v", busy)
	}
	close(release)
	a.workers.Wait()
	if len(a.operations.Busy()) != 0 || a.operations.Failures("a") != 0 || a.operations.Failures("b") != 0 {
		t.Fatal("adapter cancellation leaked reservations or poisoned retries")
	}
}
