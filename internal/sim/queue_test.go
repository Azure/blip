package sim

import (
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestQueueAllowsEitherOrderAtTheSameDeadline(t *testing.T) {
	var q Queue[string]
	a := q.Add(time.Second, "first", 1, "a")
	b := q.Add(time.Second, "second", 1, "b")
	q.Add(2*time.Second, "later", 1, "c")
	if !q.Advance() || !slices.Equal(q.Ready(), []uint64{a, b}) {
		t.Fatalf("concurrent events were not both enabled: %+v", q)
	}
	for _, order := range [][]uint64{{a, b}, {b, a}} {
		branch := q.Clone(nil)
		if _, err := branch.Take(order[0]); err != nil {
			t.Fatal(err)
		}
		if branch.Advance() || !slices.Equal(branch.Ready(), []uint64{order[1]}) {
			t.Fatal("advanced past a runnable event")
		}
		if _, err := branch.Take(order[1]); err != nil {
			t.Fatal(err)
		}
		if !branch.Advance() || branch.Now != 2*time.Second {
			t.Fatal("failed to advance after consuming both events")
		}
	}
	if len(q.Events) != 3 || q.Now != time.Second {
		t.Fatalf("branches changed their source queue: %+v", q)
	}
}

func TestQueueDropBeforeDelivery(t *testing.T) {
	var q Queue[string]
	lost := q.Add(time.Second, "agent", 1, "completion")
	retry := q.Add(2*time.Second, "agent", 1, "retry")
	if err := q.Drop(lost); err != nil {
		t.Fatal(err)
	}
	if err := q.Drop(lost); err == nil {
		t.Fatal("duplicate drop silently succeeded")
	}
	if _, err := q.Take(lost); err == nil {
		t.Fatal("dropped event remained deliverable")
	}
	if !q.Advance() || q.Now != 2*time.Second || !slices.Equal(q.Ready(), []uint64{retry}) {
		t.Fatalf("dropped event still affected scheduling: %+v", q)
	}
	if err := q.Drop(retry); err != nil || len(q.Ready()) != 0 || q.Advance() {
		t.Fatalf("ready event was not dropped: %+v, %v", q, err)
	}
}

func TestQueueCloneIsolatesPayloadAndCrash(t *testing.T) {
	var q Queue[[]string]
	old := q.Add(time.Second, "agent", 1, []string{"old"})
	q.Add(time.Second, "agent", 2, []string{"new"})
	external := q.Add(time.Second, "kernel", 1, []string{"applied"})
	clone := q.Clone(slices.Clone[[]string])
	clone.Events[0].Value[0] = "changed"
	clone.Crash("agent", 1)
	if len(clone.Events) != 2 || len(q.Events) != 3 || q.Events[0].Value[0] != "old" {
		t.Fatalf("clone/crash changed source: %+v", q)
	}
	if !clone.Advance() {
		t.Fatal("no surviving events")
	}
	if _, err := clone.Take(old); err == nil {
		t.Fatal("dead incarnation received a delivery")
	}
	if _, err := clone.Take(external); err != nil {
		t.Fatalf("process crash lost an external effect: %v", err)
	}
	if newID := clone.Add(0, "agent", 2, []string{"another"}); newID <= external {
		t.Fatalf("clone reused an event identity: %d", newID)
	}
}

func TestQueueInvalidAddLeavesQueueUnchanged(t *testing.T) {
	for _, tt := range []struct {
		name  string
		queue Queue[string]
		delay time.Duration
	}{
		{"negative delay", Queue[string]{}, -1},
		{"deadline overflow", Queue[string]{Now: time.Duration(math.MaxInt64)}, 1},
		{"identity overflow", Queue[string]{NextID: math.MaxUint64}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := tt.queue.Clone(nil)
			defer func() {
				if recover() == nil {
					t.Fatal("invalid event was accepted")
				}
				if !reflect.DeepEqual(q, tt.queue) {
					t.Fatalf("rejected event changed queue: %+v", q)
				}
			}()
			q.Add(tt.delay, "agent", 1, "event")
		})
	}
}

func TestObligationsCloneAndDeterministicFailure(t *testing.T) {
	o := Obligations{"z": time.Second, "a": time.Second, "later": 2 * time.Second}
	branch := o.Clone()
	delete(branch, "a")
	if len(o) != 3 || len(branch) != 2 {
		t.Fatal("monitor clone shares mutable state")
	}
	if err := o.Check(time.Second); err == nil || !strings.Contains(err.Error(), "[a z]") {
		t.Fatalf("overdue obligations are not deterministic: %v", err)
	}
	var empty Obligations
	if empty.Clone() != nil {
		t.Fatal("nil obligation clone should stay nil")
	}
	if err := empty.Check(time.Second); err != nil {
		t.Fatal(err)
	}
}
