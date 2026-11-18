package simapp

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/controller"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	bruntime "github.com/Azure/blip/internal/runtime"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/storage"
)

func sortedKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (w *world) Check() error {
	if w.Healed && w.RecoverySteps > 400 {
		return fmt.Errorf("fair recovery obligation expired at %s", stages[w.Stage])
	}
	claims := map[string]int{}
	for _, p := range w.Actual.Pods.Items {
		uid := p.Labels[controller.LabelBlipUID]
		if uid == "" {
			continue
		}
		claims[uid]++
		if claims[uid] > 1 {
			return fmt.Errorf("one Blip owns multiple pods")
		}
		if len(p.OwnerReferences) != 1 || string(p.OwnerReferences[0].UID) != uid {
			return fmt.Errorf("pod authorization/claim ownership differs")
		}
	}
	for id := range w.Devices {
		v, ok := w.Working[id]
		if !ok || v.Sealed {
			return fmt.Errorf("VMM holds missing or sealed %s", id)
		}
		wr := w.state(v.State).Status.Writer
		if wr == nil || wr.AttachmentID != id || wr.Node != v.Node {
			return fmt.Errorf("open device %s outlived authoritative writer", id)
		}
	}
	for id := range w.GuestMounts {
		if !w.Devices[id] {
			return fmt.Errorf("mounted guest filesystem without VMM device")
		}
	}
	for _, m := range w.runtime.Observed().Mounts {
		if m.Phase == podapi.DiskDetached && (w.Devices[m.ID] || w.GuestMounts[m.ID]) {
			return fmt.Errorf("runtime announced detach before physical fence")
		}
	}
	for _, st := range w.Actual.States.Items {
		for _, o := range st.Status.Nodes {
			for _, id := range o.Commits {
				v, present := w.Inventory[o.Node][id]
				_, durable := w.Durable[o.Node][id]
				if !present || !durable || v.Kind != storage.KindCommit || v.StateUID != string(st.UID) {
					return fmt.Errorf("node %s reported absent or unrelated commit %s", o.Node, id)
				}
			}
			for _, r := range o.Sealed {
				if r.Error != "" {
					continue
				}
				v := w.Inventory[o.Node][r.CommitID]
				if !w.Working[r.AttachmentID].Sealed || w.Devices[r.AttachmentID] || v.SizeBytes != r.SizeBytes {
					return fmt.Errorf("node %s reported unfenced or inaccurate seal %s", o.Node, r.AttachmentID)
				}
			}
		}
		if p := st.Status.Pending; p != nil && st.Status.Writer != nil {
			return fmt.Errorf("writer and save pending together")
		}
		if st.Status.Committed.Generation == 2 {
			want := "acknowledged-write:" + st.Name + ":abcdefghijklmnopqrstuvwxyz"
			if st.Status.Committed.ID != w.Saved[st.Name] {
				return fmt.Errorf("committed an unrelated seal")
			}
			for _, n := range st.Status.Placements {
				if w.Durable[n][st.Status.Committed.ID] != want {
					return fmt.Errorf("commit %s published without exact selected replica bytes on %s", st.Name, n)
				}
				found := false
				for _, o := range st.Status.Nodes {
					if o.Node == n && o.Incarnation == "inc-"+n && slices.Contains(o.Commits, st.Status.Committed.ID) {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("commit accepted old-incarnation or absent report")
				}
			}
		}
	}
	for _, n := range []string{"n1", "n2"} {
		for i, name := range []string{"root", "data"} {
			if w.Durable[n][fmt.Sprintf("%016x", 100+i)] != "initial:"+name {
				return fmt.Errorf("working write mutated immutable base")
			}
		}
	}
	if x := w.Transfer; x != nil {
		if (x.Open || x.Published) && !x.Pinned {
			return fmt.Errorf("source unpinned before device close")
		}
		if x.Published && (!x.Open || !x.Persisted) {
			return fmt.Errorf("lease export without durable registration/device")
		}
		if x.Operation == peer.ReleaseLease && !x.Published && !x.Revoked {
			return fmt.Errorf("release was not durably revoked first")
		}
		if !x.Hydrated {
			if _, ok := w.Durable["n2"][x.Commit]; ok {
				return fmt.Errorf("partial replica published")
			}
		}
	}
	for _, b := range w.Actual.Blips.Items {
		if b.Name == "second" && w.Stage <= 18 && b.Status.Pod != "" {
			return fmt.Errorf("contender acquired state while first writer is live")
		}
		if b.Status.Phase == v1.BlipFailed {
			return fmt.Errorf("recoverable workload failed: %s: %s", b.Status.Reason, b.Status.Message)
		}
		if b.Name == "first" && b.Status.Phase == v1.BlipSucceeded {
			for _, name := range []string{"root", "data"} {
				if w.state(name).Status.Committed.Generation != 2 {
					return fmt.Errorf("success before both acknowledged writes saved")
				}
			}
		}
	}
	if w.Stage == len(stages)-1 {
		b := w.blip()
		if b.Status.Node != "n2" || b.Status.Phase != v1.BlipRunning {
			return fmt.Errorf("reacquisition did not move to replica")
		}
		for _, name := range []string{"root", "data"} {
			wr := w.state(name).Status.Writer
			if wr == nil || wr.BlipUID != string(b.UID) || wr.AttachmentID == w.Attachments[name] || wr.BaseCommit != w.Saved[name] {
				return fmt.Errorf("reacquired stale writer/base for %s", name)
			}
			v := w.Working[wr.AttachmentID]
			if v.Bytes != "acknowledged-write:"+name+":abcdefghijklmnopqrstuvwxyz" || !w.GuestMounts[wr.AttachmentID] {
				return fmt.Errorf("reacquired %s lost acknowledged content", name)
			}
		}
	}
	return nil
}

func checkedStep(t *testing.T, w *world, action string) {
	t.Helper()
	if err := w.Step(action); err != nil {
		t.Fatalf("%s at %s: %v", action, stages[w.Stage], err)
	}
	if err := w.Check(); err != nil {
		t.Fatalf("%s at %s: %v", action, stages[w.Stage], err)
	}
}

// Healing imposes explicit weak fairness: watch delivery, queued I/O completion,
// and controller/runtime turns are serviced. Faults stop, durable reality is
// retained. A finite budget is an assertion; exhausting Run's budget is not.
func heal(t *testing.T, w *world) {
	t.Helper()
	w.Healed = true
	for w.Stage < len(stages)-1 && w.RecoverySteps <= 400 {
		a := fairAction(w)
		checkedStep(t, w, a)
	}
	if w.Stage != len(stages)-1 {
		t.Fatalf("did not recover at %s", stages[w.Stage])
	}
	if w.IO != nil || w.Transfer != nil || w.Removal != nil || len(w.scheduler.Busy()) != 0 {
		t.Fatal("completed workload leaked I/O/lease reservations")
	}
}

func fairAction(w *world) string {
	for _, a := range []string{"observe/cache", "runtime/effect", "hypervisor/confirm-removal", "runtime/reply"} {
		if slices.Contains(w.Enabled(), a) {
			return a
		}
	}
	return "progress/" + stages[w.Stage]
}

func TestSimulationLifecycleSeededReplayAndHealing(t *testing.T) {
	first, runs := uint64(1), uint64(12)
	for name, dst := range map[string]*uint64{"BLIP_SIM_SEED": &first, "BLIP_SIM_RUNS": &runs} {
		if value, set := os.LookupEnv(name); set {
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			*dst = n
		}
	}
	if runs == 0 || runs > 10000 || first > ^uint64(0)-(runs-1) {
		t.Fatal("simulation campaign requires 1..10000 runs and a non-overflowing seed range")
	}
	for i := uint64(0); i < runs; i++ {
		seed := first + i
		t.Run(fmt.Sprintf("seed-%02d", seed), func(t *testing.T) {
			initial := newWorld()
			trace, err := sim.Run(initial, seed, 300)
			if err != nil {
				t.Fatalf("%v\ntrace=%s", err, encode(trace))
			}
			final, err := sim.Replay(initial, trace)
			if err != nil {
				t.Fatalf("replay: %v\ntrace=%s", err, encode(trace))
			}
			if initial.Stage != 0 || initial.runtime.Key() != bruntime.NewMachine(true).Key() {
				t.Fatal("Run or Replay mutated its initial world")
			}
			heal(t, final.(*world))
		})
	}
}

func TestSimulationLifecycleEveryAmbiguousBoundary(t *testing.T) {
	// Guarantee coverage independently of random choices, and verify the entire
	// allocation -> bytes -> detach -> save -> replica -> new owner chain after
	// each fault. Each fault is injected when its physical boundary is enabled.
	for _, fault := range []string{"api-reply", "control-reply", "removal-reply", "storage-reply", "storage-before", "revocation-reply", "old-incarnation"} {
		t.Run(fault, func(t *testing.T) {
			w := newWorld()
			wanted := "fault/" + fault
			for steps := 0; !slices.Contains(w.Enabled(), wanted); steps++ {
				if steps > 250 || len(w.Enabled()) == 0 {
					t.Fatalf("unreached fault %s at %s", wanted, stages[w.Stage])
				}
				checkedStep(t, w, fairAction(w))
			}
			checkedStep(t, w, wanted)
			if fault == "old-incarnation" {
				// Explicitly give the stale observation to the actual state
				// reconciler before the matching-incarnation report arrives.
				checkedStep(t, w, "observe/cache")
				must(w.reconcile("state", "data", false))
				if w.state("data").Status.Pending == nil || w.state("data").Status.Committed.Generation != 1 {
					t.Fatal("stale incarnation satisfied replica barrier")
				}
			}
			heal(t, w)
		})
	}
}

func TestSimulationLifecycleEveryAppliedAPIWrite(t *testing.T) {
	baseline := newWorld()
	heal(t, baseline)
	for cut := 1; cut <= baseline.APIWrites; cut++ {
		t.Run(fmt.Sprintf("write-%02d", cut), func(t *testing.T) {
			w := newWorld()
			w.LoseWrite = cut
			for steps := 0; w.Coverage["lost-api"] == 0; steps++ {
				if steps > 300 || len(w.Enabled()) == 0 {
					t.Fatalf("did not reach applied write %d", cut)
				}
				checkedStep(t, w, fairAction(w))
			}
			heal(t, w)
		})
	}
	t.Logf("recovered after each of %d applied production controller writes", baseline.APIWrites)
}

func TestSimulationLifecycleSaveAndUnmountFaults(t *testing.T) {
	for _, test := range []struct {
		stage int
		fault string
	}{
		{10, "control-reply"}, {21, "control-reply"},
		{13, "storage-reply"}, {24, "storage-reply"}, {33, "storage-before"},
	} {
		t.Run(fmt.Sprintf("%s/%s", stages[test.stage], test.fault), func(t *testing.T) {
			w := newWorld()
			for steps := 0; w.Stage != test.stage || !slices.Contains(w.Enabled(), "fault/"+test.fault); steps++ {
				if steps > 300 || w.Stage > test.stage {
					t.Fatalf("fault boundary unreachable at %s", stages[w.Stage])
				}
				checkedStep(t, w, fairAction(w))
			}
			checkedStep(t, w, "fault/"+test.fault)
			heal(t, w)
		})
	}
}

func TestSimulationLifecycleContenderWaitsThenReadsSavedBytes(t *testing.T) {
	w := newWorld()
	for w.Stage != 16 {
		checkedStep(t, w, fairAction(w))
	}
	checkedStep(t, w, "client/contend")
	checkedStep(t, w, "observe/cache")
	checkedStep(t, w, "client/contend")
	for _, b := range w.Actual.Blips.Items {
		if b.Name == "second" && (b.Status.Pod != "" || b.Status.Reason != controller.ReasonStateBusy) {
			t.Fatalf("contender did not wait for writer: %+v", b.Status)
		}
	}
	heal(t, w)
}

// A bounded window includes its remaining depth in Key. Exhaustive exploration
// proves safety of all enabled schedules in that finite window; complete here
// deliberately does not mean the unbounded whole application was explored.
type window struct {
	W    *world
	Left int
}

func (x *window) Clone() sim.Model { return &window{W: x.W.Clone().(*world), Left: x.Left} }
func (x *window) Key() string      { return fmt.Sprintf("%d/%s", x.Left, x.W.Key()) }
func (x *window) Enabled() []string {
	if x.Left == 0 {
		return nil
	}
	return x.W.Enabled()
}
func (x *window) Step(a string) error { x.Left--; return x.W.Step(a) }
func (x *window) Check() error        { return x.W.Check() }

func TestSimulationLifecycleExploresObservationAndDetachWindows(t *testing.T) {
	for _, at := range []string{"allocate", "runtime-detach", "commit-data"} {
		t.Run(at, func(t *testing.T) {
			w := newWorld()
			for steps := 0; stages[w.Stage] != at; steps++ {
				if steps > 250 {
					t.Fatal("milestone unreachable")
				}
				checkedStep(t, w, fairAction(w))
			}
			report, err := sim.Explore(&window{W: w, Left: 4}, sim.Limits{States: 5000, Depth: 4})
			if err != nil {
				t.Fatalf("%v\ntrace=%s", err, encode(report.Trace))
			}
			if !report.Complete || report.Transitions < 10 {
				t.Fatalf("incomplete or vacuous window: %+v", report)
			}
			t.Logf("%s: %d states, %d transitions", at, report.States, report.Transitions)
		})
	}
}

func TestSimulationLifecycleCloneIncludesInFlightEffects(t *testing.T) {
	w := newWorld()
	for w.Removal == nil {
		checkedStep(t, w, fairAction(w))
	}
	x := w.Clone().(*world)
	if x.Key() != w.Key() {
		t.Fatal("clone lost hidden core state")
	}
	before := w.Key()
	checkedStep(t, x, "fault/removal-reply")
	if w.Key() != before || !w.Devices[w.Removal.Disk.ID] {
		t.Fatal("clone shared physical state")
	}
	heal(t, x)
}

func TestSimulationLifecycleMonitorRejectsPrematurePublication(t *testing.T) {
	w := newWorld()
	for stages[w.Stage] != "replicate-data" {
		checkedStep(t, w, fairAction(w))
	}
	s := w.state("data")
	s.Status.Committed = &v1.Commit{ID: w.Saved["data"], Generation: 2}
	s.Status.Pending = nil
	if err := w.Check(); err == nil || !strings.Contains(err.Error(), "exact selected replica bytes") {
		t.Fatalf("content monitor failed to detect premature commit: %v", err)
	}
}
