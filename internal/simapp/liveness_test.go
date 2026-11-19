package simapp

import (
	"slices"
	"testing"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simlive"
)

// The bounded liveness window is deliberately small: simlive.Check explores the
// goal-pruned graph exhaustively only inside these limits. Completeness here is
// not a claim about the unbounded workload.
const livenessDepth = 12

// progressActions lists every progress action the workload can expose. A group
// is continuously enabled while a nonterminal stage has not advanced, so weak
// fairness of this group requires the controller/runtime to keep taking turns.
func progressActions() []string {
	var actions []string
	for _, stage := range stages {
		action := "progress/" + stage
		if !slices.Contains(actions, action) {
			actions = append(actions, action)
		}
	}
	slices.Sort(actions)
	return actions
}

// livenessFairness treats the controller/runtime turn, watch delivery, runtime
// effect delivery and queued reply handling as weakly fair. Actions outside
// these groups (for example the one-shot fault injectors) are not assumed fair.
func livenessFairness() []simlive.Group {
	return []simlive.Group{
		{Name: "controller-progress", Actions: progressActions()},
		{Name: "cache-delivery", Actions: []string{"observe/cache"}},
		{Name: "runtime-effects", Actions: []string{"runtime/effect"}},
		{Name: "runtime-replies", Actions: []string{"runtime/reply"}},
	}
}

// livenessWorld extracts the workload from the model used by the checker. The
// stalled control embeds the same window, so both shapes are accepted.
func livenessWorld(m sim.Model) *world {
	switch x := m.(type) {
	case *window:
		return x.W
	case *stalledWindow:
		return x.W
	default:
		panic("unexpected liveness model")
	}
}

// goalAt is precise and depends only on the window key: the workload has entered
// the named milestone.
func goalAt(stage string) func(sim.Model) bool {
	return func(m sim.Model) bool {
		return stages[livenessWorld(m).Stage] == stage
	}
}

func reachStage(t *testing.T, w *world, stage string) {
	t.Helper()
	for steps := 0; stages[w.Stage] != stage; steps++ {
		if steps > 250 {
			t.Fatalf("unreachable stage %s at %s", stage, stages[w.Stage])
		}
		checkedStep(t, w, fairAction(w))
	}
}

// stalledWindow is the negative control. It keeps the real world and its
// enabled actions, but the selected progress action is a no-op. Weak fairness
// still sees that action as enabled and taken forever, so the checker must
// produce a goal-avoiding cycle rather than a vacuous success.
type stalledWindow struct {
	*window
	action string
}

func (x *stalledWindow) Clone() sim.Model {
	return &stalledWindow{window: x.window.Clone().(*window), action: x.action}
}

func (x *stalledWindow) Step(action string) error {
	if action == x.action {
		return nil
	}
	return x.window.Step(action)
}

func checkLiveness(t *testing.T, model sim.Model, goal string) simlive.Report {
	t.Helper()
	report, err := simlive.Check(model, simlive.Options{
		Limits:       sim.Limits{States: 5000, Depth: livenessDepth},
		Goal:         goalAt(goal),
		WeakFairness: livenessFairness(),
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !report.Complete {
		t.Fatalf("liveness window was truncated: %+v", report)
	}
	if report.Witness != nil {
		t.Fatalf("fair execution avoids the goal: prefix=%d cycle=%d", len(report.Witness.Prefix.Steps), len(report.Witness.Cycle))
	}
	return report
}

// Prove that runtime claim finalization and the handoff through mirror to the
// running controller phase cannot starve when controller progress is weakly
// fair. The window starts after the runtime has observed the claim and mounted
// the data disk, with no effect or reply left pending.
func TestSimulationLivenessRuntimeClaimToRunning(t *testing.T) {
	w := newWorld()
	reachStage(t, w, "runtime-claim")
	for steps := 0; ; steps++ {
		o := w.runtime.Observed()
		if o.ClaimID != "" && len(o.Mounts) > 0 &&
			o.Mounts[len(o.Mounts)-1].Phase == podapi.DiskMounted &&
			len(w.Effects) == 0 && len(w.Replies) == 0 {
			break
		}
		if steps > 150 {
			t.Fatalf("runtime claim phase unreachable at %s", stages[w.Stage])
		}
		checkedStep(t, w, fairAction(w))
	}
	// Keep the window's own horizon beyond simlive's depth bound so it cannot
	// manufacture a terminal state before the checker's depth bound.
	report := checkLiveness(t, &window{W: w, Left: livenessDepth + 1}, "running")
	if report.States < 2 {
		t.Fatalf("window is vacuous: %+v", report)
	}
	t.Logf("runtime claim -> running: %d states, %d transitions", report.States, report.Transitions)
}

// Prove that the controller seal/report phase cannot starve when controller
// progress and cache delivery are weakly fair. The window includes the
// contender turn and a stale informer cache, so cache delivery is genuinely
// enabled while the goal is being reached.
func TestSimulationLivenessSealDataToReportData(t *testing.T) {
	w := newWorld()
	reachStage(t, w, "seal-data")
	report := checkLiveness(t, &window{W: w, Left: livenessDepth + 1}, "report-data")
	if report.States < 10 || report.Transitions < 10 {
		t.Fatalf("window is vacuous: %+v", report)
	}
	t.Logf("seal-data -> report-data: %d states, %d transitions", report.States, report.Transitions)
}

// Negative control: the same runtime window and fairness assumptions, but its
// only progress action is deliberately stalled. The checker must not conclude
// success just because a weakly fair action is enabled.
func TestSimulationLivenessStalledProgressHasWitness(t *testing.T) {
	w := newWorld()
	reachStage(t, w, "runtime-claim")
	for steps := 0; ; steps++ {
		o := w.runtime.Observed()
		if o.ClaimID != "" && len(o.Mounts) > 0 &&
			o.Mounts[len(o.Mounts)-1].Phase == podapi.DiskMounted &&
			len(w.Effects) == 0 && len(w.Replies) == 0 {
			break
		}
		if steps > 150 {
			t.Fatalf("runtime claim phase unreachable at %s", stages[w.Stage])
		}
		checkedStep(t, w, fairAction(w))
	}
	model := &stalledWindow{
		window: &window{W: w, Left: livenessDepth + 1},
		action: "progress/runtime-claim",
	}
	report, err := simlive.Check(model, simlive.Options{
		Limits:       sim.Limits{States: 5000, Depth: livenessDepth},
		Goal:         goalAt("running"),
		WeakFairness: livenessFairness(),
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !report.Complete || report.Witness == nil || len(report.Witness.Cycle) == 0 {
		t.Fatalf("stalled progress escaped detection: %+v", report)
	}
	t.Logf("stalled progress witness: prefix=%d cycle=%d", len(report.Witness.Prefix.Steps), len(report.Witness.Cycle))
}
