package controller

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func w317MarkUnschedulable(t *testing.T, e *env, p *corev1.Pod) {
	t.Helper()
	p.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
	}}
	e.must(e.c.Status().Update(e.ctx, p))
}

// w317SchedulableVacant counts vacant pods the scheduler did not reject.
func w317SchedulableVacant(pods []corev1.Pod) int {
	n := 0
	for i := range pods {
		if isVacant(&pods[i]) && !podTerminated(&pods[i]) && !unschedulable(&pods[i]) {
			n++
		}
	}
	return n
}

// TestPoolReplacesGenericUnschedulableSpare covers a warm spare whose stale
// avoid affinity excludes a node that is usable again. The scheduler rejected
// the spare, but only pinned pods were treated as non-capacity, so the generic
// spare held maxCount forever and waiting Blips starved while other nodes were
// idle. A generic rejected spare must be replaced with a refreshed placement.
func TestPoolReplacesGenericUnschedulableSpare(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 1)

	// n2 is unusable when the spare is created, so its affinity excludes n2.
	e.setDrain("n2")
	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one spare: %+v", len(pods), pods)
	}
	spare := pods[0]
	if spare.Annotations[v1.AnnotationPinnedNode] != "" {
		t.Fatalf("spare is pinned, not generic: %+v", spare.Annotations)
	}
	if !unschedulableExcludes(&spare, "n2") {
		t.Fatalf("spare affinity does not exclude the drained node: %+v", spare.Spec.Affinity)
	}
	w317MarkUnschedulable(t, e, &spare)

	// n2 comes back and is idle. The stale spare still excludes it, so it can
	// never satisfy the pool's warm slot.
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n2"}, bn))
	bn.Spec.Drain = false
	e.must(e.c.Update(e.ctx, bn))
	e.heartbeat()

	// The rejected generic spare is kept for blockedGrace so an unplaceable
	// pool cannot churn pods at scheduler speed. The first pass observes the
	// rejection and starts the grace; once it expires the pool replaces the
	// pod once with a freshly computed placement.
	e.run(e.pool, ns, "default")
	e.now = e.now.Add(blockedGrace + time.Second)
	e.heartbeat()

	e.run(e.pool, ns, "default")
	e.run(e.pool, ns, "default")
	pods = e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one replacement within maxCount=1: %+v", len(pods), pods)
	}
	if p := pods[0]; p.Name == spare.Name || unschedulable(&p) {
		t.Fatalf("stale unschedulable spare still holds the only slot: %+v", p)
	}
	if unschedulableExcludes(&pods[0], "n2") {
		t.Fatalf("replacement keeps the stale avoid affinity: %+v", pods[0].Spec.Affinity)
	}
}

// TestPoolBoundsGenericUnschedulableChurn reproduces the unbounded create/delete
// loop: an always-unplaceable generic spare used to be deleted and recreated on
// every reconcile, at scheduler-event speed. The pool must keep the rejected pod
// for blockedGrace and replace it only once per grace instead.
func TestPoolBoundsGenericUnschedulableChurn(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 1)
	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 1 {
		t.Fatalf("%d pods, want one warm spare", n)
	}

	// Two-second reconciles over three minutes: the pod never has a node.
	const step = 2 * time.Second
	seen := map[string]bool{}
	for range 90 {
		for _, p := range e.pods() {
			if p.Spec.NodeName != "" || unschedulable(&p) {
				continue
			}
			w317MarkUnschedulable(t, e, &p)
		}
		e.run(e.pool, ns, "default")
		pods := e.pods()
		if len(pods) > 1 {
			t.Fatalf("%d live pods, want maxCount=1 to hold: %+v", len(pods), pods)
		}
		for _, p := range pods {
			seen[p.Name] = true
		}
		e.now = e.now.Add(step)
	}
	// The first pod is created, and each expired grace replaces it once. Three
	// minutes with a one-minute grace yields about three pods; the old loop
	// yielded one per reconcile.
	if len(seen) < 2 {
		t.Fatalf("only %d pod in three minutes: the rejected spare was never replaced", len(seen))
	}
	if len(seen) > 5 {
		t.Fatalf("%d pods in three minutes, want blockedGrace to bound churn: %v", len(seen), seen)
	}

	// The shortfall is visible on the pool while a rejected pod is kept.
	for _, p := range e.pods() {
		if !unschedulable(&p) {
			w317MarkUnschedulable(t, e, &p)
		}
	}
	e.run(e.pool, ns, "default")
	if st := e.getPool("default").Status; st.Reason != poolNoCapacity || st.Vacant != 0 || st.Ready != 0 {
		t.Fatalf("status %+v, want NoCapacity with no vacant/ready VM", st)
	}
}

// TestPoolReportsNoCapacity covers a pool whose only spare is Pending and
// Unschedulable: status must name the shortage, a Warning must fire once per
// transition, and both must clear when a schedulable VM exists.
func TestPoolReportsNoCapacity(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 1)
	recorder := record.NewFakeRecorder(10)
	e.pool.Recorder = recorder
	e.run(e.pool, ns, "default")

	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one warm spare", len(pods))
	}
	p := pods[0]
	p.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
		Message: "0/1 nodes are available: 1 Insufficient memory.",
	}}
	e.must(e.c.Status().Update(e.ctx, &p))

	e.run(e.pool, ns, "default")
	st := e.getPool("default").Status
	if st.Reason != poolNoCapacity {
		t.Fatalf("reason %q, want %q (status %+v)", st.Reason, poolNoCapacity, st)
	}
	if !strings.Contains(st.Message, "Insufficient memory") {
		t.Errorf("message %q does not explain the scheduler rejection", st.Message)
	}
	if st.Vacant != 0 || st.Ready != 0 {
		t.Errorf("status %+v claims capacity for an unplaceable spare", st)
	}
	event := waitForEvent(t, recorder)
	if !strings.Contains(event, corev1.EventTypeWarning+" "+poolNoCapacity) ||
		!strings.Contains(event, "Insufficient memory") {
		t.Errorf("event = %q, want a Warning NoCapacity naming the rejection", event)
	}

	// Still unschedulable: no flood of Events or pod churn.
	e.run(e.pool, ns, "default")
	e.run(e.pool, ns, "default")
	select {
	case extra := <-recorder.Events:
		t.Fatalf("duplicate event %q while the shortage did not change", extra)
	default:
	}
	if n := len(e.pods()); n != 1 {
		t.Fatalf("%d pods while the spare is kept, want one", n)
	}

	// The scheduler places the VM: capacity exists, so reason and message clear.
	cur := e.getPod(p.Name)
	cur.Spec.NodeName = "n1"
	cur.Labels[v1.LabelWarm] = "true"
	e.must(e.c.Update(e.ctx, cur))
	cur.Status.Phase = corev1.PodRunning
	cur.Status.Conditions = nil
	e.must(e.c.Status().Update(e.ctx, cur))
	e.run(e.pool, ns, "default")
	st = e.getPool("default").Status
	if st.Reason != "" || st.Message != "" {
		t.Fatalf("scheduled pool still reports %q: %q", st.Reason, st.Message)
	}
	if st.Ready != 1 || st.Vacant != 1 {
		t.Fatalf("status %+v, want the placed spare ready and vacant", st)
	}

	// A later shortage is a new transition and warns again.
	e.must(e.c.Delete(e.ctx, cur))
	e.run(e.pool, ns, "default")
	pods = e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods after deleting the spare, want a replacement", len(pods))
	}
	next := pods[0]
	w317MarkUnschedulable(t, e, &next)
	e.run(e.pool, ns, "default")
	if st := e.getPool("default").Status; st.Reason != poolNoCapacity {
		t.Fatalf("reason %q after the second shortage, want %q", st.Reason, poolNoCapacity)
	}
	event = waitForEvent(t, recorder)
	if !strings.Contains(event, corev1.EventTypeWarning+" "+poolNoCapacity) {
		t.Errorf("event = %q, want a second Warning NoCapacity", event)
	}
}

// unschedulableExcludes reports whether p carries a required node affinity of
// the form metadata.name NotIn(values) that contains node.
func unschedulableExcludes(p *corev1.Pod, node string) bool {
	aff := p.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil || aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		for _, req := range term.MatchFields {
			if req.Key == "metadata.name" && req.Operator == corev1.NodeSelectorOpNotIn {
				for _, v := range req.Values {
					if v == node {
						return true
					}
				}
			}
		}
	}
	return false
}

// TestPoolReplacesBlockedPinnedPodForFallbackBlip covers maxCount=1: the one
// slot must not be held by a pinned pod the scheduler rejected, or a Blip that
// already fell back waits for pendingTimeout while another node is idle.
func TestPoolReplacesBlockedPinnedPodForFallbackBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	home := e.readyState("data", "n1").Status.Placements[0]
	away := "n2"
	if home == away {
		away = "n1"
	}
	e.newPool("default", 0, 1)
	e.newBlip("b", withRoot("data"))

	e.run(e.blip, ns, "b")
	e.run(e.pool, ns, "default")
	pinned := pinnedPods(e, home)
	if len(pinned) != 1 {
		t.Fatalf("pinned pods %+v", e.pods())
	}
	w317MarkUnschedulable(t, e, &pinned[0])

	// The Blip gives up the local wait; its only home node rejects VMs.
	e.now = e.now.Add(localWait + time.Second)
	e.heartbeat()
	e.run(e.blip, ns, "b")
	if loc := e.getBlip("b").Status.Locality; loc == nil || !loc.Fallback {
		t.Fatalf("blip did not fall back: %+v", loc)
	}

	e.run(e.pool, ns, "default")
	e.run(e.pool, ns, "default")

	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one replacement within maxCount=1: %+v", len(pods), pods)
	}
	if r := pods[0]; unschedulable(&r) || podNode(&r) == home {
		t.Fatalf("replacement still targets the blocked node: pin=%q unschedulable=%v", podNode(&r), unschedulable(&r))
	}
	// The replacement is claimable once the scheduler places it on the idle
	// node; the Blip must then start there instead of timing out.
	e.warmOn(away)
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != away {
		t.Fatalf("started on %q, want the idle node %q", b.Status.Node, away)
	}
}

// TestPoolStopsPinnedCreatesOnBlockedNodes covers several rejected nodes and
// an uncapped pool: a third Blip must not add another pinned pod to a node
// the scheduler already rejected, and the demand must still get a VM.
func TestPoolStopsPinnedCreatesOnBlockedNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	for name, node := range map[string]string{"b0": "n1", "b1": "n2"} {
		e.newBlip(name)
		e.setBlipStatus(name, func(b *v1.Blip) {
			b.Status.Phase = v1.BlipPending
			b.Status.Locality = &v1.Locality{Node: node}
		})
	}

	e.run(e.pool, ns, "default")
	for _, node := range []string{"n1", "n2"} {
		pods := pinnedPods(e, node)
		if len(pods) != 1 {
			t.Fatalf("%d pinned pods on %s, want one: %+v", len(pods), node, e.pods())
		}
		w317MarkUnschedulable(t, e, &pods[0])
	}

	// Both nodes are now known to reject pinned pods. The existing rejected
	// pods stay while their Blips wait locally, but they are not capacity.
	e.run(e.pool, ns, "default")
	if n := len(pinnedPods(e, "n1")) + len(pinnedPods(e, "n2")); n != 2 {
		t.Fatalf("%d pinned pods after the block, want no new pinned create: %+v", n, e.pods())
	}
	if n := w317SchedulableVacant(e.pods()); n == 0 {
		t.Fatalf("blocked nodes keep absorbing all demand; no schedulable VM: %+v", e.pods())
	}

	e.newBlip("b2")
	e.setBlipStatus("b2", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipPending
		b.Status.Locality = &v1.Locality{Node: "n1"}
	})
	e.run(e.pool, ns, "default")
	if n := len(pinnedPods(e, "n1")); n != 1 {
		t.Fatalf("%d pinned pods on blocked n1 after new demand, want none added", n)
	}
	if n := len(pinnedPods(e, "n2")); n != 1 {
		t.Fatalf("%d pinned pods on blocked n2 after new demand, want none added", n)
	}
	if n := w317SchedulableVacant(e.pods()); n == 0 {
		t.Fatalf("no schedulable VM for demand on blocked nodes: %+v", e.pods())
	}
}

// TestPoolUsesSecondHomeNodeWhenFirstBlocked covers a state with two replicas:
// when the first home node rejects the pinned VM, the pool boots on the other
// home node, which also holds the data, instead of leaving the Blip with no
// claimable local VM.
func TestPoolUsesSecondHomeNodeWhenFirstBlocked(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("data", "n1", "n2")
	if len(st.Status.Placements) != 2 {
		t.Fatalf("placements %v, want two home nodes", st.Status.Placements)
	}
	home, other := st.Status.Placements[0], st.Status.Placements[1]
	e.newPool("default", 0, 1)
	e.newBlip("b", withRoot("data"))

	e.run(e.blip, ns, "b")
	if loc := e.getBlip("b").Status.Locality; loc == nil || loc.Node != home {
		t.Fatalf("locality %+v, want %s", loc, home)
	}
	e.run(e.pool, ns, "default")
	pinned := pinnedPods(e, home)
	if len(pinned) != 1 {
		t.Fatalf("pinned pods %+v", e.pods())
	}
	w317MarkUnschedulable(t, e, &pinned[0])

	e.now = e.now.Add(localWait + time.Second)
	e.heartbeat()
	e.run(e.blip, ns, "b")
	if loc := e.getBlip("b").Status.Locality; loc == nil || !loc.Fallback {
		t.Fatalf("blip did not fall back: %+v", loc)
	}
	e.run(e.pool, ns, "default")
	e.run(e.pool, ns, "default")

	pods := pinnedPods(e, other)
	if len(pods) != 1 {
		t.Fatalf("pinned pods on second home %s: %+v", other, e.pods())
	}
	if unschedulable(&pods[0]) {
		t.Fatalf("second home pod rejected: %+v", pods[0])
	}
	e.warmOn(other)
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	expectPhase(t, b, v1.BlipRunning, "")
	if b.Status.Node != other {
		t.Fatalf("started on %q, want the second home node %q", b.Status.Node, other)
	}
	if loc := b.Status.Locality; loc == nil || loc.Fallback {
		t.Fatalf("started on a home node but locality says fallback: %+v", loc)
	}
}
