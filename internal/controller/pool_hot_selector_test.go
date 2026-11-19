package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestW521HotNodeOutsideSelectorChurn covers a claimed VM running on a node
// that no longer matches the pool selector. The node must not be "hot" for
// this pool: relocating a healthy spare there only creates a pod the scheduler
// rejects, after deleting the only VM that could serve a claim.
func TestW521HotNodeOutsideSelectorChurn(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	n2 := &corev1.Node{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n2"}, n2))
	n2.Labels["w5-21/pool2"] = "true"
	e.must(e.c.Update(e.ctx, n2))
	e.newPool("default", 1, 2)
	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.NodeSelector = map[string]string{"w5-21/pool2": "true"}
	})
	pool := e.getPool("default")

	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Spec.NodeName = "n1"
	claimed.Status.Phase = corev1.PodRunning
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	spare := e.pool.podFor(pool, "default-spare")
	spare.Spec.NodeName = "n2"
	spare.Status.Phase = corev1.PodRunning
	spare.Labels[v1.LabelWarm] = "true"
	spare.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	e.create(claimed, spare)

	e.run(e.pool, ns, "default")
	if e.podGone(spare.Name) {
		t.Fatal("relocation deleted the only schedulable warm spare for an unmatched hot node")
	}
	for _, p := range e.pods() {
		if p.Annotations[v1.AnnotationPinnedNode] == "n1" {
			t.Fatalf("pod %s pinned to a node the pool selector excludes", p.Name)
		}
	}
}

// TestW622RelocationChurnsOnFullHotNode covers a hot node that is statically
// schedulable but full. Relocation cannot see capacity, so the first moved
// spare is rejected. Retrying after blockedGrace deletes the only healthy
// spare and re-pins it to the same full node every minute. A rejected
// relocation must back that node off for longer.
func TestW622RelocationChurnsOnFullHotNode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 0)
	pool := e.getPool("default")

	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Spec.NodeName = "n1"
	claimed.Status.Phase = corev1.PodRunning
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	spare := e.pool.podFor(pool, "default-spare")
	spare.Spec.NodeName = "n2"
	spare.Status.Phase = corev1.PodRunning
	spare.Labels[v1.LabelWarm] = "true"
	spare.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	e.create(claimed, spare)

	e.run(e.pool, ns, "default")
	if !e.podGone(spare.Name) {
		t.Fatal("fixture: spare was not relocated to the hot node")
	}
	var pinned *corev1.Pod
	pods := e.pods()
	for i := range pods {
		if pods[i].Annotations[v1.AnnotationPinnedNode] == "n1" && pods[i].Name != claimed.Name {
			pinned = &pods[i]
		}
	}
	if pinned == nil {
		t.Fatalf("fixture: no pinned replacement on the hot node: %+v", e.pods())
	}
	// The hot node has no room: the scheduler rejects the moved spare.
	w317MarkUnschedulable(t, e, pinned)
	e.run(e.pool, ns, "default")
	// The scheduler finally places the generic replacement on the idle node.
	e.warmOn("n2")
	var readyOnN2 string
	for _, p := range e.pods() {
		if p.Spec.NodeName == "n2" && isVacant(&p) && ready(&p) {
			readyOnN2 = p.Name
		}
	}
	if readyOnN2 == "" {
		t.Fatalf("fixture: no ready spare on the idle node: %+v", e.pods())
	}

	e.now = e.now.Add(blockedGrace + time.Second)
	e.heartbeat()
	e.run(e.pool, ns, "default")
	if e.podGone(readyOnN2) {
		t.Fatalf("relocation deleted the only schedulable spare %s and re-pinned to the full hot node: %+v", readyOnN2, e.pods())
	}
}
