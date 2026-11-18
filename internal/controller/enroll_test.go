package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// addEnrollableNode creates a Kubernetes Node that may be selected by a pool,
// plus the BlipNode an agent would have registered.
func (e *env) addEnrollableNode(name string, nodeLabels map[string]string, hypervisors ...string) {
	e.t.Helper()
	e.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: nodeLabels}})
	bn := &v1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: name}}
	e.create(bn)
	hb := metav1.NewTime(e.now)
	bn.Status = v1.BlipNodeStatus{
		Incarnation: "inc-" + name, Heartbeat: &hb, FreeBytes: 100 << 30,
		Hypervisors: hypervisors,
	}
	e.must(e.c.Status().Update(e.ctx, bn))
}

func (e *env) getNode(name string) *corev1.Node {
	e.t.Helper()
	n := &corev1.Node{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: name}, n))
	return n
}

func (e *env) getBlipNode(name string) *v1.BlipNode {
	e.t.Helper()
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: name}, bn))
	return bn
}

func (e *env) updatePool(name string, mutate func(*v1.BlipPool)) {
	e.t.Helper()
	p := &v1.BlipPool{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, p))
	mutate(p)
	e.must(e.c.Update(e.ctx, p))
}

func TestEnrollLabelsMatchingNodes(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.addEnrollableNode("n2", map[string]string{"zone": "b"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})

	e.run(e.enroll, "", "n1")
	e.run(e.enroll, "", "n2")

	n1 := e.getNode("n1")
	if n1.Labels[LabelEnrolled] != "true" {
		t.Errorf("selected node not enrolled: %v", n1.Labels)
	}
	if n1.Labels[LabelHypervisorPrefix+"kvm"] != "true" {
		t.Errorf("selected node missing hypervisor label: %v", n1.Labels)
	}
	if n1.Labels["zone"] != "a" {
		t.Errorf("enrollment changed an unrelated label: %v", n1.Labels)
	}
	n2 := e.getNode("n2")
	if n2.Labels[LabelEnrolled] != "" {
		t.Errorf("unselected node enrolled: %v", n2.Labels)
	}
	if n2.Labels[LabelHypervisorPrefix+"kvm"] != "" {
		t.Errorf("unselected node has hypervisor label: %v", n2.Labels)
	}
}

func TestEnrollDoesNotEnrollUnselectedNode(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "b"}, "kvm")
	bn := e.getBlipNode("n1")
	bn.Spec.Drain = true
	e.must(e.c.Update(e.ctx, bn))

	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	if n1.Labels[LabelEnrolled] != "" {
		t.Errorf("never-enrolled node was enrolled: %v", n1.Labels)
	}
	if n1.Labels[LabelHypervisorPrefix+"kvm"] != "" {
		t.Errorf("never-enrolled node has hypervisor label: %v", n1.Labels)
	}
}

func TestEnrollDrainsUnselectedNode(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	e.run(e.enroll, "", "n1")
	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.NodeSelector = map[string]string{"zone": "b"}
	})

	// Starting the drain removes the hypervisor label and stops new VM pods
	// from selecting the node. The node is idle, so the same pass proves the
	// drain safe and unenrolls it instead of waiting for another status pass.
	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	for _, k := range []string{LabelEnrolled, LabelHypervisorPrefix + "kvm"} {
		if _, ok := n1.Labels[k]; ok {
			t.Errorf("label %s not removed after drain: %v", k, n1.Labels)
		}
	}
	if n1.Labels["zone"] != "a" {
		t.Errorf("enrollment changed an unrelated label: %v", n1.Labels)
	}
	err := e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, &v1.BlipNode{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("BlipNode still exists after drain: %v", err)
	}
}

func TestEnrollClearsAutoDrainWhenSelectedAgain(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	bn := e.getBlipNode("n1")
	bn.Spec.Drain = true
	bn.Annotations = map[string]string{AnnotationEnrollmentDrain: "true"}
	e.must(e.c.Update(e.ctx, bn))

	e.run(e.enroll, "", "n1")

	bn = e.getBlipNode("n1")
	if bn.Spec.Drain {
		t.Error("automatic drain not cleared after the node matched a pool")
	}
	if _, ok := bn.Annotations[AnnotationEnrollmentDrain]; ok {
		t.Errorf("drain annotation not removed: %v", bn.Annotations)
	}
	if e.getNode("n1").Labels[LabelEnrolled] != "true" {
		t.Error("matching node not enrolled")
	}
}

func TestEnrollPreservesOperatorDrain(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	bn := e.getBlipNode("n1")
	bn.Spec.Drain = true
	e.must(e.c.Update(e.ctx, bn))

	e.run(e.enroll, "", "n1")

	bn = e.getBlipNode("n1")
	if !bn.Spec.Drain {
		t.Error("operator drain was cleared")
	}
	if e.getNode("n1").Labels[LabelEnrolled] != "true" {
		t.Error("operator-drained node not enrolled")
	}
}

func TestEnrollRemovesStaleHypervisorLabel(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	e.run(e.enroll, "", "n1")

	bn := e.getBlipNode("n1")
	bn.Status.Hypervisors = nil
	e.must(e.c.Status().Update(e.ctx, bn))
	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	if n1.Labels[LabelEnrolled] != "true" {
		t.Error("node with no hypervisor should stay enrolled")
	}
	if n1.Labels[LabelHypervisorPrefix+"kvm"] != "" {
		t.Errorf("stale hypervisor label remains: %v", n1.Labels)
	}
}

// TestEnrollWaitsForMigration checks that a legacy pool with no selector does
// not make the controller drain nodes during an upgrade.
func TestEnrollWaitsForMigration(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{
		LabelEnrolled:                 "true",
		LabelHypervisorPrefix + "kvm": "true",
	}, "kvm")
	e.create(&v1.BlipPool{ObjectMeta: metav1.ObjectMeta{Name: "default"}})

	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	if n1.Labels[LabelEnrolled] != "true" || n1.Labels[LabelHypervisorPrefix+"kvm"] != "true" {
		t.Errorf("migrating cluster changed enrollment labels: %v", n1.Labels)
	}
	if bn := e.getBlipNode("n1"); bn.Spec.Drain {
		t.Error("migrating cluster drained a node")
	}
}

// TestEnrollRemovesLabelsWithoutBlipNode covers a node whose agent already
// disappeared: the controller still removes the labels it owns.
func TestEnrollRemovesLabelsWithoutBlipNode(t *testing.T) {
	e := newEnv(t)
	e.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{
		LabelEnrolled:                 "true",
		LabelHypervisorPrefix + "kvm": "true",
		"keep":                        "me",
	}}})

	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	if n1.Labels[LabelEnrolled] != "" || n1.Labels[LabelHypervisorPrefix+"kvm"] != "" {
		t.Errorf("managed labels not removed: %v", n1.Labels)
	}
	if n1.Labels["keep"] != "me" {
		t.Errorf("unrelated label removed: %v", n1.Labels)
	}
}

// TestEnrollAgainAfterUnenroll checks the full cycle: drain, remove, then
// re-enroll when a pool selects the node again.
func TestEnrollAgainAfterUnenroll(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	e.run(e.enroll, "", "n1")

	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.NodeSelector = map[string]string{"zone": "b"}
	})
	// The idle node drains and is proven safe in the same retry.
	e.run(e.enroll, "", "n1")
	if e.getNode("n1").Labels[LabelEnrolled] != "" {
		t.Fatal("node still enrolled after unenroll")
	}

	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.enroll, "", "n1")
	if e.getNode("n1").Labels[LabelEnrolled] != "true" {
		t.Fatal("node not enrolled again")
	}

	// The agent registers a new BlipNode after its pod restarts; its
	// hypervisor capability comes back with it.
	bn := &v1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	e.create(bn)
	hb := metav1.NewTime(e.now)
	bn.Status = v1.BlipNodeStatus{Incarnation: "inc-n1", Heartbeat: &hb, Hypervisors: []string{"kvm"}}
	e.must(e.c.Status().Update(e.ctx, bn))
	e.run(e.enroll, "", "n1")
	if e.getNode("n1").Labels[LabelHypervisorPrefix+"kvm"] != "true" {
		t.Error("hypervisor label not restored after re-enrollment")
	}
}

func TestEnrollDropsOneOfSeveralHypervisors(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{"zone": "a"}, "kvm", "other")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       v1.BlipPoolSpec{NodeSelector: map[string]string{"zone": "a"}},
	})
	e.run(e.enroll, "", "n1")
	if e.getNode("n1").Labels[LabelHypervisorPrefix+"other"] != "true" {
		t.Fatal("second hypervisor label not added")
	}

	bn := e.getBlipNode("n1")
	bn.Status.Hypervisors = []string{"kvm"}
	e.must(e.c.Status().Update(e.ctx, bn))
	e.run(e.enroll, "", "n1")

	n1 := e.getNode("n1")
	if n1.Labels[LabelHypervisorPrefix+"other"] != "" {
		t.Errorf("removed hypervisor still advertised: %v", n1.Labels)
	}
	if n1.Labels[LabelHypervisorPrefix+"kvm"] != "true" {
		t.Errorf("remaining hypervisor lost: %v", n1.Labels)
	}
}

func TestEnrollHandlesNilLabels(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", nil, "kvm")
	bn := e.getBlipNode("n1")
	bn.Status.SafeToRemove = true
	e.must(e.c.Status().Update(e.ctx, bn))

	e.run(e.enroll, "", "n1")

	if labels := e.getNode("n1").Labels; len(labels) != 0 {
		t.Errorf("labels added to an unselected node: %v", labels)
	}
}

func TestUsableRequiresEnrollmentAndHypervisor(t *testing.T) {
	e := newEnv(t)
	e.addEnrollableNode("n1", map[string]string{LabelEnrolled: "true"}, "kvm")

	cl, err := loadCluster(e.ctx, e.c, e.now)
	e.must(err)
	if !cl.usable("n1", nil) {
		t.Fatal("healthy enrolled node with a hypervisor is not usable")
	}

	bn := e.getBlipNode("n1")
	bn.Status.Hypervisors = nil
	e.must(e.c.Status().Update(e.ctx, bn))
	cl, err = loadCluster(e.ctx, e.c, e.now)
	e.must(err)
	if cl.usable("n1", nil) {
		t.Error("node without a hypervisor is usable")
	}

	bn.Status.Hypervisors = []string{"kvm"}
	e.must(e.c.Status().Update(e.ctx, bn))
	n := e.getNode("n1")
	delete(n.Labels, LabelEnrolled)
	e.must(e.c.Update(e.ctx, n))
	cl, err = loadCluster(e.ctx, e.c, e.now)
	e.must(err)
	if cl.usable("n1", nil) {
		t.Error("node without the enrolled label is usable")
	}
}
