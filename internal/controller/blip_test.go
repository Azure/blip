package controller

import (
	"context"
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

var hexID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// warmOn plays the node agents: booting vacant pods land on nodes in order
// and become ready.
func (e *env) warmOn(nodes ...string) {
	e.t.Helper()
	i := 0
	for _, p := range e.pods() {
		if i == len(nodes) {
			return
		}
		if !isVacant(&p) || p.Labels[LabelWarm] == "true" || podTerminated(&p) {
			continue
		}
		p.Spec.NodeName = nodes[i]
		p.Labels[LabelWarm] = "true"
		e.must(e.c.Update(e.ctx, &p))
		p.Status.Phase = corev1.PodRunning
		e.must(e.c.Status().Update(e.ctx, &p))
		i++
	}
}

func (e *env) getPod(name string) *corev1.Pod {
	e.t.Helper()
	p := &corev1.Pod{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, p))
	return p
}

func (e *env) podGone(name string) bool {
	p := &corev1.Pod{}
	return e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, p) != nil
}

// startBlip creates a Blip and runs it on a fresh warm pod on node. If node
// does not hold the Blip's data, the Blip is told to stop waiting for a VM
// that does.
func (e *env) startBlip(name, node string, mutate ...func(*v1.Blip)) *v1.Blip {
	e.t.Helper()
	e.newBlip(name, mutate...)
	// In a real cluster the Blip reconciler observes a new Blip and records
	// its locality before the pool boots a VM for it. Do the same here so a
	// stateful Blip gets a pinned pod rather than a generic one.
	e.run(e.blip, ns, name)
	e.run(e.pool, ns, "default")
	e.warmOn(node)
	e.run(e.blip, ns, name)
	if b := e.getBlip(name); b.Status.Pod == "" && b.Status.Locality != nil && !b.Status.Locality.Fallback {
		b.Status.Locality.Fallback = true
		e.must(e.c.Status().Update(e.ctx, b))
		e.run(e.blip, ns, name)
	}
	b := e.getBlip(name)
	expectPhase(e.t, b, v1.BlipRunning, "")
	return b
}

// saveWriter plays the writer node and replicas: seal attachment into a
// new commit and replicate it everywhere the state asks.
func (e *env) saveWriter(state, commitID string) {
	e.t.Helper()
	st := e.getState(state)
	w := st.Status.Writer
	if w == nil {
		e.t.Fatalf("state %s has no writer", state)
	}
	e.seal(state, w.Node, v1.SealResult{AttachmentID: w.AttachmentID, CommitID: commitID, SizeBytes: st.Status.SizeBytes})
	e.hold(state, commitID, w.Node)
	e.run(e.state, ns, state)
	st = e.getState(state)
	if st.Status.Writer != nil || st.Status.Pending == nil && st.Status.Committed.ID != commitID {
		e.t.Fatalf("state %s after seal: %+v", state, st.Status)
	}
	if st.Status.Pending == nil {
		return
	}
	for _, n := range st.Status.Pending.Replicas {
		if n != w.Node {
			e.hold(state, commitID, n)
		}
	}
	e.run(e.state, ns, state)
	if st = e.getState(state); st.Status.Committed.ID != commitID {
		e.t.Fatalf("state %s did not commit %s: %+v", state, commitID, st.Status)
	}
}

func TestDurableSaveFlow(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newPool("default", 2, 0)
	e.label("zone", "a", "n1", "n2")
	e.newState("home", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 0
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})

	// Initial version.
	e.run(e.state, ns, "home")
	st := e.getState("home")
	p := st.Status.Pending
	if p == nil || p.Generation != 1 || !hexID.MatchString(p.CommitID) || len(p.Replicas) != 2 || p.SourceNode != p.Replicas[0] {
		t.Fatalf("initial pending %+v", p)
	}
	if st.Status.ImageDigest != "reg/img@sha256:aaaa" || st.Status.SizeBytes != 10<<30 || st.Status.Phase != v1.StatePending || len(st.Finalizers) != 1 {
		t.Fatalf("initial status %+v", st.Status)
	}
	e.hold("home", p.CommitID, p.Replicas[0])
	e.run(e.state, ns, "home")
	if st = e.getState("home"); st.Status.Committed != nil {
		t.Fatalf("committed before every replica reported: %+v", st.Status)
	}
	e.hold("home", p.CommitID, p.Replicas[1])
	e.run(e.state, ns, "home")
	st = e.getState("home")
	if c := st.Status.Committed; c == nil || c.ID != p.CommitID || c.Generation != 1 || st.Status.Pending != nil || st.Status.Phase != v1.StateReady {
		t.Fatalf("initial commit %+v", st.Status)
	}
	placements := st.Status.Placements
	gen1 := st.Status.Committed.ID

	// Writer and claim: prefer the warm pod on a placement node.
	e.run(e.pool, ns, "default")
	other := "n3"
	if placements[0] == "n3" || placements[1] == "n3" {
		t.Fatalf("placements %v include n3", placements)
	}
	e.warmOn(other, placements[1])
	e.newBlip("dev", withRoot("home"), withCommand("make"))
	e.run(e.blip, ns, "dev")
	b := e.getBlip("dev")
	expectPhase(t, b, v1.BlipRunning, "")
	pod := e.getPod(b.Status.Pod)
	if pod.Spec.NodeName != placements[1] || b.Status.Node != placements[1] {
		t.Errorf("claimed pod on %s, want placement %s", pod.Spec.NodeName, placements[1])
	}
	if pod.Labels[LabelBlipUID] != string(b.UID) || pod.Annotations[AnnotationBlip] != "dev" || pod.OwnerReferences[0].Kind != "Blip" || len(pod.OwnerReferences) != 1 {
		t.Errorf("claimed pod metadata %v %v %v", pod.Labels, pod.Annotations, pod.OwnerReferences)
	}
	st = e.getState("home")
	w := st.Status.Writer
	if w == nil || w.AttachmentID != b.Status.RootAttachmentID || !hexID.MatchString(w.AttachmentID) ||
		w.PodUID != string(pod.UID) || w.PodName != pod.Name || w.Node != pod.Spec.NodeName || w.BaseCommit != gen1 || w.BlipUID != string(b.UID) {
		t.Fatalf("writer %+v", w)
	}
	e.run(e.state, ns, "home")
	if st = e.getState("home"); st.Status.Phase != v1.StateInUse {
		t.Errorf("state phase %s", st.Status.Phase)
	}

	// Mirror the runtime.
	e.observe(pod.Name, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: w.AttachmentID, Sessions: 2})
	e.run(e.blip, ns, "dev")
	if b = e.getBlip("dev"); b.Status.Sessions != 2 {
		t.Errorf("sessions %d", b.Status.Sessions)
	}
	e.observe(pod.Name, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 0, Reason: "Completed"}})
	e.run(e.blip, ns, "dev")
	b = e.getBlip("dev")
	expectPhase(t, b, v1.BlipSaving, "Completed")
	if b.Status.ExitCode == nil || *b.Status.ExitCode != 0 || e.podGone(pod.Name) {
		t.Fatalf("saving status %+v", b.Status)
	}

	// Seal, replicate, commit.
	e.seal("home", w.Node, v1.SealResult{AttachmentID: w.AttachmentID, CommitID: "c2c2c2c2c2c2c2c2", SizeBytes: 10 << 30})
	e.hold("home", "c2c2c2c2c2c2c2c2", w.Node)
	e.run(e.state, ns, "home")
	st = e.getState("home")
	p = st.Status.Pending
	if st.Status.Writer != nil || p == nil || p.Generation != 2 || p.SourceNode != w.Node || p.Replicas[0] != w.Node ||
		p.AttachmentID != w.AttachmentID || p.CommitID != "c2c2c2c2c2c2c2c2" || st.Status.Phase != v1.StateSaving {
		t.Fatalf("after seal %+v", st.Status)
	}
	e.run(e.blip, ns, "dev")
	expectPhase(t, e.getBlip("dev"), v1.BlipSaving, "")
	for _, n := range p.Replicas[1:] {
		e.hold("home", "c2c2c2c2c2c2c2c2", n)
	}
	e.run(e.state, ns, "home")
	st = e.getState("home")
	if c := st.Status.Committed; c.ID != "c2c2c2c2c2c2c2c2" || c.Generation != 2 || c.AttachmentID != w.AttachmentID || st.Status.Phase != v1.StateReady {
		t.Fatalf("second commit %+v", st.Status)
	}
	e.run(e.blip, ns, "dev")
	b = e.getBlip("dev")
	expectPhase(t, b, v1.BlipSucceeded, "")
	if b.Status.FinishTime == nil || !e.podGone(pod.Name) {
		t.Errorf("finished %+v, pod gone %v", b.Status, e.podGone(pod.Name))
	}
	// Finished Blips keep their status.
	e.settle()
	expectPhase(t, e.getBlip("dev"), v1.BlipSucceeded, "")
}

func TestSealErrorFailsBlipAndKeepsCommit(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	gen1 := e.readyState("home", "n1").Status.Committed.ID
	e.newBlip("dev", withRoot("home"))
	e.run(e.blip, ns, "dev")
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "dev")
	b := e.getBlip("dev")
	e.updateBlip("dev", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited})
	e.run(e.blip, ns, "dev")
	expectPhase(t, e.getBlip("dev"), v1.BlipSaving, ReasonStopped)

	e.seal("home", "n1", v1.SealResult{AttachmentID: b.Status.RootAttachmentID, Error: "filesystem needs recovery"})
	e.run(e.state, ns, "home")
	st := e.getState("home")
	if st.Status.Writer != nil || st.Status.Pending != nil || st.Status.Committed.ID != gen1 || st.Status.Phase != v1.StateReady {
		t.Fatalf("after seal error %+v", st.Status)
	}
	// The node stops reporting the seal once the writer slot is gone.
	e.report("home", "n1", func(o *v1.NodeObservation) { o.Sealed = nil })
	e.run(e.blip, ns, "dev")
	b = e.getBlip("dev")
	expectPhase(t, b, v1.BlipFailed, ReasonSaveFailed)
	if !e.podGone(b.Status.Pod) {
		t.Error("pod not deleted")
	}
}

func TestClaimRace(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 1)
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.newBlip("a", withImage("reg/img:v1"))
	e.newBlip("b", withImage("reg/img:v1"))

	// Both controllers saw the same vacant pod; only one claim may win.
	snapshot := e.pods()
	a, b := e.getBlip("a"), e.getBlip("b")
	won, err := e.blip.claim(e.ctx, a, snapshot)
	if err != nil || won == nil {
		t.Fatalf("first claim: %v %v", won, err)
	}
	lost, err := e.blip.claim(e.ctx, b, snapshot)
	if err != nil || lost != nil {
		t.Fatalf("second claim of a stale pod succeeded: %v %v", lost, err)
	}
	if got := e.getPod(won.Name).Labels[LabelBlipUID]; got != string(a.UID) {
		t.Fatalf("pod claimed by %q", got)
	}

	// The full reconcilers agree: a runs, b waits.
	e.run(e.blip, ns, "a")
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("a"), v1.BlipRunning, "")
	expectPhase(t, e.getBlip("b"), v1.BlipPending, ReasonWaitingForVM)
	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 1 {
		t.Errorf("maxCount 1 exceeded: %d pods", n)
	}
}

func TestBlipRejectsStaleWarmPodsBeforePoolCleanup(t *testing.T) {
	for _, kind := range []string{"legacy topology", "missing hash", "old pool shape"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 1, 0)
			pool := e.getPool("default")
			old := e.pool.podFor(pool, "a-old")
			switch kind {
			case "legacy topology":
				old.Annotations[annotationTemplateHash] = "35baaef82aa3b469"
			case "missing hash":
				delete(old.Annotations, annotationTemplateHash)
			case "old pool shape":
				previous := pool.DeepCopy()
				previous.Spec.ServiceAccountName = "previous"
				old = e.pool.podFor(previous, old.Name)
			}
			e.create(old)
			e.warmOn("n1")
			e.newBlip("b", withImage("reg/img:v1"))

			// Run only the Blip reconciler: the pool has not yet retired the
			// old pod. Both selection and reconciliation must reject it.
			if pods := e.warmPods("b", nil); len(pods) != 0 {
				t.Fatalf("stale warm pod selected: %+v", pods)
			}
			e.run(e.blip, ns, "b")
			b := e.getBlip("b")
			expectPhase(t, b, v1.BlipPending, ReasonWaitingForVM)
			if b.Status.Pod != "" || !isVacant(e.getPod(old.Name)) {
				t.Fatal("Blip claimed a stale VM before pool cleanup")
			}

			// A current VM remains eligible even while the stale one exists.
			current := e.pool.podFor(pool, "z-current")
			e.create(current)
			e.warmOn("n1")
			if pods := e.warmPods("b", nil); len(pods) != 1 || pods[0].Name != current.Name {
				t.Fatalf("current warm pod not selected: %+v", pods)
			}
			e.run(e.blip, ns, "b")
			b = e.getBlip("b")
			expectPhase(t, b, v1.BlipRunning, "")
			if b.Status.Pod != current.Name || !isVacant(e.getPod(old.Name)) {
				t.Fatalf("claimed %q, want %q with stale pod still vacant", b.Status.Pod, current.Name)
			}
		})
	}
}

func TestClaimRechecksLivePool(t *testing.T) {
	for _, tt := range []struct {
		name      string
		change    func(*env, *v1.BlipPool)
		wantClaim bool
	}{
		{"unchanged", func(*env, *v1.BlipPool) {}, true},
		{"shape changed", func(e *env, p *v1.BlipPool) {
			p.Spec.CPUs++
			e.must(e.c.Update(e.ctx, p))
		}, false},
		{"service account changed", func(e *env, p *v1.BlipPool) {
			p.Spec.ServiceAccountName = "replacement"
			e.must(e.c.Update(e.ctx, p))
		}, false},
		{"deleted", func(e *env, p *v1.BlipPool) { e.must(e.c.Delete(e.ctx, p)) }, false},
		{"deleting", func(e *env, p *v1.BlipPool) {
			p.Finalizers = []string{"test"}
			e.must(e.c.Update(e.ctx, p))
			e.must(e.c.Delete(e.ctx, p))
		}, false},
		{"mutable network changed", func(e *env, p *v1.BlipPool) {
			p.Spec.Network = &v1.NetworkPolicy{Egress: []v1.NetworkEgressRule{{}}}
			e.must(e.c.Update(e.ctx, p))
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 1, 0)
			e.run(e.pool, ns, "default")
			e.warmOn("n1")
			e.newBlip("b", withImage("reg/img:v1"))
			candidates := e.warmPods("b", nil)
			if len(candidates) != 1 {
				t.Fatalf("initial candidates = %d, want 1", len(candidates))
			}
			cachedPool := e.getPool("default")
			// The cached reader keeps returning the original pool. The claim
			// must use Live to notice an edit made after candidate selection.
			e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if p, ok := obj.(*v1.BlipPool); ok && key == client.ObjectKeyFromObject(cachedPool) {
						cachedPool.DeepCopyInto(p)
						return nil
					}
					return c.Get(ctx, key, obj, opts...)
				},
			})
			tt.change(e, cachedPool.DeepCopy())
			pod, err := e.blip.claim(e.ctx, e.getBlip("b"), candidates)
			e.must(err)
			if (pod != nil) != tt.wantClaim {
				t.Fatalf("claim = %v, want claimed = %t", pod, tt.wantClaim)
			}
			if p := e.getPod(candidates[0].Name); isVacant(p) == tt.wantClaim {
				t.Fatalf("pod claim was not persisted correctly: %+v", p.Labels)
			}
			if !tt.wantClaim {
				if _, ok := e.owners()[candidates[0].Name]; ok {
					t.Error("ineligible pod received an owner entry")
				}
			}
		})
	}
}

func TestClaimRejectsConcurrentTemplateChange(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.newBlip("b", withImage("reg/img:v1"))
	candidates := e.warmPods("b", nil)
	if len(candidates) != 1 {
		t.Fatalf("initial candidates = %d, want 1", len(candidates))
	}
	e.annotatePod(candidates[0].Name, annotationTemplateHash, "stale")
	// The old candidate still matches the live pool, but the optimistic
	// claim must fail because the pod changed after candidate selection.
	pod, err := e.blip.claim(e.ctx, e.getBlip("b"), candidates)
	e.must(err)
	if pod != nil || !isVacant(e.getPod(candidates[0].Name)) {
		t.Fatal("claim ignored a concurrent pod template change")
	}
	if _, ok := e.owners()[candidates[0].Name]; ok {
		t.Error("failed claim left an owner entry")
	}
}

func TestWriterAcquisition(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 2, 0)
	for _, s := range []string{"a", "b", "c", "d"} {
		e.readyState(s, "n1")
	}
	e.newBlip("x", withRoot("a"), withMount("b", "/b", true))
	e.newBlip("y", withRoot("b"), withMount("a", "/a", true))
	x := e.getBlip("x")

	// x is mid-acquisition: it holds a (sorted first) but not b yet.
	st := e.getState("a")
	base := st.DeepCopy()
	st.Status.Writer = &v1.Writer{AttachmentID: "1111111111111111", BlipName: "x", BlipUID: string(x.UID), BaseCommit: st.Status.Committed.ID}
	e.must(patchStatus(e.ctx, e.c, st, base))

	e.run(e.pool, ns, "default")
	e.warmOn("n1", "n1")

	// y wants b and a; sorted order makes it try a first, so it takes
	// nothing and cannot block x.
	e.run(e.blip, ns, "y")
	expectPhase(t, e.getBlip("y"), v1.BlipPending, ReasonStateBusy)
	if w := e.getState("b").Status.Writer; w != nil {
		t.Fatalf("y took b while blocked: %+v", w)
	}
	e.run(e.blip, ns, "x")
	x = e.getBlip("x")
	expectPhase(t, x, v1.BlipRunning, "")
	if x.Status.RootAttachmentID != "1111111111111111" {
		t.Errorf("x did not adopt its slot: %s", x.Status.RootAttachmentID)
	}
	if w := e.getState("b").Status.Writer; w == nil || w.BlipName != "x" || w.PodUID == "" || mountOf(x, "b").AttachmentID != w.AttachmentID {
		t.Errorf("b writer %+v", w)
	}

	// A blocked acquisition releases what it took in the same attempt.
	st = e.getState("d")
	base = st.DeepCopy()
	st.Status.Writer = &v1.Writer{AttachmentID: "2222222222222222", BlipName: "other", BlipUID: "other"}
	e.must(patchStatus(e.ctx, e.c, st, base))
	e.newBlip("z", withRoot("c"), withMount("d", "/d", true))
	e.run(e.blip, ns, "z")
	z := e.getBlip("z")
	expectPhase(t, z, v1.BlipPending, ReasonStateBusy)
	if w := e.getState("c").Status.Writer; w != nil {
		t.Errorf("c still held after blocked acquisition: %+v", w)
	}
}

func TestReadOnlyMountPin(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	gen1 := e.readyState("data", "n1").Status.Committed.ID

	x := e.startBlip("reader", "n1", withImage("reg/img:v1"), withMount("data", "/data", false))
	m := mountOf(x, "data")
	if m == nil || m.Writable || m.CommitID != gen1 || m.Phase != v1.MountPending || !hexID.MatchString(m.AttachmentID) || m.StateUID == "" {
		t.Fatalf("ro mount %+v", m)
	}
	if !hexID.MatchString(x.Status.RootAttachmentID) || x.Status.ImageDigest != "reg/img@sha256:aaaa" {
		t.Errorf("image root %+v", x.Status)
	}
	if w := e.getState("data").Status.Writer; w != nil {
		t.Fatalf("read-only mount took the writer: %+v", w)
	}
	e.observe(x.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, Mounts: []podapi.DiskStatus{{ID: m.AttachmentID, State: "data", Phase: podapi.DiskMounted}}})
	e.run(e.blip, ns, "reader")
	if m = mountOf(e.getBlip("reader"), "data"); m.Phase != v1.MountMounted {
		t.Fatalf("mount phase %s", m.Phase)
	}

	// A writer saves a new version; the reader keeps its pinned version.
	w := e.startBlip("writer", "n1", withImage("reg/img:v1"), withMount("data", "/data", true))
	e.observe(w.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "writer")
	e.saveWriter("data", "d2d2d2d2d2d2d2d2")
	e.run(e.blip, ns, "writer")
	expectPhase(t, e.getBlip("writer"), v1.BlipSucceeded, "")
	e.run(e.blip, ns, "reader")
	if m = mountOf(e.getBlip("reader"), "data"); m.CommitID != gen1 || m.Phase != v1.MountMounted {
		t.Errorf("reader pin moved: %+v", m)
	}
}

func TestBlipValidationAndWaiting(t *testing.T) {
	tests := []struct {
		name   string
		blip   []func(*v1.Blip)
		phase  string
		reason string
	}{
		{"relative mount path", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "data", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"mount at /", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"dotdot", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/a/../etc", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"dot segment", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/a/./b", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"trailing slash", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/data/", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"duplicate path", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/data", false), withMount("other", "/data", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"overlap", []func(*v1.Blip){withImage("reg/img:v1"), withMount("data", "/a", false), withMount("other", "/a/b", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"root also mounted", []func(*v1.Blip){withRoot("data"), withMount("data", "/data", false)}, v1.BlipFailed, ReasonInvalidSpec},
		{"image and state", []func(*v1.Blip){withRoot("data"), withImage("reg/img:v1")}, v1.BlipFailed, ReasonInvalidSpec},
		{"empty image", []func(*v1.Blip){withImage("")}, v1.BlipFailed, ReasonInvalidSpec},
		{"empty state", []func(*v1.Blip){withRoot("")}, v1.BlipFailed, ReasonInvalidSpec},
		{"empty image and state", []func(*v1.Blip){withImage(""), withRoot("")}, v1.BlipFailed, ReasonInvalidSpec},
		{"missing image", []func(*v1.Blip){withImage("reg/missing:v1")}, v1.BlipFailed, ReasonImageNotFound},
		{"invalid image", []func(*v1.Blip){withImage("bad image!!")}, v1.BlipFailed, ReasonInvalidSpec},
		{"missing state", []func(*v1.Blip){withRoot("nope")}, v1.BlipPending, ReasonStateNotFound},
		{"uncommitted state", []func(*v1.Blip){withRoot("fresh")}, v1.BlipPending, ReasonStateNotReady},
		{"missing pool", []func(*v1.Blip){withImage("reg/img:v1"), func(b *v1.Blip) { b.Spec.Pool = "gpu" }}, v1.BlipPending, ReasonPoolNotFound},
		{"no warm VM", []func(*v1.Blip){withImage("reg/img:v1")}, v1.BlipPending, ReasonWaitingForVM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			e.readyState("data", "n1")
			e.newState("fresh")
			e.newBlip("b", tt.blip...)
			e.run(e.blip, ns, "b")
			b := e.getBlip("b")
			expectPhase(t, b, tt.phase, tt.reason)
			if b.Status.Message == "" {
				t.Error("no message")
			}
			if w := e.getState("data").Status.Writer; w != nil {
				t.Errorf("writer left behind: %+v", w)
			}
		})
	}
}

func TestStopAndDeleteBeforeStart(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("b", withRoot("home"))
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipPending, ReasonWaitingForVM)
	e.must(e.c.Delete(e.ctx, e.getBlip("b")))
	e.run(e.blip, ns, "b")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, &v1.Blip{}); err == nil {
		t.Fatal("deleted pending blip still exists")
	}
	if w := e.getState("home").Status.Writer; w != nil {
		t.Errorf("writer left behind %+v", w)
	}
}

func TestDeleteRunningBlipWaitsForSave(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	b := e.startBlip("b", "n1", withRoot("home"))
	e.must(e.c.Delete(e.ctx, b))
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipRunning, "")
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, ReasonStopped)
	e.saveWriter("home", "e2e2e2e2e2e2e2e2")
	e.run(e.blip, ns, "b")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, &v1.Blip{}); err == nil {
		t.Fatal("blip not removed after save")
	}
	if !e.podGone(b.Status.Pod) {
		t.Error("pod not deleted")
	}
}

func TestStoppedCommandSucceedsWithoutExitCode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("job", withImage("reg/img:v1"), withCommand("sleep", "600"))
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.Stop = true })
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.settle()
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if b.Status.ExitCode != nil {
		t.Errorf("exit code %d for a stopped command", *b.Status.ExitCode)
	}
}

func TestFailedCommandReportsError(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newBlip("job", withImage("reg/img:v1"), withCommand("false"))
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 1, Reason: "Completed", Output: "boom"}})
	e.settle()
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonError)
	if b.Status.ExitCode == nil || *b.Status.ExitCode != 1 || b.Status.Message != "boom" {
		t.Errorf("status %+v", b.Status)
	}
}
