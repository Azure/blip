package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

const ns = "ns"

func metadata(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

type fakeRegistry struct {
	digests map[string]string
	configs map[string]*v1.ImageConfig
}

func (f *fakeRegistry) Digest(_ context.Context, ref string) (string, error) {
	if d, ok := f.digests[ref]; ok {
		return d, nil
	}
	return "", fmt.Errorf("image %s: %w", ref, ErrImageNotFound)
}

func (f *fakeRegistry) ImageConfig(_ context.Context, ref string) (*v1.ImageConfig, error) {
	return f.configs[ref], nil
}

// env runs the reconcilers against a fake API server. Tests play the node
// agents by writing pod labels, pod annotations, and BlipState.status.nodes.
type env struct {
	t      *testing.T
	ctx    context.Context
	c      client.Client
	now    time.Time
	reg    *fakeRegistry
	node   *NodeReconciler
	pool   *PoolReconciler
	state  *StateReconciler
	blip   *BlipReconciler
	enroll *EnrollReconciler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	uids := 0
	b := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1.Blip{}, &v1.BlipState{}, &v1.BlipPool{}, &v1.BlipNode{}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
			if o.GetUID() == "" {
				uids++
				o.SetUID(types.UID(fmt.Sprintf("uid-%d", uids)))
			}
			return c.Create(ctx, o, opts...)
		}})
	for _, ix := range Indexes {
		b = b.WithIndex(ix.Obj, ix.Field, ix.Extract)
	}
	e := &env{
		t:   t,
		ctx: context.Background(),
		c:   b.Build(),
		now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
		reg: &fakeRegistry{
			digests: map[string]string{"reg/img:v1": "reg/img@sha256:aaaa"},
			configs: map[string]*v1.ImageConfig{
				"reg/img:v1":          {Env: []string{"PATH=/usr/bin"}, Cmd: []string{"sh"}, WorkingDir: "/w", User: "1000"},
				"reg/img@sha256:aaaa": {Env: []string{"PATH=/usr/bin"}, Cmd: []string{"sh"}, WorkingDir: "/w", User: "1000"},
			},
		},
	}
	cfg := Config{
		RuntimeImage: "reg/blip-runtime:dev",
		Registry:     e.reg,
		Now:          func() time.Time { return e.now },
	}
	e.node = &NodeReconciler{Client: e.c}
	e.pool = &PoolReconciler{Client: e.c, Config: cfg}
	e.state = &StateReconciler{Client: e.c, Live: e.c, Config: cfg}
	e.blip = &BlipReconciler{Client: e.c, Live: e.c, Config: cfg}
	e.enroll = &EnrollReconciler{Client: e.c}
	return e
}

func (e *env) create(objs ...client.Object) {
	e.t.Helper()
	for _, o := range objs {
		if o.GetNamespace() == "" {
			if _, ok := o.(*v1.BlipNode); !ok {
				if _, ok := o.(*corev1.Node); !ok {
					o.SetNamespace(ns)
				}
			}
		}
		if err := e.c.Create(e.ctx, o); err != nil {
			e.t.Fatal(err)
		}
	}
}

// addNodes creates healthy BlipNodes and their Kubernetes Nodes.
func (e *env) addNodes(names ...string) {
	e.t.Helper()
	for _, n := range names {
		e.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n, Labels: map[string]string{
			LabelEnrolled:                 "true",
			"blip.dev/node-pool":          "default",
			LabelHypervisorPrefix + "kvm": "true",
		}}})
		bn := &v1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: n}}
		e.create(bn)
		hb := metav1.NewTime(e.now)
		bn.Status = v1.BlipNodeStatus{
			Incarnation: "inc-" + n, Heartbeat: &hb, FreeBytes: 100 << 30,
			Hypervisors: []string{"kvm"},
		}
		if err := e.c.Status().Update(e.ctx, bn); err != nil {
			e.t.Fatal(err)
		}
	}
}

// heartbeat refreshes the heartbeat of every BlipNode except skip.
func (e *env) heartbeat(skip ...string) {
	e.t.Helper()
	var bns v1.BlipNodeList
	e.must(e.c.List(e.ctx, &bns))
	for _, bn := range bns.Items {
		if contains(skip, bn.Name) {
			continue
		}
		hb := metav1.NewTime(e.now)
		bn.Status.Heartbeat = &hb
		e.must(e.c.Status().Update(e.ctx, &bn))
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) newPool(name string, warm, max int32) {
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1.BlipPoolSpec{
			Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi"),
			WarmCount: warm, MaxCount: max, ServiceAccountName: "vm",
			NodeSelector: map[string]string{"blip.dev/node-pool": "default"},
		},
	})
}

func (e *env) newState(name string, mutate ...func(*v1.BlipState)) {
	st := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1.BlipStateSpec{Replicas: 2}}
	for _, m := range mutate {
		m(st)
	}
	e.create(st)
}

func (e *env) newBlip(name string, mutate ...func(*v1.Blip)) {
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), CreationTimestamp: metav1.NewTime(e.now)},
		Spec:       v1.BlipSpec{Pool: "default"},
	}
	for _, m := range mutate {
		m(b)
	}
	e.create(b)
}

func (e *env) run(r reconcile.Reconciler, namespace, name string) reconcile.Result {
	e.t.Helper()
	res, err := r.Reconcile(e.ctx, req(namespace, name))
	if err != nil {
		e.t.Fatalf("reconcile %s/%s: %v", namespace, name, err)
	}
	if r == reconcile.Reconciler(e.blip) && e.ackClaims() {
		return e.run(r, namespace, name)
	}
	return res
}

// ackClaims plays the node: the guest accepts every new claim at once.
func (e *env) ackClaims() bool {
	acked := false
	for _, p := range e.pods() {
		if p.Labels[LabelBlipUID] != "" && p.Annotations[AnnotationObserved] == "" {
			e.observe(p.Name, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: "claim"})
			acked = true
		}
	}
	return acked
}

// settle reconciles every object a few times, like the watches would.
func (e *env) settle() {
	e.t.Helper()
	for range 4 {
		var bns v1.BlipNodeList
		e.must(e.c.List(e.ctx, &bns))
		for _, o := range bns.Items {
			e.run(e.node, "", o.Name)
		}
		var sts v1.BlipStateList
		e.must(e.c.List(e.ctx, &sts))
		for _, o := range sts.Items {
			e.run(e.state, o.Namespace, o.Name)
		}
		var pools v1.BlipPoolList
		e.must(e.c.List(e.ctx, &pools))
		for _, o := range pools.Items {
			e.run(e.pool, o.Namespace, o.Name)
		}
		var blips v1.BlipList
		e.must(e.c.List(e.ctx, &blips))
		for _, o := range blips.Items {
			e.run(e.blip, o.Namespace, o.Name)
		}
	}
}

func (e *env) pods() []corev1.Pod {
	e.t.Helper()
	var pods corev1.PodList
	e.must(e.c.List(e.ctx, &pods, client.InNamespace(ns)))
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	return pods.Items
}

// warmPods returns the claim candidates of Blip name, best first.
func (e *env) warmPods(name string, states map[string]*v1.BlipState) []corev1.Pod {
	e.t.Helper()
	b := e.getBlip(name)
	pods, err := e.blip.poolPods(e.ctx, b)
	e.must(err)
	cl, err := loadCluster(e.ctx, e.c, e.now)
	e.must(err)
	return e.blip.warmPods(b, e.getPool(poolName(b)), states, pods, cl)
}

func (e *env) observe(pod string, obs podapi.Observed) {
	e.t.Helper()
	p := &corev1.Pod{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: pod}, p))
	raw, _ := json.Marshal(obs)
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[AnnotationObserved] = string(raw)
	e.must(e.c.Update(e.ctx, p))
}

// report plays node's SSA write of its own status.nodes entry.
func (e *env) report(state, node string, mutate func(*v1.NodeObservation)) {
	e.t.Helper()
	st := e.getState(state)
	i := -1
	for j, o := range st.Status.Nodes {
		if o.Node == node {
			i = j
		}
	}
	if i < 0 {
		st.Status.Nodes = append(st.Status.Nodes, v1.NodeObservation{Node: node, Incarnation: "inc-" + node})
		i = len(st.Status.Nodes) - 1
	}
	mutate(&st.Status.Nodes[i])
	e.must(e.c.Status().Update(e.ctx, st))
}

func (e *env) hold(state, commitID string, nodes ...string) {
	e.t.Helper()
	for _, n := range nodes {
		e.report(state, n, func(o *v1.NodeObservation) { o.Commits = append(o.Commits, commitID) })
	}
}

func (e *env) seal(state, node string, sr v1.SealResult) {
	e.t.Helper()
	e.report(state, node, func(o *v1.NodeObservation) { o.Sealed = append(o.Sealed, sr) })
}

func (e *env) getState(name string) *v1.BlipState {
	e.t.Helper()
	st := &v1.BlipState{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, st))
	return st
}

func (e *env) getBlip(name string) *v1.Blip {
	e.t.Helper()
	b := &v1.Blip{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, b))
	return b
}

func (e *env) updateBlip(name string, mutate func(*v1.Blip)) {
	e.t.Helper()
	b := e.getBlip(name)
	mutate(b)
	e.must(e.c.Update(e.ctx, b))
}

// readyState creates a committed state held by nodes.
func (e *env) readyState(name string, nodes ...string) *v1.BlipState {
	e.t.Helper()
	e.newState(name, func(st *v1.BlipState) { st.Spec.Replicas = int32(len(nodes)) })
	e.run(e.state, ns, name)
	st := e.getState(name)
	if st.Status.Pending == nil {
		e.t.Fatalf("state %s has no pending version: %+v", name, st.Status)
	}
	e.hold(name, st.Status.Pending.CommitID, st.Status.Pending.Replicas...)
	e.run(e.state, ns, name)
	st = e.getState(name)
	if st.Status.Phase != v1.StateReady {
		e.t.Fatalf("state %s: %+v", name, st.Status)
	}
	return st
}

func withRoot(state string) func(*v1.Blip) {
	return func(b *v1.Blip) { b.Spec.State = state }
}

func withImage(img string) func(*v1.Blip) {
	return func(b *v1.Blip) { b.Spec.Image = img }
}

func withMount(state, path string, writable bool) func(*v1.Blip) {
	return func(b *v1.Blip) {
		b.Spec.Mounts = append(b.Spec.Mounts, v1.Mount{State: state, Path: path, Writable: writable})
	}
}

func withCommand(cmd ...string) func(*v1.Blip) {
	return func(b *v1.Blip) { b.Spec.Command = cmd }
}

func expectPhase(t *testing.T, b *v1.Blip, phase, reason string) {
	t.Helper()
	if b.Status.Phase != phase || reason != "" && b.Status.Reason != reason {
		t.Fatalf("blip %s: phase %q reason %q (%s), want %q %q", b.Name, b.Status.Phase, b.Status.Reason, b.Status.Message, phase, reason)
	}
}

func mountOf(b *v1.Blip, state string) *v1.MountStatus {
	for i := range b.Status.Mounts {
		if b.Status.Mounts[i].State == state {
			return &b.Status.Mounts[i]
		}
	}
	return nil
}
