// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

var errSimulationLostReply = errors.New("simulation: applied operation, reply lost")

// controllerAPI models only API operations. The authoritative fake client
// enforces optimistic resource versions and status subresources; the separate
// read snapshot advances only on deliver. No claim, save, or reconciliation
// logic is duplicated here. before schedules a competing reconciler at an
// exact API boundary, on the same goroutine. loseAt drops a successful response;
// step restarts the reconciler after its normal error handling returns. This
// does not simulate abrupt process death, which would skip rollback code.
// The trace records API calls and patch bodies, not complete read responses or
// all world state; replay comparisons cover this projection and the invariants.
type controllerAPI struct {
	client.Client
	cache   client.Reader
	t       *testing.T
	loseAt  int
	writes  int
	losses  int
	trace   []string
	before  func(string, client.Object)
	check   func()
	reverse bool
}

func (c *controllerAPI) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	err := c.cache.Get(ctx, key, obj, opts...)
	c.trace = append(c.trace, fmt.Sprintf("get %T %s rv=%s err=%v", obj, key, obj.GetResourceVersion(), err))
	return err
}

func (c *controllerAPI) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	err := c.cache.List(ctx, list, opts...)
	if err == nil && c.reverse {
		items, extractErr := meta.ExtractList(list)
		c.t.Helper()
		if extractErr != nil {
			c.t.Fatal(extractErr)
		}
		slices.Reverse(items)
		if setErr := meta.SetList(list, items); setErr != nil {
			c.t.Fatal(setErr)
		}
	}
	c.trace = append(c.trace, fmt.Sprintf("list %T err=%v", list, err))
	return err
}

func (c *controllerAPI) effect(verb string, obj client.Object, detail string, apply func(client.Object) error) error {
	if c.before != nil {
		c.before(verb, obj)
	}
	// The fake writes the server response back into the supplied object. Keep
	// it separate until delivery: a lost reply cannot reveal a new UID/RV or
	// fields merged by the server to the controller's error-handling path.
	response := obj.DeepCopyObject().(client.Object)
	err := apply(response)
	c.trace = append(c.trace, fmt.Sprintf("%s %T %s %s err=%v", verb, obj, client.ObjectKeyFromObject(obj), detail, err))
	if c.check != nil {
		c.check()
	}
	if err == nil {
		c.writes++
		if c.loseAt == c.writes {
			c.losses++
			c.trace = append(c.trace, "reply lost")
			return errSimulationLostReply
		}
		reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(response).Elem())
	}
	return err
}

func (c *controllerAPI) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return c.effect("create", obj, "", func(response client.Object) error { return c.Client.Create(ctx, response, opts...) })
}

func (c *controllerAPI) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	raw, err := patch.Data(obj)
	if err != nil {
		return err
	}
	return c.effect("patch", obj, string(raw), func(response client.Object) error { return c.Client.Patch(ctx, response, patch, opts...) })
}

func (c *controllerAPI) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	return c.effect("delete", obj, "", func(response client.Object) error {
		// The pinned fake client enforces resourceVersion but not UID delete
		// preconditions. Check UID after the scheduled competing operation.
		o := (&client.DeleteOptions{}).ApplyOptions(opts)
		if o.Preconditions != nil && o.Preconditions.UID != nil {
			fresh := obj.DeepCopyObject().(client.Object)
			if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), fresh); err != nil {
				return err
			}
			if fresh.GetUID() != *o.Preconditions.UID {
				gvk, err := c.GroupVersionKindFor(obj)
				if err != nil {
					return err
				}
				resource, _ := meta.UnsafeGuessKindToResource(gvk)
				return apierrors.NewConflict(resource.GroupResource(), obj.GetName(), errors.New("UID changed"))
			}
		}
		return c.Client.Delete(ctx, response, opts...)
	})
}

func (c *controllerAPI) Status() client.SubResourceWriter {
	return &controllerStatus{SubResourceWriter: c.Client.Status(), api: c}
}

type controllerStatus struct {
	client.SubResourceWriter
	api *controllerAPI
}

func (s *controllerStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	raw, err := patch.Data(obj)
	if err != nil {
		return err
	}
	return s.api.effect("status", obj, string(raw), func(response client.Object) error { return s.SubResourceWriter.Patch(ctx, response, patch, opts...) })
}

type controllerLive struct{ api *controllerAPI }

func (l controllerLive) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	err := l.api.Client.Get(ctx, key, obj, opts...)
	l.api.trace = append(l.api.trace, fmt.Sprintf("live-get %T %s rv=%s err=%v", obj, key, obj.GetResourceVersion(), err))
	return err
}

func (l controllerLive) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	err := l.api.Client.List(ctx, list, opts...)
	l.api.trace = append(l.api.trace, fmt.Sprintf("live-list %T err=%v", list, err))
	return err
}

type controllerSimulation struct {
	*env
	api *controllerAPI
	cfg Config
}

func newControllerSimulation(t *testing.T) *controllerSimulation {
	e := newEnv(t)
	s := &controllerSimulation{env: e, api: &controllerAPI{Client: e.c, cache: e.c, t: t}}
	var ids, pods uint64
	s.cfg = Config{RuntimeImage: runtimeImage, Registry: e.reg, Now: func() time.Time { return e.now },
		NewID:      func() string { ids++; return fmt.Sprintf("%016x", ids) },
		NewPodName: func(pool string) string { pods++; return fmt.Sprintf("%s-%05d", pool, pods) },
	}
	s.restart()
	return s
}

// restart discards reconciler-local expectations but preserves the API server,
// delayed cache, virtual clock, and deterministic external ID source.
func (s *controllerSimulation) restart() {
	s.pool = &PoolReconciler{Client: s.api, Config: s.cfg}
	s.blip = &BlipReconciler{Client: s.api, Live: controllerLive{s.api}, Config: s.cfg}
	s.state = &StateReconciler{Client: s.api, Live: controllerLive{s.api}, Config: s.cfg}
}

func (s *controllerSimulation) deliver() {
	s.t.Helper()
	var objects []client.Object
	for _, list := range []client.ObjectList{&v1.BlipList{}, &v1.BlipStateList{}, &v1.BlipPoolList{}, &v1.BlipNodeList{}, &corev1.PodList{}, &corev1.NodeList{}, &corev1.ConfigMapList{}, &corev1.ServiceAccountList{}} {
		s.must(s.c.List(s.ctx, list))
		s.must(meta.EachListItem(list, func(obj runtime.Object) error {
			objects = append(objects, obj.(client.Object).DeepCopyObject().(client.Object))
			return nil
		}))
	}
	b := fake.NewClientBuilder().WithScheme(s.c.Scheme()).WithObjects(objects...).
		WithStatusSubresource(&v1.Blip{}, &v1.BlipState{}, &v1.BlipPool{}, &v1.BlipNode{})
	for _, ix := range Indexes {
		b = b.WithIndex(ix.Obj, ix.Field, ix.Extract)
	}
	s.api.cache = b.Build()
	s.api.trace = append(s.api.trace, "deliver cache")
}

func (s *controllerSimulation) step(kind, name string) {
	s.t.Helper()
	var r reconcile.Reconciler
	switch kind {
	case "blip":
		r = s.blip
	case "state":
		r = s.state
	case "pool":
		r = s.pool
	default:
		s.t.Fatal("unknown reconciler", kind)
	}
	res, err := r.Reconcile(s.ctx, req(ns, name))
	s.api.trace = append(s.api.trace, fmt.Sprintf("reconcile %s/%s after=%s err=%v", kind, name, res.RequeueAfter, err))
	switch {
	case errors.Is(err, errSimulationLostReply):
		s.api.trace = append(s.api.trace, "restart reconciler state")
		s.restart()
	case err != nil && !apierrors.IsConflict(err):
		s.t.Fatalf("%s/%s: %v\n%s", kind, name, err, strings.Join(s.api.trace, "\n"))
	}
	if s.api.check != nil {
		s.api.check()
	}
}

func (s *controllerSimulation) until(label string, done func() bool, steps ...string) {
	s.t.Helper()
	for tick := range 36 {
		for i := 0; i < len(steps); i += 2 {
			s.step(steps[i], steps[i+1])
		}
		if done() {
			return
		}
		// Repeated reconciles see the same stale objects, including after
		// a restart. Only every third turn delivers watch/cache updates.
		if tick%3 == 2 {
			s.deliver()
		}
	}
	s.t.Fatalf("did not converge: %s\n%s", label, strings.Join(s.api.trace, "\n"))
}

func (s *controllerSimulation) warm(name, node string) {
	s.t.Helper()
	p := s.pool.podFor(s.getPool("default"), name)
	p.Spec.NodeName = node
	p.Labels[v1.LabelWarm] = "true"
	p.Status.Phase = corev1.PodRunning
	s.create(p)
}

// allocationSave runs production acquisition, publication, pod claim, start,
// fencing, seal acceptance, selected-replica commit, and cleanup. Node/runtime
// effects are separate status/annotation operations supplied by the scenario.
func allocationSave(t *testing.T, loseAt int) *controllerSimulation {
	t.Helper()
	s := newControllerSimulation(t)
	s.addNodes("n1", "n2", "n3")
	s.newPool("default", 2, 2)
	s.readyState("root", "n1", "n2")
	s.readyState("data", "n1", "n2")
	s.readyState("readonly", "n1", "n2")
	root := s.getState("root")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}, {State: "readonly", Path: "/ro"}}
	s.must(s.c.Update(s.ctx, root))
	s.newBlip("job", withRoot("root"), withCommand("true"))
	s.warm("warm-a", "n1")
	s.warm("warm-b", "n1")
	s.api.writes, s.api.trace, s.api.loseAt = 0, nil, loseAt
	s.deliver()
	s.api.check = func() {
		b := s.getBlip("job")
		claimed := 0
		for _, p := range s.pods() {
			if p.Labels[v1.LabelBlipUID] == string(b.UID) {
				claimed++
				if p.Annotations[v1.AnnotationBlip] != b.Name || len(p.OwnerReferences) != 1 || p.OwnerReferences[0].UID != b.UID {
					t.Fatalf("claim ownership mismatch: %+v", p.ObjectMeta)
				}
			}
		}
		if claimed > 1 {
			t.Fatalf("one Blip claimed %d pods", claimed)
		}
		if w := s.getState("readonly").Status.Writer; w != nil {
			t.Fatalf("read-only mount acquired writer: %+v", w)
		}
		for _, name := range []string{"root", "data"} {
			st := s.getState(name)
			if w := st.Status.Writer; w != nil && w.BlipUID != string(b.UID) {
				t.Fatalf("foreign writer: %+v", w)
			}
			id := b.Status.RootAttachmentID
			if name == "data" {
				id = ""
				if m := mountOf(b, name); m != nil {
					id = m.AttachmentID
				}
			}
			if id != "" {
				reserved := st.Status.Writer != nil && st.Status.Writer.AttachmentID == id
				pending := st.Status.Pending != nil && st.Status.Pending.AttachmentID == id
				sealed := slices.ContainsFunc(st.Status.Seals, func(sr v1.SealResult) bool { return sr.AttachmentID == id })
				if !reserved && !pending && !sealed {
					t.Fatalf("published attachment %s lost its reservation and save outcome: %+v", id, st.Status)
				}
			}
			if st.Status.Committed.Generation == 2 {
				cl, err := loadCluster(s.ctx, s.c, s.now)
				s.must(err)
				for _, node := range st.Status.Placements {
					if !cl.holds(st, node, st.Status.Committed.ID) {
						t.Fatalf("committed without selected replica %s: %+v", node, st.Status)
					}
				}
			}
			if b.Status.Phase == v1.BlipSucceeded && (st.Status.Committed.Generation != 2 || st.Status.Pending != nil || st.Status.Writer != nil) {
				t.Fatalf("success before durable save: %+v", st.Status)
			}
		}
	}
	s.until("allocation", func() bool {
		b := s.getBlip("job")
		return b.Status.Pod != "" && s.getState("root").Status.Writer.PodUID == b.Status.PodUID && s.getState("data").Status.Writer.PodUID == b.Status.PodUID
	}, "blip", "job")
	b := s.getBlip("job")
	if b.Status.Pod != "warm-a" || b.Status.Node != "n1" {
		t.Fatalf("non-deterministic selected pod: %+v", b.Status)
	}
	s.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: "claim"})
	s.until("running", func() bool { return s.getBlip("job").Status.Phase == v1.BlipRunning }, "blip", "job")
	s.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 0}})
	s.until("saving", func() bool { return s.getBlip("job").Status.Phase == v1.BlipSaving }, "blip", "job")
	for i, name := range []string{"root", "data"} {
		w := s.getState(name).Status.Writer
		id := fmt.Sprintf("%016x", 100+i)
		s.seal(name, "n1", v1.SealResult{AttachmentID: w.AttachmentID, CommitID: id})
		s.hold(name, id, "n1", "n3") // n3 is deliberately not a selected replica.
	}
	s.until("pending saves", func() bool {
		return s.getState("root").Status.Pending != nil && s.getState("data").Status.Pending != nil
	}, "state", "root", "state", "data", "blip", "job")
	for _, name := range []string{"root", "data"} {
		st := s.getState(name)
		if !slices.Equal(st.Status.Pending.Replicas, []string{"n1", "n2"}) {
			t.Fatalf("selected replicas: %+v", st.Status.Pending)
		}
		s.report(name, "n2", func(o *v1.NodeObservation) {
			o.Commits = append(o.Commits, st.Status.Pending.CommitID)
			o.Incarnation = "old-n2"
		})
	}
	s.deliver()
	for range 3 {
		s.step("state", "root")
		s.step("state", "data")
		s.step("blip", "job")
	}
	for _, name := range []string{"root", "data"} {
		if st := s.getState(name); st.Status.Committed.Generation != 1 || st.Status.Pending == nil {
			t.Fatalf("unselected/old-incarnation report satisfied save: %+v", st.Status)
		}
		s.report(name, "n2", func(o *v1.NodeObservation) { o.Incarnation = "inc-n2" })
	}
	s.until("durable success", func() bool { return s.getBlip("job").Status.Phase == v1.BlipSucceeded }, "state", "root", "state", "data", "blip", "job")
	s.until("pod cleanup", func() bool {
		for _, p := range s.pods() {
			if p.Labels[v1.LabelBlipUID] == string(b.UID) {
				return false
			}
		}
		return true
	}, "blip", "job")
	return s
}

func TestSimulationAllocationSaveLostReplies(t *testing.T) {
	baseline := allocationSave(t, 0)
	replay := allocationSave(t, 0)
	if !reflect.DeepEqual(baseline.api.trace, replay.api.trace) {
		t.Fatal("identical schedules did not replay the same API trace")
	}
	for cut := 1; cut <= baseline.api.writes; cut++ {
		t.Run(fmt.Sprintf("after-write-%02d", cut), func(t *testing.T) {
			s := allocationSave(t, cut)
			if s.api.losses != 1 {
				t.Fatalf("fault point %d was not reached", cut)
			}
			if !slices.Contains(s.api.trace, "restart reconciler state") {
				t.Fatalf("fault point %d did not return the lost reply to the restart boundary", cut)
			}
			replay := allocationSave(t, cut)
			if !reflect.DeepEqual(s.api.trace, replay.api.trace) {
				t.Fatalf("fault point %d did not replay the same API trace", cut)
			}
		})
	}
	t.Logf("replayed allocation/save and each of %d single lost-reply schedules with restart after error handling", baseline.api.writes)
}

func TestSimulationLostReplyDelivery(t *testing.T) {
	for _, verb := range []string{"create", "patch", "status"} {
		t.Run(verb, func(t *testing.T) {
			s := newControllerSimulation(t)
			var obj client.Object
			var apply func() error
			switch verb {
			case "create":
				obj = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "table"}, Data: map[string]string{"new": "value"}}
				apply = func() error { return s.api.Create(s.ctx, obj) }
			case "patch":
				s.create(&corev1.ConfigMap{ObjectMeta: metadata("table"), Data: map[string]string{"old": "value"}})
				obj = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "table"}}
				apply = func() error {
					return s.api.Patch(s.ctx, obj, client.RawPatch(types.MergePatchType, []byte(`{"data":{"new":"value"}}`)))
				}
			case "status":
				s.newBlip("job")
				b := s.getBlip("job")
				base := b.DeepCopy()
				b.Status.Phase = v1.BlipPending
				obj = b
				apply = func() error { return patchStatus(s.ctx, s.api, b, base) }
			}
			s.deliver()
			request := obj.DeepCopyObject().(client.Object)
			s.api.loseAt = s.api.writes + 1
			if err := apply(); !errors.Is(err, errSimulationLostReply) {
				t.Fatalf("expected lost reply, got %v", err)
			}
			if !reflect.DeepEqual(obj, request) {
				t.Fatalf("lost reply exposed the server response: request=%+v caller=%+v", request, obj)
			}
			live := obj.DeepCopyObject().(client.Object)
			s.must(s.c.Get(s.ctx, client.ObjectKeyFromObject(obj), live))
			if live.GetUID() == "" || live.GetResourceVersion() == "" || live.GetResourceVersion() == request.GetResourceVersion() {
				t.Fatalf("server did not apply the write: %+v", live)
			}
			switch live := live.(type) {
			case *corev1.ConfigMap:
				if live.Data["new"] != "value" || verb == "patch" && live.Data["old"] != "value" {
					t.Fatalf("lost reply changed the server-side merge: %+v", live.Data)
				}
			case *v1.Blip:
				if live.Status.Phase != v1.BlipPending {
					t.Fatalf("status write was not applied: %+v", live.Status)
				}
			}
			cached := obj.DeepCopyObject().(client.Object)
			err := s.api.Get(s.ctx, client.ObjectKeyFromObject(obj), cached)
			if verb == "create" {
				if !apierrors.IsNotFound(err) {
					t.Fatalf("undelivered creation appeared in cache: %v", err)
				}
			} else if err != nil || cached.GetResourceVersion() == live.GetResourceVersion() {
				t.Fatalf("undelivered write appeared in cache: rv=%s err=%v", cached.GetResourceVersion(), err)
			}
			s.deliver()
			s.must(s.api.Get(s.ctx, client.ObjectKeyFromObject(obj), cached))
			if !reflect.DeepEqual(cached, live) {
				t.Fatalf("delivered cache differs from authoritative object: cache=%+v live=%+v", cached, live)
			}
		})
	}
}

func TestSimulationPoolDeleteLosesToClaim(t *testing.T) {
	s := newControllerSimulation(t)
	s.addNodes("n1", "n2")
	s.newPool("default", 0, 0)
	s.readyState("root", "n1", "n2")
	s.warm("warm-a", "n1")
	s.deliver()
	interleaved := false
	s.api.before = func(verb string, obj client.Object) {
		if verb != "delete" || obj.GetName() != "warm-a" {
			return
		}
		s.api.before = nil
		interleaved = true
		// The pool selected a spare before this new Blip claimed it.
		s.newBlip("job", withRoot("root"))
		s.deliver()
		s.step("blip", "job")
		if b := s.getBlip("job"); b.Status.Pod != "warm-a" {
			t.Fatalf("competing claim did not complete: %+v", b.Status)
		}
	}
	s.step("pool", "default")
	if !interleaved {
		t.Fatal("delete/claim contention point not reached")
	}
	s.deliver()
	s.step("pool", "default")
	if pods := s.pods(); len(pods) != 1 || pods[0].Labels[v1.LabelBlipUID] != string(s.getBlip("job").UID) {
		t.Fatalf("pool deleted the concurrently claimed pod: %+v", pods)
	}
}

func TestSimulationCleanupRejectsReusedPodName(t *testing.T) {
	s := newControllerSimulation(t)
	s.newPool("default", 0, 0)
	s.warm("warm-a", "n1")
	old := s.getPod("warm-a")
	s.newBlip("job")
	b := s.getBlip("job")
	b.Status.Phase, b.Status.Pod, b.Status.PodUID = v1.BlipSucceeded, old.Name, string(old.UID)
	s.must(s.c.Status().Update(s.ctx, b))
	s.deliver()
	interleaved := false
	s.api.before = func(verb string, obj client.Object) {
		if verb != "delete" || obj.GetName() != old.Name {
			return
		}
		s.api.before = nil
		interleaved = true
		s.must(s.c.Delete(s.ctx, old))
		s.warm(old.Name, "n1")
	}
	s.step("blip", "job")
	if pods := s.pods(); !interleaved || len(pods) != 1 || pods[0].UID == old.UID {
		t.Fatalf("cleanup deleted the replacement pod: interleaved=%t pods=%+v", interleaved, pods)
	}
}

func TestSimulationContendedAllocation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-writer-%t", shared), func(t *testing.T) {
			s := newControllerSimulation(t)
			s.addNodes("n1", "n2")
			s.newPool("default", 1, 1)
			for _, name := range []string{"left", "right"} {
				s.readyState(name+".root", "n1", "n2")
				s.newBlip(name, withRoot(name+".root"))
				if !shared {
					root := s.getState(name + ".root")
					root.Labels = map[string]string{v1.LabelOwner: name}
					s.must(s.c.Update(s.ctx, root))
					s.updateBlip(name, func(b *v1.Blip) { b.Labels = map[string]string{v1.LabelOwner: name} })
				}
			}
			if shared {
				s.readyState("shared", "n1", "n2")
				for _, name := range []string{"left", "right"} {
					root := s.getState(name + ".root")
					root.Spec.Mounts = []v1.Mount{{State: "shared", Path: "/shared", Writable: true}}
					s.must(s.c.Update(s.ctx, root))
				}
				s.warm("warm-b", "n1")
			}
			s.warm("warm-a", "n1")
			s.deliver()
			interleaved := false
			s.api.before = func(verb string, obj client.Object) {
				_, pod := obj.(*corev1.Pod)
				if shared && verb == "status" && obj.GetName() == "shared" || !shared && verb == "patch" && pod {
					s.api.before = nil
					interleaved = true
					// Right completes its real writer/claim operations after
					// left selected the same snapshot, before left's CAS.
					s.step("blip", "right")
				}
			}
			s.step("blip", "left")
			if !interleaved {
				t.Fatal("contention point not reached")
			}
			s.deliver()
			s.until("contended winner", func() bool {
				return s.getBlip("right").Status.Pod != "" && s.getState("left.root").Status.Writer == nil
			}, "blip", "right", "blip", "left")
			winner := s.getBlip("right")
			if loser := s.getBlip("left"); loser.Status.Pod != "" {
				t.Fatalf("loser claimed a pod: %+v", loser.Status)
			}
			if got := s.getPod(winner.Status.Pod); got.Labels[v1.LabelBlipUID] != string(winner.UID) {
				t.Fatalf("winner lost pod ownership: %+v", got.ObjectMeta)
			}
			if !shared {
				if owner := s.getPod(winner.Status.Pod).Labels[v1.LabelOwner]; owner != "right" {
					t.Fatalf("losing claim left wrong owner label: %q", owner)
				}
			} else if w := s.getState("shared").Status.Writer; w == nil || w.BlipUID != string(winner.UID) {
				t.Fatalf("losing rollback changed winner's writer: %+v", w)
			}
		})
	}
}

func TestSimulationPoolClockAndListOrder(t *testing.T) {
	s := newControllerSimulation(t)
	s.newPool("default", 1, 0)
	s.deliver()
	s.step("pool", "default")
	if pods := s.pods(); len(pods) != 1 || pods[0].Name != "default-00001" {
		t.Fatalf("injected pod name was not used: %+v", pods)
	}
	// No cache delivery: successful creates are counted by expectations.
	for range 3 {
		s.step("pool", "default")
	}
	if n := len(s.pods()); n != 1 {
		t.Fatalf("cache lag created %d pods", n)
	}
	s.now = s.now.Add(expectTimeout)
	s.step("pool", "default")
	if n := len(s.pods()); n != 1 {
		t.Fatalf("expectation expired at inclusive deadline: %d pods", n)
	}
	s.now = s.now.Add(time.Nanosecond)
	s.step("pool", "default")
	if n := len(s.pods()); n != 2 {
		t.Fatalf("virtual clock did not expire expectation: %d pods", n)
	}
	// Both pods have equal timestamps. Reverse API list order and verify the
	// production shrink decision still uses the deterministic name tie break.
	s.api.reverse = true
	s.deliver()
	s.step("pool", "default")
	if pods := s.pods(); len(pods) != 1 || pods[0].Name != "default-00002" {
		t.Fatalf("list order changed shrink choice: %+v", pods)
	}
}

func TestSimulationStatePlanConflictAndLostReply(t *testing.T) {
	s := newControllerSimulation(t)
	s.addNodes("n1", "n2", "n3")
	s.newState("root")
	s.deliver()
	// An independent node observation lands between plan read and status CAS.
	interleaved := false
	s.api.before = func(verb string, obj client.Object) {
		if verb == "status" && obj.GetName() == "root" {
			s.api.before = nil
			interleaved = true
			s.report("root", "n3", func(o *v1.NodeObservation) { o.Error = "independent node report" })
		}
	}
	s.step("state", "root")
	if !interleaved || s.getState("root").Status.Pending != nil {
		t.Fatal("stale plan overwrote concurrent observation")
	}
	s.deliver()
	s.api.loseAt = s.api.writes + 1
	s.step("state", "root")
	plan := s.getState("root").Status.Pending.DeepCopy()
	if plan == nil || !slices.Equal(plan.Replicas, []string{"n1", "n2"}) {
		t.Fatalf("initial placement: %+v", plan)
	}
	// Reconcile after restart against the pre-plan cache, then deliver.
	s.step("state", "root")
	s.deliver()
	s.step("state", "root")
	st := s.getState("root")
	if !reflect.DeepEqual(st.Status.Pending, plan) || len(st.Status.Nodes) != 1 || st.Status.Nodes[0].Error != "independent node report" {
		t.Fatalf("retry replaced durable plan or node report: %+v", st.Status)
	}
	s.hold("root", plan.CommitID, plan.Replicas...)
	s.deliver()
	s.step("state", "root")
	st = s.getState("root")
	if st.Status.Committed == nil || st.Status.Committed.ID != plan.CommitID || !st.Status.Committed.Time.Equal(&metav1.Time{Time: s.now}) {
		t.Fatalf("plan did not commit at injected time: %+v", st.Status)
	}
}

func TestSimulationLostSaveNeverSucceeds(t *testing.T) {
	for _, beforeSeal := range []bool{false, true} {
		t.Run(fmt.Sprintf("node-lost-before-seal-%t", beforeSeal), func(t *testing.T) {
			s := newControllerSimulation(t)
			s.addNodes("n1", "n2")
			s.newPool("default", 0, 0)
			s.readyState("root", "n1", "n2")
			s.newBlip("job", withRoot("root"), withCommand("true"))
			s.warm("warm-a", "n1")
			s.deliver()
			s.until("allocation", func() bool { return s.getBlip("job").Status.Pod != "" }, "blip", "job")
			b := s.getBlip("job")
			s.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseRunning, ClaimID: "claim"})
			s.until("running", func() bool { return s.getBlip("job").Status.Phase == v1.BlipRunning }, "blip", "job")
			s.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Code: 0}})
			s.until("saving", func() bool { return s.getBlip("job").Status.Phase == v1.BlipSaving }, "blip", "job")
			old := s.getState("root").Status.Committed.ID
			w := s.getState("root").Status.Writer.DeepCopy()
			if beforeSeal {
				s.must(s.c.Delete(s.ctx, &corev1.Node{ObjectMeta: metadata("n1")}))
				s.must(s.c.Delete(s.ctx, &v1.BlipNode{ObjectMeta: metadata("n1")}))
				s.deliver()
				for range 3 {
					s.step("state", "root")
					s.step("blip", "job")
				}
				if got := s.getState("root").Status.Writer; got == nil || got.AttachmentID != w.AttachmentID {
					t.Fatalf("node loss released an unsealed writer: %+v", got)
				}
				if s.getBlip("job").Status.Phase != v1.BlipSaving {
					t.Fatal("node loss completed an unresolved save")
				}
			}
			s.seal("root", "n1", v1.SealResult{AttachmentID: w.AttachmentID, CommitID: "1000000000000000"})
			s.hold("root", "1000000000000000", "n1")
			if !beforeSeal {
				s.until("pending save", func() bool { return s.getState("root").Status.Pending != nil }, "state", "root")
				s.must(s.c.Delete(s.ctx, &corev1.Node{ObjectMeta: metadata("n1")}))
				s.must(s.c.Delete(s.ctx, &v1.BlipNode{ObjectMeta: metadata("n1")}))
			}
			s.deliver()
			s.api.loseAt = s.api.writes + 1
			s.until("failed save", func() bool { return s.getBlip("job").Status.Phase == v1.BlipFailed }, "state", "root", "blip", "job")
			st := s.getState("root")
			b = s.getBlip("job")
			if st.Status.Committed.ID != old || st.Status.Pending != nil || st.Status.Writer != nil || len(st.Status.Seals) != 1 || st.Status.Seals[0].Error == "" {
				t.Fatalf("lost save changed durable state or lacked a failure seal: %+v", st.Status)
			}
			if b.Status.Reason != ReasonSaveFailed || b.Status.ExitCode == nil || *b.Status.ExitCode != 0 {
				t.Fatalf("successful process exit hid save failure: %+v", b.Status)
			}
		})
	}
}
