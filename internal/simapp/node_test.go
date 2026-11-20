// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simapp

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/node"
	"github.com/Azure/blip/internal/podapi"
	bruntime "github.com/Azure/blip/internal/runtime"
	"github.com/Azure/blip/internal/storage"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Only observations are assembled here. Decisions and scheduler reservations
// come directly from node.Compute, the same function behind the live agent.
func (w *world) nodeSnapshot(name string) node.Snapshot {
	s := node.Snapshot{Now: w.now(), Node: name, Incarnation: "inc-" + name,
		Nodes: w.Cache.Nodes.Items, KubeNodes: w.Cache.KubeNodes.Items,
		Pools: w.Cache.Pools.Items, States: w.Cache.States.Items, Blips: w.Cache.Blips.Items,
		Pods: w.Cache.Pods.Items, Directories: w.Directories[name],
		Devices: map[string]uint64{}, Busy: w.scheduler.Busy(), Pinned: map[string]bool{}}
	for _, id := range sortedKeys(w.Inventory[name]) {
		v := w.Inventory[name][id]
		s.Volumes = append(s.Volumes, v)
		if v.Kind == storage.KindWorking {
			s.Devices[id] = deviceNumber(id)
		}
	}
	if w.Transfer != nil && w.Transfer.Pinned && w.IO.Source.Node == name {
		s.Pinned[w.Transfer.Commit] = true
	}
	return s
}

func (w *world) nodePlan(name string) node.Plan { return node.Compute(w.nodeSnapshot(name)) }

func deviceNumber(id string) uint64 {
	n, err := strconv.ParseUint(id, 16, 64)
	must(err)
	return n
}

func (w *world) observeRuntime() {
	b := w.blip()
	if b.Status.Pod == "" {
		return
	}
	key := ns + "/" + b.Status.Pod
	d := w.Directories[b.Status.Node][key]
	o := w.runtime.Observed()
	d.Observed = &o
	w.Directories[b.Status.Node][key] = d
}

func (w *world) publishDesired(name string, p node.Plan) {
	for _, key := range sortedKeys(p.Desired) {
		d := w.Directories[name][key]
		v := p.Desired[key]
		d.Desired = &v
		w.Directories[name][key] = d
		if key == ns+"/"+w.blip().Status.Pod && name == w.blip().Status.Node {
			w.Desired = copyValue(v)
			w.apply(bruntime.Event{Kind: bruntime.EventDesired, Desired: v})
			w.Coverage["node-desired"]++
		}
	}
}

func (w *world) publishPods(p node.Plan) {
	c := w.Actual.client()
	for _, m := range p.Pods {
		pod := &corev1.Pod{}
		must(c.Get(ctx, client.ObjectKey{Namespace: m.Namespace, Name: m.Name}, pod))
		if pod.Labels == nil {
			pod.Labels = map[string]string{}
		}
		if m.Warm {
			pod.Labels[v1alpha1.LabelWarm] = "true"
		} else {
			delete(pod.Labels, v1alpha1.LabelWarm)
		}
		if m.Observed != "" {
			if pod.Annotations == nil {
				pod.Annotations = map[string]string{}
			}
			pod.Annotations[v1alpha1.AnnotationObserved] = m.Observed
		}
		must(c.Update(ctx, pod))
	}
	for _, key := range sortedKeys(p.PodErrors) {
		message := p.PodErrors[key]
		namespace, name, _ := strings.Cut(key, "/")
		pod := &corev1.Pod{}
		must(c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod))
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		if message == "" {
			delete(pod.Annotations, v1alpha1.AnnotationPrepareError)
		} else {
			pod.Annotations[v1alpha1.AnnotationPrepareError] = message
		}
		must(c.Update(ctx, pod))
	}
	w.Actual = snapshot(c)
}

func (w *world) stateName(uid string) string {
	for _, s := range w.Actual.States.Items {
		if string(s.UID) == uid {
			return s.Name
		}
	}
	panic("unknown physical state " + uid)
}

func (w *world) startPrepare(name string, p node.Plan, r node.PrepareRequest) {
	uid, commit := r.StateUID, r.FromCommit
	if r.Exists {
		v := w.Inventory[name][r.AttachmentID]
		uid, commit = v.StateUID, v.Base
	}
	w.startPlannedIO(p, r.AttachmentID, ioAttempt{Kind: "prepare", State: w.stateName(uid),
		ID: r.AttachmentID, Commit: commit, Node: name, Prepare: &r})
}

// A workload turn services one planned job. Its intent and reservations are
// production values; the environment supplies only completion and retry time.
func (w *world) startPlannedIO(p node.Plan, key string, i ioAttempt) {
	for _, op := range p.Operations {
		if op.Key != key {
			continue
		}
		a := w.schedule([]node.Operation{op})
		if len(a) == 0 {
			if deadline, ok := w.scheduler.Deadline(w.now()); ok {
				w.Now = deadline.Sub(epoch)
			}
			return
		}
		i.Attempt = a[0]
		w.IO = &i
		w.Coverage["node-"+i.Kind]++
		return
	}
	panic(fmt.Sprintf("planner request %s has no reservation", key))
}

func TestSimulationNodePlannerRepairsDeviceBeforeClaim(t *testing.T) {
	w := newWorld()
	for w.Stage != 3 || w.Working[w.Attachments["root"]].Base == "" {
		checkedStep(t, w, fairAction(w))
	}
	id := w.Attachments["root"]
	key := ns + "/" + w.blip().Status.Pod
	delete(w.Directories["n1"][key].Devices, id)
	p := w.nodePlan("n1")
	if len(p.Prepares) != 1 || p.Prepares[0].AttachmentID != id || !p.Prepares[0].Exists {
		t.Fatalf("missing device node did not produce repair: %+v", p.Prepares)
	}
	if d := p.Desired[key]; d.Claim != nil {
		t.Fatal("planner claimed before the device node was repaired")
	}
	heal(t, w)
	for _, kind := range []string{"desired", "prepare", "seal", "fetch", "report"} {
		if w.Coverage["node-"+kind] == 0 {
			t.Fatalf("lifecycle bypassed production node %s", kind)
		}
	}
}

func TestSimulationNodePlannerWaitsForObservedRemoval(t *testing.T) {
	w := newWorld()
	for w.Removal == nil {
		checkedStep(t, w, fairAction(w))
	}
	id := w.Attachments["data"]
	hasSeal := func() bool {
		return slices.ContainsFunc(w.nodePlan("n1").Seals, func(r node.SealRequest) bool {
			return r.AttachmentID == id && r.CommitID == node.SealCommitID(id)
		})
	}
	if hasSeal() {
		t.Fatal("node sealed after removal acceptance but before physical confirmation")
	}
	checkedStep(t, w, "hypervisor/confirm-removal")
	if hasSeal() {
		t.Fatal("node sealed before runtime received removal confirmation")
	}
	for !slices.ContainsFunc(w.runtime.Observed().Mounts, func(d podapi.DiskStatus) bool {
		return d.ID == id && d.Phase == podapi.DiskDetached
	}) {
		checkedStep(t, w, fairAction(w))
	}
	if !hasSeal() {
		t.Fatal("observed detached disk did not produce the production seal request")
	}
	heal(t, w)
}

func TestSimulationNodePlannerRejectsStaleReplicaSource(t *testing.T) {
	w := newWorld()
	for w.Stage != 16 {
		checkedStep(t, w, fairAction(w))
	}
	if slices.Contains(w.Enabled(), "observe/cache") {
		checkedStep(t, w, "observe/cache")
	}
	s := copyValue(w.nodeSnapshot("n2"))
	p := node.Compute(s)
	if len(p.Fetches) != 1 || p.Fetches[0].Source.Node != "n1" || p.Fetches[0].Source.CommitID != w.Saved["data"] {
		t.Fatalf("node did not choose the reported sealed source: %+v", p.Fetches)
	}
	for _, fault := range []string{"incarnation", "heartbeat", "identity"} {
		t.Run(fault, func(t *testing.T) {
			x := copyValue(s)
			for i := range x.Nodes {
				if x.Nodes[i].Name != "n1" {
					continue
				}
				switch fault {
				case "incarnation":
					x.Nodes[i].Status.Incarnation = "replaced"
				case "heartbeat":
					x.Now = x.Nodes[i].Status.Heartbeat.Add(61 * time.Second)
				case "identity":
					x.Nodes[i].Status.TLSPublicKey = "invalid"
				}
			}
			if got := node.Compute(x); len(got.Fetches) != 0 {
				t.Fatalf("untrusted source produced fetch: %+v", got.Fetches)
			}
		})
	}
	heal(t, w)
}
