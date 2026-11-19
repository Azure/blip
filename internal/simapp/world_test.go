// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package simapp composes public production cores in a deterministic virtual
// environment. The scenario is an integration workload, not another controller.
package simapp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/controller"
	"github.com/Azure/blip/internal/node"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	bruntime "github.com/Azure/blip/internal/runtime"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/storage"
	"github.com/Azure/blip/internal/wire"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const ns = "simulation"

var epoch = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// External state is serializable; production machines supply isolated clones
// and canonical keys that include their private pending operations.
type world struct {
	Actual, Cache          apiSnapshot
	Stage                  int
	Now                    time.Duration
	IDs                    uint64
	APIWrites, LoseWrite   int
	ContenderTurns         int
	Effects                []bruntime.Effect
	Replies                []bruntime.Event
	Removal                *bruntime.Effect
	Desired                podapi.Desired
	Directories            map[string]map[string]node.PodSnapshot
	Inventory              map[string]map[string]storage.Volume
	Devices                map[string]bool
	GuestMounts            map[string]bool
	GuestClaim             string
	GuestStopped, VMExited bool
	Working                map[string]volume
	Durable                map[string]map[string]string // node -> commit -> exact immutable bytes
	Saved                  map[string]string            // state -> sealed commit
	Attachments            map[string]string            // first workload's attachment IDs
	IO                     *ioAttempt
	Transfer               *transfer
	Faults                 map[string]bool // remaining one-shot fault permissions
	Coverage               map[string]int
	Healed                 bool
	RecoverySteps          int
	runtime                *bruntime.Machine
	scheduler              *node.Scheduler
}

type volume struct {
	State, Node, Base, Bytes string
	Sealed                   bool
}
type ioAttempt struct {
	Attempt                       node.Attempt
	Kind, State, ID, Commit, Node string
	Prepare                       *node.PrepareRequest
	Source                        *node.CommitSource
}
type transfer struct {
	State, Commit, Bytes                        string
	Operation                                   peer.LeaseOperation
	Completed                                   peer.LeaseEffect
	Pinned, Persisted, Open, Published, Revoked bool
	Copied                                      int
	Hydrated                                    bool
}

func encode(v any) string    { b, err := json.Marshal(v); must(err); return string(b) }
func copyValue[T any](v T) T { var out T; must(json.Unmarshal([]byte(encode(v)), &out)); return out }

func (w *world) Clone() sim.Model {
	x := copyValue(*w)
	x.runtime = w.runtime.Clone()
	x.scheduler = w.scheduler.Clone()
	return &x
}
func (w *world) Key() string {
	state := struct {
		World              *world
		Runtime, Scheduler string
	}{w, w.runtime.Key(), w.scheduler.Key()}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(encode(state))))
}
func (w *world) now() time.Time { return epoch.Add(w.Now) }
func (w *world) id() string     { w.IDs++; return fmt.Sprintf("%016x", w.IDs) }
func (w *world) blip() *v1.Blip {
	name := "first"
	if w.Stage >= 32 {
		name = "second"
	}
	for i := range w.Actual.Blips.Items {
		if w.Actual.Blips.Items[i].Name == name {
			return &w.Actual.Blips.Items[i]
		}
	}
	panic("missing blip " + name)
}
func (w *world) state(name string) *v1.BlipState {
	for i := range w.Actual.States.Items {
		if w.Actual.States.Items[i].Name == name {
			return &w.Actual.States.Items[i]
		}
	}
	panic("missing state " + name)
}

func newWorld() *world {
	w := &world{Devices: map[string]bool{}, GuestMounts: map[string]bool{}, Working: map[string]volume{},
		Directories: map[string]map[string]node.PodSnapshot{"n1": {}, "n2": {}},
		Inventory:   map[string]map[string]storage.Volume{"n1": {}, "n2": {}},
		Durable:     map[string]map[string]string{"n1": {}, "n2": {}}, Saved: map[string]string{}, Attachments: map[string]string{},
		Faults: map[string]bool{"api": true, "control": true, "remove": true, "storage": true, "storage-before": true, "lease": true, "incarnation": true}, Coverage: map[string]int{}}
	meta := func(n string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: n, Namespace: ns, UID: types.UID("uid-" + n), ResourceVersion: "1", Generation: 1, CreationTimestamp: metav1.NewTime(epoch)}
	}
	w.Actual.Pools.Items = []v1.BlipPool{{ObjectMeta: meta("default"), Spec: v1.BlipPoolSpec{Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi"), WarmCount: 2, MaxCount: 2, ServiceAccountName: "vm"}}}
	w.Actual.Blips.Items = []v1.Blip{{ObjectMeta: meta("first"), Spec: v1.BlipSpec{Pool: "default", State: "root"}}}
	for i, name := range []string{"n1", "n2"} {
		m := meta(name)
		m.Namespace = ""
		m.Labels = map[string]string{v1.LabelEnrolled: "true", v1.LabelHypervisorPrefix + "kvm": "true"}
		w.Actual.KubeNodes.Items = append(w.Actual.KubeNodes.Items, corev1.Node{ObjectMeta: m})
		hb := metav1.NewTime(epoch)
		key := sha256.Sum256([]byte(name))
		w.Actual.Nodes.Items = append(w.Actual.Nodes.Items, v1.BlipNode{ObjectMeta: m, Status: v1.BlipNodeStatus{Incarnation: "inc-" + name, Heartbeat: &hb, FreeBytes: 100 << 30, Hypervisors: []string{"kvm"}, Endpoint: fmt.Sprintf("10.0.0.%d", i+1), TLSPublicKey: base64.StdEncoding.EncodeToString(key[:])}})
	}
	for i, name := range []string{"root", "data"} {
		id := fmt.Sprintf("%016x", 100+i)
		s := v1.BlipState{ObjectMeta: meta(name), Spec: v1.BlipStateSpec{Replicas: 2}, Status: v1.BlipStateStatus{Phase: v1.StateReady, SizeBytes: 1 << 20,
			Committed: &v1.Commit{ID: id, Generation: 1, SizeBytes: 1 << 20, Time: metav1.NewTime(epoch)}, Placements: []string{"n1", "n2"}}}
		if name == "root" {
			s.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
		}
		for _, n := range []string{"n1", "n2"} {
			s.Status.Nodes = append(s.Status.Nodes, v1.NodeObservation{Node: n, Incarnation: "inc-" + n, Commits: []string{id}})
			w.Durable[n][id] = "initial:" + name
			w.Inventory[n][id] = storage.Volume{ID: id, Kind: storage.KindCommit, StateUID: string(s.UID), SizeBytes: s.Status.SizeBytes}
		}
		w.Actual.States.Items = append(w.Actual.States.Items, s)
	}
	w.Cache = copyValue(w.Actual)
	w.runtime = bruntime.NewMachine(true)
	w.scheduler = node.NewScheduler(map[string]int{"seal": 1, "fetch": 1})
	return w
}

// Stages name the user's workload milestones. Each controller turn is exactly
// one real Reconcile; the scenario advances only after authoritative outcomes.
var stages = []string{
	"pool", "boot", "allocate", "prepare", "runtime-claim", "mirror", "running", "write-and-detach",
	"unmount-intent", "desired-detach", "runtime-detach", "mirror", "mount-saving", "seal-data", "report-data",
	"pending-data", "replicate-data", "report-replica-data", "commit-data", "forget-mount", "stop",
	"runtime-stop", "mirror", "saving", "seal-root", "report-root", "pending-root", "replicate-root",
	"report-replica-root", "commit-root", "success", "new-client", "reacquire", "prepare", "runtime-claim", "mirror", "running", "done",
}

func (w *world) Enabled() []string {
	if w.Stage == len(stages)-1 {
		return nil
	}
	a := []string{"progress/" + stages[w.Stage]}
	if w.Stage >= 7 && w.Stage <= 18 && w.ContenderTurns < 2 {
		a = append(a, "client/contend")
	}
	if encode(w.Actual) != encode(w.Cache) {
		a = append(a, "observe/cache")
	}
	if len(w.Effects) > 0 {
		a = append(a, "runtime/effect")
	}
	if len(w.Replies) > 0 {
		a = append(a, "runtime/reply")
		if !w.Healed && w.Faults["control"] && w.Replies[0].Kind == bruntime.EventControl && w.Replies[0].Type != wire.THello {
			a = append(a, "fault/control-reply")
		}
	}
	if w.Removal != nil {
		a = append(a, "hypervisor/confirm-removal")
		if !w.Healed && w.Faults["remove"] {
			a = append(a, "fault/removal-reply")
		}
	}
	if !w.Healed {
		if w.Faults["api"] && w.controllerStage() {
			a = append(a, "fault/api-reply")
		}
		if w.Faults["storage"] && w.IO != nil && w.Transfer == nil {
			a = append(a, "fault/storage-reply")
		}
		if w.Faults["storage-before"] && w.IO != nil && w.Transfer == nil {
			a = append(a, "fault/storage-before")
		}
		if w.Faults["lease"] && w.Transfer != nil && w.Transfer.Operation == peer.ReleaseLease && peer.NextLeaseEffect(peer.ReleaseLease, w.Transfer.Completed) == peer.LeasePersistRevocation {
			a = append(a, "fault/revocation-reply")
		}
		if w.Faults["incarnation"] && (w.Stage == 17 || w.Stage == 28) {
			a = append(a, "fault/old-incarnation")
		}
	}
	return a
}

func (w *world) controllerStage() bool {
	return slices.Contains([]int{0, 2, 6, 8, 12, 15, 18, 19, 23, 26, 29, 30, 32, 36}, w.Stage)
}

func (w *world) Step(action string) error {
	if !slices.Contains(w.Enabled(), action) {
		return fmt.Errorf("disabled action %s at %s", action, stages[w.Stage])
	}
	if w.Healed {
		w.RecoverySteps++
	}
	switch action {
	case "client/contend":
		if !w.hasSecond() {
			w.createSecond()
			return nil
		}
		w.ContenderTurns++
		return w.reconcile("blip", "second", false)
	case "observe/cache":
		w.Cache = copyValue(w.Actual)
	case "runtime/effect":
		return w.effect()
	case "runtime/reply":
		e := w.Replies[0]
		w.Replies = w.Replies[1:]
		w.apply(e)
	case "fault/control-reply":
		w.Faults["control"] = false
		w.Coverage["lost-control"]++
		w.Replies = w.Replies[1:]
		// A complete guest operation survived the missing reply. Advance the
		// production response deadline; reconnect's Hello discovers reality.
		w.Now += 61 * time.Second
		w.heartbeat()
	case "hypervisor/confirm-removal", "fault/removal-reply":
		e := w.Removal
		w.Removal = nil
		delete(w.Devices, e.Disk.ID)
		r := bruntime.Event{Kind: bruntime.EventResult, Token: e.Token}
		if strings.HasPrefix(action, "fault/") {
			w.Faults["remove"] = false
			w.Coverage["lost-removal"]++
			r.Error = lostReply.Error()
		}
		w.Replies = append(w.Replies, r)
	case "fault/storage-reply":
		w.Faults["storage"] = false
		w.Coverage["lost-storage"]++
		if err := w.finishIO(true); err != nil {
			return err
		}
	case "fault/storage-before":
		w.Faults["storage-before"] = false
		w.Coverage["failed-storage"]++
		w.complete(w.IO.Attempt, node.Failed)
		w.IO = nil
	case "fault/revocation-reply":
		w.Faults["lease"] = false
		w.Coverage["lost-revocation"]++
		w.Transfer.Revoked = true
	case "fault/old-incarnation":
		w.Faults["incarnation"] = false
		w.Coverage["old-incarnation"]++
		w.report(w.saveState(), "n2", true)
	case "fault/api-reply":
		return w.progress(true)
	default:
		return w.progress(false)
	}
	return nil
}

func (w *world) heartbeat() {
	c := w.Actual.client()
	for _, n := range w.Actual.Nodes.Items {
		x := n.DeepCopy()
		hb := metav1.NewTime(w.now())
		x.Status.Heartbeat = &hb
		must(c.Status().Update(ctx, x))
	}
	w.Actual = snapshot(c)
}

func (w *world) reconcile(kind, name string, lose bool) error {
	a := &delayedAPI{Client: w.Actual.client(), cache: w.Cache.client(), lose: lose, writes: w.APIWrites, loseAt: w.LoseWrite}
	cfg := controller.Config{RuntimeImage: "sim/runtime", Now: w.now, NewID: w.id, NewPodName: func(pool string) string { return pool + "-" + w.id() }}
	var r reconcile.Reconciler
	switch kind {
	case "pool":
		r = &controller.PoolReconciler{Client: a, Config: cfg}
	case "blip":
		r = &controller.BlipReconciler{Client: a, Live: a.Client, Config: cfg}
	case "state":
		r = &controller.StateReconciler{Client: a, Live: a.Client, Config: cfg}
	}
	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	w.Actual = snapshot(a.Client)
	w.APIWrites = a.writes
	if a.lost {
		w.Faults["api"] = false
		w.Coverage["lost-api"]++
	}
	if apierrors.IsConflict(err) {
		w.Coverage["conflict"]++
		return nil
	}
	if errors.Is(err, lostReply) {
		return nil
	}
	return err
}

func (w *world) update(o client.Object) {
	c := w.Actual.client()
	must(c.Update(ctx, o))
	w.Actual = snapshot(c)
}
func (w *world) saveState() string {
	if w.Stage < 20 {
		return "data"
	}
	return "root"
}

func (w *world) progress(lose bool) error {
	b := w.blip()
	next := false
	switch w.Stage {
	case 0:
		if err := w.reconcile("pool", "default", lose); err != nil {
			return err
		}
		next = len(w.Actual.Pods.Items) >= 2
	case 1:
		c := w.Actual.client()
		for i, p := range w.Actual.Pods.Items {
			if p.Spec.NodeName != "" {
				continue
			}
			x := p.DeepCopy()
			x.Spec.NodeName = fmt.Sprintf("n%d", i+1)
			must(c.Update(ctx, x))
			x.Status.Phase = corev1.PodRunning
			must(c.Status().Update(ctx, x))
			w.Directories[x.Spec.NodeName][ns+"/"+x.Name] = node.PodSnapshot{Observed: &podapi.Observed{Phase: podapi.PhaseWarm}, Devices: map[string]uint64{}}
		}
		w.Actual = snapshot(c)
		next = true
		for _, name := range []string{"n1", "n2"} {
			w.publishPods(w.nodePlan(name))
		}
		for _, p := range w.Actual.Pods.Items {
			next = next && p.Labels[v1.LabelWarm] == "true"
		}
	case 2, 32:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		b = w.blip()
		next = b.Status.PodUID != "" && len(b.Status.Mounts) == 1
		for _, name := range []string{"root", "data"} {
			s := w.state(name)
			next = next && s.Status.Writer != nil && s.Status.Writer.PodUID == b.Status.PodUID
		}
		if next && w.Stage == 2 {
			for _, name := range []string{"root", "data"} {
				w.Attachments[name] = w.state(name).Status.Writer.AttachmentID
			}
		}
	case 3, 33:
		if w.IO != nil {
			return w.finishIO(false)
		}
		p := w.nodePlan(b.Status.Node)
		w.publishDesired(b.Status.Node, p)
		if len(p.Prepares) != 0 {
			w.startPrepare(b.Status.Node, p, p.Prepares[0])
			return nil
		}
		if w.Desired.Claim == nil {
			return nil
		}
		w.apply(bruntime.Event{Kind: bruntime.EventConnected, Generation: w.runtime.Generation()})
		w.hello(w.runtime.Generation())
		next = true
	case 4, 34:
		w.reconcileRuntime()
		o := w.runtime.Observed()
		next = o.ClaimID != "" && len(o.Mounts) > 0 && o.Mounts[len(o.Mounts)-1].Phase == podapi.DiskMounted
	case 5, 11, 22, 35:
		w.mirror()
		next = true
	case 6, 36:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		b = w.blip()
		next = b.Status.Phase == v1.BlipRunning && len(b.Status.Mounts) == 1 && b.Status.Mounts[0].Phase == v1.MountMounted
	case 7:
		for _, name := range []string{"root", "data"} {
			id := w.Attachments[name]
			if !w.GuestMounts[id] || !w.Devices[id] {
				return fmt.Errorf("write through unmounted %s", id)
			}
			v := w.Working[id]
			v.Bytes = "acknowledged-write:" + name + ":abcdefghijklmnopqrstuvwxyz"
			w.Working[id] = v
		}
		r := w.state("root").DeepCopy()
		r.Spec.Mounts = nil
		r.Generation++
		w.update(r)
		next = true
	case 8:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		b = w.blip()
		next = len(b.Status.Mounts) == 1 && b.Status.Mounts[0].Phase == v1.MountUnmounting
	case 9:
		w.publishDesired(b.Status.Node, w.nodePlan(b.Status.Node))
		next = len(w.Desired.Mounts) == 0
	case 10:
		w.reconcileRuntime()
		for _, m := range w.runtime.Observed().Mounts {
			if m.ID == w.Attachments["data"] && m.Phase == podapi.DiskDetached {
				next = true
			}
		}
	case 12:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		b = w.blip()
		next = len(b.Status.Mounts) == 1 && b.Status.Mounts[0].Phase == v1.MountSaving
	case 13, 24:
		if w.IO != nil {
			return w.finishIO(false)
		}
		name := w.saveState()
		if w.Saved[name] != "" {
			next = true
		} else {
			p := w.nodePlan(b.Status.Node)
			for _, r := range p.Seals {
				if r.StateUID == string(w.state(name).UID) {
					w.startPlannedIO(p, r.AttachmentID, ioAttempt{Kind: "seal", State: name, ID: r.AttachmentID, Commit: r.CommitID, Node: b.Status.Node})
					break
				}
			}
		}
	case 14, 25:
		w.report(w.saveState(), "n1", false)
		next = true
	case 15, 26:
		name := w.saveState()
		if err := w.reconcile("state", name, lose); err != nil {
			return err
		}
		next = w.state(name).Status.Pending != nil
	case 16, 27:
		return w.replicate()
	case 17, 28:
		w.report(w.saveState(), "n2", false)
		next = true
	case 18, 29:
		name := w.saveState()
		if err := w.reconcile("state", name, lose); err != nil {
			return err
		}
		next = w.state(name).Status.Committed.Generation == 2 && w.state(name).Status.Pending == nil
	case 19:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		next = len(w.blip().Status.Mounts) == 0
	case 20:
		if !b.Spec.Stop {
			x := b.DeepCopy()
			x.Spec.Stop = true
			w.update(x)
		}
		w.publishDesired(b.Status.Node, w.nodePlan(b.Status.Node))
		next = w.Desired.Stop
	case 21:
		w.reconcileRuntime()
		if w.GuestStopped && len(w.Replies) == 0 && len(w.Effects) == 0 && !w.VMExited {
			w.Devices = map[string]bool{}
			w.VMExited = true
			w.apply(bruntime.Event{Kind: bruntime.EventVMExited})
		}
		next = w.runtime.Observed().Phase == podapi.PhaseExited
	case 23:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		next = w.blip().Status.Phase == v1.BlipSaving
	case 30:
		if err := w.reconcile("blip", b.Name, lose); err != nil {
			return err
		}
		next = w.blip().Status.Phase == v1.BlipSucceeded
		for _, p := range w.Actual.Pods.Items {
			if p.Labels[v1.LabelBlipUID] == string(w.blip().UID) {
				next = false
			}
		}
	case 31:
		if !w.hasSecond() {
			w.createSecond()
		}
		r := w.state("root").DeepCopy()
		r.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", Writable: true}}
		r.Generation++
		w.update(r)
		w.runtime = bruntime.NewMachine(true)
		w.Desired = podapi.Desired{}
		w.Effects = nil
		w.Replies = nil
		w.GuestClaim = ""
		w.GuestMounts = map[string]bool{}
		w.GuestStopped = false
		w.VMExited = false
		next = true
	}
	if next {
		w.Stage++
	}
	return nil
}

func (w *world) hasSecond() bool {
	for _, b := range w.Actual.Blips.Items {
		if b.Name == "second" {
			return true
		}
	}
	return false
}

func (w *world) createSecond() {
	c := w.Actual.client()
	must(c.Create(ctx, &v1.Blip{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: ns, UID: "uid-second", CreationTimestamp: metav1.NewTime(w.now())}, Spec: v1.BlipSpec{Pool: "default", State: "root"}}))
	w.Actual = snapshot(c)
}

func (w *world) mirror() {
	w.publishPods(w.nodePlan(w.blip().Status.Node))
}

func (w *world) report(name, nodeName string, stale bool) {
	p := w.nodePlan(nodeName)
	c := w.Actual.client()
	for _, e := range p.Entries {
		s := w.state(e.Name).DeepCopy()
		s.Status.Nodes = slices.DeleteFunc(s.Status.Nodes, func(o v1.NodeObservation) bool { return o.Node == nodeName })
		if e.Observation != nil {
			o := *e.Observation
			if stale && e.Name == name {
				o.Incarnation = "old-" + nodeName // delayed report from the replaced store
			}
			s.Status.Nodes = append(s.Status.Nodes, o)
		}
		must(c.Status().Update(ctx, s))
		w.Coverage["node-report"]++
	}
	w.Actual = snapshot(c)
}
