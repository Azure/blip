// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

func shuffledMap[V any](rng *rand.Rand, in map[string]V) map[string]V {
	keys := sortedKeys(in)
	rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
	out := make(map[string]V, len(in))
	for _, key := range keys {
		out[key] = in[key]
	}
	return out
}

func plannerFixture(seed int64) *view {
	v := newView()
	rng := rand.New(rand.NewSource(seed))
	for _, name := range []string{"a", "b", "c"} {
		s := state("build-" + name)
		s.Status.ImageDigest = imageRef
		s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "build-" + name, Generation: 1, SourceNode: self, Replicas: []string{self}}
		v.states = append(v.states, s)
		f := state("fetch-" + name)
		f.Status.Committed = &v1alpha1.Commit{ID: "fetch-" + name, Generation: 2}
		f.Status.Placements = []string{self}
		f.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", f.Status.Committed.ID), holding("n3", f.Status.Committed.ID)}
		rng.Shuffle(len(f.Status.Nodes), func(i, j int) { f.Status.Nodes[i], f.Status.Nodes[j] = f.Status.Nodes[j], f.Status.Nodes[i] })
		v.states = append(v.states, f)
		w := state("seal-" + name)
		key := pkey("seal-" + name)
		w.Status.Writer = &v1alpha1.Writer{Node: self, PodName: "seal-" + name, PodUID: "pod-" + name, AttachmentID: "working-" + name}
		v.states = append(v.states, w)
		v.volumes[w.Status.Writer.AttachmentID] = storage.Volume{ID: w.Status.Writer.AttachmentID, Kind: storage.KindWorking, StateUID: string(w.UID)}
		v.podsGone[key] = true
		v.dirs[key] = dir(podapi.PhaseExited)
		v.dirs[key].devs = shuffledMap(rng, map[string]uint64{"z": 1, "a": 2, "q": 3})
		v.pending = append(v.pending, "pending-"+name, "pending-"+name)
		v.volumes["garbage-"+name] = commit("garbage-"+name, "gone")
		pod := vmPod("warm-"+name, "")
		v.pods[pkey(pod.Name)] = pod
		v.dirs[pkey(pod.Name)] = dir(podapi.PhaseWarm)
		v.blips = append(v.blips, blip(name))
	}
	v.statesGone["gone"] = true
	v.pinned = map[string]bool{"garbage-b": true}
	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	v.configs[imageID] = &image.Config{}
	// GC must retain an image used by a build even if the retention snapshot
	// classified it idle before the new state was observed.
	v.idleImages = map[string]bool{imageID: true}
	digest := state("digest")
	digest.Status.ImageDigest = imageRef
	digest.Status.Committed = &v1alpha1.Commit{ID: "digest", Generation: 1}
	digest.Status.Placements = []string{self}
	v.states = append(v.states, digest)
	d := commit("digest", string(digest.UID))
	d.Base = imageID
	v.volumes[d.ID] = d
	// A deleted copy source uses captured nodes, whose set order is immaterial.
	cp := state("copy")
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "copy", SourceNode: self}
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "deleted-source", CommitID: "copy-source", Nodes: []string{"n3", "n2"}}
	rng.Shuffle(len(cp.Status.CopiedFrom.Nodes), func(i, j int) {
		cp.Status.CopiedFrom.Nodes[i], cp.Status.CopiedFrom.Nodes[j] = cp.Status.CopiedFrom.Nodes[j], cp.Status.CopiedFrom.Nodes[i]
	})
	v.states = append(v.states, cp)
	rng.Shuffle(len(v.states), func(i, j int) { v.states[i], v.states[j] = v.states[j], v.states[i] })
	rng.Shuffle(len(v.blips), func(i, j int) { v.blips[i], v.blips[j] = v.blips[j], v.blips[i] })
	rng.Shuffle(len(v.pending), func(i, j int) { v.pending[i], v.pending[j] = v.pending[j], v.pending[i] })
	v.volumes = shuffledMap(rng, v.volumes)
	v.dirs = shuffledMap(rng, v.dirs)
	v.pods = shuffledMap(rng, v.pods)
	v.blipNodes = shuffledMap(rng, v.blipNodes)
	return v
}

func TestComputeDeterministicAndImmutable(t *testing.T) {
	want := compute(plannerFixture(0))
	if len(want.builds) != 3 || len(want.fetches) != 4 || len(want.seals) != 3 || len(want.digests) != 1 || len(want.rmDevs) != 9 {
		t.Fatalf("fixture did not exercise planning: %+v", want)
	}
	if !slices.Equal(want.deletes, []string{"pending-a", "pending-b", "pending-c", "garbage-a", "garbage-c"}) {
		t.Fatalf("cleanup did not honor pending retries, pins and source reads: %v", want.deletes)
	}
	for seed := int64(0); seed < 64; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			v := plannerFixture(seed)
			before := plannerFixture(seed)
			for replay := 0; replay < 3; replay++ {
				got := compute(v)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("permutation/replay changed plan:\ngot %+v\nwant %+v", got, want)
				}
				if !reflect.DeepEqual(v, before) {
					t.Fatal("compute mutated its input snapshot")
				}
			}
		})
	}
}

func TestComputeHeartbeatUsesSnapshotTime(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c", Generation: 2}
	s.Status.Placements = []string{self}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n3", "c"), holding("n2", "c")}
	v.states = []*v1alpha1.BlipState{s}
	// This heartbeat is intentionally unrelated to real time. At the exact
	// TTL boundary it is usable, and one nanosecond later it is expired.
	hb := metav1.NewTime(v.now.Add(-nodeHeartbeatTTL))
	v.blipNodes["n2"].Status.Heartbeat = &hb
	v.blipNodes["n3"].Status.Heartbeat = &hb
	first := compute(v)
	if len(first.fetches) != 1 || first.fetches[0].src.node != "n2" {
		t.Fatalf("snapshot-time holder/tie break: %+v", first.fetches)
	}
	v.now = v.now.Add(time.Nanosecond)
	expired := compute(v)
	if len(expired.fetches) != 0 || expired.errs[string(s.UID)] == "" {
		t.Fatalf("expired holder remained usable: %+v", expired)
	}
}

func TestCleanupWaitsForEveryDeviceOwner(t *testing.T) {
	v := newView()
	vol := storage.Volume{ID: "shared", Kind: storage.KindWorking, ReadOnly: true}
	v.volumes[vol.ID] = vol
	for _, name := range []string{"old", "replacement"} {
		key := pkey(name)
		v.pods[key] = vmPod(name, "")
		v.dirs[key] = dir(podapi.PhaseRunning)
		v.dirs[key].devs[vol.ID] = 1
	}
	v.dirs[pkey("old")].observed.Phase = podapi.PhaseExited
	for range 50 {
		if p := compute(v); hasDelete(p, vol.ID) {
			t.Fatal("one fenced owner caused deletion under another running pod")
		}
	}
	v.dirs[pkey("replacement")].observed.Phase = podapi.PhaseExited
	if p := compute(v); !hasDelete(p, vol.ID) {
		t.Fatal("volume not collected after all owners fenced")
	}
}

func TestCleanupReservationsAcrossCompletionAndRestart(t *testing.T) {
	v := newView()
	v.volumes["source"] = commit("source", "gone")
	v.statesGone["gone"] = true
	var scheduler Scheduler
	op := Operation{Key: "build", Writes: []string{"destination"}, Reads: []string{"source"}}
	a := scheduler.Schedule(testNow, []Operation{op})[0]
	v.busy = scheduler.Busy()
	if p := compute(v); hasDelete(p, "source") {
		t.Fatal("GC deleted a reserved source")
	}
	scheduler.Schedule(testNow, nil) // cancellation requested, I/O still live
	v.busy = scheduler.Busy()
	if p := compute(v); hasDelete(p, "source") {
		t.Fatal("GC overtook canceled I/O cleanup")
	}
	scheduler.Complete(testNow, a, Canceled)
	v.busy = scheduler.Busy()
	if p := compute(v); !hasDelete(p, "source") {
		t.Fatal("completed read permanently retained source")
	}
	// Recover a pending teardown, stale device nodes and an empty directory.
	// The planner first retries the volume delete; then removes device nodes;
	// only a later confirmed-absent snapshot can remove the directory.
	scheduler.jobs = nil
	v.busy = scheduler.Busy()
	delete(v.volumes, "source")
	v.pending = []string{"source", "source"}
	key := pkey("gone")
	v.dirs[key] = dir(podapi.PhaseExited)
	v.dirs[key].devs["source"] = 1
	v.podsGone[key] = true
	p := compute(v)
	if !slices.Equal(p.deletes, []string{"source"}) || !reflect.DeepEqual(p.rmDevs, []devRef{{pod: key, id: "source"}}) || len(p.rmDirs) != 0 {
		t.Fatalf("recovery cleanup plan: %+v", p)
	}
	v.pending = nil
	delete(v.dirs[key].devs, "source")
	p = compute(v)
	if !slices.Equal(p.rmDirs, []string{key}) {
		t.Fatalf("empty confirmed-gone directory retained: %+v", p)
	}
}

func TestPlanReservesEverySourceKind(t *testing.T) {
	p := &plan{
		prepares: []prepare{{req: storage.CreateWorking{AttachmentID: "attachment", FromCommit: "local"}},
			{req: storage.CreateWorking{AttachmentID: "image-attachment", FromImage: "working-image"}},
			{req: storage.CreateWorking{AttachmentID: "remote"}, src: &source{bases: []string{"delta"}, imageBases: []string{"image-delta"}}}},
		builds:  []build{{req: storage.CreateCommit{StateUID: "state", CommitID: "new", FromImage: "image", FromCommit: "copy"}}},
		digests: []string{"digest"},
		fetches: []fetch{{owner: "fetch", src: source{commitID: "fetched", bases: []string{"fetch-delta"}, imageBases: []string{"fetch-image"}}}},
	}
	v := newView()
	for _, id := range []string{"local", "working-image", "delta", "image-delta", "image", "copy", "digest", "fetch-delta", "fetch-image", "garbage"} {
		v.volumes[id] = commit(id, "gone")
	}
	v.statesGone["gone"] = true
	planGC(v, p, nil)
	if !slices.Equal(p.deletes, []string{"garbage"}) {
		t.Fatalf("GC failed to reserve planned reads: %v", p.deletes)
	}
	var scheduler Scheduler
	scheduler.Schedule(testNow, p.operations())
	for _, id := range []string{"local", "working-image", "delta", "image-delta", "image", "copy", "digest", "fetch-delta", "fetch-image"} {
		if !scheduler.Busy()[id] {
			t.Fatalf("admission failed to reserve source %s", id)
		}
	}
}

func TestSnapshotCapturesExportPins(t *testing.T) {
	a, st, _ := testAgent(t)
	st.add(commit("exported", "gone"))
	pinned, calls := true, 0
	a.pinned = func(id string) bool {
		calls++
		return pinned && id == "exported"
	}
	v, err := a.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v.freeBytes, v.poolBytes = 0, 1<<40 // cache pressure: keep no unneeded commit
	if calls != 1 || !v.pinned["exported"] {
		t.Fatal("snapshot did not capture export pins")
	}
	pinned = false
	for range 3 {
		if p := compute(v); hasDelete(p, "exported") || calls != 1 {
			t.Fatal("compute consulted live pins instead of its snapshot")
		}
	}
	fresh, err := a.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fresh.freeBytes, fresh.poolBytes = 0, 1<<40
	if p := compute(fresh); !hasDelete(p, "exported") {
		t.Fatal("fresh snapshot did not observe released pin")
	}
}

func TestCleanupWaitsForPodDirectoryUsers(t *testing.T) {
	for _, copying := range []bool{false, true} {
		v := newView()
		key := pkey("gone")
		v.dirs[key] = dir(podapi.PhaseExited)
		v.podsGone[key] = true
		p := &plan{}
		if copying {
			p.liveCopies = []liveCopy{{pod: key, stateUID: "state", attachmentID: "working", commitID: "copy"}}
		} else {
			p.prepares = []prepare{{pod: key, req: storage.CreateWorking{AttachmentID: "working", FromCommit: "base"}}}
		}
		var scheduler Scheduler
		attempt := scheduler.Schedule(testNow, p.operations())[0]
		// The next snapshot has confirmed pod deletion, but an earlier worker
		// still owns the empty directory while preparing a device or thawing.
		scheduler.Schedule(testNow, nil)
		v.busy = scheduler.Busy()
		if got := compute(v); len(got.rmDirs) != 0 {
			t.Fatalf("copy=%v: removed directory while operation still running", copying)
		}
		scheduler.Complete(testNow, attempt, Canceled)
		v.busy = scheduler.Busy()
		if got := compute(v); !slices.Equal(got.rmDirs, []string{key}) {
			t.Fatalf("copy=%v: completed operation retained directory: %v", copying, got.rmDirs)
		}
	}
}
