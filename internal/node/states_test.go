// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// writerOnSelf returns a view where state "s" has its writer attachment a1 on
// pod p of this node, with a working volume.
func writerOnSelf() (*view, *v1alpha1.BlipState, *podDir) {
	v := newView()
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{self}
	s.Status.Writer = &v1alpha1.Writer{AttachmentID: "a1", PodName: "p", PodUID: "poduid-p", Node: self, BaseCommit: "c1"}
	v.states = append(v.states, s)
	v.pods[pkey("p")] = vmPod("p", "blipuid-b")
	d := dir(podapi.PhaseRunning)
	v.dirs[pkey("p")] = d
	v.volumes["c1"] = commit("c1", "uid-s")
	readyDev(v, d, storage.Volume{ID: "a1", StateUID: "uid-s"}, 5)
	return v, s, d
}

func TestSealDecision(t *testing.T) {
	v, _, _ := writerOnSelf()
	if p := compute(v); len(p.seals) != 0 || hasDelete(p, "a1") {
		t.Fatalf("sealed a running VM's disk: %+v", p)
	}

	// Fenced by VMM exit.
	v, _, d := writerOnSelf()
	d.observed.Phase = podapi.PhaseExited
	p := compute(v)
	want := seal{stateUID: "uid-s", attachmentID: "a1", commitID: SealCommitID("a1")}
	if len(p.seals) != 1 || p.seals[0] != want {
		t.Fatalf("seals = %+v", p.seals)
	}
	if hasDelete(p, "a1") {
		t.Fatalf("working volume deleted before seal")
	}

	// Fenced by a detached mount.
	v, _, d = writerOnSelf()
	d.observed.Mounts = []podapi.DiskStatus{{ID: "a1", Phase: podapi.DiskDetached}}
	if p := compute(v); len(p.seals) != 1 {
		t.Fatalf("detached: seals = %+v", p.seals)
	}

	// Pod gone only counts once confirmed by a live read.
	v, _, _ = writerOnSelf()
	delete(v.pods, pkey("p"))
	if p := compute(v); len(p.seals) != 0 {
		t.Fatalf("sealed on cache absence: %+v", p.seals)
	}
	v.podsGone[pkey("p")] = true
	if p := compute(v); len(p.seals) != 1 {
		t.Fatalf("pod gone: seals = %+v", p.seals)
	}

	// Sealed: report, delete the working volume.
	v, s, d := writerOnSelf()
	d.observed.Phase = podapi.PhaseExited
	c := SealCommitID("a1")
	v.volumes[c] = commit(c, "uid-s")
	p = compute(v)
	e := entryFor(p, "s")
	if len(p.seals) != 0 || e == nil || len(e.Sealed) != 1 || e.Sealed[0].CommitID != c || e.Sealed[0].AttachmentID != "a1" {
		t.Fatalf("sealed report: seals %+v entry %+v", p.seals, e)
	}
	if !hasDelete(p, "a1") || hasDelete(p, c) {
		t.Fatalf("deletes = %v", p.deletes)
	}

	// Processed by the controller: no longer reported, commit kept as pending.
	s.Status.Writer = nil
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: c, Generation: 2, SourceNode: self, AttachmentID: "a1", Replicas: []string{self}}
	s.Status.Nodes = []v1alpha1.NodeObservation{{Node: self, Incarnation: "inc-n1", Commits: []string{"c1", c},
		Sealed: []v1alpha1.SealResult{{AttachmentID: "a1", CommitID: c, SizeBytes: 1 << 30}}}}
	p = compute(v)
	if e := entryFor(p, "s"); e == nil || len(e.Sealed) != 0 || len(e.Commits) != 2 {
		t.Fatalf("pruned entry = %+v", e)
	}
	if hasDelete(p, c) || hasDelete(p, "c1") {
		t.Fatalf("deleted needed commit: %v", p.deletes)
	}

	// Unclean: report the error, keep the volume until the controller acts.
	v, _, d = writerOnSelf()
	d.observed.Phase = podapi.PhaseExited
	v.sealErrs["a1"] = storage.ErrUnclean.Error()
	p = compute(v)
	if e := entryFor(p, "s"); e == nil || len(e.Sealed) != 1 || e.Sealed[0].Error == "" || e.Sealed[0].CommitID != "" {
		t.Fatalf("unclean entry = %+v", e)
	}
	if len(p.seals) != 0 || hasDelete(p, "a1") {
		t.Fatalf("unclean: %+v", p)
	}
}

func TestEphemeralVolumesDeletedAfterFence(t *testing.T) {
	v := newView()
	v.pods[pkey("p")] = vmPod("p", "blipuid-b")
	d := dir(podapi.PhaseRunning)
	v.dirs[pkey("p")] = d
	readyDev(v, d, storage.Volume{ID: "root"}, 1)
	readyDev(v, d, storage.Volume{ID: "ro", StateUID: "uid-x", ReadOnly: true}, 2)
	v.volumes["orphan"] = storage.Volume{ID: "orphan", Kind: storage.KindWorking}
	p := compute(v)
	if hasDelete(p, "root") || hasDelete(p, "ro") || !hasDelete(p, "orphan") {
		t.Fatalf("running: deletes = %v", p.deletes)
	}
	d.observed.Mounts = []podapi.DiskStatus{{ID: "ro", Phase: podapi.DiskDetached}}
	if p := compute(v); hasDelete(p, "root") || !hasDelete(p, "ro") {
		t.Fatalf("detached: deletes = %v", p.deletes)
	}
	d.observed.Phase = podapi.PhaseExited
	if p := compute(v); !hasDelete(p, "root") {
		t.Fatalf("exited: deletes = %v", p.deletes)
	}

	// Volumes gone: remove device nodes, then the pod directory once the pod is gone.
	delete(v.volumes, "root")
	delete(v.volumes, "ro")
	delete(v.volumes, "orphan")
	if p := compute(v); len(p.rmDevs) != 2 || len(p.rmDirs) != 0 {
		t.Fatalf("rmDevs %v rmDirs %v", p.rmDevs, p.rmDirs)
	}
	d.devs = map[string]uint64{}
	delete(v.pods, pkey("p"))
	if p := compute(v); len(p.rmDirs) != 0 {
		t.Fatalf("removed dir without live confirmation")
	}
	v.podsGone[pkey("p")] = true
	if p := compute(v); len(p.rmDirs) != 1 {
		t.Fatalf("rmDirs = %v", p.rmDirs)
	}
}

func TestPendingDeletesRetriedByGC(t *testing.T) {
	v := newView()
	v.pending = []string{"a1"}
	if p := compute(v); !hasDelete(p, "a1") {
		t.Fatalf("pending delete not planned: %v", p.deletes)
	}
	// An operation already running on the ID gets its usual pass to finish.
	v.busy["a1"] = true
	if p := compute(v); hasDelete(p, "a1") {
		t.Fatalf("pending delete planned while busy: %v", p.deletes)
	}
}

func TestFetchPlanning(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{"n2", "n3"}
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: "n2", Replicas: []string{"n2", self}}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n3", "c1")}
	v.states = append(v.states, s)
	v.volumes["c1"] = commit("c1", "uid-s")

	if p := compute(v); len(p.fetches) != 0 {
		t.Fatalf("fetched before the source holds the commit: %+v", p.fetches)
	}
	s.Status.Nodes = append(s.Status.Nodes, holding("n2", "c1", "c2"))
	p := compute(v)
	if len(p.fetches) != 1 {
		t.Fatalf("fetches = %+v", p.fetches)
	}
	f := p.fetches[0]
	if f.owner != "uid-s" || f.src.node != "n2" || f.src.commitID != "c2" ||
		f.src.purpose != "replica" || len(f.src.bases) != 1 || f.src.bases[0] != "c1" {
		t.Fatalf("fetch = %+v", f)
	}
	v.busy[stateKey("uid-s")] = true
	if p := compute(v); len(p.fetches) != 0 {
		t.Fatalf("second fetch while one runs: %+v", p.fetches)
	}
	delete(v.busy, stateKey("uid-s"))

	// Repair: a placement lacking the committed commit fetches from a holder
	// with a current incarnation.
	v = newView()
	s = state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{"n2", self}
	stale := holding("n2", "c1")
	stale.Incarnation = "old"
	s.Status.Nodes = []v1alpha1.NodeObservation{stale}
	v.states = append(v.states, s)
	if p := compute(v); len(p.fetches) != 0 {
		t.Fatalf("fetched from a stale incarnation: %+v", p.fetches)
	}
	s.Status.Nodes = append(s.Status.Nodes, holding("n3", "c1"))
	p = compute(v)
	if len(p.fetches) != 1 || p.fetches[0].src.node != "n3" || p.fetches[0].src.commitID != "c1" {
		t.Fatalf("repair fetches = %+v", p.fetches)
	}

	// A draining node is still a healthy source of the commit it already
	// holds: draining blocks new placements, not serving an existing commit.
	// Without this, repair could never move the sole copy off a draining node.
	v = newView()
	s = state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{"n2", self}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	v.states = append(v.states, s)
	v.blipNodes["n2"].Spec.Drain = true
	p = compute(v)
	if len(p.fetches) != 1 || p.fetches[0].src.node != "n2" || p.fetches[0].src.commitID != "c1" {
		t.Fatalf("repair from draining sole holder = %+v (errors %v)", p.fetches, p.errs)
	}
}

func TestBuildPlanning(t *testing.T) {
	v := newView()
	img := state("img")
	img.Status.ImageDigest = imageRef
	img.Status.Pending = &v1alpha1.PendingCommit{CommitID: "i1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	empty := state("empty")
	empty.Status.Pending = &v1alpha1.PendingCommit{CommitID: "e1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	cp := state("cp")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-src", CommitID: "s1", Nodes: []string{"n3"}}
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	other := state("other")
	other.Status.Pending = &v1alpha1.PendingCommit{CommitID: "o1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2"}}
	v.states = append(v.states, img, empty, cp, other)

	p := compute(v)
	if len(p.imports) != 1 || p.imports[0].ref != imageRef {
		t.Fatalf("imports = %v", p.imports)
	}
	if len(p.builds) != 1 || p.builds[0].req.CommitID != "e1" || p.builds[0].req.SizeBytes != 1<<30 || p.builds[0].req.FromImage != "" {
		t.Fatalf("builds = %+v", p.builds)
	}
	if len(p.fetches) != 1 || p.fetches[0].owner != "uid-cp" || p.fetches[0].src.stateUID != "uid-src" ||
		p.fetches[0].src.purpose != "copy" || p.fetches[0].src.node != "n3" {
		t.Fatalf("copy source fetch = %+v", p.fetches)
	}

	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	v.configs[imageID] = nil
	v.volumes["s1"] = commit("s1", "uid-src")
	v.volumes["e1"] = commit("e1", "uid-empty")
	p = compute(v)
	builds := map[string]storage.CreateCommit{}
	for _, b := range p.builds {
		builds[b.req.CommitID] = b.req
	}
	if len(builds) != 2 || builds["i1"].FromImage != imageID || builds["k1"].FromCommit != "s1" {
		t.Fatalf("builds = %+v", builds)
	}
	if hasDelete(p, "s1") {
		t.Fatalf("deleted copy source of a copy in progress")
	}
}

// TestCopyReplicaBuildPlanning: a replica of a committed copy builds the new
// commit locally from the source commit it already holds. A replica without
// that source commit still fetches the new commit, and a live copy never
// builds from a committed base.
func TestCopyReplicaBuildPlanning(t *testing.T) {
	cases := []struct {
		name  string
		hold  bool
		live  bool
		build string
	}{
		{name: "holds source", hold: true, build: "k1"},
		{name: "base not held"},
		{name: "live copy", hold: true, live: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			cp := state("cp")
			cf := &v1alpha1.CopySource{StateUID: "uid-src", CommitID: "s1", Nodes: []string{"n3"}}
			if tc.live {
				cf.AttachmentID = "a1"
			}
			cp.Status.CopiedFrom = cf
			cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}}
			v.states = []*v1alpha1.BlipState{cp}
			if tc.hold {
				v.volumes["s1"] = commit("s1", "uid-src")
			}
			if tc.build == "" {
				// The source node published the new commit.
				cp.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "k1")}
			}

			p := compute(v)
			if tc.build != "" {
				if len(p.builds) != 1 || p.builds[0].req.CommitID != tc.build || p.builds[0].req.FromCommit != "s1" {
					t.Fatalf("builds = %+v", p.builds)
				}
				if len(p.fetches) != 0 {
					t.Fatalf("fetches = %+v", p.fetches)
				}
				return
			}
			if len(p.builds) != 0 || len(p.fetches) != 1 ||
				p.fetches[0].owner != "uid-cp" || p.fetches[0].src.commitID != "k1" || p.fetches[0].src.node != "n2" {
				t.Fatalf("builds = %+v fetches = %+v", p.builds, p.fetches)
			}
		})
	}
}

// TestImageBuildPlanning: every node converts images itself, so the initial
// version of an image state is built by each replica and placement instead
// of fetched, and commits built from an image are offered as bases only by
// content digest.
func TestImageBuildPlanning(t *testing.T) {
	gen1 := &v1alpha1.Commit{ID: "c1", Generation: 1}
	cases := []struct {
		name      string
		image     bool
		pending   *v1alpha1.PendingCommit
		committed *v1alpha1.Commit
		held      []storage.Volume
		build     string
		fetch     string
		bases     []string
		byDigest  []string
	}{
		{name: "pending gen 1, source", image: true,
			pending: &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: self, Replicas: []string{self, "n2"}}, build: "c1"},
		{name: "pending gen 1, other replica", image: true,
			pending: &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}}, build: "c1"},
		{name: "pending gen 1, held", image: true,
			pending: &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}},
			held:    []storage.Volume{{ID: "c1", Base: imageID}}},
		{name: "pending gen 1, not a replica", image: true,
			pending: &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2"}}},
		{name: "committed gen 1, placement lacking it", image: true, committed: gen1, build: "c1"},
		{name: "committed gen 2, placement lacking it", image: true,
			committed: &v1alpha1.Commit{ID: "c2", Generation: 2, AttachmentID: "a1"},
			held:      []storage.Volume{{ID: "c1", Base: imageID}, {ID: "c0", Base: "cx"}},
			fetch:     "c2", bases: []string{"c0"}, byDigest: []string{"c1"}},
		{name: "save replicating before gen 1 repair", image: true, committed: gen1,
			pending: &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: "n2", AttachmentID: "a1", Replicas: []string{"n2", self}},
			fetch:   "c2"},
		{name: "save replicated, gen 1 repair", image: true, committed: gen1,
			pending: &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: "n2", AttachmentID: "a1", Replicas: []string{"n2", self}},
			held:    []storage.Volume{{ID: "c2", Base: "c1"}}, build: "c1"},
		{name: "empty state, other replica",
			pending: &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}}, fetch: "c1"},
		{name: "empty state, committed gen 1 repair", committed: gen1, fetch: "c1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newView()
			v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
			s := state("s")
			if c.image {
				s.Status.ImageDigest = imageRef
			}
			s.Status.Pending, s.Status.Committed = c.pending, c.committed
			if c.committed != nil {
				s.Status.Placements = []string{"n2", self}
			}
			s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1", "c2")}
			v.states = append(v.states, s)
			for _, vol := range c.held {
				vol.Kind, vol.StateUID = storage.KindCommit, "uid-s"
				v.volumes[vol.ID] = vol
			}
			p := compute(v)
			var build, fetch string
			var bases, byDigest []string
			for _, b := range p.builds {
				if b.req.FromImage != imageID && c.image {
					t.Errorf("build %+v not from the image", b.req)
				}
				build += b.req.CommitID
			}
			for _, f := range p.fetches {
				fetch += f.src.commitID
				bases, byDigest = f.src.bases, f.src.imageBases
			}
			if build != c.build || fetch != c.fetch || !slices.Equal(bases, c.bases) || !slices.Equal(byDigest, c.byDigest) {
				t.Fatalf("build %q fetch %q bases %v by digest %v, want %q %q %v %v",
					build, fetch, bases, byDigest, c.build, c.fetch, c.bases, c.byDigest)
			}
		})
	}
}

func TestImageBuildErrors(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.ImageDigest = imageRef
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	v.states = append(v.states, s)
	v.stateErrs[imageKey(imageID)] = "pull failed"
	p := compute(v)
	if len(p.builds) != 0 || len(p.fetches) != 0 || len(p.imports) != 1 {
		t.Fatalf("builds %+v fetches %+v imports %v", p.builds, p.fetches, p.imports)
	}
	if e := entryFor(p, "s"); e == nil || e.Error != "pull failed" {
		t.Fatalf("entry = %+v", e)
	}

	// Not a replica: the import error is not reported for this state.
	s.Status.Pending.Replicas = []string{"n2"}
	if e := entryFor(compute(v), "s"); e != nil {
		t.Fatalf("entry = %+v", e)
	}
}

func TestDeltaBases(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.ImageDigest = imageRef
	v.states = append(v.states, s)
	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	other := "sha256:" + strings.Repeat("2", 64)
	v.volumes[other] = storage.Volume{ID: other, Kind: storage.KindImage}
	for _, vol := range []storage.Volume{
		{ID: "c1", Base: imageID}, // built from the state's image
		{ID: "c2", Base: "c1"},    // a save
		{ID: "c3"},                // fetched in full
		{ID: "c4", Base: other},   // built from another image
	} {
		vol.Kind, vol.StateUID = storage.KindCommit, "uid-s"
		v.volumes[vol.ID] = vol
	}
	v.volumes["c5"] = storage.Volume{ID: "c5", Kind: storage.KindCommit, StateUID: "uid-s", Base: imageID, Hydrating: true}
	p := compute(v)
	if got := v.bases("uid-s"); !slices.Equal(got, []string{"c2", "c3"}) {
		t.Fatalf("bases = %v", got)
	}
	// Commits built from an image are offered by content digest, computed
	// ahead of time.
	if got := v.imageBases("uid-s"); !slices.Equal(got, []string{"c1", "c4"}) {
		t.Fatalf("image bases = %v", got)
	}
	if !slices.Equal(p.digests, []string{"c1", "c4"}) {
		t.Fatalf("digests = %v", p.digests)
	}
	// The image volume itself may be gone; its ID still marks the commit.
	delete(v.volumes, imageID)
	delete(v.volumes, other)
	if got := v.bases("uid-s"); !slices.Equal(got, []string{"c2", "c3"}) {
		t.Fatalf("bases without the image volume = %v", got)
	}
	if got := v.imageBases("uid-s"); !slices.Equal(got, []string{"c1", "c4"}) {
		t.Fatalf("image bases without the image volume = %v", got)
	}
	for _, id := range []string{"c1", "c4"} {
		vol := v.volumes[id]
		vol.Digest = "v1:sha256:" + id
		v.volumes[id] = vol
	}
	v.busy[digestKey("c5")] = true
	if p := compute(v); len(p.digests) != 0 {
		t.Fatalf("digests = %v, want none", p.digests)
	}
	if e := entryFor(p, "s"); e == nil || len(e.Commits) != 5 {
		t.Fatalf("entry reports %+v, want every held commit", e)
	}
}

func TestCommitGC(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c3", Generation: 3}
	s.Status.Placements = []string{"n2", "n3"}
	v.states = append(v.states, s)
	for _, id := range []string{"c1", "c2", "c3", "lease", "rom"} {
		v.volumes[id] = commit(id, "uid-s")
	}
	v.pinned = map[string]bool{"lease": true}
	b := blip("b")
	b.Status.Node = "n9"
	b.Status.Mounts = []v1alpha1.MountStatus{{State: "s", StateUID: "uid-s", CommitID: "rom"}}
	v.blips = append(v.blips, b)
	v.volumes["gone1"] = commit("gone1", "uid-gone")
	v.volumes["gone2"] = commit("gone2", "uid-unconfirmed")
	v.statesGone["uid-gone"] = true

	p := compute(v)
	for _, id := range []string{"c1", "c2", "c3", "gone1"} {
		if !hasDelete(p, id) {
			t.Errorf("%s not deleted", id)
		}
	}
	for _, id := range []string{"lease", "rom", "gone2"} {
		if hasDelete(p, id) {
			t.Errorf("%s deleted", id)
		}
	}

	// Committed on a placement, and a base for a pending replica, are kept.
	s.Status.Placements = []string{self}
	if p := compute(v); hasDelete(p, "c3") {
		t.Errorf("committed commit on placement deleted")
	}
	s.Status.Placements = []string{"n2"}
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c4", Generation: 4, SourceNode: "n2", Replicas: []string{"n2", self}}
	if p := compute(v); hasDelete(p, "c3") {
		t.Errorf("delta base of a pending fetch deleted")
	}

	// Without a committed version nothing is judged older.
	s.Status.Committed = nil
	s.Status.Pending = nil
	if p := compute(v); hasDelete(p, "c1") {
		t.Errorf("deleted commit of a state with no committed version")
	}

	// A commit with a running operation is never deleted.
	s.Status.Committed = &v1alpha1.Commit{ID: "c3", Generation: 3}
	v.busy["c1"] = true
	if p := compute(v); hasDelete(p, "c1") {
		t.Errorf("deleted busy commit")
	}
}

func TestEntries(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{self}
	v.states = append(v.states, s)
	v.volumes["c1"] = commit("c1", "uid-s")
	v.stateErrs["uid-s"] = "boom"
	v.progress["uid-s"] = &v1alpha1.Transfer{CommitID: "c2", DoneBytes: 1, TotalBytes: 2}
	e := entryFor(compute(v), "s")
	if e == nil || e.Incarnation != "inc-n1" || len(e.Commits) != 1 || e.Error != "boom" || e.Fetching.DoneBytes != 1 {
		t.Fatalf("entry = %+v", e)
	}
	s.Status.Nodes = []v1alpha1.NodeObservation{*e}
	if p := compute(v); len(p.entries) != 0 {
		t.Fatalf("unchanged entry re-applied: %+v", p.entries)
	}

	// Nothing to report: remove our entry.
	v = newView()
	s = state("s")
	s.Status.Nodes = []v1alpha1.NodeObservation{holding(self, "c1")}
	v.states = append(v.states, s)
	p := compute(v)
	if len(p.entries) != 1 || p.entries[0].obs != nil {
		t.Fatalf("entries = %+v", p.entries)
	}
}

func hasDelete(p *plan, id string) bool {
	for _, d := range p.deletes {
		if d == id {
			return true
		}
	}
	return false
}

func entryFor(p *plan, name string) *v1alpha1.NodeObservation {
	for _, e := range p.entries {
		if e.name == name {
			return e.obs
		}
	}
	return nil
}

func TestImageRetention(t *testing.T) {
	a := &Agent{imageUsed: map[string]time.Time{}}
	v := newView()
	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	t0 := testNow

	s := state("s")
	s.Status.ImageDigest = imageRef
	v.states = []*v1alpha1.BlipState{s}
	if idle := a.idleImages(v, t0); idle[imageID] {
		t.Fatal("referenced image is idle")
	}
	v.states = nil
	if idle := a.idleImages(v, t0.Add(imageRetention/2)); idle[imageID] {
		t.Fatal("recently used image is idle")
	}
	v.idleImages = a.idleImages(v, t0.Add(2*imageRetention))
	if !v.idleImages[imageID] {
		t.Fatal("unused image is kept")
	}
	p := &plan{needed: map[string]bool{}}
	planGC(v, p, nil)
	if !slices.Contains(p.deletes, imageID) {
		t.Fatalf("deletes = %v, want the idle image", p.deletes)
	}
}

// TestHolderFailover: an unhealthy preferred source is not returned; another
// healthy holder is used instead.
func TestHolderFailover(t *testing.T) {
	setup := func() (*view, *v1alpha1.BlipState) {
		v := newView()
		s := state("s")
		s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: "n2", Replicas: []string{"n2", self}}
		s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c2"), holding("n3", "c2")}
		v.states = append(v.states, s)
		return v, s
	}
	cases := []struct {
		name   string
		damage func(*view)
	}{
		{"stale heartbeat", func(v *view) {
			old := metav1.NewTime(testNow.Add(-2 * nodeHeartbeatTTL))
			v.blipNodes["n2"].Status.Heartbeat = &old
		}},
		{"draining", func(v *view) { v.blipNodes["n2"].Spec.Drain = true }},
		{"no endpoint", func(v *view) { v.blipNodes["n2"].Status.Endpoint = "" }},
		{"invalid endpoint", func(v *view) { v.blipNodes["n2"].Status.Endpoint = "node.example" }},
		{"IPv6 endpoint", func(v *view) { v.blipNodes["n2"].Status.Endpoint = "2001:db8::2" }},
		{"no TLS identity", func(v *view) { v.blipNodes["n2"].Status.TLSPublicKey = "" }},
		{"invalid TLS identity", func(v *view) { v.blipNodes["n2"].Status.TLSPublicKey = "invalid" }},
		{"incarnation mismatch", func(v *view) { v.blipNodes["n2"].Status.Incarnation = "new" }},
		{"kubernetes node gone", func(v *view) { delete(v.kubeNodes, "n2") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, _ := setup()
			c.damage(v)
			p := compute(v)
			if len(p.fetches) != 1 || p.fetches[0].src.node != "n3" {
				t.Fatalf("fetches = %+v", p.fetches)
			}
		})
	}

	// A draining pending source still serves the commit it sealed: draining
	// forbids new placements, not reading an existing commit. Without this a
	// drain during a save would leave every replica on "no healthy holder".
	v, st := setup()
	v.blipNodes["n2"].Spec.Drain = true
	v.blipNodes["n3"].Spec.Drain = true
	p := compute(v)
	if len(p.fetches) != 1 || p.fetches[0].src.node != "n2" || p.fetches[0].src.commitID != "c2" {
		t.Fatalf("fetch from draining pending source = %+v", p.fetches)
	}

	// The exception is limited to the pending source. A different draining
	// holder does not stand in for a source that lacks the commit.
	v, st = setup()
	v.blipNodes["n2"].Spec.Drain = true
	v.blipNodes["n3"].Spec.Drain = true
	st.Status.Nodes = []v1alpha1.NodeObservation{holding("n3", "c2")}
	p = compute(v)
	if len(p.fetches) != 0 {
		t.Fatalf("fetches = %+v", p.fetches)
	}
	if e := entryFor(p, "s"); e == nil || !strings.Contains(e.Error, "no healthy holder") {
		t.Fatalf("entry = %+v", e)
	}
}

// TestInitialReplicaWaitsForSource: a generation-1 replica does not report an
// error while its healthy source has not published the initial commit.
func TestInitialReplicaWaitsForSource(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: "n2", Replicas: []string{self, "n2"}}
	v.states = append(v.states, s)

	p := compute(v)
	if len(p.fetches) != 0 {
		t.Fatalf("fetches = %+v", p.fetches)
	}
	if e := entryFor(p, "s"); e != nil && e.Error != "" {
		t.Fatalf("replica error while the source builds: %+v", e)
	}

	// Once the source publishes the commit, the replica fetches it.
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	p = compute(v)
	if len(p.fetches) != 1 || p.fetches[0].src.node != "n2" {
		t.Fatalf("fetches = %+v", p.fetches)
	}

	// An unhealthy source is still reported: it cannot publish the commit.
	v.blipNodes["n2"].Spec.Drain = true
	p = compute(v)
	if e := entryFor(p, "s"); e == nil || !strings.Contains(e.Error, "no healthy holder") {
		t.Fatalf("entry = %+v", e)
	}
}

func TestSourcesSkipAmbiguousIdentities(t *testing.T) {
	for _, duplicateOf := range []string{"n3", self} {
		t.Run("duplicate of "+duplicateOf, func(t *testing.T) {
			v := newView()
			n4 := v.blipNodes["n3"].DeepCopy()
			n4.Name = "n4"
			n4.Status.Incarnation = "inc-n4"
			n4.Status.Endpoint = "192.0.2.4"
			n4.Status.TLSPublicKey = testPublicKey("n4")
			v.blipNodes[n4.Name] = n4
			v.kubeNodes[n4.Name] = v.kubeNodes["n3"].DeepCopy()
			v.kubeNodes[n4.Name].Name = n4.Name
			v.blipNodes["n2"].Status.TLSPublicKey = v.blipNodes[duplicateOf].Status.TLSPublicKey
			s := state("src")
			s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1"), holding("n4", "c1")}
			v.states = append(v.states, s)
			v.index()
			if got := v.holder(s, "c1", "n2"); got == nil || got.node != "n4" {
				t.Fatalf("holder = %+v, want trusted n4", got)
			}
			cf := &v1alpha1.CopySource{StateUID: string(s.UID), CommitID: "c1", Nodes: []string{"n2", "n4"}}
			if got := v.copySource(cf); got == nil || got.node != "n4" {
				t.Fatalf("copy holder = %+v, want trusted n4", got)
			}
			// With the source gone, captured nodes obey the same trust rules.
			cf.StateUID = "uid-gone"
			if got := v.copySource(cf); got == nil || got.node != "n4" {
				t.Fatalf("captured copy source = %+v, want trusted n4", got)
			}
		})
	}
}

// TestPendingSourceFetchesFromAnotherHolder: a pending source that lost its
// commit fetches from another holder instead of refusing because it is named
// as the source.
func TestPendingSourceFetchesFromAnotherHolder(t *testing.T) {
	v := newView()
	s := state("s")
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c2", Generation: 2, SourceNode: self, AttachmentID: "a1", Replicas: []string{self, "n2"}}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n3", "c2")}
	v.states = append(v.states, s)
	p := compute(v)
	if len(p.fetches) != 1 || p.fetches[0].src.node != "n3" || p.fetches[0].src.commitID != "c2" {
		t.Fatalf("fetches = %+v", p.fetches)
	}

	// Holding the commit locally skips the fetch.
	v.volumes["c2"] = commit("c2", "uid-s")
	if p := compute(v); len(p.fetches) != 0 {
		t.Fatalf("fetched a locally held commit: %+v", p.fetches)
	}
}

// TestCopySourceIncarnation checks the captured-node fallback validates the
// incarnation when an observation exists.
func TestCopySourceIncarnation(t *testing.T) {
	v := newView()
	src := state("src")
	src.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	cp := state("cp")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: string(src.UID), CommitID: "c1", Nodes: []string{"n2", "n3"}}
	v.states = append(v.states, src, cp)
	v.blipNodes["n2"].Status.Incarnation = "new"
	v.index()
	if got := v.copySource(cp.Status.CopiedFrom); got == nil || got.node != "n3" {
		t.Fatalf("copy source = %+v", got)
	}
}

// TestCopySourceRequiresServingPeer: an unhealthy or stale peer cannot serve
// a copy. Draining alone does not disqualify one (see
// TestCopySourceServingHolder), but every other liveness condition does.
func TestCopySourceRequiresServingPeer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(*v1alpha1.BlipNode)
	}{
		{"missing endpoint", func(n *v1alpha1.BlipNode) { n.Status.Endpoint = "" }},
		{"invalid endpoint", func(n *v1alpha1.BlipNode) { n.Status.Endpoint = "node.example" }},
		{"missing identity", func(n *v1alpha1.BlipNode) { n.Status.TLSPublicKey = "" }},
		{"invalid identity", func(n *v1alpha1.BlipNode) { n.Status.TLSPublicKey = "invalid" }},
		{"missing heartbeat", func(n *v1alpha1.BlipNode) { n.Status.Heartbeat = nil }},
		{"stale heartbeat", func(n *v1alpha1.BlipNode) {
			old := metav1.NewTime(testNow.Add(-2 * nodeHeartbeatTTL))
			n.Status.Heartbeat = &old
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			v.index()
			cf := &v1alpha1.CopySource{StateUID: "uid-gone", CommitID: "c1", Nodes: []string{"n2", "n3"}}
			tc.damage(v.blipNodes["n2"])
			if got := v.copySource(cf); got == nil || got.node != "n3" {
				t.Fatalf("copy source = %+v", got)
			}
			tc.damage(v.blipNodes["n3"])
			if got := v.copySource(cf); got != nil {
				t.Fatalf("selected unhealthy copy source = %+v", got)
			}
		})
	}
}

// TestCopySourceServingHolder: a committed copy source held only by a healthy
// draining node still serves the copy. Draining forbids new placements, not
// reading a commit the node already sealed. The captured-node fallback follows
// the same rule.
func TestCopySourceServingHolder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		drain      bool
		sourceGone bool
	}{
		{name: "healthy holder"},
		{name: "draining holder", drain: true},
		{name: "draining captured holder", drain: true, sourceGone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			src := state("src")
			src.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
			src.Status.Placements = []string{"n2"}
			src.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
			cf := &v1alpha1.CopySource{StateUID: string(src.UID), CommitID: "c1", Nodes: []string{"n2"}}
			if tc.sourceGone {
				cf.StateUID = "uid-gone"
			}
			cp := state("cp")
			cp.Status.CopiedFrom = cf
			cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: self, Replicas: []string{self}}
			v.states = []*v1alpha1.BlipState{src, cp}
			if tc.drain {
				v.blipNodes["n2"].Spec.Drain = true
			}

			p := compute(v)
			if len(p.builds) != 0 || len(p.fetches) != 1 || p.fetches[0].owner != "uid-cp" ||
				p.fetches[0].src.node != "n2" || p.fetches[0].src.commitID != "c1" {
				t.Fatalf("plan builds=%+v fetches=%+v errs=%v", p.builds, p.fetches, p.errs)
			}
			if p.errs["uid-cp"] != "" {
				t.Fatalf("unexpected copy source error: %q", p.errs["uid-cp"])
			}
		})
	}
}

// TestCopySourceUnavailableReportsError: a copy whose committed source has no
// readable holder must report why instead of planning nothing, so the
// controller can surface a bounded failure rather than a silent wait.
func TestCopySourceUnavailableReportsError(t *testing.T) {
	v := newView()
	src := state("src")
	src.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	src.Status.Placements = []string{"n2"}
	src.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	cp := state("cp")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: string(src.UID), CommitID: "c1", Nodes: []string{"n2"}}
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	v.states = []*v1alpha1.BlipState{src, cp}
	old := metav1.NewTime(testNow.Add(-2 * nodeHeartbeatTTL))
	v.blipNodes["n2"].Status.Heartbeat = &old

	p := compute(v)
	if len(p.builds) != 0 || len(p.fetches) != 0 {
		t.Fatalf("planned work without a readable source: builds=%+v fetches=%+v", p.builds, p.fetches)
	}
	if msg := p.errs["uid-cp"]; !strings.Contains(msg, "copy source") {
		t.Fatalf("copy source error = %q", msg)
	}
	if e := entryFor(p, "cp"); e == nil || !strings.Contains(e.Error, "copy source") {
		t.Fatalf("copy entry = %+v", e)
	}
}

// liveCopyOnSelf returns a view where state "s" has a running writer a1 (the
// root of pod p) on this node and state "cp" is a live copy of it built here.
func liveCopyOnSelf() (*view, *v1alpha1.BlipState, *podDir) {
	v, _, d := writerOnSelf()
	d.desired = &podapi.Desired{Claim: &podapi.Claim{Root: disk("a1", false)}}
	cp := state("cp")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: "uid-s", AttachmentID: "a1", Nodes: []string{self}}
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: self, Replicas: []string{self, "n2"}}
	v.states = append(v.states, cp)
	return v, cp, d
}

func TestLiveCopyPlanning(t *testing.T) {
	v, _, _ := liveCopyOnSelf()
	p := compute(v)
	want := liveCopy{pod: pkey("p"), stateUID: "uid-cp", attachmentID: "a1", commitID: "k1"}
	if len(p.liveCopies) != 1 || p.liveCopies[0] != want || len(p.builds) != 0 || len(p.fetches) != 0 || len(p.seals) != 0 {
		t.Fatalf("plan = live %+v builds %+v fetches %+v seals %+v", p.liveCopies, p.builds, p.fetches, p.seals)
	}

	v.busy["a1"] = true
	if p := compute(v); len(p.liveCopies) != 0 {
		t.Fatalf("live copy while the attachment is busy: %+v", p.liveCopies)
	}

	// A writable mount qualifies once the guest mounted it.
	v, _, d := liveCopyOnSelf()
	d.desired.Claim.Root = disk("r0", false)
	d.observed.Mounts = []podapi.DiskStatus{{ID: "a1", Phase: podapi.DiskAttaching}}
	if p := compute(v); len(p.liveCopies) != 0 || p.errs["uid-cp"] != "" {
		t.Fatalf("live copy of an unmounted disk: %+v %v", p.liveCopies, p.errs)
	}
	d.observed.Mounts[0].Phase = podapi.DiskMounted
	if p := compute(v); len(p.liveCopies) != 1 {
		t.Fatalf("mount: live copies = %+v", p.liveCopies)
	}

	// No running VM: the controller replans or the pending build times out;
	// it is transient, not a permanent state error.
	v, _, d = liveCopyOnSelf()
	d.observed.Phase = podapi.PhaseExited
	p = compute(v)
	if e := entryFor(p, "cp"); len(p.liveCopies) != 0 || e != nil {
		t.Fatalf("exited VM: live %+v entry %+v", p.liveCopies, e)
	}

	// Only the source node snapshots; replicas fetch the commit from it.
	v, cp, _ := liveCopyOnSelf()
	cp.Status.Pending = &v1alpha1.PendingCommit{CommitID: "k1", Generation: 1, SourceNode: "n2", Replicas: []string{"n2", self}}
	cp.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "k1")}
	p = compute(v)
	if len(p.liveCopies) != 0 || len(p.fetches) != 1 || p.fetches[0].src.node != "n2" ||
		p.fetches[0].src.stateUID != "uid-cp" || p.fetches[0].src.commitID != "k1" {
		t.Fatalf("replica: live %+v fetches %+v", p.liveCopies, p.fetches)
	}

	// Done: report the commit, keep it and the source's working volume.
	v, _, _ = liveCopyOnSelf()
	v.volumes["k1"] = storage.Volume{ID: "k1", Kind: storage.KindCommit, StateUID: "uid-cp", Base: "c1", SizeBytes: 1 << 30}
	p = compute(v)
	if e := entryFor(p, "cp"); len(p.liveCopies) != 0 || e == nil || len(e.Commits) != 1 || e.Commits[0] != "k1" || e.Error != "" {
		t.Fatalf("done: live %+v entry %+v", p.liveCopies, e)
	}
	if hasDelete(p, "k1") || hasDelete(p, "a1") || hasDelete(p, "c1") {
		t.Fatalf("deletes = %v", p.deletes)
	}
}
