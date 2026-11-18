package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

func TestWarmLabelAndObservedAnnotation(t *testing.T) {
	v := newView()
	v.pods[pkey("p1")] = vmPod("p1", "")
	v.dirs[pkey("p1")] = dir(podapi.PhaseWarm)
	claimed := vmPod("p2", "blipuid-x")
	claimed.Labels[LabelWarm] = "true"
	v.pods[pkey("p2")] = claimed
	v.dirs[pkey("p2")] = dir(podapi.PhaseWarm)
	same := vmPod("p3", "")
	same.Labels[LabelWarm] = "true"
	data, _ := json.Marshal(podapi.Observed{Phase: podapi.PhaseWarm})
	same.Annotations = map[string]string{AnnotationObserved: string(data)}
	v.pods[pkey("p3")] = same
	v.dirs[pkey("p3")] = dir(podapi.PhaseWarm)

	p := compute(v)
	got := map[string]podMeta{}
	for _, m := range p.podMeta {
		got[m.name] = m
	}
	if m := got["p1"]; !m.warm || m.observed != string(data) {
		t.Errorf("p1 meta = %+v", m)
	}
	if m, ok := got["p2"]; !ok || m.warm {
		t.Errorf("claimed pod keeps warm label: %+v", m)
	}
	if _, ok := got["p3"]; ok {
		t.Errorf("unchanged pod patched")
	}
	for _, key := range []string{pkey("p1"), pkey("p2"), pkey("p3")} {
		if d := p.desired[key]; d.Network == nil || !sameJSON(d.Network, denyNetwork()) || d.Claim != nil {
			t.Errorf("vacant or unresolved pod lacks default deny: %s: %+v", key, d)
		}
	}
}

func imageBlip(v *view) (*v1alpha1.Blip, *podDir) {
	b := blip("b")
	b.Spec.Image = "img"
	b.Spec.Env = []v1alpha1.EnvVar{{Name: "A", Value: "1"}}
	b.Status.ImageDigest = imageRef
	b.Status.RootAttachmentID = "r1"
	v.blips = append(v.blips, b)
	v.pods[pkey("p")] = vmPod("p", string(b.UID))
	d := dir(podapi.PhaseWarm)
	v.dirs[pkey("p")] = d
	v.configs[imageID] = &image.Config{Env: []string{"PATH=/bin"}, WorkingDir: "/w"}
	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	return b, d
}

func TestImageRootClaim(t *testing.T) {
	v := newView()
	_, d := imageBlip(v)
	p := compute(v)
	if len(p.prepares) != 1 || p.prepares[0].req.FromImage != imageID || p.prepares[0].req.AttachmentID != "r1" || p.prepares[0].pod != pkey("p") ||
		p.prepares[0].req.SizeBytes != defaultRootSize {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	if got := p.desired[pkey("p")]; got.Claim != nil || got.Network == nil {
		t.Fatalf("network must precede the claim while the disk is not ready: %+v", got)
	}

	v = newView()
	_, d = imageBlip(v)
	readyDev(v, d, storage.Volume{ID: "r1"}, 7)
	p = compute(v)
	if len(p.prepares) != 0 {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	c := p.desired[pkey("p")].Claim
	if c == nil || c.Root.Device != "/run/blip/dev/r1" || c.Root.Serial != "r1" || c.WorkingDir != "/w" ||
		len(c.Env) != 2 || c.Env[0] != "PATH=/bin" || c.Env[1] != "A=1" || c.IdleTimeoutSeconds != 30 {
		t.Fatalf("claim = %+v", c)
	}

	// A stale device node (different device number) is replaced.
	d.devs["r1"] = 8
	d.desired = &podapi.Desired{}
	p = compute(v)
	if len(p.prepares) != 1 || !p.prepares[0].exists {
		t.Fatalf("prepares = %+v", p.prepares)
	}
}

func TestIdleTimeoutOverride(t *testing.T) {
	v := newView()
	b, d := imageBlip(v)
	b.Spec.IdleTimeout = &metav1.Duration{Duration: 45 * time.Second}
	readyDev(v, d, storage.Volume{ID: "r1"}, 7)
	p := compute(v)
	if c := p.desired[pkey("p")].Claim; c == nil || c.IdleTimeoutSeconds != 45 {
		t.Fatalf("claim with idle timeout = %+v", c)
	}
}

func stateRoot(v *view) (*v1alpha1.Blip, *v1alpha1.BlipState, *podDir) {
	s := state("root")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Placements = []string{"n2"}
	s.Status.Nodes = []v1alpha1.NodeObservation{holding("n2", "c1")}
	b := blip("b")
	b.Spec.State = "root"
	b.Spec.Command = []string{"true"}
	b.Status.RootAttachmentID = "r1"
	s.Status.Writer = &v1alpha1.Writer{AttachmentID: "r1", BlipUID: string(b.UID), Node: self, BaseCommit: "c1"}
	v.states = append(v.states, s)
	v.blips = append(v.blips, b)
	v.pods[pkey("p")] = vmPod("p", string(b.UID))
	d := dir(podapi.PhaseWarm)
	v.dirs[pkey("p")] = d
	return b, s, d
}

func TestStateRootWaitsForWriterPod(t *testing.T) {
	v := newView()
	_, s, _ := stateRoot(v)
	p := compute(v)
	if len(p.prepares) != 0 || p.desired[pkey("p")].Stop {
		t.Fatalf("acted before writer.podUID was set: %+v %+v", p.prepares, p.desired)
	}

	s.Status.Writer.PodUID = "poduid-p"
	p = compute(v)
	if len(p.prepares) != 1 {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	pr := p.prepares[0]
	if pr.src == nil || pr.src.node != "n2" || pr.src.purpose != "attach" || pr.src.commitID != "c1" ||
		pr.req.StateUID != "uid-root" || pr.req.SizeBytes != 1<<30 || pr.req.ReadOnly {
		t.Fatalf("remote prepare = %+v src %+v", pr, pr.src)
	}

	v.volumes["c1"] = commit("c1", "uid-root")
	p = compute(v)
	if len(p.prepares) != 1 || p.prepares[0].req.FromCommit != "c1" || p.prepares[0].src != nil {
		t.Fatalf("local prepare = %+v", p.prepares)
	}
}

func TestStop(t *testing.T) {
	claimed := func() (*view, *v1alpha1.Blip, *v1alpha1.BlipState, *podDir) {
		v := newView()
		b, s, d := stateRoot(v)
		s.Status.Writer.PodUID = "poduid-p"
		readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)
		d.observed.Phase = podapi.PhaseRunning
		// Pin deny so this test exercises stop semantics, not the pool default.
		v.pools[ns+"/default"].Spec.Network = &v1alpha1.NetworkPolicy{}
		d.desired = &podapi.Desired{Claim: claimFor(b, disk("r1", false), nil), Network: denyNetwork()}
		return v, b, s, d
	}

	v, _, _, _ := claimed()
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("steady state rewrote desired: %+v", p.desired)
	}

	v, b, _, _ := claimed()
	b.Spec.Stop = true
	if d := compute(v).desired[pkey("p")]; !d.Stop || d.Claim == nil {
		t.Fatalf("spec.stop: %+v", d)
	}

	v, b, _, _ = claimed()
	b.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	if d := compute(v).desired[pkey("p")]; !d.Stop {
		t.Fatalf("deleting blip: %+v", d)
	}

	v, b, _, _ = claimed()
	v.blips = nil
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("blip missing from cache only: %+v", p.desired)
	}
	v.blipsGone[string(b.UID)] = true
	if d := compute(v).desired[pkey("p")]; !d.Stop || d.Claim == nil || d.Claim.Root.ID != "r1" {
		t.Fatalf("blip gone: %+v", d)
	}

	v, _, s, _ := claimed()
	s.Status.Writer = nil
	if d := compute(v).desired[pkey("p")]; !d.Stop || d.Claim == nil {
		t.Fatalf("writer lost: %+v", d)
	}

	// Stop is sticky.
	v, _, _, dd := claimed()
	dd.desired.Stop = true
	if p := compute(v); len(p.desired) != 0 {
		t.Fatalf("stop reverted: %+v", p.desired)
	}

	// No new disks once the VM exited.
	v, b, _, dd = claimed()
	dd.observed.Phase = podapi.PhaseExited
	b.Status.Mounts = []v1alpha1.MountStatus{{State: "x", Path: "/x", StateUID: "uid-x", CommitID: "cx", AttachmentID: "m1", Phase: v1alpha1.MountPending}}
	v.volumes["cx"] = commit("cx", "uid-x")
	if p := compute(v); len(p.prepares) != 0 || len(p.desired) != 0 {
		t.Fatalf("exited pod: %+v %+v", p.prepares, p.desired)
	}
}

func TestMounts(t *testing.T) {
	v := newView()
	b, s, d := stateRoot(v)
	s.Status.Writer.PodUID = "poduid-p"
	readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)

	data := state("data")
	data.Status.Committed = &v1alpha1.Commit{ID: "d1", Generation: 1}
	data.Status.Writer = &v1alpha1.Writer{AttachmentID: "mw", PodUID: "poduid-p", Node: self, BaseCommit: "d1"}
	ro := state("ro")
	v.states = append(v.states, data, ro)
	v.volumes["d1"] = commit("d1", "uid-data")
	readyDev(v, d, storage.Volume{ID: "mr", StateUID: "uid-ro", ReadOnly: true}, 9)
	b.Status.Mounts = []v1alpha1.MountStatus{
		{State: "data", Path: "/data", Writable: true, StateUID: "uid-data", CommitID: "d1", AttachmentID: "mw", Phase: v1alpha1.MountPending},
		{State: "ro", Path: "/ro", StateUID: "uid-ro", CommitID: "r9", AttachmentID: "mr", Phase: v1alpha1.MountMounted},
		{State: "old", Path: "/old", StateUID: "uid-old", CommitID: "o1", AttachmentID: "mo", Phase: v1alpha1.MountUnmounting},
	}

	p := compute(v)
	des := p.desired[pkey("p")]
	// The claim waits until every mount is ready.
	if des.Claim != nil || len(des.Mounts) != 0 {
		t.Fatalf("desired = %+v", des)
	}
	if len(p.prepares) != 1 || p.prepares[0].req.AttachmentID != "mw" || p.prepares[0].req.FromCommit != "d1" || p.prepares[0].req.SizeBytes != 1<<30 {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	if !p.needed["mw"] || !p.needed["mr"] || p.needed["mo"] {
		t.Fatalf("needed = %v", p.needed)
	}

	readyDev(v, d, storage.Volume{ID: "mw", StateUID: "uid-data"}, 8)
	des = compute(v).desired[pkey("p")]
	if des.Claim == nil || len(des.Mounts) != 2 || des.Mounts[0].ID != "mw" || des.Mounts[0].ReadOnly ||
		des.Mounts[1].ID != "mr" || !des.Mounts[1].ReadOnly || des.Mounts[1].Path != "/ro" || des.Mounts[1].State != "ro" {
		t.Fatalf("desired = %+v", des)
	}
}

// TestSamePodNameDifferentNamespaces proves identically named pods in two
// namespaces get separate plans, pod directories, and device nodes.
func TestSamePodNameDifferentNamespaces(t *testing.T) {
	v := newView()
	v.configs[imageID] = &image.Config{Env: []string{"PATH=/bin"}}
	v.volumes[imageID] = storage.Volume{ID: imageID, Kind: storage.KindImage}
	for i, namespace := range []string{"one", "two"} {
		b := &v1alpha1.Blip{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "b", UID: types.UID("uid-b-" + namespace)},
		}
		b.Spec.Image = "img"
		b.Status.ImageDigest = imageRef
		b.Status.RootAttachmentID = []string{"r1", "r2"}[i]
		v.blips = append(v.blips, b)
		pod := vmPod("p", string(b.UID))
		pod.Namespace = namespace
		v.pods[podKey(namespace, "p")] = pod
		v.dirs[podKey(namespace, "p")] = dir(podapi.PhaseWarm)
	}

	p := compute(v)
	if len(p.prepares) != 2 {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	preps := map[string]string{}
	for _, pr := range p.prepares {
		preps[pr.pod] = pr.req.AttachmentID
	}
	if preps[podKey("one", "p")] != "r1" || preps[podKey("two", "p")] != "r2" {
		t.Fatalf("prepares = %+v", p.prepares)
	}
	if podDirFor(podapi.DataDir, podKey("one", "p")) == podDirFor(podapi.DataDir, podKey("two", "p")) {
		t.Fatal("same-named pods share a directory")
	}
	if got, want := podDirFor(podapi.DataDir, podKey("one", "p")), podapi.PodDir("one", "p"); got != want {
		t.Fatalf("pod dir = %q, want %q", got, want)
	}

	for i, namespace := range []string{"one", "two"} {
		readyDev(v, v.dirs[podKey(namespace, "p")], storage.Volume{ID: []string{"r1", "r2"}[i]}, uint64(10+i))
	}
	p = compute(v)
	if len(p.desired) != 2 {
		t.Fatalf("desired = %+v", p.desired)
	}
	for i, namespace := range []string{"one", "two"} {
		claim := p.desired[podKey(namespace, "p")].Claim
		if claim == nil || claim.Root.ID != []string{"r1", "r2"}[i] {
			t.Fatalf("%s claim = %+v", namespace, claim)
		}
	}
}

// TestReadPodDirsNamespaces checks the snapshot walks namespace directories.
func TestReadPodDirsNamespaces(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"one/p", "two/p"} {
		namespace, name, _ := strings.Cut(key, "/")
		dir := filepath.Join(root, namespace, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := podapi.WriteJSON(filepath.Join(dir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
			t.Fatal(err)
		}
	}
	dirs := readPodDirs(root)
	if len(dirs) != 2 || dirs["one/p"] == nil || dirs["two/p"] == nil {
		t.Fatalf("dirs = %v", dirs)
	}
}

// TestStateConfigPersisted: the state's own ImageConfig wins over the cached
// live source, and a copy keeps its config after the source is deleted.
func TestStateConfigPersisted(t *testing.T) {
	v := newView()
	cfg := &v1alpha1.ImageConfig{Env: []string{"A=1"}, Entrypoint: []string{"/bin/e"}, Cmd: []string{"c"}, WorkingDir: "/w", User: "u"}

	img := state("img")
	img.Status.ImageDigest = imageRef
	img.Status.ImageConfig = cfg
	v.states = append(v.states, img)
	v.configs[imageID] = &image.Config{Env: []string{"STALE=1"}}
	v.index()
	if got := v.stateConfig(img); got == nil || len(got.Env) != 1 || got.Env[0] != "A=1" || got.User != "u" {
		t.Fatalf("image config = %+v", got)
	}

	// A copy resolved while the source existed inherits its config.
	src := state("src")
	src.Status.ImageConfig = cfg
	cp := state("cp")
	cp.Status.CopiedFrom = &v1alpha1.CopySource{StateUID: string(src.UID), CommitID: "c1"}
	v.states = append(v.states, src, cp)
	v.index()
	if got := v.stateConfig(cp); got == nil || got.WorkingDir != "/w" {
		t.Fatalf("inherited config = %+v", got)
	}

	// The controller persists the inherited config on the copy; deleting the
	// source then changes nothing.
	cp.Status.ImageConfig = cfg
	v.states = []*v1alpha1.BlipState{cp}
	v.index()
	if got := v.stateConfig(cp); got == nil || got.User != "u" || got.Cmd[0] != "c" || got.Entrypoint[0] != "/bin/e" {
		t.Fatalf("persisted copy config = %+v", got)
	}
}

func TestPodMetaUsesNamespace(t *testing.T) {
	v := newView()
	pod := vmPod("p", "")
	pod.Namespace = "other"
	v.pods[podKey("other", "p")] = pod
	v.dirs[podKey("other", "p")] = dir(podapi.PhaseWarm)
	m, ok := podMetaFor(pod, v.dirs[podKey("other", "p")])
	if !ok || m.namespace != "other" || m.name != "p" {
		t.Fatalf("meta = %+v", m)
	}
}

func TestFreezeDesired(t *testing.T) {
	v := newView()
	b, s, d := stateRoot(v)
	s.Status.Writer.PodUID = "poduid-p"
	s.Status.Writer.PodName = "p"
	d.observed.Phase = podapi.PhaseRunning
	readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)
	d.desired = &podapi.Desired{Claim: claimFor(b, disk("r1", false), nil)}
	v.freezes = map[string][]string{pkey("p"): {"r1"}}
	if got := compute(v).desired[pkey("p")]; len(got.Freeze) != 1 || got.Freeze[0] != "r1" || got.Claim == nil {
		t.Fatalf("freeze desired = %+v", got)
	}
	d.desired.Freeze = []string{"r1"}
	v.freezes = nil
	if got, ok := compute(v).desired[pkey("p")]; !ok || len(got.Freeze) != 0 || got.Claim == nil {
		t.Fatalf("thaw desired = %+v (written %v)", got, ok)
	}
}
