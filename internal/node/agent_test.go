// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/registryauth"
	"github.com/Azure/blip/internal/storage"
)

type fakeStore struct {
	mu          sync.Mutex
	volumes     map[string]storage.Volume
	pending     map[string]bool
	deleted     []string
	imports     map[string]int64
	createErr   error
	activations int
}

func newFakeStore() *fakeStore {
	return &fakeStore{volumes: map[string]storage.Volume{}, pending: map[string]bool{}, imports: map[string]int64{}}
}

func (f *fakeStore) Incarnation() string { return "inc-n1" }
func (f *fakeStore) FreeBytes() int64    { return 1 << 40 }

func (f *fakeStore) List() []storage.Volume {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []storage.Volume
	for _, v := range f.volumes {
		out = append(out, v)
	}
	return out
}

func (f *fakeStore) PendingDeletes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.pending {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func (f *fakeStore) setPending(ids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		f.pending[id] = true
	}
}

func (f *fakeStore) add(v storage.Volume) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.volumes[v.ID] = v
}

// CreateImage records the size; it does not call fill, which would run mke2fs.
func (f *fakeStore) CreateImage(ctx context.Context, id string, size int64, fill func(dev string) error) error {
	f.mu.Lock()
	f.imports[id] = size
	f.mu.Unlock()
	f.add(storage.Volume{ID: id, Kind: storage.KindImage, SizeBytes: size})
	return nil
}

func (f *fakeStore) CreateCommit(ctx context.Context, req storage.CreateCommit) error {
	f.add(storage.Volume{ID: req.CommitID, Kind: storage.KindCommit, StateUID: req.StateUID, SizeBytes: req.SizeBytes,
		Base: req.FromImage + req.FromCommit})
	return nil
}

func (f *fakeStore) FetchCommit(ctx context.Context, stateUID, commitID string, src storage.Remote, progress func(done, total int64)) error {
	f.add(storage.Volume{ID: commitID, Kind: storage.KindCommit, StateUID: stateUID, SizeBytes: src.SizeBytes})
	if src.Release != nil {
		src.Release()
	}
	return nil
}

func (f *fakeStore) CreateWorking(ctx context.Context, req storage.CreateWorking) (string, error) {
	f.mu.Lock()
	err := f.createErr
	f.mu.Unlock()
	if err != nil {
		return "", err
	}
	f.add(storage.Volume{ID: req.AttachmentID, Kind: storage.KindWorking, StateUID: req.StateUID, Device: "/dev/fake/" + req.AttachmentID})
	return "/dev/fake/" + req.AttachmentID, nil
}

func (f *fakeStore) Activate(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.volumes[id]
	if !ok {
		return "", storage.ErrNotFound
	}
	f.activations++
	v.Device = "/dev/fake/" + id
	f.volumes[id] = v
	return v.Device, nil
}

func (f *fakeStore) Seal(ctx context.Context, attachmentID, commitID string) (int64, error) {
	f.mu.Lock()
	w := f.volumes[attachmentID]
	f.mu.Unlock()
	f.add(storage.Volume{ID: commitID, Kind: storage.KindCommit, StateUID: w.StateUID, SizeBytes: 1 << 30})
	return 1 << 30, nil
}

func (f *fakeStore) LiveCopy(ctx context.Context, attachmentID, commitID, stateUID string) (int64, error) {
	f.add(storage.Volume{ID: commitID, Kind: storage.KindCommit, StateUID: stateUID, SizeBytes: 1 << 30})
	return 1 << 30, nil
}

func (f *fakeStore) Digest(ctx context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.volumes[id]
	if !ok {
		return "", storage.ErrNotFound
	}
	if v.Digest == "" {
		v.Digest = "v1:sha256:" + id
		f.volumes[id] = v
	}
	return v.Digest, nil
}

func (f *fakeStore) Delete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.volumes, id)
	delete(f.pending, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeStore) Device(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.volumes[id]
	if !ok {
		return "", storage.ErrNotFound
	}
	if v.Device == "" {
		v.Device = "/dev/fake/" + id
		f.volumes[id] = v
	}
	return v.Device, nil
}

func (f *fakeStore) OpenView(ctx context.Context, stateUID, commitID, viewID string) (string, error) {
	return "", storage.ErrNotFound
}

func (f *fakeStore) CloseView(viewID string) error { return nil }

// gatedLiveCopyStore holds each live copy inside LiveCopy so a test can
// interleave two copies deterministically.
type gatedLiveCopyStore struct {
	*fakeStore
	started chan string
	release map[string]chan struct{}
}

func (g *gatedLiveCopyStore) LiveCopy(ctx context.Context, attachmentID, commitID, stateUID string) (int64, error) {
	g.started <- commitID
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-g.release[commitID]:
	}
	return g.fakeStore.LiveCopy(ctx, attachmentID, commitID, stateUID)
}

type applied struct {
	mu      sync.Mutex
	patches map[string]map[string]any // name -> last applied status
}

func (a *applied) get(name string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.patches[name]
}

func testAgent(t *testing.T, objs ...client.Object) (*Agent, *fakeStore, *applied) {
	t.Helper()
	scheme, err := Scheme()
	if err != nil {
		t.Fatal(err)
	}
	ap := &applied{patches: map[string]map[string]any{}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.BlipState{}, &v1alpha1.BlipNode{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} }).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if patch.Type() != types.ApplyPatchType {
					t.Errorf("status patch type %s", patch.Type())
				}
				var po client.SubResourcePatchOptions
				po.ApplyOptions(opts)
				if po.FieldManager != "blip-node/"+self || po.Force == nil || !*po.Force {
					t.Errorf("apply options %+v", po)
				}
				data, err := patch.Data(obj)
				if err != nil {
					return err
				}
				var m map[string]any
				if err := json.Unmarshal(data, &m); err != nil {
					return err
				}
				ap.mu.Lock()
				ap.patches[obj.GetName()] = m["status"].(map[string]any)
				ap.mu.Unlock()
				return nil
			},
		}).Build()
	st := newFakeStore()
	cfg := Config{NodeName: self, HostIP: "192.0.2.1", DataDir: t.TempDir(), Peers: peer.NewRegistry()}
	cfg.Identity, err = peer.LoadIdentity(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PeerClient = peer.NewClient(cfg.Identity, cfg.Peers, nil)
	t.Cleanup(cfg.PeerClient.Close)
	a := newAgent(cfg, c, c, st)
	return a, st, ap
}

// settle runs passes until a pass starts no background operation.
func settle(t *testing.T, a *Agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	idle := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.operations.Busy()) == 0
	}
	// A pass plans its status entries before its operations finish. Require
	// two idle passes so the last one observes their result.
	idles := 0
	for {
		if err := a.sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if idle() {
			if idles++; idles == 2 {
				return
			}
		} else {
			idles = 0
		}
		for !idle() {
			if time.Now().After(deadline) {
				t.Fatal("operations did not finish")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestAgentPass(t *testing.T) {
	pod := vmPod("p1", "")
	s := state("s")
	s.Status.ImageDigest = imageRef
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	bn := &v1alpha1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: self}}
	a, st, ap := testAgent(t, pod, s, bn)
	a.pull = func(ctx context.Context, ref string, secrets []registryauth.PullSecret, dir string) (image.Config, string, error) {
		if ref != imageRef {
			t.Errorf("pull %s", ref)
		}
		tar := filepath.Join(dir, "image.tar")
		return image.Config{Env: []string{"X=1"}}, tar, os.WriteFile(tar, []byte("tar!"), 0o644)
	}
	podDir := a.podDirFor(podKey(ns, "p1"))
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(podDir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
		t.Fatal(err)
	}

	settle(t, a)

	st.mu.Lock()
	n := st.imports[imageID]
	_, built := st.volumes["c1"]
	st.mu.Unlock()
	if n != image.FSSize(4) {
		t.Fatalf("imported image of %d bytes", n)
	}
	if ents, _ := os.ReadDir(filepath.Join(a.cfg.DataDir, "tmp")); len(ents) != 0 {
		t.Fatalf("scratch left behind: %v", ents)
	}
	var cfg image.Config
	if err := podapi.ReadJSON(filepath.Join(a.cfg.DataDir, "images", imageID+".json"), &cfg); err != nil || cfg.Env[0] != "X=1" {
		t.Fatalf("saved config %+v, %v", cfg, err)
	}
	if !built {
		t.Fatalf("initial commit not built")
	}
	status := ap.get("s")
	nodes, _ := status["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("applied status = %v", status)
	}
	e := nodes[0].(map[string]any)
	if e["node"] != self || e["incarnation"] != "inc-n1" || len(e["commits"].([]any)) != 1 {
		t.Fatalf("entry = %v", e)
	}

	var got corev1.Pod
	if err := a.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[v1alpha1.LabelWarm] != "true" || !strings.Contains(got.Annotations[v1alpha1.AnnotationObserved], `"Warm"`) {
		t.Fatalf("pod metadata %v %v", got.Labels, got.Annotations)
	}

	// The pod and its directory go away once the pod is deleted.
	if err := a.client.Delete(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	settle(t, a)
	if _, err := os.Stat(podDir); !os.IsNotExist(err) {
		t.Fatalf("pod directory not removed: %v", err)
	}
}

func TestAgentRetriesPendingDelete(t *testing.T) {
	a, st, _ := testAgent(t)
	const id = "a0000000000000f1"
	st.setPending(id)
	settle(t, a)

	st.mu.Lock()
	deleted := slices.Clone(st.deleted)
	pending := len(st.pending)
	st.mu.Unlock()
	if pending != 0 || !slices.Contains(deleted, id) {
		t.Fatalf("deleted %v, pending %d; the GC pass did not retry %s", deleted, pending, id)
	}
}

func TestRegisterNode(t *testing.T) {
	a, _, ap := testAgent(t)
	if err := a.registerNode(context.Background()); err != nil {
		t.Fatal(err)
	}
	var bn v1alpha1.BlipNode
	if err := a.client.Get(context.Background(), client.ObjectKey{Name: self}, &bn); err != nil {
		t.Fatal(err)
	}
	st := ap.get(self)
	if st["incarnation"] != "inc-n1" || st["endpoint"] != "192.0.2.1" || st["heartbeat"] == nil ||
		st["tlsPublicKey"] != a.cfg.Identity.PublicKey() {
		t.Fatalf("status = %v", st)
	}
	if err := a.registerNode(context.Background()); err != nil {
		t.Fatalf("second registration: %v", err)
	}
	a.cfg.HostIP = "192.0.2.10"
	if err := a.applyNodeStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	st = ap.get(self)
	if st["endpoint"] != a.cfg.HostIP || st["tlsPublicKey"] != a.cfg.Identity.PublicKey() {
		t.Fatalf("heartbeat lost peer identity: %v", st)
	}
}

func TestSyncPeersRevokesTrustBeforeFirewall(t *testing.T) {
	a, _, _ := testAgent(t)
	v := newView()
	// Draining blocks new source selection, but must not break existing leases.
	v.blipNodes["n3"].Spec.Drain = true
	oldKey := v.blipNodes["n3"].Status.TLSPublicKey
	a.peers = func(peers []peer.Peer) error {
		select {
		case <-a.cfg.Peers.Ready():
		default:
			t.Fatal("registry not ready before firewall update")
		}
		if len(peers) != 2 || peers[0].Node != "n2" || peers[1].Node != "n3" {
			t.Fatalf("firewall peers = %+v", peers)
		}
		if _, ok := a.cfg.Peers.Lookup("n3"); !ok {
			t.Fatal("draining node lost trust")
		}
		if got, ok := a.cfg.Peers.Lookup(self); !ok || got != nodePeer(v.blipNodes[self]) {
			t.Fatal("local node missing from trust registry")
		}
		return nil
	}
	if err := a.syncPeers(v); err != nil {
		t.Fatal(err)
	}
	delete(v.blipNodes, "n2")
	v.blipNodes["n3"].Status.TLSPublicKey = testPublicKey("replacement-n3")
	v.blipNodes["n3"].Status.Endpoint = "192.0.2.30"
	firewallErr := errors.New("firewall unavailable")
	calls := 0
	a.peers = func(peers []peer.Peer) error {
		calls++
		if _, ok := a.cfg.Peers.Lookup("n2"); ok {
			t.Fatal("deleted node remains trusted during firewall update")
		}
		if _, ok := a.cfg.Peers.NodeForKey(oldKey); ok {
			t.Fatal("replaced key remains trusted during firewall update")
		}
		want := nodePeer(v.blipNodes["n3"])
		if got, ok := a.cfg.Peers.Lookup("n3"); !ok || got != want {
			t.Fatalf("replacement peer = %+v, %v", got, ok)
		}
		if len(peers) != 1 || peers[0] != want {
			t.Fatalf("firewall peers = %+v", peers)
		}
		if calls == 1 {
			return firewallErr
		}
		return nil
	}
	if err := a.syncPeers(v); !errors.Is(err, firewallErr) {
		t.Fatalf("firewall failure = %v", err)
	}
	if err := a.syncPeers(v); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("firewall update was not retried: %d calls", calls)
	}
}

func TestSyncPeersRejectsInvalidAndAmbiguousIdentities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(*view)
	}{
		{"missing key", func(v *view) {
			v.blipNodes["n2"].Status.TLSPublicKey = ""
			v.blipNodes["n3"].Status.TLSPublicKey = ""
		}},
		{"invalid key", func(v *view) {
			v.blipNodes["n2"].Status.TLSPublicKey = "invalid"
			v.blipNodes["n3"].Status.TLSPublicKey = "invalid"
		}},
		{"invalid endpoint", func(v *view) {
			v.blipNodes["n2"].Status.Endpoint = ""
			v.blipNodes["n3"].Status.Endpoint = "node.example"
		}},
		{"duplicate key", func(v *view) {
			v.blipNodes["n3"].Status.TLSPublicKey = v.blipNodes["n2"].Status.TLSPublicKey
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := testAgent(t)
			v := newView()
			if err := a.syncPeers(v); err != nil {
				t.Fatal(err)
			}
			tc.damage(v)
			called := false
			a.peers = func(peers []peer.Peer) error {
				called = true
				if len(peers) != 0 {
					t.Fatalf("invalid peers admitted to firewall: %+v", peers)
				}
				return nil
			}
			if err := a.syncPeers(v); err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("firewall was not updated")
			}
			for _, n := range []string{"n2", "n3"} {
				if _, ok := a.cfg.Peers.Lookup(n); ok {
					t.Fatalf("invalid peer %s remains trusted", n)
				}
			}
		})
	}
}

func TestSyncPeersRejectsDuplicateLocalIdentity(t *testing.T) {
	a, _, _ := testAgent(t)
	v := newView()
	v.blipNodes[self].Status.TLSPublicKey = a.cfg.Identity.PublicKey()
	v.blipNodes["n2"].Status.TLSPublicKey = a.cfg.Identity.PublicKey()
	a.peers = func(peers []peer.Peer) error {
		if len(peers) != 1 || peers[0] != nodePeer(v.blipNodes["n3"]) {
			t.Fatalf("firewall peers = %+v, want only n3", peers)
		}
		return nil
	}
	if err := a.syncPeers(v); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{self, "n2"} {
		if _, ok := a.cfg.Peers.Lookup(n); ok {
			t.Fatalf("ambiguous node %s remains trusted", n)
		}
	}
	if _, ok := a.cfg.Peers.NodeForKey(a.cfg.Identity.PublicKey()); ok {
		t.Fatal("duplicate local key resolves to a trusted node")
	}
	if _, ok := a.cfg.Peers.Lookup("n3"); !ok {
		t.Fatal("unambiguous peer lost trust")
	}
}

func TestOpenRemoteUsesNodeName(t *testing.T) {
	a, _, _ := testAgent(t)
	releases := 0
	a.open = func(ctx context.Context, node string, req peer.ExportRequest) (storage.Remote, error) {
		if node != "n2" || req.StateUID != "uid-s" || req.CommitID != "c1" || req.HostNQN != peer.HostNQN(self) {
			t.Fatalf("export node=%q request=%+v", node, req)
		}
		return storage.Remote{ID: "n2/lease-1", Release: func() { releases++ }}, nil
	}
	remote, release, err := a.openRemote(context.Background(), source{node: "n2", stateUID: "uid-s", commitID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if remote.ID != "n2/lease-1" {
		t.Fatalf("remote identity = %q", remote.ID)
	}
	remote.Release()
	release()
	if releases != 1 {
		t.Fatalf("release called %d times", releases)
	}
}

func waitIdle(t *testing.T, a *Agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		busy := len(a.operations.Busy())
		a.mu.Unlock()
		if busy == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("operations did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPrepareErrorAnnotation: a preparation failure is visible on the claimed
// pod, and a later success clears it.
func TestPrepareErrorAnnotation(t *testing.T) {
	b := blip("b")
	b.Status.RootAttachmentID = "r1"
	pod := vmPod("p", string(b.UID))
	s := state("root")
	s.Status.Committed = &v1alpha1.Commit{ID: "c1", Generation: 1}
	s.Status.Writer = &v1alpha1.Writer{AttachmentID: "r1", PodUID: string(pod.UID), PodName: pod.Name, BlipUID: string(b.UID), Node: self, BaseCommit: "c1"}
	a, st, _ := testAgent(t, pod, b, s)
	st.add(commit("c1", string(s.UID)))
	a.mknod = func(string, string) error { return nil }
	podDir := a.podDirFor(podKey(ns, "p"))
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(podDir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
		t.Fatal(err)
	}
	st.createErr = errors.New("create working: boom")

	ctx := context.Background()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, a)

	var got corev1.Pod
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(pod), &got); err != nil {
		t.Fatal(err)
	}
	if msg := got.Annotations[v1alpha1.AnnotationPrepareError]; !strings.Contains(msg, "create working: boom") {
		t.Fatalf("prepare error annotation = %q", msg)
	}
	if n := len(got.Annotations[v1alpha1.AnnotationPrepareError]); n > maxPrepareErr {
		t.Fatalf("prepare error is %d bytes", n)
	}

	a.reportPrepare(ctx, prepare{pod: podKey(ns, "p")}, nil)
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(pod), &got); err != nil {
		t.Fatal(err)
	}
	if msg := got.Annotations[v1alpha1.AnnotationPrepareError]; msg != "" {
		t.Fatalf("prepare error annotation not cleared: %q", msg)
	}
}

// TestPrepareReactivatesReadyWorkingVolume: a ready working volume whose
// device was missing from the pass's snapshot is reactivated during prepare
// instead of failing and putting "has no active device" on the pod.
func TestPrepareReactivatesReadyWorkingVolume(t *testing.T) {
	b := blip("b")
	b.Status.RootAttachmentID = "r1"
	pod := vmPod("p", string(b.UID))
	s := state("root")
	s.Status.Writer = &v1alpha1.Writer{AttachmentID: "r1", PodUID: string(pod.UID), PodName: pod.Name,
		BlipUID: string(b.UID), Node: self, BaseCommit: "c1"}
	a, st, _ := testAgent(t, pod, b, s)
	st.add(storage.Volume{ID: "r1", Kind: storage.KindWorking, StateUID: string(s.UID)})
	var gotPath, gotDev string
	a.mknod = func(path, device string) error {
		gotPath, gotDev = path, device
		return nil
	}
	podDir := a.podDirFor(podKey(ns, "p"))
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(podDir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, a)

	st.mu.Lock()
	activations := st.activations
	vol := st.volumes["r1"]
	st.mu.Unlock()
	if activations != 1 {
		t.Fatalf("Activate calls = %d, want 1", activations)
	}
	if vol.Device != "/dev/fake/r1" {
		t.Fatalf("volume still has no device: %+v", vol)
	}
	if gotDev != vol.Device || gotPath != filepath.Join(podDir, podapi.DevDir, "r1") {
		t.Fatalf("device node = %q -> %q", gotPath, gotDev)
	}
	var got corev1.Pod
	if err := a.client.Get(ctx, client.ObjectKeyFromObject(pod), &got); err != nil {
		t.Fatal(err)
	}
	if msg := got.Annotations[v1alpha1.AnnotationPrepareError]; msg != "" {
		t.Fatalf("prepare error annotation = %q", msg)
	}
}

// TestMissingPullSecretIsReported: a missing image pull secret fails the
// import with a clear message that reaches this node's state observation.
func TestMissingPullSecretIsReported(t *testing.T) {
	s := state("s")
	s.Status.ImageDigest = imageRef
	s.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "nope"}}
	s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", Generation: 1, SourceNode: self, Replicas: []string{self}}
	bn := &v1alpha1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: self}}
	a, _, ap := testAgent(t, s, bn)

	ctx := context.Background()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, a)
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, a)

	status := ap.get("s")
	nodes, _ := status["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("applied status = %v", status)
	}
	if msg, _ := nodes[0].(map[string]any)["error"].(string); !strings.Contains(msg, "image pull secret default/nope") {
		t.Fatalf("state error = %q", msg)
	}
}

// TestLiveAbsenceUsesNamespace: a live read confirms absence per namespace, so
// deleting a pod in one namespace never marks its same-named twin elsewhere
// gone.
func TestLiveAbsenceUsesNamespace(t *testing.T) {
	podOne := vmPod("p", "")
	podOne.Namespace = "one"
	podTwo := vmPod("p", "")
	podTwo.Namespace = "two"
	a, _, _ := testAgent(t, podOne, podTwo)
	for _, key := range []string{"one/p", "three/p"} {
		dir := filepath.Join(a.podsDir(), filepath.FromSlash(key))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := podapi.WriteJSON(filepath.Join(dir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseWarm}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := a.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.pods["one/p"] == nil || v.pods["two/p"] == nil {
		t.Fatalf("pods = %v", v.pods)
	}
	a.mu.Lock()
	gone := clone(a.podsGone)
	a.mu.Unlock()
	if !gone["three/p"] {
		t.Fatalf("missing pod not confirmed gone: %v", gone)
	}
	if gone["one/p"] || gone["two/p"] {
		t.Fatalf("present pod marked gone: %v", gone)
	}
	// A nameless key must never be recorded.
	if gone["p"] {
		t.Fatalf("name-only key in podsGone: %v", gone)
	}
}

func TestLiveCopyAbandonsGonePod(t *testing.T) {
	a, st, _ := testAgent(t)
	key := podKey(ns, "p")
	// The pod directory is gone: liveCopy must not wait for a freeze.
	err := a.liveCopy(context.Background(), liveCopy{pod: key, stateUID: "uid-cp", attachmentID: "a1", commitID: "k1"})
	if err != nil {
		t.Fatalf("live copy of gone pod: %v", err)
	}
	st.mu.Lock()
	_, copied := st.volumes["k1"]
	st.mu.Unlock()
	if copied {
		t.Fatal("snapshotted a gone pod")
	}
}

func TestLiveCopyAbandonsStoppingPod(t *testing.T) {
	a, st, _ := testAgent(t)
	key := podKey(ns, "p")
	dir := a.podDirFor(key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(dir, podapi.DesiredFile), podapi.Desired{Stop: true}); err != nil {
		t.Fatal(err)
	}
	if err := podapi.WriteJSON(filepath.Join(dir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseRunning}); err != nil {
		t.Fatal(err)
	}
	// The source started stopping: the guest may never freeze again.
	start := time.Now()
	err := a.liveCopy(context.Background(), liveCopy{pod: key, stateUID: "uid-cp", attachmentID: "a1", commitID: "k1"})
	if err != nil {
		t.Fatalf("live copy of stopping pod: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waited %s for a stopping pod", elapsed)
	}
	st.mu.Lock()
	_, copied := st.volumes["k1"]
	st.mu.Unlock()
	if copied {
		t.Fatal("snapshotted a stopping pod")
	}
}

func TestWaitFrozenReportsGonePod(t *testing.T) {
	a, _, _ := testAgent(t)
	key := podKey(ns, "p")
	start := time.Now()
	err := a.waitFrozen(context.Background(), key, "a1", true)
	if !errors.Is(err, errPodGone) {
		t.Fatalf("waitFrozen = %v, want errPodGone", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waited %s for a gone pod", elapsed)
	}
}

func TestLiveCopyJob(t *testing.T) {
	a, st, _ := testAgent(t)
	key := podKey(ns, "p")
	dir := a.podDirFor(key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A previous copy's freeze still reported: wait for its thaw first.
	obsPath := filepath.Join(dir, podapi.ObservedFile)
	if err := podapi.WriteJSON(obsPath, podapi.Observed{Phase: podapi.PhaseRunning, Frozen: []string{"a1"}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- a.liveCopy(context.Background(), liveCopy{pod: key, stateUID: "uid-cp", attachmentID: "a1", commitID: "k1"})
	}()
	time.Sleep(300 * time.Millisecond)
	a.mu.Lock()
	stale := slices.Contains(a.freezes[key], "a1")
	a.mu.Unlock()
	if stale {
		t.Fatal("freeze requested while a previous freeze was still reported")
	}
	if err := podapi.WriteJSON(obsPath, podapi.Observed{Phase: podapi.PhaseRunning}); err != nil {
		t.Fatal(err)
	}

	// Play the runtime: report the disk frozen once the agent asks for it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		want := slices.Contains(a.freezes[key], "a1")
		a.mu.Unlock()
		if want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("freeze not requested")
		}
		time.Sleep(5 * time.Millisecond)
	}
	st.mu.Lock()
	_, early := st.volumes["k1"]
	st.mu.Unlock()
	if early {
		t.Fatal("snapshot taken before the guest froze")
	}
	if err := podapi.WriteJSON(filepath.Join(dir, podapi.ObservedFile), podapi.Observed{Phase: podapi.PhaseRunning, Frozen: []string{"a1"}}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	vol := st.volumes["k1"]
	st.mu.Unlock()
	if vol.Kind != storage.KindCommit || vol.StateUID != "uid-cp" {
		t.Fatalf("commit %+v", vol)
	}
	a.mu.Lock()
	left := a.freezes[key]
	a.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("still frozen: %v", left)
	}
}

// TestConcurrentLiveCopiesKeepFreeze: two copies of one writer share a single
// desired freeze, but neither may thaw the guest while the other is still
// snapshotting.
func TestConcurrentLiveCopiesKeepFreeze(t *testing.T) {
	a, st, _ := testAgent(t)
	key := podKey(ns, "p")
	dir := a.podDirFor(key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	obsPath := filepath.Join(dir, podapi.ObservedFile)
	if err := podapi.WriteJSON(obsPath, podapi.Observed{Phase: podapi.PhaseRunning}); err != nil {
		t.Fatal(err)
	}

	ids := []string{"k1", "k2"}
	store := &gatedLiveCopyStore{fakeStore: st, started: make(chan string, len(ids)), release: map[string]chan struct{}{}}
	for _, id := range ids {
		store.release[id] = make(chan struct{})
	}
	a.store = store

	done := map[string]chan error{}
	for _, id := range ids {
		done[id] = make(chan error, 1)
	}
	for _, id := range ids {
		go func(id string) {
			done[id] <- a.liveCopy(context.Background(), liveCopy{pod: key, stateUID: "uid-" + id, attachmentID: "a1", commitID: id})
		}(id)
	}

	// Keep the guest thawed until both copies have requested the freeze, so
	// both pass the thaw pre-wait before either snapshot starts.
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		refs := a.freezeRefs[key]["a1"]
		a.mu.Unlock()
		if refs == len(ids) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("freeze refs = %d, want %d", refs, len(ids))
		}
		time.Sleep(time.Millisecond)
	}
	if err := podapi.WriteJSON(obsPath, podapi.Observed{Phase: podapi.PhaseRunning, Frozen: []string{"a1"}}); err != nil {
		t.Fatal(err)
	}

	// Both copies now snapshot. Finish the first while the second is still
	// held inside the store.
	first, second := <-store.started, <-store.started
	close(store.release[first])
	if err := <-done[first]; err != nil {
		t.Fatalf("first live copy: %v", err)
	}
	a.mu.Lock()
	frozen := slices.Contains(a.freezes[key], "a1")
	refs := a.freezeRefs[key]["a1"]
	a.mu.Unlock()
	if !frozen || refs != 1 {
		t.Fatalf("after first copy finished: frozen=%v refs=%d, want the second copy's freeze retained", frozen, refs)
	}

	close(store.release[second])
	if err := <-done[second]; err != nil {
		t.Fatalf("second live copy: %v", err)
	}
	a.mu.Lock()
	frozen = slices.Contains(a.freezes[key], "a1")
	refs = a.freezeRefs[key]["a1"]
	a.mu.Unlock()
	if frozen || refs != 0 {
		t.Fatalf("after both copies finished: frozen=%v refs=%d, want thawed", frozen, refs)
	}
}

// TestConfirmGoneSeesRunningBuildState: an in-flight build has no visible
// volume yet, so its running operation is the only evidence that the state it
// belongs to may have been deleted.
func TestConfirmGoneSeesRunningBuildState(t *testing.T) {
	a, _, _ := testAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.opCancels = map[string]context.CancelFunc{stateKey("uid-building"): cancel}
	a.confirmGone(ctx, &view{node: self, dirs: map[string]*podDir{}, volumes: map[string]storage.Volume{}})
	a.mu.Lock()
	gone := a.statesGone["uid-building"]
	a.mu.Unlock()
	if !gone {
		t.Fatal("running build's state was not confirmed gone")
	}
	a.cancelGoneBuilds(&view{statesGone: map[string]bool{"uid-building": true}})
	if ctx.Err() == nil {
		t.Fatal("running build was not cancelled")
	}
}

// TestAgentCancelsBuildWhenStateGone: a state confirmed absent by a live read
// must cancel its running build, not just forget it, or mkfs keeps allocating
// thin-pool space after the object is gone.
func TestAgentCancelsBuildWhenStateGone(t *testing.T) {
	a := &Agent{operations: *NewScheduler(map[string]int{"image": 2}), wake: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := stateKey("uid-gone")
	started := make(chan struct{})
	finished := make(chan error, 1)
	a.runOperations(ctx, []Operation{{Key: key, Class: "image", Writes: []string{"c1"}}},
		map[string]operationJob{key: {what: "build commit", run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			finished <- ctx.Err()
			return ctx.Err()
		}}})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("build did not start")
	}
	a.cancelGoneBuilds(&view{statesGone: map[string]bool{}})
	select {
	case err := <-finished:
		t.Fatalf("build cancelled while its state still exists: %v", err)
	default:
	}

	a.cancelGoneBuilds(&view{statesGone: map[string]bool{"uid-gone": true}})
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("build stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("build not cancelled after its state disappeared")
	}
	a.workers.Wait()
	a.mu.Lock()
	left := len(a.opCancels)
	a.mu.Unlock()
	if left != 0 {
		t.Fatalf("cancelled operation still registered: %d", left)
	}
}
