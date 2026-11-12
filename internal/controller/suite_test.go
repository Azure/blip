package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
)

// The envtest suite runs one controller against a real kube-apiserver and
// fake nodes. Set KUBEBUILDER_ASSETS to run it, for example:
//
//	KUBEBUILDER_ASSETS=/mnt/nvme2/blip/controller/assets/k8s/1.33.0-linux-amd64 go test ./internal/controller/
var env struct {
	cfg     *rest.Config
	k       client.Client
	ctrl    *Controller
	nodes   map[string]*fakenode.Node
	wmu     sync.Mutex
	work    map[string]fakenode.Workload // by Blip name
	created func(client.Object) error    // output create interceptor
	cancel  context.CancelFunc

	opts       Options
	cancelCtrl func()
}

// startController runs a controller and waits until it is created. The
// returned function stops it and waits for it to exit.
func startController(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	ready := make(chan struct{})
	done := make(chan struct{})
	hooks := &Hooks{
		Auth:     fakeAuth{},
		Created:  func(c *Controller) { env.ctrl = c; close(ready) },
		WrapLive: wrapLive,
		Mint:     func(m TokenMinter) TokenMinter { return testMinter{m} },
	}
	go func() {
		defer close(done)
		if err := Run(ctx, env.cfg, env.opts, hooks); err != nil {
			fmt.Println("controller:", err)
		}
	}()
	<-ready
	return func() {
		cancel()
		<-done
	}
}

const sys = "blip-system"

type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, token string) (string, error) {
	if n, ok := strings.CutPrefix(token, "node:"); ok {
		return n, nil
	}
	return "", fmt.Errorf("bad token")
}

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		fmt.Println("KUBEBUILDER_ASSETS not set; envtest suite only runs unit tests")
		os.Exit(m.Run())
	}
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) int {
	if os.Getenv("BLIP_TEST_LOG") != "" {
		ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	}
	te := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "base", "crd")}, ErrorIfCRDPathMissing: true}
	cfg, err := te.Start()
	if err != nil {
		fmt.Println("envtest:", err)
		return 1
	}
	defer te.Stop()
	env.cfg = cfg
	s := clientgoscheme.Scheme
	_ = v1.AddToScheme(s)
	env.k, err = client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		fmt.Println(err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel
	defer cancel()
	if err := setupCluster(ctx); err != nil {
		fmt.Println("setup:", err)
		return 1
	}
	addr := freeAddr()
	opts := DefaultOptions()
	opts.ListenAddr = addr
	opts.MetricsAddr = "0"
	opts.ProbeAddr = "0"
	opts.DNSNames = []string{"localhost"}
	opts.SlotImage = "slot:test"
	opts.NodeLostTimeout = 4 * time.Second
	opts.Heartbeat = time.Second
	opts.SaveTimeout = 20 * time.Second
	opts.CommandTimeout = 20 * time.Second
	opts.GracefulTimeout = 2 * time.Second
	opts.TransferAttempts = 3
	opts.RepairInterval = time.Second
	opts.OrphanAge = 2 * time.Second
	opts.ScrubInterval = time.Hour
	// A 5m snapshot interval becomes 2s.
	opts.SnapshotIntervalScale = 150
	env.opts = opts
	env.cancelCtrl = startController(ctx)
	var cm corev1.ConfigMap
	for i := 0; ; i++ {
		if err := env.k.Get(ctx, types.NamespacedName{Namespace: sys, Name: api.CAConfigMap}, &cm); err == nil {
			break
		}
		if i > 100 {
			fmt.Println("no CA configmap")
			return 1
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The fake nodes read slot pods through a cache, as the kubelet
	// would not load the API server either.
	pods, err := cache.New(cfg, cache.Options{Scheme: s})
	if err != nil {
		fmt.Println(err)
		return 1
	}
	go pods.Start(ctx)
	if _, err := pods.GetInformer(ctx, &corev1.Pod{}); err != nil {
		fmt.Println(err)
		return 1
	}
	pods.WaitForCacheSync(ctx)
	env.nodes = map[string]*fakenode.Node{}
	env.work = map[string]fakenode.Workload{}
	for i, n := range []struct {
		name             string
		storage, compute bool
		disks            int32
	}{
		{"s1", true, true, 0}, {"s2", true, true, 0}, {"s3", true, true, 0},
		{"s4", true, false, 0}, {"s5", true, false, 0}, {"s6", true, false, 0},
		{"c9", false, true, 0}, {"c8", false, true, 2},
	} {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.name}}
		if err := env.k.Create(ctx, node); err != nil {
			fmt.Println(err)
			return 1
		}
		node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: fmt.Sprintf("10.1.0.%d", i+1)}}
		if err := env.k.Status().Update(ctx, node); err != nil {
			fmt.Println(err)
			return 1
		}
		fn := fakenode.New(fakenode.Config{Addr: addr, CA: []byte(cm.Data[keyCACert]), Token: "node:" + n.name, Name: n.name, Storage: n.storage, Compute: n.compute, Slots: 128, DisksPerSlot: n.disks, Kube: pods})
		fn.SetWorkload(dispatch)
		if err := fn.Start(ctx); err != nil {
			fmt.Println(err)
			return 1
		}
		env.nodes[n.name] = fn
	}
	for i := 0; ; i++ {
		all := true
		for n := range env.nodes {
			all = all && env.ctrl.nodes.Connected(n)
		}
		if all {
			break
		}
		if i > 200 {
			fmt.Println("nodes did not connect")
			return 1
		}
		time.Sleep(50 * time.Millisecond)
	}
	return m.Run()
}

func dispatch(n *fakenode.Node, s *nodepb.StartWorkload) {
	env.wmu.Lock()
	w := env.work[s.Blip.GetNamespace()+"/"+s.Blip.GetName()]
	env.wmu.Unlock()
	if w == nil {
		w = fakenode.Succeed(200 * time.Millisecond)
	}
	w(n, s)
}

func setWork(ns, name string, w fakenode.Workload) {
	env.wmu.Lock()
	env.work[ns+"/"+name] = w
	env.wmu.Unlock()
}

func freeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func setupCluster(ctx context.Context) error {
	k := env.k
	objs := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sys}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: sys, Name: api.StorageConfigMap}, Data: map[string]string{
			api.StorageConfigKey: "groups: [{name: sg-1, nodes: [s1, s2, s3]}, {name: sg-2, nodes: [s4, s5, s6]}]",
		}},
	}
	for _, o := range objs {
		if err := k.Create(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers ---

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newNS(t *testing.T, annotations map[string]string) string {
	t.Helper()
	name := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	if len(name) > 50 {
		name = name[:50]
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations}}
	if err := env.k.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	// envtest runs no service account controller.
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: name, Name: "default"}}
	if err := env.k.Create(context.Background(), sa); err != nil {
		t.Fatal(err)
	}
	return name
}

// pool creates n free Ready slot pods of sku in namespace ns, one per node
// given. Each namespace is its own pool.
func pool(t *testing.T, ns, sku string, nodes ...string) {
	t.Helper()
	for _, n := range nodes {
		slot(t, ns, sku, n)
	}
}

var slotSeq int
var slotMu sync.Mutex

// staticPool makes sure ns has a BlipPool for sku that never creates pods
// (maxSlots 0), so the SKU exists for scheduling while the tests place
// slot pods by hand. Hand-made pods have no pool owner: the pool ignores
// them.
func staticPool(t *testing.T, ns, sku string) {
	t.Helper()
	zero := int32(0)
	p := &v1.BlipPool{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "static-" + sku},
		Spec: v1.BlipPoolSpec{SKU: sku, CPUs: 1, Memory: resource.MustParse("512Mi"), MinFree: 0, MaxFree: 0, MaxSlots: &zero}}
	if err := env.k.Create(context.Background(), p); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

func slot(t *testing.T, ns, sku, node string) *corev1.Pod {
	t.Helper()
	ctx := context.Background()
	staticPool(t, ns, sku)
	slotMu.Lock()
	slotSeq++
	name := fmt.Sprintf("pool-%s-%d", sku, slotSeq)
	slotMu.Unlock()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
			Labels: map[string]string{api.LabelSKU: sku, api.LabelSlot: api.SlotFree},
		},
		Spec: corev1.PodSpec{NodeName: node, ServiceAccountName: "default", Containers: []corev1.Container{{Name: "slot", Image: "slot"}}},
	}
	if err := env.k.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	makeReady(t, p)
	return p
}

// makeReady stands in for the kubelet: the pod runs and is Ready.
func makeReady(t *testing.T, p *corev1.Pod) {
	t.Helper()
	slotMu.Lock()
	slotSeq++
	n := slotSeq
	slotMu.Unlock()
	ip := fmt.Sprintf("10.244.%d.%d", n/250, n%250+1)
	p.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
	if err := env.k.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func newVol(t *testing.T, ns, name string, spec v1.BlipVolSpec) *v1.BlipVol {
	t.Helper()
	bv := &v1.BlipVol{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: spec}
	if err := env.k.Create(context.Background(), bv); err != nil {
		t.Fatal(err)
	}
	return bv
}

func getVol(ns, name string) *v1.BlipVol {
	var bv v1.BlipVol
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &bv); err != nil {
		return nil
	}
	return &bv
}

func readyVol(t *testing.T, ns, name string, spec v1.BlipVolSpec) *v1.BlipVol {
	t.Helper()
	newVol(t, ns, name, spec)
	var bv *v1.BlipVol
	eventually(t, 20*time.Second, "blipvol "+name+" ready", func() bool {
		bv = getVol(ns, name)
		return bv != nil && bv.Status.Phase == v1.BlipVolReady
	})
	return bv
}

// vol is a spec volume.
func vol(name, ref string) v1.BlipVolume {
	return v1.BlipVolume{Name: name, BlipVolRef: v1.LocalObjectRef{Name: ref}}
}

// policyVol makes a Ready empty BlipVol with a snapshot policy.
func policyVol(t *testing.T, ns, name string, p *v1.SnapshotPolicy) *v1.BlipVol {
	t.Helper()
	return readyVol(t, ns, name, v1.BlipVolSpec{SnapshotPolicy: p})
}

// skipVol makes a Ready empty BlipVol with skipShutdown.
func skipVol(t *testing.T, ns, name string) *v1.BlipVol {
	t.Helper()
	return policyVol(t, ns, name, &v1.SnapshotPolicy{SkipShutdown: true})
}

// every is a snapshot interval (5m, scaled to 2s in the suite).
func every(limit int32) *v1.SnapshotPolicy {
	return &v1.SnapshotPolicy{Interval: &metav1.Duration{Duration: 5 * time.Minute}, Limit: limit}
}

// ss returns the shutdown snapshot record of a volume of b.
func ss(b *v1.Blip, name string) *v1.ShutdownSnapshot {
	if vs := volStatus(b, name); vs != nil {
		return vs.ShutdownSnapshot
	}
	return nil
}

// snap returns snapshot seq of a BlipVol, or nil.
func snap(ns, name string, seq int64) *v1.VolSnapshot {
	if v := getVol(ns, name); v != nil {
		return v.Snapshot(seq)
	}
	return nil
}

// cur returns the current snapshot of a BlipVol (fatal if none).
func cur(t *testing.T, v *v1.BlipVol) *v1.VolSnapshot {
	t.Helper()
	s := v.Snapshot(v.Status.Current)
	if s == nil {
		t.Fatalf("blipvol %s has no current snapshot: %+v", v.Name, v.Status)
	}
	return s
}

// readySeqs lists the sequences of the Ready snapshots of a BlipVol.
func readySeqs(v *v1.BlipVol) []int64 {
	var out []int64
	for _, s := range v.Status.Snapshots {
		if s.State == v1.SnapshotReady {
			out = append(out, s.Sequence)
		}
	}
	return out
}

// newBlip creates a Blip; the first volume is the root volume. With no
// volumes, root is a volume named after ref.
func newBlip(t *testing.T, ns, name, ref, sku string, mut func(*v1.Blip), vols ...v1.BlipVolume) *v1.Blip {
	t.Helper()
	if len(vols) == 0 {
		vols = []v1.BlipVolume{vol("root", ref)}
	}
	b := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: v1.BlipSpec{SKU: sku, RootVolume: vols[0].Name, Volumes: vols}}
	if mut != nil {
		mut(b)
	}
	if err := env.k.Create(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	return b
}

func getBlip(ns, name string) *v1.Blip {
	var b v1.Blip
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &b); err != nil {
		return nil
	}
	return &b
}

func waitBlip(t *testing.T, ns, name string, d time.Duration, f func(b *v1.Blip) bool) *v1.Blip {
	t.Helper()
	var b *v1.Blip
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if b = getBlip(ns, name); b != nil && f(b) {
			return b
		}
		time.Sleep(50 * time.Millisecond)
	}
	if b != nil {
		t.Fatalf("timed out waiting for blip %s: status %+v", name, b.Status)
	}
	t.Fatalf("timed out waiting for blip %s: not found", name)
	return nil
}

func finished(t *testing.T, ns, name string) *v1.Blip {
	t.Helper()
	return waitBlip(t, ns, name, 30*time.Second, func(b *v1.Blip) bool { return isFinished(b) })
}

func failedWith(t *testing.T, ns, name, reason string) *v1.Blip {
	t.Helper()
	b := finished(t, ns, name)
	if c := meta.FindStatusCondition(b.Status.Conditions, api.CondFailed); c == nil || c.Status != metav1.ConditionTrue || c.Reason != reason {
		t.Fatalf("blip %s: want Failed/%s, got %+v (message %q)", name, reason, c, b.Status.Message)
	}
	if isTrue(b.Status.Conditions, api.CondComplete) {
		t.Fatalf("failed blip is Complete")
	}
	if condReason(b.Status.Conditions, api.CondFinished) != reason {
		t.Fatalf("Finished reason %q", condReason(b.Status.Conditions, api.CondFinished))
	}
	return b
}

// released checks that no claim or hold of the Blip is left on the volumes.
func released(t *testing.T, ns string, b *v1.Blip, names ...string) {
	t.Helper()
	for _, n := range names {
		v := getVol(ns, n)
		if v == nil {
			continue
		}
		if cl := v.Status.Claim; cl != nil && cl.BlipUID == string(b.UID) {
			t.Fatalf("%s still claimed by %s", n, b.Name)
		}
		for _, h := range v.Status.Holds {
			if h.Holder.UID == string(b.UID) {
				t.Fatalf("%s still has a %s hold of %s", n, h.Kind, b.Name)
			}
		}
	}
}

func volState(b *v1.Blip, name string) *v1.BlipVolumeStatus { return volStatus(b, name) }

// opsFor returns the kinds of commands for an allocation on a node, in order.
func opsFor(n *fakenode.Node, alloc string) []string {
	var out []string
	for _, c := range n.Commands() {
		if !strings.HasPrefix(c.OperationId, alloc) && !strings.HasPrefix(c.OperationId, "t-") && !strings.HasPrefix(c.OperationId, "cap-") {
			continue
		}
		switch x := c.Op.(type) {
		case *nodepb.Command_AssignSlot:
			out = append(out, "assign")
		case *nodepb.Command_AttachVolume:
			out = append(out, "attach")
		case *nodepb.Command_StartWorkload:
			out = append(out, "start")
		case *nodepb.Command_Kill:
			out = append(out, "kill")
		case *nodepb.Command_CaptureLocal:
			if x.CaptureLocal.AllocationId == alloc {
				out = append(out, "capture")
			}
		case *nodepb.Command_WriteSnapshot:
			if x.WriteSnapshot.AllocationId == alloc {
				out = append(out, "send")
			}
		case *nodepb.Command_DetachVolume:
			out = append(out, "detach")
		case *nodepb.Command_ReleaseAttachment:
			out = append(out, "relatt")
		case *nodepb.Command_Release:
			out = append(out, "release")
		}
	}
	return out
}

// before checks that every a precedes every b in ops.
func before(ops []string, a, b string) bool {
	lastA, firstB := -1, len(ops)
	for i, o := range ops {
		if o == a {
			lastA = i
		}
		if o == b && i < firstB {
			firstB = i
		}
	}
	return lastA >= 0 && firstB < len(ops) && lastA < firstB
}

func isOp[T any](f func(*nodepb.Command) T) func(*nodepb.Command) bool {
	return func(c *nodepb.Command) bool {
		var zero T
		return any(f(c)) != any(zero)
	}
}

func emptyVol(t *testing.T, ns, name string) *v1.BlipVol {
	return readyVol(t, ns, name, v1.BlipVolSpec{})
}

func podGone(ns, name string) bool {
	var p corev1.Pod
	// Without a kubelet, deleted pods keep a deletionTimestamp.
	err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p)
	return err != nil || p.DeletionTimestamp != nil
}

func q(s string) *resource.Quantity { v := resource.MustParse(s); return &v }

// loseAppend, when set, loses the response of the next BlipVol status
// write that appends a capture (the write itself succeeds).
var loseAppend atomic.Bool

// wrapLive simulates lost API responses on the uncached client.
func wrapLive(client.Client) client.Client {
	ww, err := client.NewWithWatch(env.cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		panic(err)
	}
	return interceptor.NewClient(ww, interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		err := c.SubResource(sub).Update(ctx, obj, opts...)
		if v, ok := obj.(*v1.BlipVol); ok && err == nil && sub == "status" {
			for _, s := range v.Status.Snapshots {
				if s.State == v1.SnapshotPending && s.Writer != nil && loseAppend.CompareAndSwap(true, false) {
					return errors.New("simulated lost response")
				}
			}
		}
		return err
	}})
}

func skipNoEnv(t *testing.T) {
	if env.ctrl == nil {
		t.Skip("envtest not configured (set KUBEBUILDER_ASSETS)")
	}
}

func complete(t *testing.T, ns, name string) *v1.Blip {
	t.Helper()
	b := finished(t, ns, name)
	if !isTrue(b.Status.Conditions, api.CondComplete) || b.Status.Phase != v1.BlipSucceeded {
		t.Fatalf("blip %s did not complete: %+v", name, b.Status)
	}
	// The guest booted, however short the run.
	if !isTrue(b.Status.Conditions, api.CondStarted) {
		t.Fatalf("blip %s completed without Started: %+v", name, b.Status.Conditions)
	}
	return b
}

func taint(t *testing.T, node string, on bool) {
	t.Helper()
	for range 10 {
		var n corev1.Node
		if err := env.k.Get(context.Background(), types.NamespacedName{Name: node}, &n); err != nil {
			t.Fatal(err)
		}
		n.Spec.Taints = nil
		if on {
			n.Spec.Taints = []corev1.Taint{{Key: api.TaintOutOfService, Value: "nodeshutdown", Effect: corev1.TaintEffectNoExecute}}
		}
		if err := env.k.Update(context.Background(), &n); err == nil {
			return
		}
	}
	t.Fatal("could not taint node")
}

func patchVolumes(t *testing.T, ns, name string, f func([]v1.BlipVolume) []v1.BlipVolume) {
	t.Helper()
	for range 10 {
		b := getBlip(ns, name)
		b.Spec.Volumes = f(b.Spec.Volumes)
		if err := env.k.Update(context.Background(), b); err == nil {
			return
		} else if !strings.Contains(err.Error(), "modified") {
			t.Fatal(err)
		}
	}
	t.Fatal("update kept conflicting")
}

func nsName(ns, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: ns, Name: name}
}
