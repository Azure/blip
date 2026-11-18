package runtime

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/guest"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

// fakeCH serves the subset of the Cloud Hypervisor API the runtime uses.
type fakeCH struct {
	mu    sync.Mutex
	disks map[string]map[string]any
}

func startFakeCH(t *testing.T, sock string) *fakeCH {
	f := &fakeCH{disks: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/vm.add-disk", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.disks[body["id"].(string)] = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/vm.remove-device", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		delete(f.disks, body["id"].(string))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v1/vm.info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var disks []map[string]any
		for _, d := range f.disks {
			disks = append(disks, d)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"config": map[string]any{"disks": disks}})
	})
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeCH) disk(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disks[id]
}

type fakeGuest struct {
	t      *testing.T
	r      *runtime
	frames chan frame
	conn   *wire.Conn
}

type frame struct {
	t       wire.Type
	payload []byte
}

func newTestRuntime(t *testing.T) (*runtime, *fakeCH, *fakeGuest) {
	dir := t.TempDir()
	o := Options{Dir: dir, SkipNetwork: true}
	ch := startFakeCH(t, o.path(podapi.APISocket))
	r := &runtime{
		o:         o,
		ch:        newCHClient(o.path(podapi.APISocket)),
		disks:     map[string]*disk{},
		ctlEvents: make(chan ctlEvent, 16),
		removed:   make(chan removeResult, 16),
	}
	r.resetFreeze()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	r.raw, r.conn = a, wire.NewConn(a)
	g := &fakeGuest{t: t, r: r, frames: make(chan frame, 64), conn: wire.NewConn(b)}
	go func() {
		for {
			typ, p, err := g.conn.Read()
			if err != nil {
				return
			}
			g.frames <- frame{typ, p}
		}
	}()
	return r, ch, g
}

// expect waits for the next frame the runtime sent to the guest.
func (g *fakeGuest) expect(typ wire.Type, v any) {
	g.t.Helper()
	select {
	case f := <-g.frames:
		if f.t != typ {
			g.t.Fatalf("got frame %d %s, want %d", f.t, f.payload, typ)
		}
		if v != nil {
			if err := json.Unmarshal(f.payload, v); err != nil {
				g.t.Fatal(err)
			}
		}
	case <-time.After(5 * time.Second):
		g.t.Fatalf("no frame %d", typ)
	}
}

func (g *fakeGuest) none() {
	g.t.Helper()
	time.Sleep(20 * time.Millisecond)
	select {
	case f := <-g.frames:
		g.t.Fatalf("unexpected frame %d %s", f.t, f.payload)
	default:
	}
}

// reply delivers a guest frame to the runtime and reconciles, like the
// main loop.
func (g *fakeGuest) reply(typ wire.Type, v any) {
	data, _ := json.Marshal(v)
	g.r.handleControl(ctlEvent{t: typ, payload: data})
	g.r.reconcile()
	g.r.writeObserved()
}

func observed(t *testing.T, r *runtime) podapi.Observed {
	t.Helper()
	var o podapi.Observed
	if err := podapi.ReadJSON(r.o.path(podapi.ObservedFile), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestClaimMountUnmountLifecycle(t *testing.T) {
	r, ch, g := newTestRuntime(t)
	r.writeObserved()
	if o := observed(t, r); o.Phase != podapi.PhaseBooting {
		t.Fatalf("phase %s", o.Phase)
	}
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	if o := observed(t, r); o.Phase != podapi.PhaseWarm {
		t.Fatalf("phase %s", o.Phase)
	}

	root := podapi.Disk{ID: "00000000000000aa", Serial: "00000000000000aa", Device: "/dev/root"}
	r.desired = podapi.Desired{Claim: &podapi.Claim{BlipName: "b", Root: root, Command: []string{"true"}, WaitForClient: true}}
	r.reconcile()
	r.writeObserved()
	var claim wire.Claim
	g.expect(wire.TClaim, &claim)
	if claim.ID != root.ID || claim.Hostname != "b" || !claim.WaitForClient {
		t.Fatalf("claim %+v", claim)
	}
	if d := ch.disk(root.ID); d == nil || d["pci_segment"].(float64) != 1 || d["serial"] != root.ID || d["readonly"] != false {
		t.Fatalf("root disk %v", d)
	}
	if o := observed(t, r); o.Phase != podapi.PhaseClaiming {
		t.Fatalf("phase %s", o.Phase)
	}
	g.reply(wire.TClaimResult, wire.Result{ID: root.ID})
	if o := observed(t, r); o.Phase != podapi.PhaseRunning || o.ClaimID != root.ID {
		t.Fatalf("observed %+v", o)
	}

	data := podapi.Disk{ID: "00000000000000bb", Serial: "00000000000000bb", Device: "/dev/data", Path: "/data", State: "s", ReadOnly: true}
	r.desired.Mounts = []podapi.Disk{data}
	r.reconcile()
	var m wire.Mount
	g.expect(wire.TMount, &m)
	if m.Path != "/data" || !m.ReadOnly || ch.disk(data.ID)["readonly"] != true {
		t.Fatalf("mount %+v disk %v", m, ch.disk(data.ID))
	}
	g.reply(wire.TMountResult, wire.Result{ID: data.ID})
	if o := observed(t, r); o.Mounts[0].Phase != podapi.DiskMounted || o.Mounts[0].State != "s" {
		t.Fatalf("observed %+v", o)
	}

	// Busy unmount: Failed, still attached, no immediate retry.
	r.desired.Mounts = nil
	r.reconcile()
	g.expect(wire.TUnmount, nil)
	g.reply(wire.TUnmountResult, wire.Result{ID: data.ID, Error: "target is busy"})
	if o := observed(t, r); o.Mounts[0].Phase != podapi.DiskFailed || !strings.Contains(o.Mounts[0].Message, "busy") {
		t.Fatalf("observed %+v", o)
	}
	if ch.disk(data.ID) == nil {
		t.Fatalf("disk removed after failed unmount")
	}
	r.reconcile()
	g.none()

	// A retry (desired changed or 10s passed) unmounts and detaches.
	r.disks[data.ID].retryAt = time.Time{}
	r.reconcile()
	g.expect(wire.TUnmount, nil)
	g.reply(wire.TUnmountResult, wire.Result{ID: data.ID})
	r.handleRemoved(<-r.removed)
	r.writeObserved()
	if o := observed(t, r); o.Mounts[0].Phase != podapi.DiskDetached {
		t.Fatalf("observed %+v", o)
	}
	if ch.disk(data.ID) != nil {
		t.Fatalf("disk still attached")
	}

	// Exit from the guest, then stop.
	g.reply(wire.TExit, wire.Exit{Code: 3, Reason: "Completed"})
	if o := observed(t, r); o.Phase != podapi.PhaseStopping || o.Exit == nil || o.Exit.Code != 3 {
		t.Fatalf("observed %+v", o)
	}
	r.vmExited()
	r.writeObserved()
	if o := observed(t, r); o.Phase != podapi.PhaseExited || o.Exit.Reason != "Completed" {
		t.Fatalf("observed %+v", o)
	}
}

func TestStopAndResync(t *testing.T) {
	r, _, g := newTestRuntime(t)
	r.disks["m"] = &disk{d: podapi.Disk{ID: "m"}, phase: podapi.DiskAttaching, inVM: true, waiting: true}
	r.order = []string{"m"}
	r.desired = podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "r"}}, Mounts: []podapi.Disk{{ID: "m", Path: "/m"}}}
	// A reconnecting runtime learns the claim and mounts from Hello and
	// does not resend them.
	g.reply(wire.THello, wire.Hello{Version: wire.Version, ClaimID: "r", Mounts: []string{"m"}})
	g.none()
	if o := observed(t, r); o.Phase != podapi.PhaseRunning || o.Mounts[0].Phase != podapi.DiskMounted {
		t.Fatalf("observed %+v", o)
	}
	r.desired.Stop = true
	r.reconcile()
	g.expect(wire.TShutdown, nil)
	r.reconcile()
	g.none()
	r.vmExited()
	r.writeObserved()
	if o := observed(t, r); o.Phase != podapi.PhaseExited || o.Exit == nil || o.Exit.Reason != "Stopped" || o.Mounts[0].Phase != podapi.DiskDetached {
		t.Fatalf("observed %+v", o)
	}
}

func TestFreeze(t *testing.T) {
	r, _, g := newTestRuntime(t)
	r.desired = podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "r"}}}
	g.reply(wire.THello, wire.Hello{Version: wire.Version, ClaimID: "r"})
	frozen := func() string { return strings.Join(observed(t, r).Frozen, ",") }

	r.desired.Freeze = []string{"r"}
	r.reconcile()
	var f wire.Freeze
	g.expect(wire.TFreeze, &f)
	if f.ID != "r" {
		t.Fatalf("freeze %+v", f)
	}
	r.reconcile()
	g.none()
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Frozen: true})
	if got := frozen(); got != "r" {
		t.Fatalf("frozen %q", got)
	}

	// Removing it from Desired.Freeze thaws.
	r.desired.Freeze = nil
	r.reconcile()
	g.expect(wire.TThaw, &f)
	r.writeObserved()
	if got := frozen(); got != "" {
		t.Fatalf("frozen %q", got)
	}
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r"})
	g.none()

	// A guest-side auto-thaw is not retried until the ID leaves Freeze.
	r.desired.Freeze = []string{"r"}
	r.reconcile()
	g.expect(wire.TFreeze, nil)
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Frozen: true})
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Error: "thawed after timeout"})
	g.none()
	if got := frozen(); got != "" {
		t.Fatalf("frozen %q", got)
	}
	r.desired.Freeze = nil
	r.reconcile()
	g.none()
	r.desired.Freeze = []string{"r"}
	r.reconcile()
	g.expect(wire.TFreeze, nil)

	// A failed freeze is not reported and not retried.
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Error: "boom"})
	g.none()
	if got := frozen(); got != "" {
		t.Fatalf("frozen %q", got)
	}

	// Hello resyncs: a disk frozen but no longer desired is thawed.
	r.desired.Freeze = nil
	g.reply(wire.THello, wire.Hello{Version: wire.Version, ClaimID: "r", Frozen: []string{"r"}})
	g.expect(wire.TThaw, nil)
}

// Two back-to-back copies: the second re-adds the ID before the first
// copy's thaw result arrives. It must not be reported frozen until a fresh
// freeze sent after the thaw is confirmed.
func TestFreezeReaddedDuringThaw(t *testing.T) {
	r, _, g := newTestRuntime(t)
	r.desired = podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "r"}}}
	g.reply(wire.THello, wire.Hello{Version: wire.Version, ClaimID: "r"})
	frozen := func() string { return strings.Join(observed(t, r).Frozen, ",") }

	r.desired.Freeze = []string{"r"}
	r.reconcile()
	g.expect(wire.TFreeze, nil)
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Frozen: true})
	if got := frozen(); got != "r" {
		t.Fatalf("frozen %q", got)
	}

	r.desired.Freeze = nil
	r.reconcile()
	g.expect(wire.TThaw, nil)
	r.desired.Freeze = []string{"r"}
	r.reconcile()
	g.none()
	r.writeObserved()
	if got := frozen(); got != "" {
		t.Fatalf("frozen %q while thaw in flight", got)
	}

	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r"})
	g.expect(wire.TFreeze, nil)
	if got := frozen(); got != "" {
		t.Fatalf("frozen %q before fresh freeze confirmed", got)
	}
	g.reply(wire.TFreezeResult, wire.FreezeResult{ID: "r", Frozen: true})
	if got := frozen(); got != "r" {
		t.Fatalf("frozen %q", got)
	}
}

func TestObservedWrittenOnlyOnChange(t *testing.T) {
	r, _, _ := newTestRuntime(t)
	r.writeObserved()
	path := r.o.path(podapi.ObservedFile)
	st1, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	r.writeObserved()
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatalf("observed rewritten without change")
	}
}

func TestWatchDesiredKeepsLastValid(t *testing.T) {
	r, _, _ := newTestRuntime(t)
	ch := make(chan podapi.Desired, 4)
	go r.watchDesired(ch)
	path := r.o.path(podapi.DesiredFile)
	if err := podapi.WriteJSON(path, podapi.Desired{Stop: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-ch:
		if !d.Stop {
			t.Fatalf("got %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no desired")
	}
	os.WriteFile(path, []byte("{bad"), 0o644)
	os.Remove(path)
	select {
	case d := <-ch:
		t.Fatalf("delivered %+v for missing/malformed file", d)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestChArgs(t *testing.T) {
	o := Options{Dir: "/run/blip", Kernel: "/k", Initramfs: "/i", CPUs: 2, MemoryMB: 512}
	got := strings.Join(chArgs(o, "/run/blip/c.img", "tap0", "aa:bb:cc:dd:ee:ff"), " ")
	for _, want := range []string{
		"--api-socket path=/run/blip/ch-api.sock",
		"--cmdline console=ttyS0",
		"--cpus boot=2",
		"--memory size=512M",
		"--platform num_pci_segments=2",
		"serial=blip-config",
		"readonly=on",
		"--vsock cid=3,socket=/run/blip/vsock/vsock.sock",
		"--serial tty",
		"--net tap=tap0,mac=aa:bb:cc:dd:ee:ff",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
}

func TestReadResolvConf(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, "resolv.conf")
	os.WriteFile(rc, []byte("# c\nnameserver 10.96.0.10\nsearch a.svc b.svc\noptions ndots:5 edns0\n"), 0o644)
	dns, search, opts := readResolvConf(rc)
	if strings.Join(dns, ",") != "10.96.0.10" || strings.Join(search, ",") != "a.svc,b.svc" || strings.Join(opts, ",") != "ndots:5,edns0" {
		t.Fatalf("%v %v %v", dns, search, opts)
	}
}

func TestClaimEnvironmentIsNotPodEnvironment(t *testing.T) {
	r, _, g := newTestRuntime(t)
	r.o.KubeNamespace = "ns"
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	g.none()
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	r.desired = podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "r"}, Env: []string{"KUBERNETES_SERVICE_PORT=6443", "A=1"}}}
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	var claim wire.Claim
	g.expect(wire.TClaim, &claim)
	if got := strings.Join(claim.Env, " "); got != "KUBERNETES_SERVICE_PORT=6443 A=1" {
		t.Fatalf("env %q", got)
	}
}

func TestBootNamespaceAndVsockDirectory(t *testing.T) {
	t.Setenv("BLIP_KUBE_NAMESPACE", "tenant")
	t.Setenv("BLIP_GATEWAY_LOOPBACK_PORT", "8123")
	if got := OptionsFromEnv().KubeNamespace; got != "tenant" {
		t.Fatalf("namespace %q", got)
	}
	if got := OptionsFromEnv().GatewayLoopbackPort; got != 8123 {
		t.Fatalf("gateway loopback port %d", got)
	}
	dir := t.TempDir()
	// An older release created the pod directory 0755; boot must tighten it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	o := Options{Dir: dir, SkipNetwork: true, KubeNamespace: "tenant", GatewayLoopbackPort: 8123, CH: "/bin/true"}
	// The API sidecar can bind its suffix socket before the VMM starts.
	suffix := o.path(podapi.VsockSocket) + "_1026"
	vsockDir := filepath.Dir(suffix)
	if err := os.MkdirAll(vsockDir, 0o770); err != nil { // kubelet fsGroup mode
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", suffix)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// /bin/true never binds CH's sockets; secureCHSockets is covered by its
	// own test.
	r := &runtime{o: o, vmDone: make(chan struct{}), secureSockets: func() error { return nil }}
	if _, err := r.boot(); err != nil {
		t.Fatal(err)
	}
	<-r.vmDone
	img, err := os.ReadFile(o.path("guest-config.img"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := guest.DecodeConfig(img)
	if err != nil || cfg.KubeNamespace != "tenant" || cfg.GatewayLoopbackPort != 8123 {
		t.Fatalf("config %+v: %v", cfg, err)
	}
	if _, err := os.Stat(suffix); err != nil {
		t.Fatalf("sidecar socket removed: %v", err)
	}
	if got := modeOf(t, dir); got != 0o700 {
		t.Fatalf("pod directory mode %#o, want 0700", got)
	}
	// The vsock emptyDir is shared with the non-root API proxy (fsGroup).
	if got := modeOf(t, vsockDir); got != 0o770 {
		t.Fatalf("vsock directory mode %#o, want 0770 preserved", got)
	}
	// Also check the empty-directory case, without a sidecar to create it.
	r.o.Dir = t.TempDir()
	r.vmDone = make(chan struct{})
	if _, err := r.boot(); err != nil {
		t.Fatal(err)
	}
	<-r.vmDone
	if st, err := os.Stat(filepath.Dir(r.o.path(podapi.VsockSocket))); err != nil || !st.IsDir() {
		t.Fatalf("missing vsock directory: %v", err)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestWaitSocketChmodsExistingSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), podapi.APISocket)
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := waitSocket(path, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("socket mode %#o, want 0600", got)
	}
}

func TestWaitSocketWaitsForCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vsock", "vsock.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(50 * time.Millisecond)
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Errorf("listen: %v", err)
			return
		}
		t.Cleanup(func() { l.Close() })
	}()
	if err := waitSocket(path, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	<-done
	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("socket mode %#o, want 0600", got)
	}
}

func TestWaitSocketFailsWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), podapi.APISocket)
	err := waitSocket(path, 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("got %v, want missing-socket error", err)
	}
}

func TestWaitSocketRejectsNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), podapi.APISocket)
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := waitSocket(path, time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a unix socket") {
		t.Fatalf("got %v, want not-a-socket error", err)
	}
}

type fakePolicyNetwork struct {
	calls  int
	policy *network.Policy
	active bool
	err    error
}

func (n *fakePolicyNetwork) apply(p *network.Policy, active bool) error {
	n.calls++
	n.policy, n.active = p, active
	return n.err
}

func TestPolicyGatesClaimAndReconcilesWithoutGuest(t *testing.T) {
	r, ch, g := newTestRuntime(t)
	r.o.SkipNetwork = false
	n := &fakePolicyNetwork{}
	r.network = n
	// A warm VM can preinstall policy, but forwarding stays closed.
	r.desired.Network = &network.Policy{Revision: "one"}
	r.reconcile()
	r.writeObserved()
	if n.calls != 1 || n.active || observed(t, r).NetworkRevision != "one" {
		t.Fatalf("network %+v", n)
	}
	r.desired.Claim = &podapi.Claim{Root: podapi.Disk{ID: "root"}}
	n.err = errors.New("apply failed")
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	g.none()
	if ch.disk("root") != nil || observed(t, r).NetworkError == "" || observed(t, r).NetworkRevision != "" {
		t.Fatal("claim escaped failed policy gate")
	}
	// A corrected policy is applied immediately, without waiting for retry.
	n.err = nil
	r.desired.Network = &network.Policy{Revision: "two"}
	r.reconcile()
	g.expect(wire.TClaim, nil)
	if !n.active {
		t.Fatal("claim did not open policy gate")
	}
	g.reply(wire.TClaimResult, wire.Result{ID: "root"})
	r.conn = nil
	r.desired.Network = &network.Policy{Revision: "revoked"}
	r.reconcile()
	r.writeObserved()
	if n.policy.Revision != "revoked" || observed(t, r).NetworkRevision != "revoked" {
		t.Fatal("policy update depended on guest connection")
	}
}

func TestMissingPolicyBlocksClaimButNotStopOrMounts(t *testing.T) {
	r, _, g := newTestRuntime(t)
	r.o.SkipNetwork = false
	n := &fakePolicyNetwork{}
	r.network = n
	r.desired.Claim = &podapi.Claim{Root: podapi.Disk{ID: "root"}}
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	g.none()
	if r.networkReady {
		t.Fatal("nil policy ready")
	}
	// Once running, a policy error must not strand attached disks or stop.
	r.claimID = "root"
	r.desired.Network = &network.Policy{Revision: "bad"}
	n.err = errors.New("invalid policy")
	r.desired.Mounts = []podapi.Disk{{ID: "data", Path: "/data"}}
	r.reconcile()
	g.expect(wire.TMount, nil)
	r.desired.Stop = true
	r.reconcile()
	g.expect(wire.TShutdown, nil)
}

// mountedRuntime returns a running runtime with d mounted in the guest.
func mountedRuntime(t *testing.T, d podapi.Disk) (*runtime, *fakeCH, *fakeGuest) {
	t.Helper()
	r, ch, g := newTestRuntime(t)
	r.writeObserved()
	g.reply(wire.THello, wire.Hello{Version: wire.Version})
	root := podapi.Disk{ID: "root", Serial: "root", Device: "/dev/root"}
	r.desired = podapi.Desired{Claim: &podapi.Claim{BlipName: "b", Root: root, Command: []string{"true"}}}
	r.reconcile()
	g.expect(wire.TClaim, nil)
	g.reply(wire.TClaimResult, wire.Result{ID: root.ID})
	r.desired.Mounts = []podapi.Disk{d}
	r.reconcile()
	g.expect(wire.TMount, nil)
	g.reply(wire.TMountResult, wire.Result{ID: d.ID})
	return r, ch, g
}

// detach removes d from Desired and drives unmount and device removal until
// the runtime reports it Detached.
func detach(t *testing.T, r *runtime, g *fakeGuest, id string) {
	t.Helper()
	r.desired.Mounts = nil
	r.reconcile()
	g.expect(wire.TUnmount, nil)
	g.reply(wire.TUnmountResult, wire.Result{ID: id})
	r.handleRemoved(<-r.removed)
	r.writeObserved()
	if o := observed(t, r); len(o.Mounts) != 1 || o.Mounts[0].Phase != podapi.DiskDetached {
		t.Fatalf("observed %+v", o)
	}
}

// The same attachment ID can be mounted again after its disk was detached.
func TestReattachDetachedDisk(t *testing.T) {
	data := podapi.Disk{ID: "data", Serial: "data", Device: "/dev/data", Path: "/data"}
	r, ch, g := mountedRuntime(t, data)
	detach(t, r, g, data.ID)
	if ch.disk(data.ID) != nil {
		t.Fatal("disk still attached")
	}

	r.desired.Mounts = []podapi.Disk{data}
	r.reconcile()
	var m wire.Mount
	g.expect(wire.TMount, &m)
	if m.ID != data.ID || m.Path != data.Path || ch.disk(data.ID) == nil {
		t.Fatalf("reattach %+v disk %v", m, ch.disk(data.ID))
	}
	e := r.disks[data.ID]
	if !e.inVM || !e.waiting || e.mounted || e.phase != podapi.DiskAttaching {
		t.Fatalf("entry after reattach %+v", e)
	}
	g.reply(wire.TMountResult, wire.Result{ID: data.ID})
	if o := observed(t, r); len(o.Mounts) != 1 || o.Mounts[0].Phase != podapi.DiskMounted {
		t.Fatalf("observed %+v", o)
	}
	if len(r.order) != 1 || r.order[0] != data.ID {
		t.Fatalf("order %v", r.order)
	}
}

// A re-add that arrives while the asynchronous device removal is in flight
// must not be lost to the removal result.
func TestReaddedWhileRemovalInFlight(t *testing.T) {
	data := podapi.Disk{ID: "data", Serial: "data", Device: "/dev/data", Path: "/data"}
	r, ch, g := mountedRuntime(t, data)

	r.desired.Mounts = nil
	r.reconcile()
	g.expect(wire.TUnmount, nil)
	g.reply(wire.TUnmountResult, wire.Result{ID: data.ID})
	if e := r.disks[data.ID]; !e.removing {
		t.Fatalf("removal not started: %+v", e)
	}

	// Desired wants the ID again before the remove result is delivered: the
	// device must not be re-added while remove-device is already in flight.
	r.desired.Mounts = []podapi.Disk{data}
	r.reconcile()
	g.none()

	r.handleRemoved(<-r.removed)
	r.reconcile()
	var m wire.Mount
	g.expect(wire.TMount, &m)
	if m.ID != data.ID || ch.disk(data.ID) == nil {
		t.Fatalf("mount %+v disk %v", m, ch.disk(data.ID))
	}
	g.reply(wire.TMountResult, wire.Result{ID: data.ID})
	if o := observed(t, r); len(o.Mounts) != 1 || o.Mounts[0].Phase != podapi.DiskMounted {
		t.Fatalf("observed %+v", o)
	}
	if e := r.disks[data.ID]; e.removing || !e.inVM || !e.mounted {
		t.Fatalf("entry %+v", e)
	}
}

// Genuine removal still ends Detached without attaching the device again.
func TestRemovedDiskStaysDetached(t *testing.T) {
	data := podapi.Disk{ID: "data", Serial: "data", Device: "/dev/data", Path: "/data"}
	r, ch, g := mountedRuntime(t, data)
	detach(t, r, g, data.ID)

	r.reconcile()
	g.none()
	if ch.disk(data.ID) != nil {
		t.Fatal("disk reattached")
	}
	if len(r.order) != 1 || r.order[0] != data.ID {
		t.Fatalf("order %v", r.order)
	}
	if o := observed(t, r); len(o.Mounts) != 1 || o.Mounts[0].Phase != podapi.DiskDetached {
		t.Fatalf("observed %+v", o)
	}
}

// A detached read-only disk that is no longer wanted is forgotten instead of
// lingering in order/observed.json, and re-adding it still attaches once.
func TestDetachedReadOnlyDiskIsForgotten(t *testing.T) {
	data := podapi.Disk{ID: "data", Serial: "data", Device: "/dev/data", Path: "/data", ReadOnly: true}
	r, ch, g := mountedRuntime(t, data)

	r.desired.Mounts = nil
	r.reconcile()
	g.expect(wire.TUnmount, nil)
	g.reply(wire.TUnmountResult, wire.Result{ID: data.ID})
	r.handleRemoved(<-r.removed)
	r.reconcile() // the main loop reconciles before writing observed
	r.writeObserved()
	if o := observed(t, r); len(o.Mounts) != 0 {
		t.Fatalf("stale detached mount: %+v", o.Mounts)
	}
	if len(r.order) != 0 || r.disks[data.ID] != nil {
		t.Fatalf("order %v disk %+v", r.order, r.disks[data.ID])
	}

	r.desired.Mounts = []podapi.Disk{data}
	r.reconcile()
	g.expect(wire.TMount, nil)
	if len(r.order) != 1 || r.order[0] != data.ID || ch.disk(data.ID) == nil {
		t.Fatalf("order %v disk %v", r.order, ch.disk(data.ID))
	}
}
