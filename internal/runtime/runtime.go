// Package runtime is blip-runtime: it runs Cloud Hypervisor in a VM pod,
// applies desired.json through the guest control port, and reports
// observed.json.
package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Azure/blip/internal/guest"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

const (
	retryInterval = 10 * time.Second
	// A busy unmount is retried often: it is cheap and a user is waiting.
	unmountRetryInterval = 2 * time.Second
	stopTimeout          = 60 * time.Second
	removeTimeout        = 30 * time.Second
)

// Options configures the runtime. OptionsFromEnv fills it from the pod.
type Options struct {
	Dir         string // pod directory
	Kernel      string
	Initramfs   string
	CH          string // cloud-hypervisor binary
	CPUs        int
	MemoryMB    int
	SkipNetwork bool
	// KubeNamespace enables the guest's tokenless Kubernetes API connection.
	KubeNamespace string
	// GatewayLoopbackPort enables the guest's loopback forwarder to the
	// gateway proxy.
	GatewayLoopbackPort int
}

func (o Options) path(name string) string { return filepath.Join(o.Dir, name) }

// OptionsFromEnv reads BLIP_CPUS, BLIP_MEMORY_MB and BLIP_SKIP_NETWORK. The
// remaining BLIP_* variables exist for local testing outside a pod.
func OptionsFromEnv() Options {
	o := Options{
		Dir:       podapi.MountPath,
		Kernel:    "/opt/blip/vmlinuz",
		Initramfs: "/opt/blip/initramfs.gz",
		CH:        "/usr/local/bin/cloud-hypervisor",
		CPUs:      1,
		MemoryMB:  1024,
	}
	str := func(env string, dst *string) {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	num := func(env string, dst *int) {
		if v, err := strconv.Atoi(os.Getenv(env)); err == nil && v > 0 {
			*dst = v
		}
	}
	str("BLIP_DIR", &o.Dir)
	str("BLIP_KERNEL", &o.Kernel)
	str("BLIP_INITRAMFS", &o.Initramfs)
	str("BLIP_CH", &o.CH)
	str("BLIP_KUBE_NAMESPACE", &o.KubeNamespace)
	num("BLIP_CPUS", &o.CPUs)
	num("BLIP_MEMORY_MB", &o.MemoryMB)
	num("BLIP_GATEWAY_LOOPBACK_PORT", &o.GatewayLoopbackPort)
	o.SkipNetwork = os.Getenv("BLIP_SKIP_NETWORK") == "1"
	return o
}

type disk struct {
	d        podapi.Disk
	phase    string
	message  string
	inVM     bool // attached in Cloud Hypervisor
	mounted  bool // mounted in the guest
	waiting  bool // Mount or Unmount sent, no result yet
	removing bool // device removal in progress
	retryAt  time.Time
}

type ctlEvent struct {
	gen     int
	conn    net.Conn // set on connect
	t       wire.Type
	payload []byte
	err     error
}

type removeResult struct {
	id  string
	err error
}

type runtime struct {
	o      Options
	ch     *chClient
	vm     *exec.Cmd
	vmDone chan struct{}
	vmErr  error

	desired podapi.Desired

	ctlEvents chan ctlEvent
	removed   chan removeResult
	gen       int
	conn      *wire.Conn
	raw       net.Conn

	hello        bool // a guest Hello was ever received
	claimID      string
	claimWaiting bool
	claimRetryAt time.Time
	rootInVM     bool
	disks        map[string]*disk
	order        []string
	sessions     int
	exit         *podapi.Exit
	errMsg       string
	sigterm      bool
	shutdownSent bool
	shutdownDone bool
	stopSince    time.Time
	exited       bool

	// frozen holds disk IDs the guest reports frozen; freezeWaiting those
	// with a Freeze or Thaw in flight; thawing those whose in-flight request
	// is a Thaw; freezeSkip those whose freeze failed or timed out, not
	// retried until they leave Desired.Freeze.
	frozen        map[string]bool
	freezeWaiting map[string]bool
	thawing       map[string]bool
	freezeSkip    map[string]bool

	network         policyNetwork
	networkReady    bool
	networkRevision string
	networkError    string
	networkKey      string
	networkRetryAt  time.Time

	lastObserved []byte
}

// Run supervises one VM until the VMM exits.
func Run(o Options) error {
	r := &runtime{
		o:         o,
		ch:        newCHClient(o.path(podapi.APISocket)),
		vmDone:    make(chan struct{}),
		ctlEvents: make(chan ctlEvent, 16),
		removed:   make(chan removeResult, 16),
		disks:     map[string]*disk{},
	}
	r.resetFreeze()
	desiredCh := make(chan podapi.Desired, 1)
	go r.watchDesired(desiredCh)
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	r.writeObserved()

	pn, err := r.boot()
	if err != nil {
		r.errMsg = err.Error()
		r.exited = true
		r.writeObserved()
		return err
	}
	if pn != nil {
		defer pn.teardown()
	}
	go r.connect(r.gen)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case d := <-desiredCh:
			r.desired = d
			for _, e := range r.disks {
				e.retryAt = time.Time{}
			}
			r.claimRetryAt = time.Time{}
		case ev := <-r.ctlEvents:
			r.handleControl(ev)
		case res := <-r.removed:
			r.handleRemoved(res)
		case <-sig:
			log.Printf("received stop signal")
			r.sigterm = true
		case <-r.vmDone:
			r.vmExited()
			r.writeObserved()
			return nil
		case <-tick.C:
		}
		// Apply everything already queued before the (fsynced) observed
		// write, so bursts of guest messages coalesce into one write.
		for drained := false; !drained; {
			select {
			case ev := <-r.ctlEvents:
				r.handleControl(ev)
			case res := <-r.removed:
				r.handleRemoved(res)
			default:
				drained = true
			}
		}
		r.reconcile()
		r.writeObserved()
	}
}

// boot writes the config disk, sets up networking and starts the VMM.
func (r *runtime) boot() (*podNet, error) {
	hostname, _ := os.Hostname()
	cfg := guest.Config{Hostname: hostname, KubeNamespace: r.o.KubeNamespace, GatewayLoopbackPort: r.o.GatewayLoopbackPort}
	var pn *podNet
	started := false
	defer func() {
		if !started && pn != nil {
			pn.teardown()
		}
	}()
	if !r.o.SkipNetwork {
		var err error
		if pn, err = setupNetwork(&cfg); err != nil {
			r.networkError = err.Error()
			return nil, fmt.Errorf("network: %w", err)
		}
		r.network = pn
	}
	img, err := guest.EncodeConfig(cfg)
	if err != nil {
		return nil, err
	}
	configDisk := r.o.path("guest-config.img")
	if err := os.WriteFile(configDisk, img, 0o600); err != nil {
		return nil, err
	}
	for _, s := range []string{podapi.APISocket, podapi.VsockSocket} {
		if err := os.MkdirAll(filepath.Dir(r.o.path(s)), 0o755); err != nil {
			return nil, err
		}
		_ = os.Remove(r.o.path(s))
	}
	tap, mac := "", ""
	if pn != nil {
		tap, mac = tapName, pn.mac
	}
	cmd := exec.Command(r.o.CH, chArgs(r.o, configDisk, tap, mac)...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cloud-hypervisor: %w", err)
	}
	started = true
	log.Printf("cloud-hypervisor started (pid %d)", cmd.Process.Pid)
	r.vm = cmd
	go func() {
		r.vmErr = cmd.Wait()
		log.Printf("cloud-hypervisor exited: %v", r.vmErr)
		close(r.vmDone)
	}()
	return pn, nil
}

// connect dials the guest control port until it answers, then forwards
// frames to the main loop.
func (r *runtime) connect(gen int) {
	for {
		select {
		case <-r.vmDone:
			return
		default:
		}
		c, err := wire.DialVsock(r.o.path(podapi.VsockSocket), wire.ControlPort, 2*time.Second)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		r.ctlEvents <- ctlEvent{gen: gen, conn: c}
		wc := wire.NewConn(c)
		for {
			t, p, err := wc.Read()
			r.ctlEvents <- ctlEvent{gen: gen, t: t, payload: p, err: err}
			if err != nil {
				return
			}
		}
	}
}

func (r *runtime) send(t wire.Type, v any) {
	if r.conn == nil {
		return
	}
	if err := r.conn.WriteJSON(t, v); err != nil {
		log.Printf("control write: %v", err)
		r.raw.Close()
	}
}

func (r *runtime) handleControl(ev ctlEvent) {
	if ev.gen != r.gen {
		if ev.conn != nil {
			ev.conn.Close()
		}
		return
	}
	if ev.conn != nil {
		r.raw, r.conn = ev.conn, wire.NewConn(ev.conn)
		return
	}
	if ev.err != nil {
		log.Printf("control connection lost: %v", ev.err)
		r.raw.Close()
		r.conn, r.raw = nil, nil
		if !r.shutdownDone && !r.exited {
			r.gen++
			go r.connect(r.gen)
		}
		return
	}
	switch ev.t {
	case wire.THello:
		var h wire.Hello
		if err := wire.Decode(ev.payload, &h); err != nil {
			log.Printf("bad hello: %v", err)
			return
		}
		r.resync(h)
	case wire.TClaimResult:
		var res wire.Result
		_ = wire.Decode(ev.payload, &res)
		r.claimWaiting = false
		if res.Error != "" {
			for _, e := range r.disks {
				e.waiting = false
			}
			log.Printf("claim failed: %s", res.Error)
			r.errMsg = "claim: " + res.Error
			r.claimRetryAt = time.Now().Add(retryInterval)
			return
		}
		r.claimID, r.errMsg = res.ID, ""
		log.Printf("claimed %s", res.ID)
	case wire.TMountResult:
		var res wire.Result
		_ = wire.Decode(ev.payload, &res)
		if e := r.disks[res.ID]; e != nil && e.waiting {
			e.waiting = false
			if res.Error != "" {
				e.phase, e.message, e.retryAt = podapi.DiskFailed, res.Error, time.Now().Add(retryInterval)
			} else {
				e.phase, e.message, e.mounted = podapi.DiskMounted, "", true
			}
		}
	case wire.TUnmountResult:
		var res wire.Result
		_ = wire.Decode(ev.payload, &res)
		if e := r.disks[res.ID]; e != nil && e.waiting {
			e.waiting = false
			if res.Error != "" {
				e.phase, e.message, e.retryAt = podapi.DiskFailed, res.Error, time.Now().Add(unmountRetryInterval)
			} else {
				e.mounted, e.message = false, ""
				delete(r.frozen, res.ID)
			}
		}
	case wire.TFreezeResult:
		var res wire.FreezeResult
		_ = wire.Decode(ev.payload, &res)
		delete(r.freezeWaiting, res.ID)
		if r.thawing[res.ID] {
			// Only a freeze confirmed after this thaw counts as frozen.
			delete(r.thawing, res.ID)
			if res.Error != "" {
				log.Printf("thaw %s: %s", res.ID, res.Error)
			}
			break
		}
		if res.Frozen {
			r.frozen[res.ID] = true
		} else {
			delete(r.frozen, res.ID)
		}
		if res.Error != "" {
			log.Printf("freeze %s: %s", res.ID, res.Error)
			if !res.Frozen {
				r.freezeSkip[res.ID] = true
			}
		}
	case wire.TStatus:
		var st wire.Status
		_ = wire.Decode(ev.payload, &st)
		r.sessions = st.Sessions
	case wire.TExit:
		var ex wire.Exit
		_ = wire.Decode(ev.payload, &ex)
		r.recordExit(ex)
	case wire.TShutdownDone:
		var sd wire.ShutdownDone
		_ = wire.Decode(ev.payload, &sd)
		log.Printf("guest shutdown done (clean=%v %s)", sd.Clean, sd.Error)
		if !sd.Clean {
			r.errMsg = "guest shutdown: " + sd.Error
		}
		r.shutdownDone = true
		r.raw.Close()
	}
}

func (r *runtime) recordExit(ex wire.Exit) {
	if r.exit != nil {
		return
	}
	r.exit = &podapi.Exit{Code: ex.Code, Signal: ex.Signal, Reason: ex.Reason, Output: ex.Output}
	if r.stopSince.IsZero() {
		r.stopSince = time.Now()
	}
	log.Printf("guest exit: %+v", *r.exit)
}

// resync adopts the guest's view after a (re)connect.
func (r *runtime) resync(h wire.Hello) {
	log.Printf("guest hello: claim=%q mounts=%v", h.ClaimID, h.Mounts)
	if h.ClaimID == "" && r.claimID != "" {
		// The guest kernel panicked and rebooted (panic=-1) after the claim.
		r.errMsg = "the VM guest crashed and restarted"
		log.Print(r.errMsg)
		_ = r.vm.Process.Kill()
		return
	}
	r.hello = true
	if h.Exit != nil {
		r.recordExit(*h.Exit)
	}
	if h.ClaimID != "" {
		r.claimID, r.rootInVM = h.ClaimID, true
	}
	r.claimWaiting = false
	r.shutdownSent = false
	r.frozen, r.freezeWaiting, r.thawing = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, id := range h.Frozen {
		r.frozen[id] = true
	}
	mounted := map[string]bool{}
	for _, id := range h.Mounts {
		mounted[id] = true
	}
	for _, e := range r.disks {
		e.waiting = false
		e.mounted = mounted[e.d.ID]
		if e.mounted && e.phase != podapi.DiskFailed {
			e.phase = podapi.DiskMounted
		}
	}
}

func (r *runtime) handleRemoved(res removeResult) {
	e := r.disks[res.id]
	if e == nil {
		return
	}
	e.removing = false
	if res.err != nil {
		e.phase, e.message, e.retryAt = podapi.DiskFailed, res.err.Error(), time.Now().Add(retryInterval)
		return
	}
	if r.wanted(res.id) && !r.stopRequested() && r.exit == nil {
		// The ID was re-added while the asynchronous removal was in
		// flight. Do not record Detached: forget the removal state and let
		// reconcileMounts run the normal attach path again. (While the VM
		// is stopping there is nothing to attach for.)
		e.inVM, e.mounted, e.waiting, e.phase, e.message = false, false, false, podapi.DiskAttaching, ""
		e.retryAt = time.Time{}
		log.Printf("disk %s removed; wanted again, reattaching", res.id)
		return
	}
	e.inVM, e.phase, e.message = false, podapi.DiskDetached, ""
	log.Printf("disk %s detached", res.id)
}

// wanted reports whether the attachment ID is in the current desired mounts.
func (r *runtime) wanted(id string) bool {
	for _, d := range r.desired.Mounts {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (r *runtime) stopRequested() bool { return r.desired.Stop || r.sigterm }

func (r *runtime) reconcile() {
	if r.exited {
		return
	}
	now := time.Now()
	// Policy updates and revocations do not depend on the guest control link.
	r.reconcileNetwork(now)
	if r.stopRequested() && r.stopSince.IsZero() {
		r.stopSince = now
	}
	if !r.stopSince.IsZero() && now.Sub(r.stopSince) > stopTimeout {
		log.Printf("VM did not stop within %v; killing it", stopTimeout)
		_ = r.vm.Process.Kill()
		return
	}
	if r.conn == nil || !r.hello {
		return
	}
	if r.stopRequested() {
		if !r.shutdownSent && !r.shutdownDone {
			log.Printf("sending shutdown")
			r.send(wire.TShutdown, wire.Shutdown{Reason: "Stop"})
			r.shutdownSent = true
		}
		return
	}
	if r.exit != nil {
		return // the guest is shutting itself down
	}
	c := r.desired.Claim
	if c == nil {
		return
	}
	if r.claimID == "" {
		if !r.networkReady || r.claimWaiting || now.Before(r.claimRetryAt) {
			return
		}
		if !r.rootInVM {
			if err := r.ch.addDisk(c.Root); err != nil {
				r.errMsg = "attach root: " + err.Error()
				r.claimRetryAt = now.Add(retryInterval)
				return
			}
			r.rootInVM = true
		}
		serial := c.Root.Serial
		if serial == "" {
			serial = c.Root.ID
		}
		// Mounts known at claim time are mounted before the command starts.
		var mounts []wire.Mount
		for _, d := range r.desired.Mounts {
			e := r.disks[d.ID]
			if e == nil {
				e = &disk{d: d, phase: podapi.DiskAttaching}
				r.disks[d.ID] = e
				r.order = append(r.order, d.ID)
			}
			if !e.inVM {
				if err := r.ch.addDisk(d); err != nil {
					r.errMsg = "attach " + d.Path + ": " + err.Error()
					r.claimRetryAt = now.Add(retryInterval)
					return
				}
				e.inVM = true
			}
			mounts = append(mounts, wire.Mount{ID: d.ID, Serial: diskSerial(d), Path: d.Path, ReadOnly: d.ReadOnly})
		}
		for _, m := range mounts {
			r.disks[m.ID].waiting = true
		}
		r.send(wire.TClaim, wire.Claim{
			ID:                 c.Root.ID,
			Serial:             serial,
			Hostname:           c.BlipName,
			Command:            c.Command,
			TTY:                c.TTY,
			Env:                c.Env,
			WorkingDir:         c.WorkingDir,
			User:               c.User,
			WaitForClient:      c.WaitForClient,
			IdleTimeoutSeconds: c.IdleTimeoutSeconds,
			Mounts:             mounts,
		})
		r.claimWaiting = true
		return
	}
	r.reconcileMounts(now)
	r.reconcileFreeze()
}

type policyNetwork interface {
	apply(*network.Policy, bool) error
}

func (r *runtime) reconcileNetwork(now time.Time) {
	p := r.desired.Network
	if r.o.SkipNetwork {
		r.networkReady, r.networkError, r.networkRevision = true, "", ""
		if p != nil {
			r.networkRevision = p.Revision
		}
		return
	}
	// Warm VMs can validate/preinstall policy during disk preparation, but
	// only a desired claim opens the forwarding path.
	active := r.desired.Claim != nil
	data, _ := json.Marshal(struct {
		Policy *network.Policy
		Active bool
	}{p, active})
	key := string(data)
	if key == r.networkKey && (r.networkError == "" || now.Before(r.networkRetryAt)) {
		return
	}
	r.networkKey = key
	r.networkReady, r.networkRevision, r.networkError = false, "", ""
	var err error
	if r.network == nil {
		err = fmt.Errorf("network is not initialized")
	} else {
		err = r.network.apply(p, active)
	}
	if err != nil {
		r.networkError = err.Error()
		r.networkRetryAt = now.Add(retryInterval)
		log.Printf("network policy: %v", err)
		// If neither nftables nor disabling the TAP worked, the only safe
		// fallback is to stop the VM. Normal policy errors do not stop disks
		// or the guest's shutdown protocol.
		if pn, ok := r.network.(*podNet); ok && pn.unsafe && r.vm != nil {
			_ = r.vm.Process.Kill()
		}
		return
	}
	if p != nil {
		r.networkReady, r.networkRevision = true, p.Revision
	}
}

func (r *runtime) resetFreeze() {
	r.frozen, r.freezeWaiting, r.thawing, r.freezeSkip = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
}

func (r *runtime) reconcileFreeze() {
	want := map[string]bool{}
	for _, id := range r.desired.Freeze {
		want[id] = true
		if r.frozen[id] || r.freezeWaiting[id] || r.freezeSkip[id] {
			continue
		}
		r.send(wire.TFreeze, wire.Freeze{ID: id})
		r.freezeWaiting[id] = true
	}
	for id := range r.freezeSkip {
		if !want[id] {
			delete(r.freezeSkip, id)
		}
	}
	for id := range r.frozen {
		if !want[id] && !r.freezeWaiting[id] {
			r.send(wire.TThaw, wire.Freeze{ID: id})
			// Not frozen from here on: a re-desired ID waits for this
			// thaw's result and then sends a fresh Freeze.
			delete(r.frozen, id)
			r.freezeWaiting[id], r.thawing[id] = true, true
		}
	}
}

func (r *runtime) reconcileMounts(now time.Time) {
	want := map[string]bool{}
	for _, d := range r.desired.Mounts {
		want[d.ID] = true
		e := r.disks[d.ID]
		if e == nil {
			e = &disk{d: d, phase: podapi.DiskAttaching}
			r.disks[d.ID] = e
			r.order = append(r.order, d.ID)
		} else if e.phase == podapi.DiskDetached {
			// Wanted again after a detach: reset the entry and run the
			// normal attach path below. Reusing the entry keeps order (and
			// observed.json) free of duplicate records for the ID.
			*e = disk{d: d, phase: podapi.DiskAttaching}
		}
		if e.waiting || e.removing || e.mounted || now.Before(e.retryAt) {
			continue
		}
		e.d = d
		if !e.inVM {
			if err := r.ch.addDisk(d); err != nil {
				e.phase, e.message, e.retryAt = podapi.DiskFailed, "attach: "+err.Error(), now.Add(retryInterval)
				continue
			}
			e.inVM = true
		}
		r.send(wire.TMount, wire.Mount{ID: d.ID, Serial: diskSerial(d), Path: d.Path, ReadOnly: d.ReadOnly})
		e.waiting = true
		if e.phase != podapi.DiskFailed {
			e.phase = podapi.DiskAttaching
		}
	}
	var stale []string
	for _, id := range r.order {
		e := r.disks[id]
		if want[id] || e.waiting || e.removing || now.Before(e.retryAt) {
			continue
		}
		if e.phase == podapi.DiskDetached {
			// A genuine removal has finished. A read-only disk is done
			// with, so stop tracking it: the node has dropped the mount
			// from Desired and keeping the record only accumulates stale
			// entries in order/observed.json. Writable attachments stay
			// visible because the node uses their Detached status to
			// fence the final seal of the writer.
			if e.d.ReadOnly {
				stale = append(stale, id)
			}
			continue
		}
		switch {
		case e.mounted:
			r.send(wire.TUnmount, wire.Unmount{ID: id})
			e.waiting = true
			if e.phase != podapi.DiskFailed {
				e.phase = podapi.DiskUnmounting
			}
		case e.inVM:
			e.removing = true
			e.phase = podapi.DiskUnmounting
			go func() { r.removed <- removeResult{id, r.ch.removeDisk(id, removeTimeout)} }()
		default:
			e.phase = podapi.DiskDetached
		}
	}
	for _, id := range stale {
		r.dropDisk(id)
	}
}

// dropDisk forgets a fully detached mount that is no longer desired.
func (r *runtime) dropDisk(id string) {
	delete(r.disks, id)
	delete(r.frozen, id)
	delete(r.freezeSkip, id)
	for i, oid := range r.order {
		if oid == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func diskSerial(d podapi.Disk) string {
	if d.Serial != "" {
		return d.Serial
	}
	return d.ID
}

func (r *runtime) vmExited() {
	r.exited = true
	r.conn = nil
	r.resetFreeze()
	if r.raw != nil {
		r.raw.Close()
	}
	if r.exit == nil {
		switch {
		case r.stopRequested():
			r.exit = &podapi.Exit{Reason: "Stopped"}
		default:
			r.exit = &podapi.Exit{Code: 255, Reason: "GuestCrashed"}
			if r.errMsg == "" {
				r.errMsg = fmt.Sprintf("VM exited unexpectedly (cloud-hypervisor: %v)", r.vmErr)
			}
		}
	}
	for _, e := range r.disks {
		if e.inVM || e.mounted {
			e.inVM, e.mounted, e.phase = false, false, podapi.DiskDetached
		}
	}
}

func (r *runtime) phase() string {
	switch {
	case r.exited:
		return podapi.PhaseExited
	case r.shutdownSent || r.shutdownDone || r.exit != nil || (r.stopRequested() && r.hello):
		return podapi.PhaseStopping
	case r.claimID != "":
		return podapi.PhaseRunning
	case r.desired.Claim != nil && r.hello:
		return podapi.PhaseClaiming
	case r.hello:
		return podapi.PhaseWarm
	}
	return podapi.PhaseBooting
}

func (r *runtime) writeObserved() {
	o := podapi.Observed{
		Phase:           r.phase(),
		ClaimID:         r.claimID,
		Sessions:        r.sessions,
		Exit:            r.exit,
		Error:           r.errMsg,
		NetworkRevision: r.networkRevision,
		NetworkError:    r.networkError,
	}
	for _, id := range r.desired.Freeze {
		if r.frozen[id] {
			o.Frozen = append(o.Frozen, id)
		}
	}
	for _, id := range r.order {
		e := r.disks[id]
		o.Mounts = append(o.Mounts, podapi.DiskStatus{ID: id, State: e.d.State, Phase: e.phase, Message: e.message})
	}
	data, _ := json.Marshal(o)
	if bytes.Equal(data, r.lastObserved) {
		return
	}
	if err := podapi.WriteJSON(r.o.path(podapi.ObservedFile), o); err != nil {
		log.Printf("write observed: %v", err)
		return
	}
	r.lastObserved = data
	log.Printf("observed: %s", data)
}

// watchDesired polls desired.json and delivers every new valid version. A
// missing or malformed file keeps the last valid one.
func (r *runtime) watchDesired(ch chan<- podapi.Desired) {
	path := r.o.path(podapi.DesiredFile)
	// inotify wakes the loop as soon as the node renames a new version into
	// place; the 100ms poll is the fallback.
	wake := make(chan struct{}, 1)
	if fd, err := unix.InotifyInit1(unix.IN_CLOEXEC); err == nil {
		if _, err := unix.InotifyAddWatch(fd, r.o.Dir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE); err == nil {
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := unix.Read(fd, buf); err != nil && err != unix.EINTR {
						return
					}
					select {
					case wake <- struct{}{}:
					default:
					}
				}
			}()
		}
	}
	var last, bad []byte
	t := time.NewTicker(100 * time.Millisecond)
	for {
		data, err := os.ReadFile(path)
		if err == nil && !bytes.Equal(data, last) && !bytes.Equal(data, bad) {
			var d podapi.Desired
			if err := json.Unmarshal(data, &d); err != nil {
				log.Printf("ignoring malformed %s: %v", path, err)
				bad = data
			} else {
				last = data
				ch <- d
			}
		}
		select {
		case <-t.C:
		case <-wake:
		}
	}
}
