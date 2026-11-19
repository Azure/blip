// Package runtime is blip-runtime: it runs Cloud Hypervisor in a VM pod,
// applies desired.json through the guest control port, and reports
// observed.json.
package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/blip/internal/bootconfig"
	"github.com/Azure/blip/internal/netpolicy"
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
	// Endpoints are the guest hostnames the sidecar routes.
	Endpoints []string
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
	for _, name := range strings.Split(os.Getenv("BLIP_ENDPOINT_NAMES"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			o.Endpoints = append(o.Endpoints, name)
		}
	}
	num("BLIP_CPUS", &o.CPUs)
	num("BLIP_MEMORY_MB", &o.MemoryMB)
	o.SkipNetwork = os.Getenv("BLIP_SKIP_NETWORK") == "1"
	return o
}

type ctlEvent struct {
	gen     int
	conn    net.Conn // set on connect
	t       wire.Type
	payload []byte
	err     error
}

type removeResult struct {
	id    string
	err   error
	token uint64
}

type policyNetwork interface {
	apply(*netpolicy.Policy, bool) (unsafe bool, err error)
}

// runtime is the effect runner. All lifecycle state and decisions live in the
// embedded Machine; only the runner owns live host/guest resources and time.
type runtime struct {
	Machine
	o             Options
	ch            *chClient
	vm            *exec.Cmd
	vmDone        chan struct{}
	vmErr         error
	ctlEvents     chan ctlEvent
	removed       chan removeResult
	conn          *wire.Conn
	raw           net.Conn
	rawGeneration int
	network       policyNetwork
	lastObserved  []byte
	ctx           context.Context
	cancel        context.CancelFunc
	workers       sync.WaitGroup
	clockEpoch    time.Time
	// elapsed is a test seam; nil uses time.Since's monotonic clock.
	elapsed func(time.Time) time.Duration
	// secureSockets is a test seam for boot; nil means secureCHSockets.
	secureSockets func() error
}

// Run supervises one VM until the VMM exits.
func Run(o Options) error {
	r := newRuntime(o)
	defer r.close()
	return r.run()
}

func newRuntime(o Options) *runtime {
	ctx, cancel := context.WithCancel(context.Background())
	r := &runtime{
		Machine:    *NewMachine(o.SkipNetwork),
		o:          o,
		ch:         newCHClient(o.path(podapi.APISocket)),
		vmDone:     make(chan struct{}),
		ctlEvents:  make(chan ctlEvent, 16),
		removed:    make(chan removeResult, 16),
		ctx:        ctx,
		cancel:     cancel,
		clockEpoch: time.Now(),
	}
	r.ch.ctx = ctx
	return r
}

// now projects monotonic elapsed time onto a fixed wall epoch. The machine can
// strip Go's monotonic metadata for canonical keys without making its deadlines
// sensitive to later wall-clock corrections. Calls are serialized by the runner.
func (r *runtime) now() time.Time {
	if r.clockEpoch.IsZero() {
		r.clockEpoch = time.Now() // support runtime literals in tests
	}
	elapsed := r.elapsed
	if elapsed == nil {
		elapsed = time.Since
	}
	return r.clockEpoch.Add(elapsed(r.clockEpoch))
}

func (r *runtime) start(f func()) {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		f()
	}()
}

func (r *runtime) close() {
	r.cancel()
	if r.raw != nil {
		r.raw.Close()
	}
	r.workers.Wait()
	r.ch.hc.CloseIdleConnections()
}

func (r *runtime) run() error {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	r.writeObserved()
	pn, err := r.boot()
	if err != nil {
		r.errMsg, r.exited = err.Error(), true
		r.writeObserved()
		return err
	}
	if pn != nil {
		defer pn.teardown()
	}
	desiredCh := make(chan podapi.Desired, 1)
	r.start(func() { r.watchDesired(desiredCh) })
	gen := r.gen
	r.start(func() { r.connect(gen) })
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case d := <-desiredCh:
			r.execute(r.Apply(r.now(), Event{Kind: EventDesired, Desired: d}))
		case ev := <-r.ctlEvents:
			r.handleControl(ev)
		case res := <-r.removed:
			r.handleRemoved(res)
		case <-sig:
			log.Printf("received stop signal")
			r.execute(r.Apply(r.now(), Event{Kind: EventStop}))
		case <-r.vmDone:
			r.vmExited()
			r.writeObserved()
			return nil
		case <-tick.C:
		}
		// Coalesce queued frames before the fsynced observed write.
		for drained := false; !drained; {
			select {
			case <-r.vmDone:
				r.vmExited()
				r.writeObserved()
				return nil
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

// execute returns whether a synchronous operation completed, in which case the
// caller reconciles again. Device removal retains the complete CH confirmation
// workflow in a goroutine so a busy detach cannot block Stop or policy updates.
func (r *runtime) execute(effects []Effect) bool {
	completed := false
	for _, e := range effects {
		// A synchronous completion can kill the VM while later effects from
		// the same batch are still queued. Only close/kill may run afterward.
		if (r.killSent || r.exited) && e.Kind != EffectKill && e.Kind != EffectClose {
			continue
		}
		var err error
		unsafe := false
		switch e.Kind {
		case EffectAddDisk:
			err = r.ch.addDisk(e.Disk)
		case EffectNetwork:
			if r.network == nil {
				err = fmt.Errorf("network is not initialized")
			} else {
				unsafe, err = r.network.apply(e.Policy, e.Active)
			}
		case EffectRemoveDisk:
			r.start(func() {
				res := removeResult{id: e.Disk.ID, token: e.Token, err: r.ch.removeDisk(e.Disk.ID, removeTimeout)}
				select {
				case r.removed <- res:
				case <-r.ctx.Done():
				}
			})
			continue
		case EffectSend:
			if r.conn != nil && e.Generation == r.gen {
				if err := r.conn.WriteJSON(e.Type, e.Payload); err != nil {
					log.Printf("control write: %v", err)
					r.execute(r.Apply(r.now(), Event{Kind: EventDisconnected, Generation: e.Generation, Error: err.Error()}))
				}
			}
			continue
		case EffectClose:
			if r.raw != nil && e.Generation == r.rawGeneration {
				r.raw.Close()
				r.conn, r.raw = nil, nil
			}
			continue
		case EffectConnect:
			r.start(func() { r.connect(e.Generation) })
			continue
		case EffectKill:
			if r.vm != nil && r.vm.Process != nil {
				_ = r.vm.Process.Kill()
			}
			continue
		default:
			continue
		}
		result := Event{Kind: EventResult, Token: e.Token, Unsafe: unsafe}
		if err != nil {
			result.Error = err.Error()
		}
		r.execute(r.Apply(r.now(), result))
		completed = true
	}
	return completed
}

func (r *runtime) handleControl(ev ctlEvent) {
	if ev.gen != r.gen {
		if ev.conn != nil {
			ev.conn.Close()
		}
		return
	}
	if ev.conn != nil {
		if r.raw != nil {
			r.raw.Close()
		}
		r.raw, r.conn, r.rawGeneration = ev.conn, wire.NewConn(ev.conn), ev.gen
		r.execute(r.Apply(r.now(), Event{Kind: EventConnected, Generation: ev.gen}))
		return
	}
	evMachine := Event{Kind: EventControl, Generation: ev.gen, Type: ev.t, Payload: ev.payload}
	if ev.err != nil {
		evMachine.Kind, evMachine.Error = EventDisconnected, ev.err.Error()
	}
	r.execute(r.Apply(r.now(), evMachine))
}

func (r *runtime) handleRemoved(res removeResult) {
	ev := Event{Kind: EventResult, Token: res.token}
	if res.err != nil {
		ev.Error = res.err.Error()
	}
	r.execute(r.Apply(r.now(), ev))
}

func (r *runtime) reconcile() {
	for r.execute(r.Reconcile(r.now())) {
	}
}

func (r *runtime) vmExited() {
	r.execute(r.Apply(r.now(), Event{Kind: EventVMExited, Error: fmt.Sprint(r.vmErr)}))
}

func (r *runtime) writeObserved() {
	o := r.Observed()
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

// boot writes the config disk, sets up networking and starts the VMM.
func (r *runtime) boot() (*podNet, error) {
	hostname, _ := os.Hostname()
	cfg := bootconfig.Config{Hostname: hostname, KubeNamespace: r.o.KubeNamespace, Endpoints: r.o.Endpoints}
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
	img, err := bootconfig.EncodeConfig(cfg)
	if err != nil {
		return nil, err
	}
	configDisk := r.o.path("guest-config.img")
	if err := os.WriteFile(configDisk, img, 0o600); err != nil {
		return nil, err
	}
	// The pod directory is mounted only into this privileged (root) container,
	// so it can be root-only; tighten it from an older release's 0755.
	if err := podapi.EnsureDir(r.o.Dir); err != nil {
		return nil, err
	}
	// The vsock directory is an emptyDir shared with the non-root API-proxy
	// sidecar, which binds vsock.sock_<port> there (kubelet fsGroup makes it
	// group-writable). Leave its mode alone; only the CH-owned socket is
	// restricted below.
	if err := os.MkdirAll(filepath.Dir(r.o.path(podapi.VsockSocket)), 0o755); err != nil {
		return nil, err
	}
	for _, s := range []string{podapi.APISocket, podapi.VsockSocket} {
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
	// Cloud Hypervisor binds its sockets with the runtime's umask, so restrict
	// them once they appear, before anything connects to the VM.
	secure := r.secureSockets
	if secure == nil {
		secure = r.secureCHSockets
	}
	if err := secure(); err != nil {
		started = false // tear down the network, we killed the VMM
		_ = cmd.Process.Kill()
		<-r.vmDone
		return nil, fmt.Errorf("secure cloud-hypervisor sockets: %w", err)
	}
	return pn, nil
}

// connect dials the guest control port until it answers, then forwards frames.
func (r *runtime) connect(gen int) {
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.vmDone:
			return
		default:
		}
		c, err := wire.DialVsock(r.o.path(podapi.VsockSocket), wire.ControlPort, 2*time.Second)
		if err != nil {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-timer.C:
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-r.vmDone:
				timer.Stop()
				return
			}
			continue
		}
		defer c.Close()
		stop := context.AfterFunc(r.ctx, func() { c.Close() })
		defer stop()
		if !r.deliverControl(ctlEvent{gen: gen, conn: c}) {
			return
		}
		wc := wire.NewConn(c)
		for {
			t, p, err := wc.Read()
			if !r.deliverControl(ctlEvent{gen: gen, t: t, payload: p, err: err}) || err != nil {
				return
			}
		}
	}
}

func (r *runtime) deliverControl(ev ctlEvent) bool {
	select {
	case r.ctlEvents <- ev:
		return true
	case <-r.ctx.Done():
	case <-r.vmDone:
	}
	return false
}

// watchDesired keeps the last valid desired file. inotify wakes it promptly;
// polling is the fallback when inotify is unavailable.
func (r *runtime) watchDesired(ch chan<- podapi.Desired) {
	path := r.o.path(podapi.DesiredFile)
	wake := make(chan struct{}, 1)
	if fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK); err == nil {
		// A nonblocking os.File uses Go's poller, so Close interrupts Read.
		f := os.NewFile(uintptr(fd), "inotify")
		if _, err := unix.InotifyAddWatch(fd, r.o.Dir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE); err == nil {
			done := make(chan struct{})
			defer func() { f.Close(); <-done }()
			go func() {
				defer close(done)
				buf := make([]byte, 4096)
				for {
					if _, err := f.Read(buf); err != nil {
						return
					}
					select {
					case wake <- struct{}{}:
					default:
					}
				}
			}()
		} else {
			f.Close()
		}
	}
	var last, bad []byte
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil && !bytes.Equal(data, last) && !bytes.Equal(data, bad) {
			var d podapi.Desired
			if err := json.Unmarshal(data, &d); err != nil {
				log.Printf("ignoring malformed %s: %v", path, err)
				bad = data
			} else {
				last = data
				select {
				case ch <- d:
				case <-r.ctx.Done():
					return
				}
			}
		}
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		case <-wake:
		}
	}
}
