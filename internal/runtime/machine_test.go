package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

type logicalDetachClock struct {
	now    time.Time
	sleeps int
}

func (c *logicalDetachClock) Now() time.Time { return c.now }
func (c *logicalDetachClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	c.sleeps++
	return nil
}

// simulatedCH models only the external API. addDisk/removeDisk/hasDisk are the
// production operations, including all confirmation polls and ambiguous replies.
type simulatedCH struct {
	disks                      map[string]bool
	attachments                map[string]map[string]any
	tree                       map[string]int
	removePolls                int
	lostAdd, lostRemove, stuck bool
	infoErrors                 int
	calls                      []string
}

func newSimulatedCH() *simulatedCH {
	return &simulatedCH{disks: map[string]bool{}, attachments: map[string]map[string]any{}, tree: map[string]int{}, removePolls: 2}
}

func (v *simulatedCH) RoundTrip(req *http.Request) (*http.Response, error) {
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/")
	v.calls = append(v.calls, path)
	var body struct {
		ID       string `json:"id"`
		Path     string `json:"path"`
		Serial   string `json:"serial"`
		ReadOnly bool   `json:"readonly"`
	}
	if req.Body != nil {
		_ = json.NewDecoder(req.Body).Decode(&body)
	}
	var response any = map[string]any{}
	switch path {
	case "vm.add-disk":
		v.disks[body.ID] = true
		v.attachments[body.ID] = map[string]any{"id": body.ID, "path": body.Path, "serial": body.Serial, "readonly": body.ReadOnly}
		if v.lostAdd {
			v.lostAdd = false
			return nil, errors.New("add response lost after commit")
		}
	case "vm.remove-device":
		delete(v.disks, body.ID)
		v.tree[body.ID] = v.removePolls
		if v.lostRemove {
			v.lostRemove = false
			return nil, errors.New("remove response lost after commit")
		}
	case "vm.info":
		if v.infoErrors > 0 {
			v.infoErrors--
			return nil, errors.New("info unavailable")
		}
		var disks []map[string]any
		for id := range v.disks {
			if d := v.attachments[id]; d != nil {
				disks = append(disks, d)
			} else {
				disks = append(disks, map[string]any{"id": id})
			}
		}
		tree := map[string]any{}
		for id, polls := range v.tree {
			if polls > 0 || v.stuck {
				tree[id] = map[string]string{"id": id}
				v.tree[id]--
			} else {
				delete(v.tree, id)
			}
		}
		response = map[string]any{"config": map[string]any{"disks": disks}, "device_tree": tree}
	default:
		return nil, fmt.Errorf("unexpected CH call %s", path)
	}
	data, _ := json.Marshal(response)
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
}

type lifecycleSimulation struct {
	t     *testing.T
	m     *Machine
	clock *logicalDetachClock
	vmm   *simulatedCH
	ch    *chClient
	out   []Effect
	trace []string
}

func newLifecycleSimulation(t *testing.T) *lifecycleSimulation {
	t.Helper()
	clock := &logicalDetachClock{now: time.Unix(100, 0)}
	vmm := newSimulatedCH()
	s := &lifecycleSimulation{t: t, m: NewMachine(true), clock: clock, vmm: vmm, ch: &chClient{hc: &http.Client{Transport: vmm}, clock: clock}}
	s.apply(Event{Kind: EventConnected})
	s.control(wire.THello, wire.Hello{Version: wire.Version})
	return s
}

func (s *lifecycleSimulation) apply(ev Event) {
	s.t.Helper()
	s.record(s.m.Apply(s.clock.now, ev))
	s.settle()
}

func (s *lifecycleSimulation) record(effects []Effect) {
	for _, e := range effects {
		data, _ := json.Marshal(e)
		s.trace = append(s.trace, string(data))
		s.out = append(s.out, e)
	}
}

func (s *lifecycleSimulation) settle() {
	s.t.Helper()
	for turn := 0; turn < 100; turn++ {
		s.record(s.m.Reconcile(s.clock.now))
		index := -1
		for i, e := range s.out {
			if e.Kind == EffectAddDisk {
				index = i
				break
			}
		}
		if index == -1 {
			return
		}
		e := s.out[index]
		s.out = append(s.out[:index], s.out[index+1:]...)
		ev := Event{Kind: EventResult, Token: e.Token}
		if err := s.ch.addDisk(e.Disk); err != nil {
			ev.Error = err.Error()
		}
		s.record(s.m.Apply(s.clock.now, ev))
	}
	s.t.Fatal("machine failed to quiesce")
}

func (s *lifecycleSimulation) control(typ wire.Type, value any) {
	s.t.Helper()
	payload, _ := json.Marshal(value)
	s.apply(Event{Kind: EventControl, Generation: s.m.Generation(), Type: typ, Payload: payload})
}

func (s *lifecycleSimulation) desired(d podapi.Desired) {
	s.apply(Event{Kind: EventDesired, Desired: d})
}

func (s *lifecycleSimulation) take(kind EffectKind, typ wire.Type) Effect {
	s.t.Helper()
	if len(s.out) == 0 {
		s.t.Fatalf("no effect, want %s/%v", kind, typ)
	}
	e := s.out[0]
	s.out = s.out[1:]
	if e.Kind != kind || (kind == EffectSend && e.Type != typ) {
		s.t.Fatalf("effect %+v, want %s/%v", e, kind, typ)
	}
	return e
}

func (s *lifecycleSimulation) none() {
	s.t.Helper()
	if len(s.out) != 0 {
		s.t.Fatalf("unexpected effects %+v", s.out)
	}
}

func (s *lifecycleSimulation) remove(e Effect) {
	s.t.Helper()
	if e.Kind != EffectRemoveDisk {
		s.t.Fatal("not a removal")
	}
	ev := Event{Kind: EventResult, Token: e.Token}
	if err := s.ch.removeDisk(e.Disk.ID, time.Second); err != nil {
		ev.Error = err.Error()
	}
	s.apply(ev)
}

func simulationDesired() podapi.Desired {
	return podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "root"}}, Mounts: []podapi.Disk{{ID: "data", Path: "/data"}}}
}

func (s *lifecycleSimulation) claim(d podapi.Desired) {
	s.t.Helper()
	s.desired(d)
	s.take(EffectSend, wire.TClaim)
	for _, mount := range d.Mounts {
		s.control(wire.TMountResult, wire.Result{ID: mount.ID})
	}
	s.control(wire.TClaimResult, wire.Result{ID: d.Claim.Root.ID})
	s.none()
}

func TestMachineLostClaimAndMountRepliesResync(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.vmm.lostAdd = true // CH committed root attachment, then lost its response.
	s.desired(d)
	s.take(EffectSend, wire.TClaim)
	if !s.m.rootInVM || !s.vmm.disks["root"] {
		t.Fatal("root attach not confirmed")
	}
	// The guest claimed and mounted, but neither reply arrived. A deadline
	// reconnects rather than reissuing potentially destructive operations.
	s.clock.Sleep(context.Background(), controlResponseTimeout)
	s.settle()
	s.take(EffectClose, 0)
	connect := s.take(EffectConnect, 0)
	s.apply(Event{Kind: EventConnected, Generation: connect.Generation})
	s.none() // hello from the new generation is required
	old, _ := json.Marshal(wire.Result{ID: "root"})
	s.apply(Event{Kind: EventControl, Generation: connect.Generation - 1, Type: wire.TClaimResult, Payload: old})
	if s.m.claimID != "" {
		t.Fatal("accepted old-generation claim result")
	}
	s.control(wire.THello, wire.Hello{Version: wire.Version, ClaimID: "root", Mounts: []string{"data"}})
	s.none()
	if o := s.m.Observed(); o.Phase != podapi.PhaseRunning || o.Mounts[0].Phase != podapi.DiskMounted {
		t.Fatalf("resync %+v", o)
	}
}

func TestMachineLostUnmountReplyReaddAndStaleRemoval(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	// A delayed mount result must not be mistaken for the unmount result.
	s.control(wire.TMountResult, wire.Result{ID: "data"})
	s.none()
	if !s.m.disks["data"].mounted {
		t.Fatal("stale mount result completed unmount")
	}
	s.clock.Sleep(context.Background(), controlResponseTimeout)
	s.settle()
	s.take(EffectClose, 0)
	connect := s.take(EffectConnect, 0)
	s.apply(Event{Kind: EventConnected, Generation: connect.Generation})
	s.none()
	s.control(wire.THello, wire.Hello{ClaimID: "root"}) // unmount actually committed
	remove := s.take(EffectRemoveDisk, 0)
	d.Mounts = simulationDesired().Mounts
	s.desired(d)
	s.none() // re-add waits for the old CH device to be confirmed absent
	s.remove(remove)
	s.take(EffectSend, wire.TMount)
	if s.clock.sleeps < 3 {
		t.Fatal("remove did not poll device-tree confirmation")
	}
	s.control(wire.TMountResult, wire.Result{ID: "data"})
	before := s.m.Observed()
	s.apply(Event{Kind: EventResult, Token: remove.Token})
	s.none()
	if !reflect.DeepEqual(before, s.m.Observed()) {
		t.Fatal("duplicate completion detached re-added device")
	}
	// A stale completion from the first removal cannot finish a second one.
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	s.control(wire.TUnmountResult, wire.Result{ID: "data"})
	second := s.take(EffectRemoveDisk, 0)
	s.apply(Event{Kind: EventResult, Token: remove.Token, Error: "stale failure"})
	if !s.m.disks["data"].removing || second.Token == remove.Token {
		t.Fatal("removal token reused")
	}
	s.remove(second)
	if o := s.m.Observed(); o.Mounts[0].Phase != podapi.DiskDetached {
		t.Fatalf("detach %+v", o)
	}
}

func TestMachineFreezeDetachReaddStop(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Freeze = []string{"data"}
	s.desired(d)
	s.take(EffectSend, wire.TFreeze)
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	s.control(wire.TUnmountResult, wire.Result{ID: "data"})
	remove := s.take(EffectRemoveDisk, 0)
	s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data", Frozen: true})
	if len(s.m.Observed().Frozen) != 0 {
		t.Fatal("late freeze acknowledged unmounted disk")
	}
	d.Mounts = simulationDesired().Mounts
	s.desired(d)
	s.none()
	s.remove(remove)
	s.take(EffectSend, wire.TMount)
	s.none() // cannot freeze before mount acknowledgement
	s.control(wire.TMountResult, wire.Result{ID: "data"})
	s.take(EffectSend, wire.TFreeze)
	s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data", Frozen: true})
	d.Freeze = nil
	s.desired(d)
	s.take(EffectSend, wire.TThaw)
	d.Freeze = []string{"data"}
	s.desired(d)
	s.none()
	s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data"})
	s.take(EffectSend, wire.TFreeze)
	if len(s.m.Observed().Frozen) != 0 {
		t.Fatal("readded freeze confirmed before fresh acknowledgement")
	}
	d.Stop = true
	s.desired(d)
	s.take(EffectSend, wire.TShutdown)
	s.clock.Sleep(context.Background(), stopTimeout+time.Nanosecond)
	s.settle()
	s.take(EffectKill, 0)
	s.settle()
	s.none() // kill is an idempotent effect
	s.apply(Event{Kind: EventVMExited})
	s.take(EffectClose, 0)
	s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data", Frozen: true})
	s.apply(Event{Kind: EventResult, Token: remove.Token, Error: "late failure"})
	if o := s.m.Observed(); o.Phase != podapi.PhaseExited || o.Mounts[0].Phase != podapi.DiskDetached || len(o.Frozen) != 0 {
		t.Fatalf("exit %+v", o)
	}
}

func TestMachineReaddAfterAmbiguousDetachMustConfirm(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	s.control(wire.TUnmountResult, wire.Result{ID: "data"})
	remove := s.take(EffectRemoveDisk, 0)
	d.Mounts = simulationDesired().Mounts
	s.desired(d)
	s.vmm.lostRemove = true
	s.remove(remove) // request committed, reply lost, device still in CH tree
	s.none()
	if o := s.m.Observed(); o.Mounts[0].Phase != podapi.DiskFailed {
		t.Fatalf("unconfirmed detach: %+v", o)
	}
	if !s.m.disks["data"].detachPending {
		t.Fatal("forgot uncertain removal")
	}
	s.clock.Sleep(context.Background(), retryInterval)
	s.settle()
	retry := s.take(EffectRemoveDisk, 0)
	s.none() // no Mount can race an eject that may still be taking effect
	s.remove(retry)
	s.take(EffectSend, wire.TMount)
	s.control(wire.TMountResult, wire.Result{ID: "data"})
	if !s.vmm.disks["data"] || s.m.Observed().Mounts[0].Phase != podapi.DiskMounted {
		t.Fatal("failed to re-add after confirming detach")
	}
}

func TestMachineStopWhileReaddedRemovalCompletes(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	s.control(wire.TUnmountResult, wire.Result{ID: "data"})
	remove := s.take(EffectRemoveDisk, 0)
	d.Mounts, d.Stop = simulationDesired().Mounts, true
	s.desired(d)
	s.take(EffectSend, wire.TShutdown)
	s.remove(remove)
	s.none()
	if s.vmm.disks["data"] || s.m.Observed().Mounts[0].Phase != podapi.DiskDetached {
		t.Fatal("reattached while stopping")
	}
	s.control(wire.TShutdownDone, wire.ShutdownDone{Clean: true})
	s.take(EffectClose, 0)
	s.none() // no reconnect after shutdown acknowledgement
	s.apply(Event{Kind: EventVMExited})
	s.take(EffectClose, 0)
	if o := s.m.Observed(); o.Phase != podapi.PhaseExited || o.Exit.Reason != "Stopped" {
		t.Fatalf("stop: %+v", o)
	}
}

func TestMachineFreezeReplyLostReconnectAndGuestReboot(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Freeze = []string{"data"}
	s.desired(d)
	s.take(EffectSend, wire.TFreeze)
	s.clock.Sleep(context.Background(), controlResponseTimeout)
	s.settle()
	s.take(EffectClose, 0)
	e := s.take(EffectConnect, 0)
	s.apply(Event{Kind: EventConnected, Generation: e.Generation})
	s.none()
	s.control(wire.THello, wire.Hello{ClaimID: "root", Mounts: []string{"data"}, Frozen: []string{"data"}})
	s.none()
	if got := s.m.Observed().Frozen; !reflect.DeepEqual(got, []string{"data"}) {
		t.Fatalf("freeze resync %v", got)
	}
	s.control(wire.THello, wire.Hello{})
	s.take(EffectKill, 0)
	s.apply(Event{Kind: EventVMExited, Error: "guest rebooted"})
	s.take(EffectClose, 0)
	if o := s.m.Observed(); o.Exit.Reason != "GuestCrashed" || !strings.Contains(o.Error, "restarted") {
		t.Fatalf("reboot %+v", o)
	}
}

func TestMachineNetworkCompletionRevisionAndUnsafe(t *testing.T) {
	m := NewMachine(false)
	now := time.Unix(100, 0)
	d := podapi.Desired{Network: &netpolicy.Policy{Revision: "old"}, Claim: &podapi.Claim{Root: podapi.Disk{ID: "root"}}}
	m.Apply(now, Event{Kind: EventDesired, Desired: d})
	e := m.Reconcile(now)[0]
	d.Network = &netpolicy.Policy{Revision: "new"}
	m.Apply(now, Event{Kind: EventDesired, Desired: d})
	m.Apply(now, Event{Kind: EventResult, Token: e.Token})
	if m.networkReady || m.Observed().NetworkRevision != "" {
		t.Fatal("stale policy completion opened claim gate")
	}
	current := m.Reconcile(now)[0]
	m.Apply(now, Event{Kind: EventResult, Token: current.Token, Error: "nft failed"})
	if effects := m.Reconcile(now.Add(retryInterval - time.Nanosecond)); len(effects) != 0 {
		t.Fatal("network retried early")
	}
	retry := m.Reconcile(now.Add(retryInterval))[0]
	m.Apply(now, Event{Kind: EventResult, Token: retry.Token})
	if !m.networkReady || m.Observed().NetworkRevision != "new" {
		t.Fatal("network retry did not complete")
	}
	d.Network = nil
	m.Apply(now, Event{Kind: EventDesired, Desired: d})
	revoke := m.Reconcile(now)[0]
	d.Network = &netpolicy.Policy{Revision: "latest"}
	m.Apply(now, Event{Kind: EventDesired, Desired: d})
	// Even an obsolete policy completion must kill when the runner could not
	// enforce its deny-all fallback.
	kill := m.Apply(now, Event{Kind: EventResult, Token: revoke.Token, Error: "TAP disable failed", Unsafe: true})
	if len(kill) != 1 || kill[0].Kind != EffectKill {
		t.Fatalf("unsafe result %+v", kill)
	}
}

func TestMachineLateRootAttachCannotClaimAnotherRoot(t *testing.T) {
	for _, change := range []string{"ID", "device"} {
		t.Run(change, func(t *testing.T) {
			now := time.Unix(100, 0)
			m := NewMachine(true)
			d := podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "old", Device: "/dev/old"}}}
			m.Apply(now, Event{Kind: EventDesired, Desired: d})
			m.Apply(now, Event{Kind: EventConnected})
			m.Apply(now, Event{Kind: EventControl, Type: wire.THello, Payload: json.RawMessage(`{}`)})
			attach := m.Reconcile(now)[0]
			if change == "ID" {
				d.Claim.Root.ID = "new"
			} else {
				d.Claim.Root.Device = "/dev/new"
			}
			m.Apply(now, Event{Kind: EventDesired, Desired: d})
			m.Apply(now, Event{Kind: EventResult, Token: attach.Token})
			effects := m.Reconcile(now)
			if len(effects) != 1 || effects[0].Kind != EffectKill || m.claimWaiting {
				t.Fatalf("old root authorized a different claim: %+v", effects)
			}
		})
	}
}

func TestMachineHelloClaimIdentity(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewMachine(true)
	m.Apply(now, Event{Kind: EventConnected})
	// Hello may precede the initial desired read; preserve adoption in that case.
	hello, _ := json.Marshal(wire.Hello{ClaimID: "old"})
	if effects := m.Apply(now, Event{Kind: EventControl, Type: wire.THello, Payload: hello}); len(effects) != 0 || m.Observed().ClaimID != "old" {
		t.Fatalf("failed to adopt early Hello: %+v", effects)
	}
	c := m.Clone()
	c.Apply(now, Event{Kind: EventDesired, Desired: podapi.Desired{Claim: &podapi.Claim{Root: podapi.Disk{ID: "new"}}}})
	if effects := c.Reconcile(now); len(effects) != 1 || effects[0].Kind != EffectKill {
		t.Fatalf("adopted Hello authorized a different desired root: %+v", effects)
	}
	hello, _ = json.Marshal(wire.Hello{ClaimID: "other"})
	if effects := m.Apply(now, Event{Kind: EventControl, Type: wire.THello, Payload: hello}); len(effects) != 1 || effects[0].Kind != EffectKill || m.Observed().ClaimID != "old" {
		t.Fatalf("Hello replaced a known claim: %+v", effects)
	}
}

func TestMachineRootSerialDefaultIsSameIdentity(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.claim(d)
	d.Claim.Root.Serial = d.Claim.Root.ID
	s.desired(d)
	s.none()
}

func TestCHAmbiguousAttachRequiresMatchingIdentity(t *testing.T) {
	d := podapi.Disk{ID: "data", Device: "/dev/data", Serial: "serial", ReadOnly: true}
	for _, tc := range []struct {
		name, info string
		wantError  bool
	}{
		{"match", `{"config":{"disks":[{"id":"data","path":"/dev/data","serial":"serial","readonly":true}]}}`, false},
		{"wrong device", `{"config":{"disks":[{"id":"data","path":"/dev/old","serial":"serial","readonly":true}]}}`, true},
		{"wrong serial", `{"config":{"disks":[{"id":"data","path":"/dev/data","serial":"old","readonly":true}]}}`, true},
		{"wrong access", `{"config":{"disks":[{"id":"data","path":"/dev/data","serial":"serial","readonly":false}]}}`, true},
		{"tree only", `{"device_tree":{"data":{}}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &chClient{hc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "vm.add-disk") {
					return nil, errors.New("ambiguous attach")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.info))}, nil
			})}}
			if err := c.addDisk(d); (err != nil) != tc.wantError {
				t.Fatalf("addDisk: %v", err)
			}
		})
	}
}

func TestMachineClaimFailureAndBusyUnmountDeadlines(t *testing.T) {
	s := newLifecycleSimulation(t)
	d := simulationDesired()
	s.desired(d)
	s.take(EffectSend, wire.TClaim)
	s.control(wire.TClaimResult, wire.Result{ID: "root", Error: "root not ready"})
	s.none()
	s.clock.Sleep(context.Background(), retryInterval-time.Nanosecond)
	s.settle()
	s.none()
	s.clock.Sleep(context.Background(), time.Nanosecond)
	s.settle()
	s.take(EffectSend, wire.TClaim)
	s.control(wire.TMountResult, wire.Result{ID: "data"})
	s.control(wire.TClaimResult, wire.Result{ID: "root"})
	d.Mounts = nil
	s.desired(d)
	s.take(EffectSend, wire.TUnmount)
	s.control(wire.TUnmountResult, wire.Result{ID: "data", Error: "busy"})
	s.none()
	s.clock.Sleep(context.Background(), unmountRetryInterval-time.Nanosecond)
	s.settle()
	s.none()
	if !s.vmm.disks["data"] {
		t.Fatal("busy disk detached")
	}
	s.clock.Sleep(context.Background(), time.Nanosecond)
	s.settle()
	s.take(EffectSend, wire.TUnmount)
}

func TestCHDetachConfirmationFaults(t *testing.T) {
	for _, tc := range []struct {
		name              string
		lost              bool
		polls, infoErrors int
		stuck, wantError  bool
	}{
		{name: "tree lags config", polls: 3},
		{name: "info temporarily unavailable", polls: 2, infoErrors: 2},
		{name: "lost reply already absent", lost: true},
		{name: "lost reply unconfirmed", lost: true, polls: 2, wantError: true},
		{name: "device never leaves tree", stuck: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newSimulatedCH()
			v.disks["data"] = true
			v.lostRemove, v.removePolls, v.infoErrors, v.stuck = tc.lost, tc.polls, tc.infoErrors, tc.stuck
			clock := &logicalDetachClock{now: time.Unix(100, 0)}
			c := &chClient{hc: &http.Client{Transport: v}, clock: clock}
			err := c.removeDisk("data", 200*time.Millisecond)
			if (err != nil) != tc.wantError {
				t.Fatalf("remove: %v", err)
			}
			if len(v.calls) < 2 || v.calls[0] != "vm.remove-device" || v.calls[1] != "vm.info" {
				t.Fatalf("confirmation not executed: %v", v.calls)
			}
			if !tc.wantError && v.tree["data"] > 0 {
				t.Fatal("detached before tree confirmation")
			}
			if !tc.lost && tc.polls > 0 && clock.sleeps < tc.polls {
				t.Fatalf("polls %d", clock.sleeps)
			}
		})
	}
}

// The seeded schedules vary re-add timing, stale completion delivery, guest
// disconnection, and freeze/thaw around each detach. Replaying a seed must yield
// byte-identical effects; every Detached observation must be fenced by CH.
func TestMachineSeededAdversarialSchedules(t *testing.T) {
	for seed := int64(0); seed < 32; seed++ {
		run := func() []string {
			s := newLifecycleSimulation(t)
			rng := rand.New(rand.NewSource(seed))
			d := simulationDesired()
			s.claim(d)
			for cycle := 0; cycle < 8; cycle++ {
				if rng.Intn(2) == 0 {
					d.Freeze = []string{"data"}
					s.desired(d)
					s.take(EffectSend, wire.TFreeze)
					s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data", Frozen: true})
					d.Freeze = nil
					s.desired(d)
					s.take(EffectSend, wire.TThaw)
					s.control(wire.TFreezeResult, wire.FreezeResult{ID: "data"})
				}
				d.Mounts = nil
				s.desired(d)
				s.take(EffectSend, wire.TUnmount)
				if rng.Intn(2) == 0 {
					s.apply(Event{Kind: EventDisconnected, Generation: s.m.Generation()})
					s.take(EffectClose, 0)
					e := s.take(EffectConnect, 0)
					s.apply(Event{Kind: EventConnected, Generation: e.Generation})
					s.none()
					s.control(wire.THello, wire.Hello{ClaimID: "root"})
				} else {
					s.control(wire.TUnmountResult, wire.Result{ID: "data"})
				}
				remove := s.take(EffectRemoveDisk, 0)
				readd := rng.Intn(2) == 0
				if readd {
					d.Mounts = simulationDesired().Mounts
					s.desired(d)
					s.none()
				}
				s.vmm.removePolls = rng.Intn(4)
				s.remove(remove)
				if !readd {
					if s.m.Observed().Mounts[0].Phase != podapi.DiskDetached || s.vmm.disks["data"] || s.vmm.tree["data"] > 0 {
						t.Fatalf("seed %d cycle %d: detached without fencing", seed, cycle)
					}
					d.Mounts = simulationDesired().Mounts
					s.desired(d)
				}
				s.take(EffectSend, wire.TMount)
				s.control(wire.TMountResult, wire.Result{ID: "data"})
				if rng.Intn(2) == 0 {
					s.apply(Event{Kind: EventResult, Token: remove.Token})
				}
				if !s.vmm.disks["data"] || s.m.Observed().Mounts[0].Phase != podapi.DiskMounted {
					t.Fatalf("seed %d lost re-add", seed)
				}
				s.none()
			}
			return s.trace
		}
		first, second := run(), run()
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("seed %d is not deterministic", seed)
		}
	}
}
