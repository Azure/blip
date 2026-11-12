package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/example/blip/internal/api"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/storage"
)

// PodRef names a pod.
type PodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

// PodLister maps slot device IDs to the pods that hold them. The real one
// uses the kubelet PodResources API.
type PodLister interface {
	SlotPods(ctx context.Context) (map[string]PodRef, error)
}

// Config holds everything the node daemon needs. Zero durations get
// defaults.
type Config struct {
	NodeName   string
	BootID     string
	NodeConfig *api.NodeConfig
	// SlotsDir holds one directory per slot device: <SlotsDir>/<slotID>.
	SlotsDir string
	// StateDir keeps allocation records. It should be on tmpfs (/run),
	// so a reboot clears it together with the local compute state.
	StateDir string

	Storage Storage
	// StoragePort is the nvmet TCP port reported in Capabilities. Default 4420.
	StoragePort uint32
	Pods        PodLister
	// Hypervisor hot-plugs volumes and presses the power button.
	// Default: CloudHypervisor.
	Hypervisor Hypervisor
	// DisksPerSlot is the number of hot-pluggable disks per slot
	// (/dev/blip/disks/0..N-1). Default storage.DefaultDisksPerSlot.
	DisksPerSlot int
	// ContainerRunDir is the slot directory as seen by Cloud Hypervisor.
	// Default ContainerRunDir (/run/blip).
	ContainerRunDir string
	// SlotDiskPath is the target of the slot volume links, slot disk i
	// as seen by Cloud Hypervisor. Default /dev/blip/disks/<i>. Tests
	// that run Cloud Hypervisor outside a container point it at host
	// devices.
	SlotDiskPath func(slotID string, i int) string

	Poll time.Duration
	// CapacityPoll is how often capacity is checked and reported when
	// it changed. Default 10s.
	CapacityPoll time.Duration
	// MaxReconnectBackoff bounds the wait between controller session
	// attempts. The wait starts at 1s (or this, if smaller) and doubles.
	// Default 30s.
	MaxReconnectBackoff time.Duration
	// SlotLostAfter is how long a slot pod may be missing before its
	// allocation is reported lost.
	SlotLostAfter time.Duration
	// ReleaseWait is how long Release waits for Cloud Hypervisor to exit.
	ReleaseWait time.Duration
	// SlotUnreachableAfter is how long the CH API may be gone while
	// exit.json is missing before an allocation is reported lost.
	SlotUnreachableAfter time.Duration
	// UnknownThinGrace is how long a compute pool thin ID must stay
	// unknown (no device, no journal entry) in consecutive scans before
	// the node deletes it. Default 10 minutes (the controller's orphan
	// age). Negative disables the cleanup.
	UnknownThinGrace time.Duration
}

func (c *Config) defaults() {
	if c.Poll == 0 {
		c.Poll = time.Second
	}
	if c.CapacityPoll == 0 {
		c.CapacityPoll = 10 * time.Second
	}
	if c.MaxReconnectBackoff == 0 {
		c.MaxReconnectBackoff = 30 * time.Second
	}
	if c.SlotLostAfter == 0 {
		c.SlotLostAfter = 10 * time.Second
	}
	if c.ReleaseWait == 0 {
		c.ReleaseWait = 15 * time.Second
	}
	if c.SlotUnreachableAfter == 0 {
		c.SlotUnreachableAfter = 30 * time.Second
	}
	if c.UnknownThinGrace == 0 {
		c.UnknownThinGrace = 10 * time.Minute
	}
	if c.Hypervisor == nil {
		c.Hypervisor = &CloudHypervisor{}
	}
	if c.DisksPerSlot == 0 {
		c.DisksPerSlot = storage.DefaultDisksPerSlot
	}
	if c.ContainerRunDir == "" {
		c.ContainerRunDir = ContainerRunDir
	}
}

// Node is the node daemon state.
type Node struct {
	cfg Config
	st  Storage
	out *outbox
	ops *opCache

	mu        sync.Mutex
	allocs    map[string]*alloc
	finished  map[string]time.Time
	pods      map[string]PodRef // slot ID -> pod
	podsAt    time.Time
	missing   map[string]time.Time // slot ID -> first time its pod was missing
	lastSlots []*pb.SlotInfo
	lastCap   *pb.Capacity
	hostNQN   string
	bg        context.Context
	bgCancel  context.CancelFunc
	metrics   metrics
	// gens is the highest claim generation seen per BlipVol UID.
	gens map[string]int64
	// unknownThins is when each unknown compute thin ID was first seen
	// unknown. In memory only: a daemon restart starts the grace again.
	unknownThins map[uint32]time.Time
}

// SlotIDs returns the device IDs of the configured slots.
func SlotIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("slot-%d", i)
	}
	return ids
}

// New creates a Node and loads allocation records from StateDir.
func New(cfg Config) (*Node, error) {
	cfg.defaults()
	n := &Node{
		cfg: cfg, st: cfg.Storage, out: newOutbox(), ops: newOpCache(),
		allocs: map[string]*alloc{}, finished: map[string]time.Time{}, gens: map[string]int64{},
		pods: map[string]PodRef{}, missing: map[string]time.Time{},
	}
	// The background context exists from the start, so watchers started
	// by commands before Run are stopped with the node.
	n.bg, n.bgCancel = context.WithCancel(context.Background())
	for _, d := range []string{cfg.StateDir, filepath.Join(cfg.StateDir, "allocs"), cfg.SlotsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := n.load(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Node) disksPerSlot() int { return n.cfg.DisksPerSlot }

func (n *Node) slotDir(id string) string { return filepath.Join(n.cfg.SlotsDir, id) }

func (n *Node) validSlot(id string) bool {
	for _, s := range SlotIDs(n.cfg.NodeConfig.Slots) {
		if s == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Persistence

func (n *Node) allocPath(id string) string {
	return filepath.Join(n.cfg.StateDir, "allocs", id+".json")
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stateFile is the node-wide state in StateDir/node.json. Per-allocation
// records are in StateDir/allocs. Both are boot-scoped.
type stateFile struct {
	BootID   string               `json:"bootID"`
	Finished map[string]time.Time `json:"finished"`
	// Gens is the highest claim generation seen per BlipVol UID.
	Gens map[string]int64 `json:"gens,omitempty"`
}

func (n *Node) statePath() string { return filepath.Join(n.cfg.StateDir, "node.json") }

func (n *Node) load() error {
	var sf stateFile
	b, err := os.ReadFile(n.statePath())
	if err == nil {
		if err := json.Unmarshal(b, &sf); err != nil {
			return fmt.Errorf("node.json: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	reboot := sf.BootID != "" && sf.BootID != n.cfg.BootID
	if !reboot {
		if sf.Finished != nil {
			n.finished = sf.Finished
		}
		if sf.Gens != nil {
			n.gens = sf.Gens
		}
	}
	ents, err := os.ReadDir(filepath.Join(n.cfg.StateDir, "allocs"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(n.cfg.StateDir, "allocs", e.Name())
		if reboot {
			os.Remove(p)
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r allocRecord
		if err := json.Unmarshal(b, &r); err != nil {
			log.Printf("drop bad allocation record %s: %v", p, err)
			os.Remove(p)
			continue
		}
		n.allocs[r.ID] = newAlloc(r)
	}
	return n.saveState()
}

// saveState writes node.json. n.mu must be held (or the node not yet
// shared).
func (n *Node) saveState() error {
	// Keep the set bounded: drop entries older than a week.
	cut := time.Now().Add(-7 * 24 * time.Hour)
	for id, t := range n.finished {
		if t.Before(cut) {
			delete(n.finished, id)
		}
	}
	return writeJSON(n.statePath(), stateFile{BootID: n.cfg.BootID, Finished: n.finished, Gens: n.gens})
}

// isFinished reports whether the allocation was released or the
// controller said it is finished.
func (n *Node) isFinished(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.finished[id]
	return ok
}

// ---------------------------------------------------------------------------
// Slots

// syncSlots refreshes the pod map and reports lost slots. It runs every
// Poll. Slot readiness is not tracked here: the controller uses the
// Kubernetes readiness of the slot pod.
func (n *Node) syncSlots(ctx context.Context) {
	if n.cfg.NodeConfig.Slots == 0 {
		return
	}
	pods, err := n.cfg.Pods.SlotPods(ctx)
	now := time.Now()
	n.mu.Lock()
	if err != nil {
		n.mu.Unlock()
		log.Printf("list slot pods: %v", err)
		return
	}
	n.pods, n.podsAt = pods, now
	bySlot := map[string]*alloc{}
	for _, a := range n.allocs {
		if a.rec.SlotID != "" {
			bySlot[a.rec.SlotID] = a
		}
	}
	n.mu.Unlock()

	for _, id := range SlotIDs(n.cfg.NodeConfig.Slots) {
		pod, has := pods[id]
		a := bySlot[id]
		if has {
			n.mu.Lock()
			delete(n.missing, id)
			n.mu.Unlock()
		} else {
			n.mu.Lock()
			if _, ok := n.missing[id]; !ok {
				n.missing[id] = now
			}
			gone := now.Sub(n.missing[id])
			n.mu.Unlock()
			if a != nil && gone >= n.cfg.SlotLostAfter {
				n.slotLost(a, "slot pod is gone")
			}
			continue
		}
		if a != nil {
			r := a.record()
			if r.Pod.Name != pod.Name || r.Pod.Namespace != pod.Namespace {
				n.slotLost(a, fmt.Sprintf("slot now belongs to pod %s/%s", pod.Namespace, pod.Name))
			}
		}
	}
	n.reportSlots()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// resetSlotDir removes files left by an earlier pod. Called by the device
// plugin when a slot is given to a new pod.
func (n *Node) resetSlotDir(id string) error {
	dir := n.slotDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	n.mu.Lock()
	var lost *alloc
	for _, a := range n.allocs {
		if a.rec.SlotID == id {
			lost = a
		}
	}
	n.mu.Unlock()
	if lost != nil {
		n.slotLost(lost, "slot given to a new pod")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, slot.DirVolumes), 0o755); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// slotInfos is the current SlotInfo list, sorted by device ID.
func (n *Node) slotInfos() []*pb.SlotInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*pb.SlotInfo
	for _, id := range SlotIDs(n.cfg.NodeConfig.Slots) {
		pod, ok := n.pods[id]
		if !ok {
			continue
		}
		si := &pb.SlotInfo{DeviceId: id, Pod: &pb.ObjectRef{Namespace: pod.Namespace, Name: pod.Name, Uid: pod.UID}}
		for _, a := range n.allocs {
			if a.rec.SlotID == id {
				si.AllocationId = a.rec.ID
			}
		}
		out = append(out, si)
	}
	return out
}

func (n *Node) reportSlots() {
	s := n.slotInfos()
	n.mu.Lock()
	same := len(s) == len(n.lastSlots)
	for i := 0; same && i < len(s); i++ {
		same = proto.Equal(s[i], n.lastSlots[i])
	}
	n.lastSlots = s
	n.mu.Unlock()
	if !same {
		n.out.markDirty()
	}
}

// slotForPod returns the slot ID held by pod.
func (n *Node) slotForPod(pod *pb.ObjectRef) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, p := range n.pods {
		if p.Name == pod.GetName() && p.Namespace == pod.GetNamespace() {
			return id, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// State and capacity

func (n *Node) capabilities() *pb.Capabilities {
	c := n.cfg.NodeConfig
	caps := &pb.Capabilities{
		Compute: c.Slots > 0, Hypervisor: c.Hypervisor, Slots: int32(c.Slots),
		StorageAddress: c.Address, ChunkSizeBytes: c.ChunkSizeBytes,
	}
	if c.Storage != nil {
		caps.Storage, caps.Vg, caps.MaxLvs = true, c.Storage.VG, int32(c.Storage.MaxLVs)
		caps.StoragePort = n.cfg.StoragePort
		if caps.StoragePort == 0 {
			caps.StoragePort = 4420
		}
	}
	return caps
}

func (n *Node) capacity(ctx context.Context) *pb.Capacity {
	sc, cc, err := n.st.Capacity(ctx)
	if err != nil {
		log.Printf("storage capacity: %v", err)
	}
	if n.cfg.NodeConfig.Storage == nil {
		sc = nil
	} else if sc == nil {
		sc = &pb.StorageCapacity{}
	}
	if n.cfg.NodeConfig.Slots > 0 {
		if cc == nil {
			cc = &pb.ComputeCapacity{}
		}
		cc.Slots = int32(n.cfg.NodeConfig.Slots)
		cc.DisksPerSlot = int32(n.disksPerSlot())
		cc.AssignedSlots = 0
		for _, s := range n.slotInfos() {
			if s.AllocationId != "" {
				cc.AssignedSlots++
			}
		}
		cc.MemoryPressure = memoryPressure()
	} else {
		cc = nil
	}
	if sc != nil {
		sc.Vg = n.cfg.NodeConfig.Storage.VG
		sc.MaxLvs = int32(n.cfg.NodeConfig.Storage.MaxLVs)
	}
	return &pb.Capacity{Storage: sc, Compute: cc}
}

// memoryPressure is true when less than 10% of memory is available.
func memoryPressure() bool {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	var total, avail int64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		var v int64
		fmt.Sscan(f[1], &v)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total > 0 && avail*10 < total
}

func (n *Node) reportCapacity(ctx context.Context) {
	c := n.capacity(ctx)
	n.mu.Lock()
	same := n.lastCap != nil && proto.Equal(c, n.lastCap)
	n.lastCap = c
	n.mu.Unlock()
	if !same {
		n.out.markDirty()
	}
}

// State builds the full NodeState.
func (n *Node) State(ctx context.Context) (*pb.NodeState, error) {
	ss, err := n.st.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage state: %w", err)
	}
	n.noteUnknownThins(ss.UnknownThins, time.Now())
	s := &pb.NodeState{Contents: ss.Contents, Slots: n.slotInfos(), Capacity: n.capacity(ctx)}
	n.mu.Lock()
	as := map[string]*alloc{}
	for id, a := range n.allocs {
		as[id] = a
	}
	n.mu.Unlock()
	ids := make([]string, 0, len(as)+len(ss.Allocations))
	for id := range as {
		ids = append(ids, id)
	}
	for id := range ss.Allocations {
		if as[id] == nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if a := as[id]; a != nil {
			s.Allocations = append(s.Allocations, a.info(ss.Allocations[id]))
			continue
		}
		// Devices of an allocation the node has no record of (released
		// or lost): reported so the controller sends Release.
		ai := &pb.AllocationInfo{AllocationId: id}
		atts := make([]string, 0, len(ss.Allocations[id]))
		for att := range ss.Allocations[id] {
			atts = append(atts, att)
		}
		sort.Strings(atts)
		for _, att := range atts {
			ai.Attachments = append(ai.Attachments, storageAttachmentInfo(att, ss.Allocations[id][att]))
		}
		s.Allocations = append(s.Allocations, ai)
	}
	return s, nil
}

// Run runs the background loops until ctx ends.
func (n *Node) Run(ctx context.Context) {
	stop := context.AfterFunc(ctx, n.bgCancel)
	defer stop()
	defer n.bgCancel()
	n.mu.Lock()
	var as []*alloc
	for _, a := range n.allocs {
		as = append(as, a)
	}
	n.mu.Unlock()
	for _, a := range as {
		n.resume(ctx, a)
	}
	t := time.NewTicker(n.cfg.Poll)
	defer t.Stop()
	capT := time.NewTicker(n.cfg.CapacityPoll)
	defer capT.Stop()
	gcEvery := n.cfg.UnknownThinGrace / 4
	if gcEvery <= 0 {
		gcEvery = time.Hour
	}
	gcT := time.NewTicker(gcEvery)
	defer gcT.Stop()
	n.syncSlots(ctx)
	n.reportCapacity(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.syncSlots(ctx)
		case <-capT.C:
			n.reportCapacity(ctx)
		case <-gcT.C:
			n.collectUnknownThins(ctx)
		}
	}
}

// noteUnknownThins records the unknown compute thin IDs of one scan and
// returns those that stayed unknown for UnknownThinGrace. IDs missing
// from the scan are forgotten, so the grace counts consecutive scans.
func (n *Node) noteUnknownThins(ids []uint32, now time.Time) []uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	seen := map[uint32]time.Time{}
	var due []uint32
	for _, id := range ids {
		t, ok := n.unknownThins[id]
		if !ok {
			t = now
			log.Printf("compute pool thin %d belongs to nothing known", id)
		}
		seen[id] = t
		if n.cfg.UnknownThinGrace > 0 && now.Sub(t) >= n.cfg.UnknownThinGrace {
			due = append(due, id)
		}
	}
	n.unknownThins = seen
	return due
}

// collectUnknownThins scans the storage state and deletes compute thin
// IDs that have been unknown for UnknownThinGrace. Thin creation is
// journaled before the thin exists (under the storage lock), and the
// journal survives daemon restarts, so an unknown thin is not part of
// any operation; DeleteThins checks again under the lock.
func (n *Node) collectUnknownThins(ctx context.Context) {
	ss, err := n.st.State(ctx)
	if err != nil {
		return
	}
	due := n.noteUnknownThins(ss.UnknownThins, time.Now())
	if len(due) == 0 {
		return
	}
	if err := n.st.DeleteThins(ctx, due); err != nil {
		log.Printf("delete unknown compute thins %v: %v", due, err)
		return
	}
	log.Printf("deleted unknown compute thins %v", due)
	n.mu.Lock()
	for _, id := range due {
		delete(n.unknownThins, id)
	}
	n.mu.Unlock()
}
