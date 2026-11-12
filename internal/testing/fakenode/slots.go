package fakenode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/meta"
	"github.com/example/blip/internal/node"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/slot/chapi"
)

// This file plays the host side the node daemon does not own: the
// kubelet (which pod holds which slot), blipd slot (slot directory,
// kill file, exit.json), the boot stub (metadata disk guest
// area) and Cloud Hypervisor (hot-plug, power button).

// pods is the node's PodLister. A slot pod of the node gets the first
// free slot, whose directory is then prepared as blipd slot does once
// the warm VM waits for work. A slot is free when no pod holds it and
// the node has no allocation on it.
type pods Node

func (p *pods) SlotPods(ctx context.Context) (map[string]node.PodRef, error) {
	n := (*Node)(p)
	out := map[string]node.PodRef{}
	if n.cfg.Kube == nil || !n.cfg.Compute {
		return out, nil
	}
	list, err := n.podList(ctx)
	if err != nil {
		return nil, err
	}
	live := map[types.UID]bool{}
	var fresh []corev1.Pod
	n.mu.Lock()
	defer n.mu.Unlock()
	mapped := map[types.UID]bool{}
	for _, ref := range n.slots {
		mapped[types.UID(ref.UID)] = true
	}
	for _, p := range list {
		if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || n.hidden[p.UID] {
			continue
		}
		live[p.UID] = true
		if !mapped[p.UID] {
			fresh = append(fresh, p)
		}
	}
	for id, ref := range n.slots {
		if live[types.UID(ref.UID)] {
			out[id] = ref
		}
	}
	sort.Slice(fresh, func(i, j int) bool {
		a, b := fresh[i].CreationTimestamp, fresh[j].CreationTimestamp
		return a.Before(&b) || a.Equal(&b) && fresh[i].Name < fresh[j].Name
	})
	for _, p := range fresh {
		id := n.freeSlotLocked(out)
		if id == "" {
			break
		}
		if err := bootSlot(n.slotPath(id)); err != nil {
			return nil, err
		}
		ref := node.PodRef{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)}
		n.slots[id], out[id] = ref, ref
	}
	return out, nil
}

func (n *Node) slotPath(id string) string { return filepath.Join(n.dir, "slots", id) }

// freeSlotLocked returns a slot that is not in use, or "".
func (n *Node) freeSlotLocked(used map[string]node.PodRef) string {
	for _, id := range node.SlotIDs(int(n.cfg.Slots)) {
		if _, ok := used[id]; ok {
			continue
		}
		as, err := readAssignment(n.slotPath(id))
		if err == nil && exists(filepath.Join(n.dir, "state", "allocs", as.AllocationID+".json")) {
			continue
		}
		return id
	}
	return ""
}

// bootSlot prepares a slot directory like blipd slot does when the boot
// stub reports WAITING.
func bootSlot(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, slot.DirVolumes), 0o755); err != nil {
		return err
	}
	if err := meta.Create(filepath.Join(dir, slot.FileMeta)); err != nil {
		return err
	}
	if err := writeGuest(dir, &meta.GuestData{State: meta.StateWaiting, BootCount: 1}); err != nil {
		return err
	}
	files := map[string]string{
		slot.FileResolvConf: "nameserver 10.96.0.10\n",
		slot.FileNetwork:    `{"iface":"eth0","mac":"0a:58:0a:f4:01:05","mtu":1500,"addresses":["10.244.1.5/24"],"routes":[{"gateway":"10.244.1.1"}]}`,
		slot.FileReady:      "",
	}
	for _, f := range []string{slot.FileResolvConf, slot.FileNetwork, slot.FileReady} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(files[f]), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeGuest(dir string, g *meta.GuestData) error {
	d, err := meta.Open(filepath.Join(dir, slot.FileMeta))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.WriteGuest(g)
}

func readAssignment(dir string) (*slot.Assignment, error) {
	b, err := os.ReadFile(filepath.Join(dir, slot.FileAssignment))
	if err != nil {
		return nil, err
	}
	var as slot.Assignment
	if err := json.Unmarshal(b, &as); err != nil {
		return nil, err
	}
	return &as, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// runSlots ends VMs like blipd slot: on the kill file, and at the kill
// time of the assignment (deadline + AssignSlot.kill_grace). The
// controller stops the Blip at its deadline with a graceful Kill first.
func (n *Node) runSlots(ctx context.Context) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n.mu.Lock()
		ids := make([]string, 0, len(n.slots))
		for id := range n.slots {
			ids = append(ids, id)
		}
		n.mu.Unlock()
		for _, id := range ids {
			dir := n.slotPath(id)
			as, err := readAssignment(dir)
			if err != nil || exists(filepath.Join(dir, slot.FileExit)) {
				continue
			}
			switch {
			case exists(filepath.Join(dir, slot.FileKill)):
				n.writeExit(dir, as.AllocationID, slot.ExitRecord{ExitCode: -1, Signal: "killed", Cause: "killed"}, nil, "", nil)
			case !as.KillTime.IsZero() && time.Now().After(as.KillTime):
				n.writeExit(dir, as.AllocationID, slot.ExitRecord{ExitCode: -1, Signal: "killed", Cause: "deadline"}, nil, "", nil)
			}
		}
	}
}

// writeExit writes exit.json once, as blipd slot does when Cloud
// Hypervisor has exited: r has how Cloud Hypervisor ended, g the guest
// area changes (exit code, FAIL), and slot.Classify classifies it.
func (n *Node) writeExit(dir, allocID string, r slot.ExitRecord, g *meta.GuestData, panicLine string, initCode *int) {
	p := filepath.Join(dir, slot.FileExit)
	if exists(p) {
		return
	}
	if g == nil {
		g = &meta.GuestData{State: meta.StateExec}
	}
	n.mu.Lock()
	g.BootCount = int(n.boots[allocID])
	n.mu.Unlock()
	slot.Classify(&r, g, 0, panicLine, initCode)
	r.Time = time.Now()
	b, _ := json.Marshal(r)
	if err := os.WriteFile(p+".tmp", b, 0o644); err == nil {
		os.Rename(p+".tmp", p)
	}
}

// allocSlot returns the slot directory assigned to an allocation, or "".
func (n *Node) allocSlot(allocID string) string {
	for _, id := range node.SlotIDs(int(n.cfg.Slots)) {
		if as, err := readAssignment(n.slotPath(id)); err == nil && as.AllocationID == allocID {
			return n.slotPath(id)
		}
	}
	return ""
}

// hypervisor stands in for Cloud Hypervisor. Hot-plug always works; the
// power button powers the guest off unless SetGracefulHang is on.
type hypervisor Node

func (h *hypervisor) AddDisk(context.Context, string, chapi.DiskConfig) error { return nil }

func (h *hypervisor) RemoveDisk(context.Context, string, string, string) error { return nil }

func (h *hypervisor) PowerButton(_ context.Context, dir string) error {
	n := (*Node)(h)
	as, err := readAssignment(dir)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.buttons[as.AllocationID]++
	hang := n.hang
	n.mu.Unlock()
	if !hang {
		n.writeExit(dir, as.AllocationID, slot.ExitRecord{Cause: "exited"}, nil, "", nil)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Guest events

// Started reports a boot that reached EXEC, as the boot stub does: boot
// 1 is the first boot, higher numbers follow guest reboots, 0 means the
// next boot. It returns once the node has reported it.
func (n *Node) Started(allocID string, boot int32) {
	dir := n.allocSlot(allocID)
	if dir == "" {
		return
	}
	n.mu.Lock()
	if boot <= 0 {
		boot = n.boots[allocID] + 1
	}
	n.boots[allocID] = boot
	n.mu.Unlock()
	if err := writeGuest(dir, &meta.GuestData{State: meta.StateExec, BootCount: int(boot)}); err != nil {
		return
	}
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		a := n.Alloc(allocID)
		if a == nil || a.BootCount >= boot || a.Exit != nil || a.SlotLost != "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// GuestReboot reports a guest reboot that reached EXEC again.
func (n *Node) GuestReboot(allocID string) { n.Started(allocID, 0) }

// end ends the VM once, as blipd slot would.
func (n *Node) end(allocID string, r slot.ExitRecord, g *meta.GuestData, panicLine string, initCode *int) {
	if dir := n.allocSlot(allocID); dir != "" {
		n.writeExit(dir, allocID, r, g, panicLine, initCode)
	}
}

// Poweroff reports a clean guest shutdown with an optional guest exit
// code.
func (n *Node) Poweroff(allocID string, code *int32) {
	g := &meta.GuestData{State: meta.StateExec}
	if code != nil {
		c := int(*code)
		g.ExitCode = &c
	}
	n.end(allocID, slot.ExitRecord{Cause: "exited"}, g, "", nil)
}

// Crash ends the VM as if Cloud Hypervisor died with status.
func (n *Node) Crash(allocID string, status int) {
	n.end(allocID, slot.ExitRecord{Cause: "exited", ExitCode: status}, nil, "", nil)
}

// SlotLost hides the slot pod of an allocation from the node, which then
// reports the slot lost ("slot pod is gone") after Config.SlotLostAfter.
func (n *Node) SlotLost(allocID string) {
	dir := n.allocSlot(allocID)
	n.mu.Lock()
	defer n.mu.Unlock()
	if ref, ok := n.slots[filepath.Base(dir)]; ok && dir != "" {
		n.hidden[types.UID(ref.UID)] = true
	}
}

// ---------------------------------------------------------------------------
// Workloads

// Succeed boots, runs for d and powers off without an exit code.
func Succeed(d time.Duration) Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		time.Sleep(d)
		n.Poweroff(s.AllocationId, nil)
	}
}

// Fail boots and powers off with guest exit code code.
func Fail(code int32) Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		n.Poweroff(s.AllocationId, Code(code))
	}
}

// Panic boots, then the guest kernel panics.
func Panic(msg string) Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		n.end(s.AllocationId, slot.ExitRecord{Cause: "panic", ExitCode: -1, Signal: "killed"}, nil, msg, nil)
	}
}

// InitExited boots, then init (PID 1) exits with code.
func InitExited(code int32) Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
		c := int(code)
		n.end(s.AllocationId, slot.ExitRecord{Cause: "panic", ExitCode: -1, Signal: "killed"}, nil, "Kernel panic - not syncing: Attempted to kill init!", &c)
	}
}

// BootFailed fails in the boot stub (for example reason RootMountFailed)
// without reaching EXEC.
func BootFailed(reason, msg string) Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.end(s.AllocationId, slot.ExitRecord{Cause: "exited"}, &meta.GuestData{State: meta.StateFail, Reason: reason, Message: msg}, "", nil)
	}
}

// Hang boots and never ends.
func Hang() Workload {
	return func(n *Node, s *nodepb.StartWorkload) {
		n.Started(s.AllocationId, 1)
	}
}
