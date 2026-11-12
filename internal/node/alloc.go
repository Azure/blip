package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/example/blip/internal/meta"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/slot"
)

// allocRecord is the persisted state of one allocation on a compute node.
type allocRecord struct {
	ID       string    `json:"id"`
	SlotID   string    `json:"slotID"`
	Blip     PodRef    `json:"blip"` // namespace, name, uid of the Blip
	Pod      PodRef    `json:"pod"`
	Deadline time.Time `json:"deadline"`
	Created  time.Time `json:"created"`

	Assigned bool `json:"assigned"`
	Started  bool `json:"started"`
	// RootAttachmentID is the attachment mounted as / (StartWorkload).
	RootAttachmentID string `json:"rootAttachmentID,omitempty"`
	// Attachments by attachment ID.
	Attachments map[string]*attRecord `json:"attachments,omitempty"`
	// Captures maps a CaptureLocal seq to its sorted attachment IDs, so
	// a repeat with another set is refused.
	Captures map[int64][]string `json:"captures,omitempty"`

	// Boot parameters from StartWorkload, rewritten to the metadata disk
	// with every host slot update.
	Init             []string `json:"init,omitempty"`
	RootMountOptions string   `json:"rootMountOptions,omitempty"`
	Hostname         string   `json:"hostname,omitempty"`
	RootVolume       string   `json:"rootVolume,omitempty"`

	// BootCount is the guest boot count of the last Started event.
	BootCount  int     `json:"bootCount"`
	HVExit     *hvExit `json:"hvExit,omitempty"`
	KillReason string  `json:"killReason,omitempty"`
	SlotLost   string  `json:"slotLost,omitempty"`
}

// attRecord is one attachment of an allocation.
type attRecord struct {
	ID         string              `json:"id"`
	UID        string              `json:"uid"`
	Name       string              `json:"name"`
	Generation int64               `json:"generation"`
	ContentID  string              `json:"contentID"`
	SizeBytes  int64               `json:"sizeBytes"`
	SlotDisk   int                 `json:"slotDisk"`
	Paths      []*pb.Path          `json:"paths,omitempty"`
	State      pb.AttachmentState  `json:"state"`
	GuestPath  string              `json:"guestPath,omitempty"`
	HostPath   string              `json:"hostPath,omitempty"`
	BlipVol    PodRef              `json:"blipvol"`
	Snaps      map[int64]time.Time `json:"snaps,omitempty"` // local snapshot seq -> created
}

func (a *attRecord) clone() *attRecord {
	c := *a
	c.Paths = append([]*pb.Path(nil), a.Paths...)
	if a.Snaps != nil {
		c.Snaps = make(map[int64]time.Time, len(a.Snaps))
		for k, v := range a.Snaps {
			c.Snaps[k] = v
		}
	}
	return &c
}

// clone returns a deep copy.
func (r allocRecord) clone() allocRecord {
	c := r
	if r.Attachments != nil {
		c.Attachments = make(map[string]*attRecord, len(r.Attachments))
		for k, v := range r.Attachments {
			c.Attachments[k] = v.clone()
		}
	}
	c.Init = append([]string(nil), r.Init...)
	if r.Captures != nil {
		c.Captures = make(map[int64][]string, len(r.Captures))
		for k, v := range r.Captures {
			c.Captures[k] = append([]string(nil), v...)
		}
	}
	if r.HVExit != nil {
		h := *r.HVExit
		if h.ExitCode != nil {
			x := *h.ExitCode
			h.ExitCode = &x
		}
		c.HVExit = &h
	}
	return c
}

// vmGone reports whether Cloud Hypervisor is known to be gone (or was
// never given this allocation).
func (r allocRecord) vmGone() bool {
	return !r.Assigned || r.HVExit != nil || r.SlotLost != ""
}

// hvExit is the end of the VM as blipd slot classified it (exit.json).
type hvExit struct {
	Reason   string `json:"blipReason"`
	Message  string `json:"message,omitempty"`
	ExitCode *int32 `json:"exitCode,omitempty"`
	Restarts int32  `json:"restarts,omitempty"`
}

// alloc is one allocation. ID and SlotID never change, so they may be
// read under Node.mu alone; everything else needs a.mu.
type alloc struct {
	opMu sync.Mutex // serializes commands on this allocation
	// persistMu serializes writes of the record file, so concurrent
	// persists neither share a temp file nor land out of order.
	persistMu sync.Mutex

	mu       sync.Mutex
	rec      allocRecord
	ctx      context.Context
	stop     context.CancelFunc // stops the watcher
	watching bool
	unreach  time.Time // first time the CH API was unreachable
	exited   chan struct{}
	// creds are the latest service account credentials (StartWorkload or
	// UpdateCredentials). Memory only: never in rec, never on disk.
	creds *pb.Credentials
}

func newAlloc(r allocRecord) *alloc {
	if r.Attachments == nil {
		r.Attachments = map[string]*attRecord{}
	}
	if r.Captures == nil {
		r.Captures = map[int64][]string{}
	}
	a := &alloc{rec: r, exited: make(chan struct{})}
	if r.vmGone() && r.Assigned {
		close(a.exited)
	}
	return a
}

func (a *alloc) record() allocRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rec.clone()
}

// update changes the record under a.mu.
func (a *alloc) update(f func(r *allocRecord)) {
	a.mu.Lock()
	f(&a.rec)
	a.mu.Unlock()
}

func ref(r PodRef) *pb.ObjectRef {
	return &pb.ObjectRef{Namespace: r.Namespace, Name: r.Name, Uid: r.UID}
}

func (a *alloc) info(cs map[string]AttachmentStorage) *pb.AllocationInfo {
	r := a.record()
	ai := &pb.AllocationInfo{
		AllocationId: r.ID, Blip: ref(r.Blip), Pod: ref(r.Pod), Assigned: r.Assigned,
		BootCount: int32(r.BootCount), Deadline: timestamppb.New(r.Deadline), SlotLost: r.SlotLost,
		RootAttachmentId: r.RootAttachmentID,
	}
	if r.HVExit != nil {
		ai.Exit = r.HVExit.exited(r.ID)
	}
	ids := make([]string, 0, len(r.Attachments))
	for id := range r.Attachments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ai.Attachments = append(ai.Attachments, attachmentInfo(r.Attachments[id]))
	}
	// Attachments the host has and the record lacks (should not happen;
	// reported so the controller can release them).
	var extra []string
	for id := range cs {
		if _, ok := r.Attachments[id]; !ok {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		ai.Attachments = append(ai.Attachments, storageAttachmentInfo(id, cs[id]))
	}
	return ai
}

func attachmentInfo(at *attRecord) *pb.AttachmentInfo {
	return &pb.AttachmentInfo{
		AttachmentId: at.ID, Uid: at.UID, Name: at.Name, Generation: at.Generation, ContentId: at.ContentID,
		SlotDisk: int32(at.SlotDisk), State: at.State,
	}
}

func storageAttachmentInfo(id string, s AttachmentStorage) *pb.AttachmentInfo {
	return &pb.AttachmentInfo{
		AttachmentId: id, Uid: s.UID, Generation: s.Generation, ContentId: s.ContentID, SlotDisk: int32(s.SlotDisk),
		State: pb.AttachmentState_ATTACHMENT_STATE_DETACHED,
	}
}

func (h *hvExit) exited(id string) *pb.Exited {
	e := &pb.Exited{AllocationId: id, Reason: h.Reason, Message: h.Message, RestartCount: h.Restarts}
	if h.ExitCode != nil {
		c := *h.ExitCode
		e.ExitCode = &c
	}
	return e
}

// errReject marks a command the node refuses (RESULT_STATUS_REJECTED).
type errReject struct {
	msg  string
	code pb.ErrorCode
}

func (e *errReject) Error() string { return e.msg }

func rejectf(format string, args ...any) error { return &errReject{msg: fmt.Sprintf(format, args...)} }

// rejectCode is rejectf with an error code.
func rejectCode(code pb.ErrorCode, format string, args ...any) error {
	return &errReject{msg: fmt.Sprintf(format, args...), code: code}
}

func (n *Node) persist(a *alloc) error {
	a.persistMu.Lock()
	defer a.persistMu.Unlock()
	a.mu.Lock()
	r := a.rec.clone()
	a.mu.Unlock()
	return writeJSON(n.allocPath(r.ID), r)
}

func (n *Node) getAlloc(id string) (*alloc, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.finished[id]; ok {
		return nil, rejectf("allocation %s is finished", id)
	}
	a := n.allocs[id]
	if a == nil {
		return nil, Codef(pb.ErrorCode_ERROR_CODE_NOT_FOUND, "allocation %s not found on this node", id)
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// Commands

// AssignSlot claims the slot of the pod and writes the assignment. The VM
// runs with no disks; AttachVolume hot-plugs them.
func (n *Node) AssignSlot(ctx context.Context, c *pb.AssignSlot) error {
	if c.AllocationId == "" || c.GetBlip().GetUid() == "" || c.GetPod().GetName() == "" || c.Deadline == nil {
		return rejectf("assign slot: allocation_id, blip uid, pod and deadline are required")
	}
	if n.isFinished(c.AllocationId) {
		return rejectf("allocation %s is finished", c.AllocationId)
	}
	slotID, ok := n.slotForPod(c.Pod)
	if !ok {
		// The pod map may be older than the claim; refresh it once.
		n.syncSlots(ctx)
		if slotID, ok = n.slotForPod(c.Pod); !ok {
			return rejectf("pod %s/%s holds no slot on this node", c.Pod.Namespace, c.Pod.Name)
		}
	}
	n.mu.Lock()
	a := n.allocs[c.AllocationId]
	if a == nil {
		for _, o := range n.allocs {
			if o.rec.SlotID == slotID {
				n.mu.Unlock()
				return rejectf("slot %s is used by allocation %s", slotID, o.rec.ID)
			}
		}
		if as, err := readAssignment(n.slotDir(slotID)); err == nil && as.AllocationID != c.AllocationId {
			n.mu.Unlock()
			return rejectf("slot %s was assigned to allocation %s", slotID, as.AllocationID)
		}
		if exists(filepath.Join(n.slotDir(slotID), slot.FileExit)) {
			n.mu.Unlock()
			return rejectf("slot %s already ran a VM", slotID)
		}
		a = newAlloc(allocRecord{
			ID: c.AllocationId, SlotID: slotID,
			Blip:     PodRef{Namespace: c.Blip.Namespace, Name: c.Blip.Name, UID: c.Blip.Uid},
			Pod:      PodRef{Namespace: c.Pod.Namespace, Name: c.Pod.Name, UID: c.Pod.Uid},
			Deadline: c.Deadline.AsTime(), Created: time.Now(),
		})
		n.allocs[a.rec.ID] = a
		n.mu.Unlock()
		if err := n.persist(a); err != nil {
			return err
		}
	} else {
		n.mu.Unlock()
		r := a.record()
		if r.Pod.Name != c.Pod.Name || r.Pod.Namespace != c.Pod.Namespace || r.Blip.UID != c.Blip.Uid {
			return rejectf("allocation %s exists with pod %s/%s", r.ID, r.Pod.Namespace, r.Pod.Name)
		}
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	if r.Assigned {
		return nil
	}
	if r.SlotLost != "" {
		return fmt.Errorf("slot lost: %s", r.SlotLost)
	}
	dir := n.slotDir(r.SlotID)
	if err := os.MkdirAll(filepath.Join(dir, slot.DirVolumes), 0o755); err != nil {
		return err
	}
	// Assign first, so the deadline is enforced even if a later step hangs.
	kill := r.Deadline.Add(c.GetKillGrace().AsDuration())
	if err := slot.WriteAssignment(dir, slot.Assignment{AllocationID: r.ID, KillTime: kill, Ports: c.Ports}); err != nil {
		return fmt.Errorf("write assignment: %w", err)
	}
	// The slot pod is no longer ready for another assignment.
	os.Remove(filepath.Join(dir, slot.FileReady))
	a.update(func(r *allocRecord) { r.Assigned = true })
	if err := n.persist(a); err != nil {
		return err
	}
	n.startWatch(a)
	n.reportSlots()
	return nil
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

// StartWorkload writes the boot parameters, identity and credentials to
// the metadata disk host slot. The boot stub in the warm VM then mounts
// the root volume and execs init; Started follows when it reports EXEC.
// The root attachment and every listed volume must be attached.
func (n *Node) StartWorkload(ctx context.Context, c *pb.StartWorkload) error {
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return err
	}
	p := c.GetParams()
	if len(p.GetInit()) == 0 || !strings.HasPrefix(p.GetInit()[0], "/") {
		return rejectf("start: init must be an argv with an absolute path first")
	}
	if c.RootAttachmentId == "" {
		return rejectf("start: root_attachment_id is required")
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	r := a.record()
	if !r.Assigned {
		return rejectf("allocation %s has no slot assigned", r.ID)
	}
	if r.HVExit != nil || r.SlotLost != "" {
		return rejectf("allocation %s has ended", r.ID)
	}
	if r.Started && r.RootAttachmentID != c.RootAttachmentId {
		return rejectf("allocation %s was started with root attachment %s", r.ID, r.RootAttachmentID)
	}
	root := r.Attachments[c.RootAttachmentId]
	if root == nil || root.State != pb.AttachmentState_ATTACHMENT_STATE_ATTACHED {
		return rejectf("root attachment %s is not attached", c.RootAttachmentId)
	}
	for _, v := range c.Volumes {
		at := r.Attachments[v.AttachmentId]
		if at == nil || at.State != pb.AttachmentState_ATTACHMENT_STATE_ATTACHED {
			return rejectf("volume %s (%s) is not attached", v.Name, v.AttachmentId)
		}
	}
	a.mu.Lock()
	if c.Credentials != nil {
		a.creds = c.Credentials
	}
	a.mu.Unlock()
	hostname := p.Hostname
	if hostname == "" {
		hostname = r.Blip.Name
	}
	a.update(func(r *allocRecord) {
		r.RootAttachmentID, r.RootVolume = c.RootAttachmentId, root.Name
		r.Init = append([]string(nil), p.Init...)
		r.RootMountOptions, r.Hostname = p.RootMountOptions, hostname
	})
	if err := n.writeMeta(a); err != nil {
		return fmt.Errorf("write metadata disk: %w", err)
	}
	a.update(func(r *allocRecord) { r.Started = true })
	return n.persist(a)
}

// writeMeta writes the host slot of the metadata disk from the record
// and the credentials in memory. If the node has no credentials (it
// restarted), those already on the disk are kept.
func (n *Node) writeMeta(a *alloc) error {
	r := a.record()
	a.mu.Lock()
	creds := a.creds
	a.mu.Unlock()
	dir := n.slotDir(r.SlotID)
	w, err := meta.OpenWriter(filepath.Join(dir, slot.FileMeta))
	if err != nil {
		return err
	}
	defer w.Close()
	h := &meta.HostData{
		AllocationID: r.ID,
		Identity:     meta.Identity{Name: r.Blip.Name, Namespace: r.Blip.Namespace, UID: r.Blip.UID},
		Boot:         meta.Boot{RootSerial: r.RootVolume, Init: r.Init, RootMountOptions: r.RootMountOptions, RootFSType: "ext4"},
		Hostname:     r.Hostname,
	}
	if creds != nil {
		h.Credentials = &meta.Credentials{Token: string(creds.Token), CACrt: string(creds.CaCrt), Namespace: creds.Namespace}
		if creds.Expiration != nil {
			h.Credentials.Expiration = creds.Expiration.AsTime()
		}
	} else if old, _, err := w.ReadHost(); err == nil && old.AllocationID == r.ID {
		h.Credentials = old.Credentials
	}
	var vols []meta.Volume
	for _, at := range r.Attachments {
		if at.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHED {
			vols = append(vols, meta.Volume{Name: at.Name, Serial: at.Name})
		}
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	h.Volumes = vols
	if pn, err := slot.ReadNetwork(dir); err == nil {
		nw := &meta.Network{MAC: pn.MAC, MTU: pn.MTU}
		for _, ad := range pn.Addresses {
			nw.Addresses = append(nw.Addresses, ad)
		}
		for _, rt := range pn.Routes {
			if rt.IPv6 {
				continue
			}
			dst := rt.Destination
			if dst == "" {
				dst = "0.0.0.0/0"
			}
			nw.Routes = append(nw.Routes, meta.Route{Dst: dst, Gateway: rt.Gateway})
		}
		nw.DNS, nw.Search = parseResolvConf(filepath.Join(dir, slot.FileResolvConf))
		h.Network = nw
	}
	_, err = w.WriteHost(h)
	return err
}

// UpdateCredentials replaces the credentials in the metadata disk host
// slot. Before the workload started they are kept (in memory) for
// StartWorkload.
func (n *Node) UpdateCredentials(ctx context.Context, c *pb.UpdateCredentials) error {
	if c.GetCredentials() == nil {
		return rejectf("update credentials: credentials are required")
	}
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return err
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	a.creds = c.Credentials
	a.mu.Unlock()
	r := a.record()
	if r.HVExit != nil || r.SlotLost != "" {
		return rejectf("allocation %s has ended", r.ID)
	}
	if !r.Started {
		return nil
	}
	if err := n.writeMeta(a); err != nil {
		return fmt.Errorf("write metadata disk: %w", err)
	}
	return nil
}

func parseResolvConf(path string) (servers, search []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			servers = append(servers, f[1])
		case "search":
			search = f[1:]
		}
	}
	return servers, search
}

// defaultGracefulTimeout is Kill.graceful_timeout when unset.
const defaultGracefulTimeout = 30 * time.Second

// Kill stops the VM. With graceful the ACPI power button is pressed
// first; Cloud Hypervisor is killed if it has not exited within the
// graceful timeout. The result is OK once it has exited.
func (n *Node) Kill(ctx context.Context, c *pb.Kill) error {
	a, err := n.getAlloc(c.AllocationId)
	if err != nil {
		return err
	}
	r := a.record()
	if r.vmGone() {
		return nil
	}
	if c.Graceful {
		d := defaultGracefulTimeout
		if c.GracefulTimeout != nil && c.GracefulTimeout.AsDuration() > 0 {
			d = c.GracefulTimeout.AsDuration()
		}
		if n.stopGracefully(ctx, a, d) {
			return nil
		}
		log.Printf("allocation %s: no exit %s after the power button; killing", r.ID, d)
	}
	n.kill(a, c.Reason)
	if !n.waitExit(ctx, a, n.cfg.ReleaseWait) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("cloud hypervisor of allocation %s did not exit within %s", r.ID, n.cfg.ReleaseWait)
	}
	return nil
}

// stopGracefully presses the power button and waits up to d for Cloud
// Hypervisor to exit. It reports whether it exited.
func (n *Node) stopGracefully(ctx context.Context, a *alloc, d time.Duration) bool {
	end := time.Now().Add(d)
	pctx, cancel := context.WithTimeout(ctx, min(d, 10*time.Second))
	err := n.cfg.Hypervisor.PowerButton(pctx, n.slotDir(a.rec.SlotID))
	cancel()
	if err != nil {
		log.Printf("allocation %s: power button: %v", a.rec.ID, err)
	} else {
		log.Printf("allocation %s: pressed the power button", a.rec.ID)
	}
	return n.waitExit(ctx, a, time.Until(end))
}

func (n *Node) kill(a *alloc, reason string) {
	a.mu.Lock()
	if a.rec.KillReason == "" {
		a.rec.KillReason = reason
	}
	ended := a.rec.HVExit != nil
	dir := n.slotDir(a.rec.SlotID)
	a.mu.Unlock()
	if ended {
		return
	}
	_ = n.persist(a)
	log.Printf("allocation %s: killing the VM: %s", a.rec.ID, reason)
	if err := slot.RequestKill(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("allocation %s: kill: %v", a.rec.ID, err)
	}
}

// Release tears down an allocation and marks it finished: it kills the
// VM if it still runs, releases every remaining attachment and resets the
// slot disks.
func (n *Node) Release(ctx context.Context, id string) error {
	if id == "" {
		return rejectf("release: allocation_id is required")
	}
	n.mu.Lock()
	_, done := n.finished[id]
	a := n.allocs[id]
	n.mu.Unlock()
	if done && a == nil {
		return nil
	}
	slotID := ""
	if a != nil {
		a.opMu.Lock()
		defer a.opMu.Unlock()
		r := a.record()
		slotID = r.SlotID
		if !r.vmGone() {
			n.kill(a, "released")
			n.waitExit(ctx, a, n.cfg.ReleaseWait)
		}
		a.mu.Lock()
		if a.stop != nil {
			a.stop()
		}
		a.mu.Unlock()
		for _, at := range r.Attachments {
			n.removeSlotLink(r.SlotID, at.UID)
		}
	}
	if err := n.st.ReleaseAllocation(ctx, id); err != nil {
		return fmt.Errorf("release storage: %w", err)
	}
	if slotID != "" && n.cfg.NodeConfig.Slots > 0 {
		if err := n.st.ResetSlot(ctx, slotID); err != nil {
			return fmt.Errorf("reset slot disks: %w", err)
		}
	}
	n.mu.Lock()
	delete(n.allocs, id)
	n.finished[id] = time.Now()
	err := n.saveState()
	n.mu.Unlock()
	if a != nil {
		if err := os.Remove(n.allocPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	n.reportSlots()
	return err
}

// waitExit waits up to d for Cloud Hypervisor to exit (or the slot to
// be lost) and reports whether it did.
func (n *Node) waitExit(ctx context.Context, a *alloc, d time.Duration) bool {
	t := time.NewTimer(max(d, 0))
	defer t.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		n.checkExit(a)
		r := a.record()
		if r.vmGone() {
			return true
		}
		n.mu.Lock()
		_, has := n.pods[r.SlotID]
		n.mu.Unlock()
		if !has || !exists(n.slotDir(r.SlotID)) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return false
		case <-a.exited:
			return true
		case <-tick.C:
		}
	}
}

// finishAll handles the finished list from Welcome.
func (n *Node) finishAll(ctx context.Context, ids []string) {
	for _, id := range ids {
		n.mu.Lock()
		a := n.allocs[id]
		if a == nil {
			n.finished[id] = time.Now()
		}
		n.mu.Unlock()
		if a != nil {
			if err := n.Release(ctx, id); err != nil {
				log.Printf("release finished allocation %s: %v", id, err)
			}
		}
	}
	n.mu.Lock()
	_ = n.saveState()
	n.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Watchers

func (n *Node) bgContext() context.Context {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bg == nil {
		return context.Background()
	}
	return n.bg
}

// ensureStop makes the per-allocation context. a.mu is held.
func (n *Node) ensureStopLocked(a *alloc) context.Context {
	if a.stop == nil || a.ctx == nil || a.ctx.Err() != nil {
		a.ctx, a.stop = context.WithCancel(n.bgContext())
	}
	return a.ctx
}

func (n *Node) startWatch(a *alloc) {
	a.mu.Lock()
	if a.watching {
		a.mu.Unlock()
		return
	}
	a.watching = true
	ctx := n.ensureStopLocked(a)
	a.mu.Unlock()
	go func() {
		t := time.NewTicker(n.cfg.Poll / 4)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n.watchOnce(a)
			}
		}
	}()
}

func (n *Node) watchOnce(a *alloc) {
	n.checkExit(a)
	r := a.record()
	if r.HVExit == nil && r.SlotLost == "" && r.Started {
		n.checkGuest(a)
	}
	if r.HVExit == nil && r.SlotLost == "" {
		n.checkReachable(a)
	}
}

// checkGuest records a new boot when the boot stub reports EXEC for it
// in the metadata disk guest area.
func (n *Node) checkGuest(a *alloc) {
	w, err := meta.OpenWriter(filepath.Join(n.slotDir(a.rec.SlotID), slot.FileMeta))
	if err != nil {
		return
	}
	g, err := w.ReadGuest()
	w.Close()
	if err != nil || g.State != meta.StateExec || g.BootCount < 1 || g.BootCount > 1<<20 {
		return
	}
	a.mu.Lock()
	if g.BootCount <= a.rec.BootCount || a.rec.HVExit != nil {
		a.mu.Unlock()
		return
	}
	a.rec.BootCount = g.BootCount
	id := a.rec.ID
	a.mu.Unlock()
	_ = n.persist(a)
	log.Printf("allocation %s: guest init started (boot %d)", id, g.BootCount)
	n.out.markDirty()
}

// checkReachable reports the slot lost when the Cloud Hypervisor API
// socket is gone for too long and exit.json was never written.
func (n *Node) checkReachable(a *alloc) {
	sock := filepath.Join(n.slotDir(a.rec.SlotID), slot.FileAPISocket)
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err == nil {
		c.Close()
		a.mu.Lock()
		a.unreach = time.Time{}
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	if a.unreach.IsZero() {
		a.unreach = time.Now()
	}
	lost := time.Since(a.unreach) >= n.cfg.SlotUnreachableAfter
	a.mu.Unlock()
	if lost {
		// Give exit.json one more chance; blipd slot writes it after CH exits.
		if _, err := slot.ReadExit(n.slotDir(a.rec.SlotID)); err == nil {
			return
		}
		n.slotLost(a, "cloud hypervisor API is unreachable and no exit was recorded")
	}
}

// checkExit records the exit once exit.json appears.
func (n *Node) checkExit(a *alloc) {
	a.mu.Lock()
	if a.rec.HVExit != nil || !a.rec.Assigned {
		a.mu.Unlock()
		return
	}
	dir := n.slotDir(a.rec.SlotID)
	a.mu.Unlock()
	er, err := slot.ReadExit(dir)
	if err != nil {
		return
	}
	a.mu.Lock()
	if a.rec.HVExit != nil {
		a.mu.Unlock()
		return
	}
	h := exitFromRecord(a.rec, er)
	a.rec.HVExit = h
	if er.BootCount > a.rec.BootCount {
		a.rec.BootCount = er.BootCount
	}
	a.markDetachedLocked()
	if a.stop != nil {
		a.stop()
	}
	a.watching = false
	id := a.rec.ID
	// Mark the state changed before anyone can see the exit, so a Kill
	// result (queued after waitExit) never overtakes the exit.
	n.out.markDirty()
	a.closeExitedLocked()
	a.mu.Unlock()
	_ = n.persist(a)
	log.Printf("allocation %s: the VM exited (%s): %s", id, er.Reason, er.Message)
}

// exitFromRecord takes the exit from the slot's exit.json unchanged.
func exitFromRecord(r allocRecord, er *slot.ExitRecord) *hvExit {
	h := &hvExit{Reason: er.Reason, Message: er.Message}
	boots := max(er.BootCount, r.BootCount)
	if boots > 1 {
		h.Restarts = int32(boots - 1)
	}
	if er.GuestExitCode != nil {
		c := int32(*er.GuestExitCode)
		h.ExitCode = &c
	}
	return h
}

// closeExitedLocked wakes waitExit. a.mu is held.
func (a *alloc) closeExitedLocked() {
	select {
	case <-a.exited:
	default:
		close(a.exited)
	}
}

// markDetachedLocked marks attached volumes detached once the VM is gone:
// no hypervisor holds them any more. a.mu is held.
func (a *alloc) markDetachedLocked() {
	for _, at := range a.rec.Attachments {
		if at.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHED || at.State == pb.AttachmentState_ATTACHMENT_STATE_ATTACHING {
			at.State = pb.AttachmentState_ATTACHMENT_STATE_DETACHED
		}
	}
}

// slotLost records the slot lost once and stops watching.
func (n *Node) slotLost(a *alloc, reason string) {
	a.mu.Lock()
	if a.rec.SlotLost != "" || a.rec.HVExit != nil {
		a.mu.Unlock()
		return
	}
	a.rec.SlotLost = reason
	a.markDetachedLocked()
	if a.stop != nil {
		a.stop()
	}
	a.watching = false
	id := a.rec.ID
	a.closeExitedLocked()
	a.mu.Unlock()
	_ = n.persist(a)
	log.Printf("allocation %s: slot lost: %s", id, reason)
	n.out.markDirty()
}

// resume restarts the watchers of an allocation loaded from disk.
func (n *Node) resume(_ context.Context, a *alloc) {
	r := a.record()
	if r.vmGone() {
		return
	}
	n.startWatch(a)
}
