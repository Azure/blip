package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/proto/nodepb"
)

// NodeAuthenticator checks a node token and returns the name of the node the
// token's pod runs on.
type NodeAuthenticator interface {
	Authenticate(ctx context.Context, token string) (node string, err error)
}

// Owner is the object to reconcile when an operation finishes.
type Owner struct {
	Kind      string // "Blip" or "BlipVol"; empty means nobody
	Namespace string
	Name      string
}

// NodeHooks connect the node manager to the reconcilers.
type NodeHooks struct {
	// Finished returns allocation IDs the controller considers finished on node.
	Finished func(node string) []string
	// Connected runs after a node sent Hello (in its own goroutine).
	Connected func(node string, state *nodepb.NodeState)
	// AllocChanged runs when the runtime state of an allocation changed.
	AllocChanged func(allocID string)
	// OpDone runs when an operation has a final result.
	OpDone func(o Owner)
}

// AllocRuntime is what nodes reported about an allocation.
type AllocRuntime struct {
	ID       string
	Node     string
	Assigned bool
	// Started: the boot stub reported EXEC at least once.
	Started bool
	// BootCount is the number of boots that reached EXEC.
	BootCount int32
	// Exit is set once the VM exited (terminal).
	Exit     *nodepb.Exited
	SlotLost string
}

// RestartCount is the number of guest reboots.
func (rt *AllocRuntime) RestartCount() int32 {
	n := rt.BootCount - 1
	if rt.Exit != nil && rt.Exit.RestartCount > n {
		n = rt.Exit.RestartCount
	}
	if n < 0 {
		return 0
	}
	return n
}

type nodeRec struct {
	name           string
	sess           *session
	bootID         string
	caps           *nodepb.Capabilities
	capacity       *nodepb.Capacity
	contents       map[string]*nodepb.ContentInfo
	allocations    map[string]*nodepb.AllocationInfo
	slots          []*nodepb.SlotInfo
	disconnectedAt time.Time
	everConnected  bool
}

type session struct {
	node   string
	send   chan *nodepb.ControllerMessage
	cancel context.CancelFunc
}

type op struct {
	id       string
	node     string
	cmd      *nodepb.Command
	owner    Owner
	result   *nodepb.CommandResult
	created  time.Time
	deadline time.Time
	done     chan struct{}
}

// ErrNodeNotConnected is returned by Call when the node has no session.
var ErrNodeNotConnected = errors.New("node not connected")

// NodeManager serves nodepb.Controller and tracks node sessions, operations
// and allocation runtime state.
type NodeManager struct {
	nodepb.UnimplementedControllerServer

	log        logr.Logger
	auth       NodeAuthenticator
	clusterKey []byte
	opts       *Options
	hooks      NodeHooks
	started    time.Time

	mu     sync.Mutex
	nodes  map[string]*nodeRec
	ops    map[string]*op
	allocs map[string]*AllocRuntime
	authOK map[string]authEntry
}

type authEntry struct {
	node string
	exp  time.Time
}

// NewNodeManager returns a node manager.
func NewNodeManager(log logr.Logger, auth NodeAuthenticator, clusterKey []byte, opts *Options, hooks NodeHooks) *NodeManager {
	return &NodeManager{
		log: log, auth: auth, clusterKey: clusterKey, opts: opts, hooks: hooks,
		started: time.Now(),
		nodes:   map[string]*nodeRec{}, ops: map[string]*op{}, allocs: map[string]*AllocRuntime{},
		authOK: map[string]authEntry{},
	}
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *NodeManager) authenticate(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	var token string
	for _, v := range md.Get("authorization") {
		if t, ok := strings.CutPrefix(v, "Bearer "); ok {
			token = strings.TrimSpace(t)
		}
	}
	if token == "" {
		return "", status.Error(codes.Unauthenticated, "missing bearer token")
	}
	m.mu.Lock()
	e, ok := m.authOK[token]
	m.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.node, nil
	}
	node, err := m.auth.Authenticate(ctx, token)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	m.mu.Lock()
	m.authOK[token] = authEntry{node: node, exp: time.Now().Add(time.Minute)}
	m.mu.Unlock()
	return node, nil
}

// Session implements nodepb.ControllerServer.
func (m *NodeManager) Session(stream nodepb.Controller_SessionServer) error {
	authNode, err := m.authenticate(stream.Context())
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.NodeName == "" {
		return status.Error(codes.InvalidArgument, "first message must be Hello with node_name")
	}
	node := hello.NodeName
	if node != authNode {
		return status.Errorf(codes.PermissionDenied, "token belongs to a pod on node %q, not %q", authNode, node)
	}
	log := m.log.WithValues("node", node)
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	sess := &session{node: node, send: make(chan *nodepb.ControllerMessage, 4096), cancel: cancel}

	var finished []string
	if m.hooks.Finished != nil {
		finished = m.hooks.Finished(node)
	}
	hostNQN := api.HostNQN(node)
	w := &nodepb.Welcome{
		HostNqn: hostNQN, HostPsk: PSK(m.clusterKey, hostNQN), FinishedAllocationIds: finished,
		HeartbeatInterval: durationpb.New(m.opts.Heartbeat),
	}
	welcome := &nodepb.ControllerMessage{Msg: &nodepb.ControllerMessage_Welcome{Welcome: w}}
	if err := stream.Send(welcome); err != nil {
		return err
	}

	m.mu.Lock()
	rec := m.node(node)
	old := rec.sess
	rec.sess = sess
	rec.everConnected = true
	if rec.bootID != "" && rec.bootID != hello.BootId {
		log.Info("node rebooted", "oldBootID", rec.bootID, "bootID", hello.BootId)
	}
	rec.bootID = hello.BootId
	rec.caps = hello.Capabilities
	if hello.Capacity != nil {
		rec.capacity = hello.Capacity
	}
	m.applyStateLocked(rec, hello.State, true)
	var pending []*op
	for _, o := range m.ops {
		if o.node == node && o.result == nil {
			pending = append(pending, o)
		}
	}
	m.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	log.Info("node connected", "bootID", hello.BootId)
	metricNodesConnected.Inc()
	defer metricNodesConnected.Dec()

	sort.Slice(pending, func(i, j int) bool { return pending[i].created.Before(pending[j].created) })
	for _, o := range pending {
		sess.send <- &nodepb.ControllerMessage{Msg: &nodepb.ControllerMessage_Command{Command: o.cmd}}
	}
	if m.hooks.Connected != nil {
		go m.hooks.Connected(node, hello.State)
	}
	m.notifyAllocsOn(node)

	// Writer.
	werr := make(chan error, 1)
	go func() {
		t := time.NewTicker(m.opts.Heartbeat)
		defer t.Stop()
		for {
			var msg *nodepb.ControllerMessage
			select {
			case <-ctx.Done():
				werr <- nil
				return
			case msg = <-sess.send:
			case now := <-t.C:
				msg = &nodepb.ControllerMessage{Msg: &nodepb.ControllerMessage_Heartbeat{Heartbeat: &nodepb.Heartbeat{Time: timestamppb.New(now)}}}
			}
			if err := stream.Send(msg); err != nil {
				werr <- err
				cancel()
				return
			}
		}
	}()

	// Reader with an idle limit of 3 heartbeats.
	msgs := make(chan *nodepb.NodeMessage)
	rerr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				rerr <- err
				return
			}
			select {
			case msgs <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
	idle := time.NewTimer(3 * m.opts.Heartbeat)
	defer idle.Stop()
	var exitErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-rerr:
			if err != io.EOF {
				exitErr = err
			}
			break loop
		case <-idle.C:
			exitErr = status.Error(codes.DeadlineExceeded, "no message from node within 3 heartbeats")
			break loop
		case msg := <-msgs:
			idle.Reset(3 * m.opts.Heartbeat)
			m.handle(node, sess, msg)
		}
	}
	cancel()
	m.mu.Lock()
	if rec.sess == sess {
		rec.sess = nil
		rec.disconnectedAt = time.Now()
	}
	m.mu.Unlock()
	log.Info("node disconnected", "err", exitErr)
	m.notifyAllocsOn(node)
	return exitErr
}

func (m *NodeManager) node(name string) *nodeRec {
	r := m.nodes[name]
	if r == nil {
		r = &nodeRec{name: name, contents: map[string]*nodepb.ContentInfo{}, allocations: map[string]*nodepb.AllocationInfo{}, disconnectedAt: m.started}
		m.nodes[name] = r
	}
	return r
}

// applyStateLocked records a full node state and returns the allocations
// whose runtime state changed (new boot, exit, slot lost, assigned). It
// replaces the node's previous state; facts about an allocation (exit,
// slot lost, boots) are only ever added, so the exit is recorded once.
// With hello set, allocations on the node that are missing from the
// state are marked lost.
func (m *NodeManager) applyStateLocked(rec *nodeRec, st *nodepb.NodeState, hello bool) []string {
	if st == nil {
		return nil
	}
	rec.contents = map[string]*nodepb.ContentInfo{}
	for _, c := range st.Contents {
		rec.contents[c.ContentId] = c
	}
	if st.Capacity != nil {
		rec.capacity = st.Capacity
	}
	rec.slots = st.Slots
	var changed []string
	seen := map[string]bool{}
	rec.allocations = map[string]*nodepb.AllocationInfo{}
	for _, a := range st.Allocations {
		// Only an assigned allocation with a record on the node counts:
		// devices left without one (the node lost its state, e.g. a
		// tmpfs, while device-mapper kept the overlays) are reported
		// record-less, and the slot is gone.
		if a.Assigned {
			seen[a.AllocationId] = true
		}
		rec.allocations[a.AllocationId] = a
		rt := m.alloc(a.AllocationId)
		was := *rt
		rt.Node = rec.name
		rt.Assigned = rt.Assigned || a.Assigned
		if a.BootCount > 0 {
			rt.Started = true
		}
		if a.BootCount > rt.BootCount {
			rt.BootCount = a.BootCount
		}
		if a.SlotLost != "" && rt.SlotLost == "" {
			rt.SlotLost = a.SlotLost
		}
		if a.Exit != nil && rt.Exit == nil {
			rt.Exit = a.Exit
		}
		if was != *rt {
			changed = append(changed, a.AllocationId)
		}
	}
	if hello {
		for _, rt := range m.allocs {
			if rt.Node == rec.name && rt.Assigned && !seen[rt.ID] && rt.SlotLost == "" && rt.Exit == nil {
				rt.SlotLost = "allocation missing after node reconnect"
				changed = append(changed, rt.ID)
			}
		}
	}
	return changed
}

// applyState records a state the node sent on its current session and
// wakes the owners of changed allocations. A state from a replaced
// session (an older connection, maybe an older boot) is ignored.
func (m *NodeManager) applyState(node string, sess *session, st *nodepb.NodeState) {
	m.mu.Lock()
	rec := m.node(node)
	if rec.sess != sess {
		m.mu.Unlock()
		return
	}
	changed := m.applyStateLocked(rec, st, false)
	m.mu.Unlock()
	if m.hooks.AllocChanged != nil {
		for _, id := range changed {
			m.hooks.AllocChanged(id)
		}
	}
}

func (m *NodeManager) alloc(id string) *AllocRuntime {
	rt := m.allocs[id]
	if rt == nil {
		rt = &AllocRuntime{ID: id}
		m.allocs[id] = rt
	}
	return rt
}

func (m *NodeManager) notifyAllocsOn(node string) {
	if m.hooks.AllocChanged == nil {
		return
	}
	m.mu.Lock()
	var ids []string
	for id, rt := range m.allocs {
		if rt.Node == node {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.hooks.AllocChanged(id)
	}
}

func (m *NodeManager) handle(node string, sess *session, msg *nodepb.NodeMessage) {
	switch x := msg.Msg.(type) {
	case *nodepb.NodeMessage_Result:
		m.handleResult(node, x.Result)
	case *nodepb.NodeMessage_State:
		m.applyState(node, sess, x.State)
	case *nodepb.NodeMessage_Heartbeat:
	case *nodepb.NodeMessage_Hello:
		m.log.Info("ignoring repeated Hello", "node", node)
	}
}

func (m *NodeManager) handleResult(node string, r *nodepb.CommandResult) {
	if r.Status == nodepb.ResultStatus_RESULT_STATUS_IN_PROGRESS {
		return
	}
	m.mu.Lock()
	o := m.ops[r.OperationId]
	if o == nil || o.node != node || o.result != nil {
		m.mu.Unlock()
		return
	}
	o.result = r
	close(o.done)
	var changed []string
	if st := r.GetState(); st != nil {
		changed = m.applyStateLocked(m.node(node), st, false)
	}
	m.trackResultLocked(o)
	owner := o.owner
	m.mu.Unlock()
	if m.hooks.AllocChanged != nil {
		for _, id := range changed {
			m.hooks.AllocChanged(id)
		}
	}
	if owner.Kind != "" && m.hooks.OpDone != nil {
		m.hooks.OpDone(owner)
	}
}

// trackResultLocked keeps the content view current after successful commands.
func (m *NodeManager) trackResultLocked(o *op) {
	if o.result.Status != nodepb.ResultStatus_RESULT_STATUS_OK {
		return
	}
	rec := m.node(o.node)
	switch c := o.cmd.Op.(type) {
	case *nodepb.Command_Seal:
		ci := rec.contents[c.Seal.ContentId]
		if ci == nil {
			ci = &nodepb.ContentInfo{ContentId: c.Seal.ContentId, Created: timestamppb.Now()}
			rec.contents[c.Seal.ContentId] = ci
		}
		ci.Sealed = true
	case *nodepb.Command_DeleteContent:
		for _, id := range c.DeleteContent.ContentIds {
			delete(rec.contents, id)
		}
	case *nodepb.Command_AssignSlot:
		rt := m.alloc(c.AssignSlot.AllocationId)
		rt.Node, rt.Assigned = o.node, true
	}
}

// Do starts an operation, or returns its result once known. It returns
// (nil, nil) while the operation is pending. The command is sent when the
// node is connected, and sent again after each reconnect until it has a result.
// An operation past its deadline (plus a grace period) without a result gets a
// local DEADLINE_EXCEEDED result.
func (m *NodeManager) Do(node, opID string, owner Owner, timeout time.Duration, cmd *nodepb.Command) *nodepb.CommandResult {
	m.mu.Lock()
	o := m.ops[opID]
	if o != nil {
		if o.result == nil && time.Now().After(o.deadline.Add(30*time.Second)) {
			o.result = &nodepb.CommandResult{OperationId: opID, Status: nodepb.ResultStatus_RESULT_STATUS_DEADLINE_EXCEEDED, Error: "no result before the deadline"}
			close(o.done)
		}
		r := o.result
		m.mu.Unlock()
		return r
	}
	now := time.Now()
	cmd.OperationId = opID
	cmd.Deadline = timestamppb.New(now.Add(timeout))
	o = &op{id: opID, node: node, cmd: cmd, owner: owner, created: now, deadline: now.Add(timeout), done: make(chan struct{})}
	m.ops[opID] = o
	sess := m.node(node).sess
	m.mu.Unlock()
	if sess != nil {
		m.sendTo(sess, cmd)
	}
	return nil
}

func (m *NodeManager) sendTo(sess *session, cmd *nodepb.Command) {
	select {
	case sess.send <- &nodepb.ControllerMessage{Msg: &nodepb.ControllerMessage_Command{Command: cmd}}:
	default:
		m.log.Info("send queue full, dropping session", "node", sess.node)
		sess.cancel()
	}
}

// Call runs an operation and waits for its result.
func (m *NodeManager) Call(ctx context.Context, node, opID string, timeout time.Duration, cmd *nodepb.Command) (*nodepb.CommandResult, error) {
	if !m.Connected(node) {
		return nil, fmt.Errorf("%s: %w", node, ErrNodeNotConnected)
	}
	if r := m.Do(node, opID, Owner{}, timeout, cmd); r != nil {
		return r, nil
	}
	m.mu.Lock()
	o := m.ops[opID]
	m.mu.Unlock()
	t := time.NewTimer(timeout + 30*time.Second)
	defer t.Stop()
	select {
	case <-o.done:
		return o.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return m.Do(node, opID, Owner{}, timeout, cmd), nil
	}
}

// Send sends a command without tracking a result (fire and forget).
func (m *NodeManager) Send(node string, cmd *nodepb.Command) {
	m.mu.Lock()
	sess := m.node(node).sess
	m.mu.Unlock()
	if sess != nil {
		if cmd.OperationId == "" {
			cmd.OperationId = "x-" + randID()
		}
		m.sendTo(sess, cmd)
	}
}

// Forget drops operations whose ID starts with prefix.
func (m *NodeManager) Forget(prefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.ops {
		if strings.HasPrefix(id, prefix) {
			delete(m.ops, id)
		}
	}
}

// ForgetAlloc drops the runtime state of an allocation.
func (m *NodeManager) ForgetAlloc(id string) {
	m.mu.Lock()
	delete(m.allocs, id)
	m.mu.Unlock()
}

// GC drops finished operations older than age.
func (m *NodeManager) GC(age time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, o := range m.ops {
		if o.result != nil && time.Since(o.created) > age {
			delete(m.ops, id)
		}
	}
}

// Pending reports whether any operation with the prefix has no result yet.
func (m *NodeManager) Pending(prefix string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, o := range m.ops {
		if o.result == nil && strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// Alloc returns a copy of the runtime state of an allocation.
func (m *NodeManager) Alloc(id string) AllocRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rt := m.allocs[id]; rt != nil {
		return *rt
	}
	return AllocRuntime{}
}

// MarkServing restarts the node-lost clock; call it when the server starts
// accepting nodes (after winning leader election).
func (m *NodeManager) MarkServing() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = time.Now()
	for _, r := range m.nodes {
		if r.sess == nil {
			r.disconnectedAt = m.started
		}
	}
}

// ReportsAlloc reports whether the node's last reported state (Hello,
// ListState or State event) lists the allocation.
func (m *NodeManager) ReportsAlloc(node, id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	return r != nil && r.allocations[id] != nil
}

// Connected reports whether the node has a session.
func (m *NodeManager) Connected(node string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	return r != nil && r.sess != nil
}

// AllocMissing reports whether the node is connected and its latest state
// has no assigned allocation id. A controller that started after the
// allocation was assigned has no runtime record of it, so the hello check
// for missing allocations cannot see it; callers use this instead once the
// allocation is known to have been assigned (the guest started).
func (m *NodeManager) AllocMissing(node, id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	if r == nil || r.sess == nil {
		return false
	}
	a := r.allocations[id]
	return a == nil || !a.Assigned
}

// Lost reports whether the node has been disconnected for the node-lost timeout.
// A node never seen since controller start counts from controller start.
func (m *NodeManager) Lost(node string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	if r == nil {
		return time.Since(m.started) > m.opts.NodeLostTimeout
	}
	return r.sess == nil && time.Since(r.disconnectedAt) > m.opts.NodeLostTimeout
}

// NodeInfo is a snapshot of a node.
type NodeInfo struct {
	Name      string
	Connected bool
	Caps      *nodepb.Capabilities
	Capacity  *nodepb.Capacity
	Contents  map[string]*nodepb.ContentInfo
	Slots     []*nodepb.SlotInfo
}

// DisksPerSlot is the number of hot-pluggable disks per slot of a compute
// node (from its capacity, else the default).
func (i NodeInfo) DisksPerSlot() int {
	if c := i.Capacity.GetCompute(); c != nil && c.DisksPerSlot > 0 {
		return int(c.DisksPerSlot)
	}
	return api.DefaultDisksPerSlot
}

// HasAttachment reports whether the last known state of the node has the
// attachment, or false if the node state is unknown.
func (m *NodeManager) HasAttachment(node, attachmentID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	if r == nil {
		return false
	}
	for _, a := range r.allocations {
		for _, at := range a.Attachments {
			if at.AttachmentId == attachmentID {
				return true
			}
		}
	}
	return false
}

// Info returns a snapshot of a node (contents are shared, read only).
func (m *NodeManager) Info(node string) NodeInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.nodes[node]
	if r == nil {
		return NodeInfo{Name: node}
	}
	c := make(map[string]*nodepb.ContentInfo, len(r.contents))
	for k, v := range r.contents {
		c[k] = proto.Clone(v).(*nodepb.ContentInfo)
	}
	return NodeInfo{Name: node, Connected: r.sess != nil, Caps: r.caps, Capacity: r.capacity, Contents: c, Slots: r.slots}
}

// Nodes returns the names of all known nodes.
func (m *NodeManager) Nodes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n []string
	for k := range m.nodes {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func resultErr(r *nodepb.CommandResult) string {
	if r == nil {
		return "no result"
	}
	if r.Error != "" {
		return fmt.Sprintf("%s: %s", r.Status, r.Error)
	}
	return r.Status.String()
}
