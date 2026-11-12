// Package fakenode runs the real node daemon (internal/node) in-process
// for controller tests. It replaces only what needs a host:
//
//   - storage: nodetest.FakeStorage (contents in memory, snapshot writes
//     between fake nodes as small files);
//   - slot pods: the node's PodLister reads the slot pods of the
//     Kubernetes node from the API server, and a fake blipd slot
//     prepares a ready slot directory for each, as the real one does
//     when the warm VM is up;
//   - Cloud Hypervisor: hot-plug does nothing, the power button powers
//     the guest off, and the kill file ends the VM like blipd slot does.
//
// The node dials the controller and runs the real session, command and
// event code. Tests drive the guest with Workload and the event helpers
// (Started, Poweroff, ...), which write the metadata disk and exit.json
// like the boot stub and blipd slot. Faults are injected with SetHook (a
// command interceptor on the session stream), Pause and Reboot, and the
// FakeStorage and hypervisor switches.
package fakenode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/node"
	"github.com/example/blip/internal/node/nodetest"
	"github.com/example/blip/internal/proto/nodepb"
)

// Config describes the node.
type Config struct {
	Addr       string // controller address, host:port
	ServerName string // TLS server name, default "localhost"
	CA         []byte // PEM CA of the controller
	Token      string // bearer token
	Name       string
	Storage    bool
	Compute    bool
	Slots      int32
	BootID     string // default "boot-1"
	// DisksPerSlot defaults to api.DefaultDisksPerSlot.
	DisksPerSlot int32
	// Kube reads the slot pods of the node (spec.nodeName = Name),
	// best through a cache. Required for compute nodes.
	Kube client.Reader
}

// Workload runs after StartWorkload succeeded. It plays the guest with
// the event helpers of the node.
type Workload func(n *Node, s *nodepb.StartWorkload)

// Hook intercepts commands before the node sees them. Returning nil
// passes the command on. Returning a result sends it instead; a result
// with status UNSPECIFIED drops the command (no result, like a lost
// response).
type Hook func(cmd *nodepb.Command) *nodepb.CommandResult

// Node is a node daemon under test.
type Node struct {
	cfg  Config
	dir  string
	st   *nodetest.FakeStorage
	conn *grpc.ClientConn
	ctx  context.Context

	mu       sync.Mutex
	daemon   *node.Node
	stop     context.CancelFunc
	wg       sync.WaitGroup
	hook     Hook
	workload Workload
	commands []*nodepb.Command
	welcome  *nodepb.Welcome
	paused   bool
	resumed  chan struct{}
	stream   *stream
	starts   map[string]*nodepb.StartWorkload // operation ID -> pending StartWorkload
	ran      map[string]bool                  // allocations whose workload ran
	exits    map[string]*nodepb.Exited
	buttons  map[string]int   // allocation -> power button presses
	boots    map[string]int32 // allocation -> last boot reported by Started
	hang     bool             // the guest ignores the power button
	slots    map[string]node.PodRef
	hidden   map[types.UID]bool // slot pods hidden from the node (SlotLost)
}

// New creates a node; Start connects it.
func New(cfg Config) *Node {
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}
	if cfg.BootID == "" {
		cfg.BootID = "boot-1"
	}
	if cfg.DisksPerSlot == 0 {
		cfg.DisksPerSlot = api.DefaultDisksPerSlot
	}
	dir, err := os.MkdirTemp("", "fakenode-"+cfg.Name+"-")
	if err != nil {
		panic(err)
	}
	st := nodetest.NewFakeStorage(cfg.Name, filepath.Join(dir, "storage"))
	st.DisksPerSlot = int(cfg.DisksPerSlot)
	st.SetCapacity(&nodepb.StorageCapacity{PoolSizeBytes: 100 << 30})
	if err := os.MkdirAll(st.Dir, 0o755); err != nil {
		panic(err)
	}
	return &Node{
		cfg: cfg, dir: dir, st: st, workload: Succeed(0), resumed: make(chan struct{}),
		starts: map[string]*nodepb.StartWorkload{}, ran: map[string]bool{}, exits: map[string]*nodepb.Exited{},
		buttons: map[string]int{}, boots: map[string]int32{}, slots: map[string]node.PodRef{}, hidden: map[types.UID]bool{},
	}
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}
func (bearer) RequireTransportSecurity() bool { return true }

// Start runs the node daemon until ctx ends or Stop is called.
func (n *Node) Start(ctx context.Context) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(n.cfg.CA) {
		return errors.New("fakenode: bad CA")
	}
	conn, err := grpc.NewClient(n.cfg.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: n.cfg.ServerName})),
		grpc.WithPerRPCCredentials(bearer(n.cfg.Token)))
	if err != nil {
		return err
	}
	n.conn, n.ctx = conn, ctx
	return n.boot()
}

func (n *Node) boot() error {
	nc := &api.NodeConfig{Hypervisor: "kvm", Address: "127.0.0.1"}
	if n.cfg.Compute {
		nc.Slots = int(n.cfg.Slots)
		nc.Compute = &api.NodeComputeConfig{Device: "/dev/null"}
	}
	if n.cfg.Storage {
		nc.Storage = &api.NodeStorageConfig{VG: "blip-" + n.cfg.Name, MaxLVs: 5000}
	}
	nc.Default()
	d, err := node.New(node.Config{
		NodeName: n.cfg.Name, BootID: n.cfg.BootID, NodeConfig: nc,
		SlotsDir: filepath.Join(n.dir, "slots"), StateDir: filepath.Join(n.dir, "state"),
		Storage: n.st, StoragePort: 4420, Pods: (*pods)(n), Hypervisor: (*hypervisor)(n),
		DisksPerSlot: int(n.cfg.DisksPerSlot),
		Poll:         200 * time.Millisecond, CapacityPoll: 100 * time.Millisecond, MaxReconnectBackoff: 100 * time.Millisecond,
		SlotLostAfter: time.Second, ReleaseWait: 5 * time.Second,
		SlotUnreachableAfter: 24 * time.Hour, UnknownThinGrace: -1,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(n.ctx)
	n.mu.Lock()
	n.daemon, n.stop = d, cancel
	n.mu.Unlock()
	cl := &controllerClient{n: n, inner: nodepb.NewControllerClient(n.conn)}
	n.wg.Add(3)
	go func() { defer n.wg.Done(); d.Run(ctx) }()
	go func() { defer n.wg.Done(); d.RunSession(ctx, cl) }()
	go func() { defer n.wg.Done(); n.runSlots(ctx) }()
	return nil
}

// halt stops the node daemon and waits for it.
func (n *Node) halt() {
	n.mu.Lock()
	stop := n.stop
	n.mu.Unlock()
	if stop != nil {
		stop()
	}
	n.wg.Wait()
}

// Stop stops the node for good and removes its files.
func (n *Node) Stop() {
	n.halt()
	if n.conn != nil {
		n.conn.Close()
	}
	os.RemoveAll(n.dir)
}

// Pause breaks the session and keeps the node away until Resume. The
// node daemon keeps running.
func (n *Node) Pause() {
	n.mu.Lock()
	if !n.paused {
		n.paused, n.resumed = true, make(chan struct{})
	}
	s := n.stream
	n.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// Resume lets the node reconnect after Pause.
func (n *Node) Resume() {
	n.mu.Lock()
	if n.paused {
		n.paused = false
		close(n.resumed)
	}
	n.mu.Unlock()
}

// Reboot restarts the node daemon with a new boot ID, as after a host
// reboot: the slot and state directories (tmpfs) and the compute state of
// the storage are gone; storage contents stay.
func (n *Node) Reboot(bootID string) {
	n.halt()
	n.mu.Lock()
	n.cfg.BootID = bootID
	n.slots, n.hidden = map[string]node.PodRef{}, map[types.UID]bool{}
	n.mu.Unlock()
	os.RemoveAll(filepath.Join(n.dir, "slots"))
	os.RemoveAll(filepath.Join(n.dir, "state"))
	n.st.Reboot()
	if err := n.boot(); err != nil {
		panic(err)
	}
}

// Compute reports whether the node has slots.
func (n *Node) Compute() bool { return n.cfg.Compute }

// Name returns the node name.
func (n *Node) Name() string { return n.cfg.Name }

// Storage returns the fake storage of the node.
func (n *Node) Storage() *nodetest.FakeStorage { return n.st }

// Content returns a copy of a content on the node, or nil.
func (n *Node) Content(id string) *nodepb.ContentInfo { return n.st.Content(id) }

// Origin returns the base (snapshot) or parent (clone) of a content.
func (n *Node) Origin(id string) string { return n.st.Origin(id) }

// SetStorageCapacity sets the storage capacity the node reports.
func (n *Node) SetStorageCapacity(c *nodepb.StorageCapacity) { n.st.SetCapacity(c) }

// FailTransfersTo makes snapshot writes to the node named target fail.
func (n *Node) FailTransfersTo(target string, fail bool) { n.st.FailWritesTo(target, fail) }

// FailNextCapture makes the next local capture fail with code.
func (n *Node) FailNextCapture(code nodepb.ErrorCode) {
	n.st.FailNextCall("CaptureLocal", node.Codef(code, "injected capture failure"))
}

// SetGracefulHang makes the guest ignore the power button: a graceful
// Kill then ends with a hard kill (HypervisorExited).
func (n *Node) SetGracefulHang(on bool) {
	n.mu.Lock()
	n.hang = on
	n.mu.Unlock()
}

// SetHook sets the command interceptor; nil removes it.
func (n *Node) SetHook(h Hook) {
	n.mu.Lock()
	n.hook = h
	n.mu.Unlock()
}

// SetWorkload sets what the guest does after StartWorkload.
func (n *Node) SetWorkload(w Workload) {
	n.mu.Lock()
	n.workload = w
	n.mu.Unlock()
}

// Commands returns the commands received, in order.
func (n *Node) Commands() []*nodepb.Command {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*nodepb.Command(nil), n.commands...)
}

// CountOps counts received commands for which match returns true.
func (n *Node) CountOps(match func(*nodepb.Command) bool) int {
	k := 0
	for _, c := range n.Commands() {
		if match(c) {
			k++
		}
	}
	return k
}

// Welcome returns the last Welcome.
func (n *Node) Welcome() *nodepb.Welcome {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.welcome
}

// State returns the node state as ListState reports it.
func (n *Node) State() *nodepb.NodeState {
	n.mu.Lock()
	d := n.daemon
	n.mu.Unlock()
	s, err := d.State(context.Background())
	if err != nil {
		panic(err)
	}
	return s
}

// Alloc returns the state of an allocation, or nil if the node has none.
func (n *Node) Alloc(id string) *nodepb.AllocationInfo {
	for _, a := range n.State().Allocations {
		if a.AllocationId == id {
			return a
		}
	}
	return nil
}

// Attachments returns the attachments of an allocation by slot disk.
func (n *Node) Attachments(allocID string) []*nodepb.AttachmentInfo {
	a := n.Alloc(allocID)
	if a == nil {
		return nil
	}
	out := a.Attachments
	sort.Slice(out, func(i, j int) bool { return out[i].SlotDisk < out[j].SlotDisk })
	return out
}

// Exit returns the exit the node reported for an allocation, or nil.
func (n *Node) Exit(allocID string) *nodepb.Exited {
	n.mu.Lock()
	defer n.mu.Unlock()
	if e := n.exits[allocID]; e != nil {
		return proto.Clone(e).(*nodepb.Exited)
	}
	return nil
}

// PowerButtons returns how often the power button of an allocation's VM
// was pressed.
func (n *Node) PowerButtons(allocID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.buttons[allocID]
}

// ---------------------------------------------------------------------------
// Session interception

// controllerClient opens sessions through stream, and waits while the
// node is paused.
type controllerClient struct {
	n     *Node
	inner nodepb.ControllerClient
}

func (c *controllerClient) Session(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[nodepb.NodeMessage, nodepb.ControllerMessage], error) {
	for {
		c.n.mu.Lock()
		paused, resumed := c.n.paused, c.n.resumed
		c.n.mu.Unlock()
		if !paused {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-resumed:
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	inner, err := c.inner.Session(ctx, opts...)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &stream{BidiStreamingClient: inner, n: c.n, cancel: cancel, done: make(chan struct{})}
	c.n.mu.Lock()
	c.n.stream = s
	c.n.mu.Unlock()
	return s, nil
}

// stream records what passes, applies the hook to commands and starts
// workloads when StartWorkload succeeds.
type stream struct {
	grpc.BidiStreamingClient[nodepb.NodeMessage, nodepb.ControllerMessage]
	n      *Node
	cancel context.CancelFunc
	sendMu sync.Mutex
	once   sync.Once
	done   chan struct{} // closed when Recv failed
}

// close breaks the stream and waits until the node noticed.
func (s *stream) close() {
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}

func (s *stream) Send(m *nodepb.NodeMessage) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.n.sent(m)
	return s.BidiStreamingClient.Send(m)
}

func (s *stream) Recv() (*nodepb.ControllerMessage, error) {
	for {
		m, err := s.BidiStreamingClient.Recv()
		if err != nil {
			s.once.Do(func() { close(s.done) })
			return nil, err
		}
		if w := m.GetWelcome(); w != nil {
			s.n.mu.Lock()
			s.n.welcome = w
			s.n.mu.Unlock()
		}
		c := m.GetCommand()
		if c == nil {
			return m, nil
		}
		r := s.n.received(c)
		if r == nil {
			return m, nil
		}
		if r.Status != nodepb.ResultStatus_RESULT_STATUS_UNSPECIFIED {
			r.OperationId = c.OperationId
			_ = s.Send(&nodepb.NodeMessage{Msg: &nodepb.NodeMessage_Result{Result: r}})
		}
	}
}

// received records a command and runs the hook.
func (n *Node) received(c *nodepb.Command) *nodepb.CommandResult {
	n.mu.Lock()
	n.commands = append(n.commands, c)
	if s := c.GetStartWorkload(); s != nil {
		n.starts[c.OperationId] = s
	}
	h := n.hook
	n.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(c)
}

// sent records reported exits and starts the workload once StartWorkload is OK.
func (n *Node) sent(m *nodepb.NodeMessage) {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := m.GetState()
	if h := m.GetHello(); h != nil {
		st = h.State
	}
	for _, a := range st.GetAllocations() {
		if e := a.GetExit(); e != nil && n.exits[a.AllocationId] == nil {
			n.exits[a.AllocationId] = proto.Clone(e).(*nodepb.Exited)
		}
	}
	r := m.GetResult()
	s := n.starts[r.GetOperationId()]
	if s == nil || r.Status == nodepb.ResultStatus_RESULT_STATUS_IN_PROGRESS {
		return
	}
	delete(n.starts, r.OperationId)
	if r.Status != nodepb.ResultStatus_RESULT_STATUS_OK || n.ran[s.AllocationId] {
		return
	}
	n.ran[s.AllocationId] = true
	if w := n.workload; w != nil {
		go w(n, s)
	}
}

// Code returns a pointer to c, for Exited.exit_code.
func Code(c int32) *int32 { return &c }

// podList lists the slot pods scheduled to the node.
func (n *Node) podList(ctx context.Context) ([]corev1.Pod, error) {
	var l corev1.PodList
	if err := n.cfg.Kube.List(ctx, &l, client.HasLabels{api.LabelSlot}); err != nil {
		return nil, err
	}
	var out []corev1.Pod
	for _, p := range l.Items {
		if p.Spec.NodeName == n.cfg.Name {
			out = append(out, p)
		}
	}
	return out, nil
}
