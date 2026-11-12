package node

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
)

// outbox holds what goes to the controller: command results and
// heartbeats in a queue, and a dirty flag for the node state. Nothing is
// dropped: results stay queued across reconnects, and the state is not
// queued at all. The sender builds one fresh NodeState when it sees the
// flag, so any number of changes collapse into one complete state. The
// state goes before any queued message, so a change made before a
// result was queued reaches the controller no later than the result.
type outbox struct {
	mu    sync.Mutex
	q     []outMsg
	dirty bool
	wake  chan struct{}
}

type outMsg struct {
	m *pb.NodeMessage
	// state: m is nil; send a fresh NodeState.
	state bool
}

func newOutbox() *outbox { return &outbox{wake: make(chan struct{}, 1)} }

func (o *outbox) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// push queues m.
func (o *outbox) push(m *pb.NodeMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.q = append(o.q, outMsg{m: m})
	o.signal()
}

// markDirty records that the node state changed.
func (o *outbox) markDirty() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dirty = true
	o.signal()
}

// clearDirty forgets a pending state, because the caller is about to
// build and send one (Hello).
func (o *outbox) clearDirty() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dirty = false
}

// pop waits for the next message. A pending state comes first; it
// clears the flag, so changes after this point produce another state.
func (o *outbox) pop(ctx context.Context) (outMsg, error) {
	for {
		o.mu.Lock()
		if o.dirty {
			o.dirty = false
			o.mu.Unlock()
			return outMsg{state: true}, nil
		}
		if len(o.q) > 0 {
			m := o.q[0]
			o.q = o.q[1:]
			o.mu.Unlock()
			return m, nil
		}
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return outMsg{}, ctx.Err()
		case <-o.wake:
		}
	}
}

// unpop puts a message back after a failed send.
func (o *outbox) unpop(m outMsg) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if m.state {
		o.dirty = true
		return
	}
	o.q = append([]outMsg{m}, o.q...)
}

func (o *outbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(o.q)
	if o.dirty {
		n++
	}
	return n
}

// opCache remembers command results by operation ID, so a resent command
// returns the first result or IN_PROGRESS.
type opCache struct {
	mu sync.Mutex
	m  map[string]*opEntry
}

type opEntry struct {
	res *pb.CommandResult // nil while running
	at  time.Time
}

const opKeep = time.Hour

func newOpCache() *opCache { return &opCache{m: map[string]*opEntry{}} }

// begin returns the cached result of id, or nil and true if the caller
// should run it now.
func (c *opCache) begin(id string) (*pb.CommandResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if e.res != nil && time.Since(e.at) > opKeep {
			delete(c.m, k)
		}
	}
	if e, ok := c.m[id]; ok {
		if e.res == nil {
			return &pb.CommandResult{OperationId: id, Status: pb.ResultStatus_RESULT_STATUS_IN_PROGRESS}, false
		}
		return e.res, false
	}
	c.m[id] = &opEntry{at: time.Now()}
	return nil, true
}

func (c *opCache) finish(id string, r *pb.CommandResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = &opEntry{res: r, at: time.Now()}
}

// Dispatch runs a command in the background and queues its result.
func (n *Node) Dispatch(c *pb.Command) {
	if c.OperationId == "" {
		log.Printf("command without operation_id dropped: %T", c.Op)
		return
	}
	// ListState is not cached: it must return fresh state.
	_, listState := c.Op.(*pb.Command_ListState)
	cached := !listState
	if cached {
		if r, run := n.ops.begin(c.OperationId); !run {
			n.out.push(&pb.NodeMessage{Msg: &pb.NodeMessage_Result{Result: r}})
			return
		}
	}
	go func() {
		r := n.run(c)
		if cached {
			n.ops.finish(c.OperationId, r)
			// The command may have changed the state; it goes out
			// before the result. Scrub only reads.
			if _, scrub := c.Op.(*pb.Command_Scrub); !scrub {
				n.out.markDirty()
			}
		}
		n.out.push(&pb.NodeMessage{Msg: &pb.NodeMessage_Result{Result: r}})
		if listState {
			// A state may have changed since the result was built;
			// a fresh state follows it, so the older one never wins.
			n.out.markDirty()
		}
	}()
}

// run executes one command and builds its result.
func (n *Node) run(c *pb.Command) *pb.CommandResult {
	ctx := n.bgContext()
	var cancel context.CancelFunc
	if c.Deadline != nil {
		ctx, cancel = context.WithDeadline(ctx, c.Deadline.AsTime())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	start := time.Now()
	r := &pb.CommandResult{OperationId: c.OperationId}
	err := n.exec(ctx, c, r)
	n.metrics.command(fmt.Sprintf("%T", c.Op), err, time.Since(start))
	var rej *errReject
	switch {
	case err == nil:
		r.Status = pb.ResultStatus_RESULT_STATUS_OK
	case errors.As(err, &rej), errors.Is(err, storage.ErrStaleGeneration):
		r.Status, r.Error = pb.ResultStatus_RESULT_STATUS_REJECTED, err.Error()
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		r.Status, r.Error = pb.ResultStatus_RESULT_STATUS_DEADLINE_EXCEEDED, err.Error()
	default:
		r.Status, r.Error = pb.ResultStatus_RESULT_STATUS_FAILED, err.Error()
	}
	if err != nil {
		r.Code = ErrorCodeOf(err)
		log.Printf("operation %s (%T): %s: %v", c.OperationId, c.Op, r.Status, err)
	}
	return r
}

// checkAllocation rejects commands for allocations that are finished.
func (n *Node) checkAllocation(id string) error {
	if id != "" && n.isFinished(id) {
		return rejectf("allocation %s is finished", id)
	}
	return nil
}

func (n *Node) exec(ctx context.Context, c *pb.Command, r *pb.CommandResult) error {
	if c.Deadline != nil && time.Now().After(c.Deadline.AsTime()) {
		return context.DeadlineExceeded
	}
	n.mu.Lock()
	keyed := n.hostNQN != ""
	n.mu.Unlock()
	switch op := c.Op.(type) {
	case *pb.Command_Export:
		if err := n.checkAllocation(op.Export.AllocationId); err != nil {
			return err
		}
		res, err := n.st.Export(ctx, op.Export)
		if res != nil {
			r.Result = &pb.CommandResult_Export{Export: res}
		}
		return err
	case *pb.Command_Unexport:
		return n.st.Unexport(ctx, op.Unexport)
	case *pb.Command_Seal:
		return n.st.Seal(ctx, op.Seal)
	case *pb.Command_DeleteContent:
		return n.st.DeleteContent(ctx, op.DeleteContent)
	case *pb.Command_CreateContent:
		return n.st.CreateContent(ctx, op.CreateContent)
	case *pb.Command_Import:
		if !keyed {
			return errors.New("no host key yet")
		}
		res, err := n.st.Import(ctx, op.Import)
		if res != nil {
			r.Result = &pb.CommandResult_Import{Import: res}
		}
		return err
	case *pb.Command_Clone:
		res, err := n.st.Clone(ctx, op.Clone)
		if res != nil {
			r.Result = &pb.CommandResult_Copy{Copy: res}
		}
		return err
	case *pb.Command_Repair:
		if !keyed {
			return errors.New("no host key yet")
		}
		res, err := n.st.Repair(ctx, op.Repair)
		if res != nil {
			r.Result = &pb.CommandResult_Copy{Copy: res}
		}
		return err
	case *pb.Command_Scrub:
		res, err := n.st.Scrub(ctx, op.Scrub)
		if res != nil {
			r.Result = &pb.CommandResult_Scrub{Scrub: res}
		}
		return err
	case *pb.Command_PrepareReceive:
		res, err := n.PrepareReceive(ctx, op.PrepareReceive)
		if res != nil {
			r.Result = &pb.CommandResult_PrepareReceive{PrepareReceive: res}
		}
		return err
	case *pb.Command_AssignSlot:
		if n.cfg.NodeConfig.Slots == 0 {
			return rejectf("not a compute node")
		}
		return n.AssignSlot(ctx, op.AssignSlot)
	case *pb.Command_AttachVolume:
		if n.cfg.NodeConfig.Slots == 0 {
			return rejectf("not a compute node")
		}
		if !keyed {
			return errors.New("no host key yet")
		}
		res, err := n.AttachVolume(ctx, op.AttachVolume)
		if res != nil {
			r.Result = &pb.CommandResult_AttachVolume{AttachVolume: res}
		}
		return err
	case *pb.Command_DetachVolume:
		return n.DetachVolume(ctx, op.DetachVolume)
	case *pb.Command_CaptureLocal:
		res, err := n.CaptureLocal(ctx, op.CaptureLocal)
		if res != nil {
			r.Result = &pb.CommandResult_CaptureLocal{CaptureLocal: res}
		}
		return err
	case *pb.Command_DropLocalSnapshot:
		return n.DropLocalSnapshot(ctx, op.DropLocalSnapshot)
	case *pb.Command_WriteSnapshot:
		if !keyed {
			return errors.New("no host key yet")
		}
		res, err := n.WriteSnapshot(ctx, op.WriteSnapshot)
		if res != nil {
			r.Result = &pb.CommandResult_WriteSnapshot{WriteSnapshot: res}
		}
		return err
	case *pb.Command_ReleaseAttachment:
		return n.ReleaseAttachment(ctx, op.ReleaseAttachment)
	case *pb.Command_StartWorkload:
		return n.StartWorkload(ctx, op.StartWorkload)
	case *pb.Command_UpdateCredentials:
		return n.UpdateCredentials(ctx, op.UpdateCredentials)
	case *pb.Command_Kill:
		return n.Kill(ctx, op.Kill)
	case *pb.Command_Release:
		return n.Release(ctx, op.Release.AllocationId)
	case *pb.Command_ListState:
		s, err := n.State(ctx)
		if s != nil {
			r.Result = &pb.CommandResult_State{State: s}
		}
		return err
	}
	return rejectf("unknown command %T", c.Op)
}
