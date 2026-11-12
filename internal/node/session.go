package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/example/blip/internal/proto/nodepb"
)

// RunSession keeps a session with the controller open until ctx ends,
// reconnecting with backoff.
func (n *Node) RunSession(ctx context.Context, client pb.ControllerClient) {
	first := min(time.Second, n.cfg.MaxReconnectBackoff)
	backoff := first
	for ctx.Err() == nil {
		start := time.Now()
		err := n.session(ctx, client)
		n.metrics.setConnected(false)
		if ctx.Err() != nil {
			return
		}
		log.Printf("controller session ended: %v", err)
		if time.Since(start) > time.Minute {
			backoff = first
		}
		d := backoff/2 + rand.N(backoff/2+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		backoff = min(backoff*2, n.cfg.MaxReconnectBackoff)
	}
}

func (n *Node) hello(ctx context.Context) (*pb.Hello, error) {
	// Hello carries the full state; only later changes need another.
	n.out.clearDirty()
	s, err := n.State(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.Hello{
		NodeName: n.cfg.NodeName, BootId: n.cfg.BootID,
		Capabilities: n.capabilities(), Capacity: s.Capacity, State: s,
	}, nil
}

// session runs one session and returns when it breaks.
func (n *Node) session(ctx context.Context, client pb.ControllerClient) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Session(sctx)
	if err != nil {
		return err
	}
	h, err := n.hello(sctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.NodeMessage{Msg: &pb.NodeMessage_Hello{Hello: h}}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	m, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("wait for welcome: %w", err)
	}
	w := m.GetWelcome()
	if w == nil {
		return errors.New("first controller message is not Welcome")
	}
	if w.HostNqn == "" || len(w.HostPsk) != 32 {
		return errors.New("welcome without host NQN or 32-byte PSK")
	}
	if err := n.st.SetHostKey(sctx, w.HostNqn, w.HostPsk); err != nil {
		return fmt.Errorf("install host key: %w", err)
	}
	n.mu.Lock()
	n.hostNQN = w.HostNqn
	n.mu.Unlock()
	n.finishAll(sctx, w.FinishedAllocationIds)
	interval := 10 * time.Second
	if d := w.HeartbeatInterval.AsDuration(); w.HeartbeatInterval != nil && d > 0 {
		interval = d
	}
	log.Printf("controller session up")
	n.metrics.setConnected(true)

	errc := make(chan error, 2)
	// Sender.
	go func() {
		for {
			om, err := n.out.pop(sctx)
			if err != nil {
				errc <- err
				return
			}
			if om.state {
				s, err := n.State(sctx)
				if err != nil {
					n.out.unpop(om)
					errc <- fmt.Errorf("build state: %w", err)
					return
				}
				om.m = &pb.NodeMessage{Msg: &pb.NodeMessage_State{State: s}}
			}
			if err := stream.Send(om.m); err != nil {
				n.out.unpop(om)
				errc <- fmt.Errorf("send: %w", err)
				return
			}
		}
	}()
	// Receiver.
	seen := make(chan struct{}, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = errors.New("controller closed the session")
				}
				errc <- err
				return
			}
			select {
			case seen <- struct{}{}:
			default:
			}
			switch x := m.Msg.(type) {
			case *pb.ControllerMessage_Command:
				n.Dispatch(x.Command)
			case *pb.ControllerMessage_Heartbeat:
			case *pb.ControllerMessage_Welcome:
				log.Printf("unexpected second Welcome ignored")
			}
		}
	}()
	t := time.NewTicker(interval)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case err := <-errc:
			return err
		case <-seen:
			last = time.Now()
		case <-t.C:
			if time.Since(last) > 3*interval {
				return errors.New("no message from the controller for 3 heartbeat intervals")
			}
			n.out.push(&pb.NodeMessage{Msg: &pb.NodeMessage_Heartbeat{Heartbeat: &pb.Heartbeat{Time: timestamppb.Now()}}})
		}
	}
}
