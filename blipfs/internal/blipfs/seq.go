package blipfs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/blipfs/blipfs/proto"
)

const (
	controlBlob   = "control"
	leaseSeconds  = 60
	renewEvery    = 20 * time.Second
	holeTimeout   = 5 * time.Second
	scanMargin    = 4096
	tailHintEvery = 5 * time.Second
)

var ErrBusy = errors.New("EBUSY")

type pending struct {
	t        time.Time
	epoch    uint64
	streams  []string
	backptrs []uint64
}

// Sequencer runs on the leader (or in-process with --standalone). It hands
// out LSNs with per-stream backpointers and repairs holes.
type Sequencer struct {
	v       *Vol
	lease   *Lease
	mu      sync.Mutex
	meta    map[string]string
	epoch   uint64
	next    uint64
	trim    uint64
	tails   map[string]uint64
	pending map[uint64]*pending
	stopped bool
	stop    chan struct{}
}

func metaU64(m map[string]string, k string) uint64 {
	n, _ := strconv.ParseUint(m[k], 10, 64)
	return n
}

// startSequencer runs leader recovery: bump the epoch, seal the WAL, scan from
// the lowest checkpoint to find the tail, junk-fill holes, rebuild stream
// tails, and publish the new leader.
func (v *Vol) startSequencer(ctx context.Context, l *Lease) (*Sequencer, error) {
	p, err := v.st.Props(ctx, controlBlob)
	if err != nil {
		return nil, err
	}
	s := &Sequencer{v: v, lease: l, meta: p.Meta, tails: map[string]uint64{}, pending: map[uint64]*pending{}, stop: make(chan struct{})}
	s.epoch = metaU64(p.Meta, "epoch") + 1
	s.meta["epoch"] = fmt.Sprint(s.epoch)
	s.meta["leader"] = v.cfg.Advertise
	s.meta["host"] = v.host
	s.meta["mode"] = "cluster"
	if v.cfg.Standalone {
		s.meta["mode"] = "standalone"
	}
	if err := v.st.SetMeta(ctx, controlBlob, s.meta, l.ID); err != nil {
		return nil, err
	}
	if err := v.wal.Seal(ctx, s.epoch); err != nil {
		return nil, err
	}
	trim, tails, err := v.snapTails(ctx)
	if err != nil {
		return nil, err
	}
	s.trim, s.tails = trim, tails
	hint := metaU64(p.Meta, "tail")
	maxValid := trim
	var missing []uint64
	const batch = 512
	for lsn := trim + 1; lsn <= hint || lsn <= maxValid+scanMargin; lsn += batch {
		lsns := make([]uint64, batch)
		for i := range lsns {
			lsns[i] = lsn + uint64(i)
		}
		recs, err := v.wal.ReadMany(ctx, lsns)
		if err != nil {
			return nil, err
		}
		for _, l := range lsns {
			r := recs[l]
			if r == nil {
				missing = append(missing, l)
				continue
			}
			maxValid = l
			for _, st := range r.Streams {
				s.tails[st] = max(s.tails[st], l)
			}
		}
	}
	s.next = maxValid + 1
	var holes []uint64
	for _, l := range missing {
		if l < s.next {
			holes = append(holes, l)
		}
	}
	for _, l := range holes {
		if err := v.wal.Write(ctx, &Record{Epoch: s.epoch, LSN: l, Type: RecJunk, Node: v.node}); err != nil {
			return nil, err
		}
	}
	s.meta["tail"] = fmt.Sprint(s.next)
	s.meta["trim"] = fmt.Sprint(s.trim)
	if err := v.st.SetMeta(ctx, controlBlob, s.meta, l.ID); err != nil {
		return nil, err
	}
	log.Printf("leader: epoch %d, next lsn %d, trim %d, filled %d holes", s.epoch, s.next, s.trim, len(holes))
	go s.loop()
	return s, nil
}

func (s *Sequencer) Token(streams []string, n int, acked []uint64) (uint64, uint64, []uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return 0, 0, nil, status.Error(codes.Unavailable, "not leader")
	}
	for _, a := range acked {
		delete(s.pending, a)
	}
	if n < 1 {
		n = 1
	}
	if s.next+uint64(n) > s.trim+s.v.wal.Capacity() {
		return 0, 0, nil, status.Error(codes.ResourceExhausted, "wal full: waiting for checkpoint")
	}
	lsn := s.next
	s.next += uint64(n)
	back := make([]uint64, len(streams))
	for i, st := range streams {
		back[i] = s.tails[st]
		s.tails[st] = lsn + uint64(n) - 1
	}
	now := time.Now()
	for i := 0; i < n; i++ {
		b := back
		if i > 0 {
			b = make([]uint64, len(streams))
			for j := range b {
				b[j] = lsn + uint64(i) - 1
			}
		}
		s.pending[lsn+uint64(i)] = &pending{t: now, epoch: s.epoch, streams: streams, backptrs: b}
	}
	return s.epoch, lsn, back, nil
}

func (s *Sequencer) Tail(streams []string) (uint64, uint64, []uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return 0, 0, nil, status.Error(codes.Unavailable, "not leader")
	}
	t := make([]uint64, len(streams))
	for i, st := range streams {
		t[i] = s.tails[st]
	}
	return s.epoch, s.next, t, nil
}

func (s *Sequencer) Ack(lsns []uint64) {
	s.mu.Lock()
	for _, l := range lsns {
		delete(s.pending, l)
	}
	s.mu.Unlock()
}

func (s *Sequencer) Stop() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stop)
	}
	s.mu.Unlock()
}

func (s *Sequencer) loop() {
	holes := time.NewTicker(time.Second)
	hint := time.NewTicker(tailHintEvery)
	trim := time.NewTicker(30 * time.Second)
	defer holes.Stop()
	defer hint.Stop()
	defer trim.Stop()
	lastHint := uint64(0)
	for {
		select {
		case <-s.stop:
			return
		case <-holes.C:
			if err := s.repairHoles(context.Background()); err != nil {
				log.Printf("sequencer: hole repair: %v", err)
			}
		case <-hint.C:
			s.mu.Lock()
			next := s.next
			s.mu.Unlock()
			if next != lastHint {
				s.mu.Lock()
				s.meta["tail"] = fmt.Sprint(next)
				s.meta["trim"] = fmt.Sprint(s.trim)
				m := cloneMap(s.meta)
				s.mu.Unlock()
				if err := s.v.st.SetMeta(context.Background(), controlBlob, m, s.lease.ID); err == nil {
					lastHint = next
				}
			}
		case <-trim.C:
			if t, err := s.v.snapTrim(context.Background()); err == nil {
				s.mu.Lock()
				s.trim = max(s.trim, t)
				s.mu.Unlock()
			}
		}
	}
}

func cloneMap(m map[string]string) map[string]string {
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// repairHoles checks tokens that were handed out more than holeTimeout ago
// and were never acked. If their slot is still empty the WAL is sealed at a
// new epoch (so the slow writer cannot land) and the slot is filled with JUNK.
func (s *Sequencer) repairHoles(ctx context.Context) error {
	s.mu.Lock()
	var old []uint64
	for l, p := range s.pending {
		if time.Since(p.t) > holeTimeout {
			old = append(old, l)
		}
	}
	s.mu.Unlock()
	if len(old) == 0 {
		return nil
	}
	recs, err := s.v.wal.ReadMany(ctx, old)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	need := false
	for _, l := range old {
		if recs[l] != nil {
			delete(s.pending, l)
		} else if s.pending[l] != nil {
			need = true
		}
	}
	if !need || s.stopped {
		return nil
	}
	// Seal: publish the new epoch first, then fence all stripes.
	s.epoch++
	s.meta["epoch"] = fmt.Sprint(s.epoch)
	if err := s.v.st.SetMeta(ctx, controlBlob, s.meta, s.lease.ID); err != nil {
		return err
	}
	if err := s.v.wal.Seal(ctx, s.epoch); err != nil {
		return err
	}
	var check []uint64
	for l, p := range s.pending {
		if p.epoch < s.epoch {
			check = append(check, l)
		}
	}
	recs, err = s.v.wal.ReadMany(ctx, check)
	if err != nil {
		return err
	}
	filled := 0
	for _, l := range check {
		p := s.pending[l]
		if recs[l] == nil {
			r := &Record{Epoch: s.epoch, LSN: l, Type: RecJunk, Streams: p.streams, Backptrs: p.backptrs, Node: s.v.node}
			if err := s.v.wal.Write(ctx, r); err != nil {
				return err
			}
			filled++
		}
		delete(s.pending, l)
	}
	log.Printf("sequencer: sealed epoch %d, filled %d holes", s.epoch, filled)
	return nil
}

// seqServer exposes the local sequencer over gRPC.
type seqServer struct {
	pb.UnimplementedSequencerServer
	v *Vol
}

func (g *seqServer) leader() (*Sequencer, error) {
	s := g.v.leader.Load()
	if s == nil {
		return nil, status.Error(codes.Unavailable, "not leader")
	}
	return s, nil
}

func (g *seqServer) Token(ctx context.Context, r *pb.TokenReq) (*pb.TokenResp, error) {
	s, err := g.leader()
	if err != nil {
		return nil, err
	}
	e, l, b, err := s.Token(r.Streams, int(r.N), r.Acked)
	if err != nil {
		return nil, err
	}
	return &pb.TokenResp{Epoch: e, Lsn: l, Backptrs: b}, nil
}

func (g *seqServer) Tail(ctx context.Context, r *pb.TailReq) (*pb.TailResp, error) {
	s, err := g.leader()
	if err != nil {
		return nil, err
	}
	e, n, t, err := s.Tail(r.Streams)
	if err != nil {
		return nil, err
	}
	return &pb.TailResp{Epoch: e, Next: n, Tails: t}, nil
}

func (g *seqServer) Ack(ctx context.Context, r *pb.AckReq) (*pb.AckResp, error) {
	s, err := g.leader()
	if err != nil {
		return nil, err
	}
	s.Ack(r.Lsns)
	return &pb.AckResp{}, nil
}

// SeqClient talks to the in-process sequencer when this node leads, and to
// the leader published in the control blob otherwise.
type SeqClient struct {
	v     *Vol
	mu    sync.Mutex
	addr  string
	conn  *grpc.ClientConn
	cli   pb.SequencerClient
	acked []uint64
}

func (c *SeqClient) remote(ctx context.Context, refresh bool) (pb.SequencerClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cli != nil && !refresh {
		return c.cli, nil
	}
	p, err := c.v.st.Props(ctx, controlBlob)
	if err != nil {
		return nil, err
	}
	if p.Meta["mode"] == "standalone" && p.Leased && p.Meta["host"] != c.v.host {
		return nil, fmt.Errorf("%w: volume held in standalone mode by %s", ErrBusy, p.Meta["host"])
	}
	addr := p.Meta["leader"]
	if addr == "" || !p.Leased {
		return nil, status.Error(codes.Unavailable, "no leader")
	}
	if addr != c.addr || c.cli == nil {
		if c.conn != nil {
			c.conn.Close()
		}
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		c.addr, c.conn, c.cli = addr, conn, pb.NewSequencerClient(conn)
	}
	return c.cli, nil
}

func (c *SeqClient) takeAcks() []uint64 {
	c.mu.Lock()
	a := c.acked
	c.acked = nil
	c.mu.Unlock()
	return a
}

// Acked queues an LSN acknowledgement to piggyback on the next request.
func (c *SeqClient) Acked(lsn uint64) {
	if s := c.v.leader.Load(); s != nil {
		s.Ack([]uint64{lsn})
		return
	}
	c.mu.Lock()
	c.acked = append(c.acked, lsn)
	c.mu.Unlock()
}

// retry runs f against the current leader until it succeeds, re-reading the
// control blob after failures, for up to ~2 lease periods.
func (c *SeqClient) retry(ctx context.Context, f func(s *Sequencer, cli pb.SequencerClient) error) error {
	deadline := time.Now().Add(2 * leaseSeconds * time.Second)
	refresh := false
	delay := 20 * time.Millisecond
	warn := time.Now().Add(5 * time.Second)
	for {
		var err error
		if s := c.v.leader.Load(); s != nil {
			err = f(s, nil)
		} else {
			var cli pb.SequencerClient
			cli, err = c.remote(ctx, refresh)
			if errors.Is(err, ErrBusy) {
				return err
			}
			if err == nil {
				cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err = f(nil, &timeoutClient{cli, cctx})
				cancel()
			}
		}
		if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		if time.Now().After(warn) {
			log.Printf("sequencer unreachable, retrying: %v", err)
			warn = time.Now().Add(30 * time.Second)
		}
		refresh = true
		time.Sleep(delay)
		delay = min(delay*2, time.Second)
	}
}

type timeoutClient struct {
	pb.SequencerClient
	ctx context.Context
}

func (c *SeqClient) Token(ctx context.Context, streams []string, n int) (epoch, lsn uint64, back []uint64, err error) {
	err = c.retry(ctx, func(s *Sequencer, cli pb.SequencerClient) error {
		if s != nil {
			epoch, lsn, back, err = s.Token(streams, n, nil)
			return err
		}
		tc := cli.(*timeoutClient)
		r, err := tc.SequencerClient.Token(tc.ctx, &pb.TokenReq{Streams: streams, N: uint32(n), Acked: c.takeAcks()})
		if err != nil {
			return err
		}
		epoch, lsn, back = r.Epoch, r.Lsn, r.Backptrs
		return nil
	})
	return
}

// Tail returns the next LSN to be issued and the last LSN of each stream.
func (c *SeqClient) Tail(ctx context.Context, streams ...string) (next uint64, tails []uint64, err error) {
	err = c.retry(ctx, func(s *Sequencer, cli pb.SequencerClient) error {
		if s != nil {
			_, next, tails, err = s.Tail(streams)
			return err
		}
		tc := cli.(*timeoutClient)
		r, err := tc.SequencerClient.Tail(tc.ctx, &pb.TailReq{Streams: streams})
		if err != nil {
			return err
		}
		next, tails = r.Next, r.Tails
		return nil
	})
	return
}

func (c *SeqClient) flushAcks(ctx context.Context) {
	if c.v.leader.Load() != nil {
		return
	}
	a := c.takeAcks()
	if len(a) == 0 {
		return
	}
	cli, err := c.remote(ctx, false)
	if err == nil {
		_, err = cli.Ack(ctx, &pb.AckReq{Lsns: a})
	}
}

// elect keeps trying to hold the control lease; whoever holds it leads.
// A standalone daemon passes the lease it already holds.
func (v *Vol) elect(ctx context.Context, l *Lease) {
	lastRenew := time.Now()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if l != nil && time.Since(lastRenew) >= renewEvery {
			if err := l.Renew(ctx); err != nil {
				log.Printf("lost leadership: %v", err)
				if s := v.leader.Swap(nil); s != nil {
					s.Stop()
				}
				l = nil
			} else {
				lastRenew = time.Now()
			}
		}
		if l == nil {
			p, err := v.st.Props(ctx, controlBlob)
			if err == nil && !p.Leased {
				nl, err := v.st.AcquireLease(ctx, controlBlob, v.leaseID, leaseSeconds)
				if err == nil && nl != nil {
					s, err := v.startSequencer(ctx, nl)
					if err != nil {
						log.Printf("leader recovery failed: %v", err)
						nl.Release(ctx)
					} else {
						l, lastRenew = nl, time.Now()
						v.leader.Store(s)
						v.seq.flushAcks(ctx)
					}
				}
			}
		}
		v.seq.flushAcks(ctx)
		select {
		case <-ctx.Done():
			if l != nil {
				if s := v.leader.Swap(nil); s != nil {
					s.Stop()
				}
				l.Release(context.Background())
			}
			return
		case <-tick.C:
		}
	}
}
