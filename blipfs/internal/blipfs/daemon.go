package blipfs

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/google/uuid"
	"google.golang.org/grpc"

	pb "github.com/blipfs/blipfs/proto"
)

// Config holds the daemon flags.
type Config struct {
	Conn       string // connection string
	AccountURL string // used with the default Azure credential when Conn is empty
	Container  string
	Stripes    int // WAL stripes (new volumes only)
	Shards     int // snapshot shards (new volumes only)
	SlotSize   int // WAL slot size (new volumes only)
	Slots      int // slots per stripe (new volumes only)
	TmpDir     string
	Standalone bool
	Listen     string // sequencer gRPC address
	Advertise  string // address other hosts use to reach Listen
	Socket     string // control socket for the CLI
	Host       string
}

// Vol is one open volume on this host.
type Vol struct {
	cfg     Config
	st      *Store
	wal     *WAL
	snap    *Snap
	chunks  *Chunks
	table   *branchTable
	seq     *SeqClient
	leader  atomic.Pointer[Sequencer]
	host    string
	node    string // host plus incarnation
	leaseID string
	shards  int

	mu       sync.Mutex
	branches map[string]*Branch
	mounts   map[string]*Mount
	own      map[uint64]*Record // recently written records, to skip reading them back

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	srvs   []*grpc.Server
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// layout reads the volume geometry from the control blob, creating the
// volume first if the container is empty.
func layout(ctx context.Context, st *Store, cfg Config) (map[string]string, error) {
	meta := map[string]*string{
		"stripes": to.Ptr(strconv.Itoa(cfg.Stripes)),
		"shards":  to.Ptr(strconv.Itoa(cfg.Shards)),
		"slot":    to.Ptr(strconv.Itoa(cfg.SlotSize)),
		"slots":   to.Ptr(strconv.Itoa(cfg.Slots)),
	}
	created, err := st.CreatePage(ctx, controlBlob, 512, 0, meta)
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		p, err := st.Props(ctx, controlBlob)
		if err != nil {
			return nil, err
		}
		if p.Meta["ready"] == "1" {
			return p.Meta, nil
		}
		if created {
			n := func(k string) int { v, _ := strconv.Atoi(p.Meta[k]); return v }
			w := &WAL{st: st, stripes: n("stripes"), slotSize: n("slot"), slots: n("slots")}
			if err := w.Create(ctx, 0); err != nil {
				return nil, err
			}
			s := &Snap{v: &Vol{st: st}, shards: make([]*shard, n("shards"))}
			if err := s.create(ctx); err != nil {
				return nil, err
			}
			p.Meta["ready"] = "1"
			if err := st.SetMeta(ctx, controlBlob, p.Meta, ""); err != nil {
				return nil, err
			}
			log.Printf("created volume %s", st)
			continue
		}
		if i > 300 {
			return nil, errors.New("volume creation by another host did not finish")
		}
		time.Sleep(time.Second)
	}
}

// Open opens (creating if needed) the volume and starts the daemon's
// background work. Mounts are added later through the control socket.
func Open(ctx context.Context, cfg Config) (*Vol, error) {
	if cfg.Host == "" {
		cfg.Host, _ = os.Hostname()
	}
	if cfg.TmpDir == "" {
		cfg.TmpDir = os.TempDir()
	}
	cfg.Stripes = cmp.Or(cfg.Stripes, 16)
	cfg.Shards = cmp.Or(cfg.Shards, 4)
	cfg.SlotSize = cmp.Or(cfg.SlotSize, 64<<10)
	cfg.Slots = cmp.Or(cfg.Slots, 16384)
	if cfg.SlotSize%512 != 0 || cfg.SlotSize < 4096 {
		return nil, errors.New("slot size must be a multiple of 512 and at least 4 KiB")
	}
	if err := os.MkdirAll(cfg.TmpDir, 0o700); err != nil {
		return nil, err
	}
	st, err := NewStore(cfg.Conn, cfg.AccountURL, cfg.Container)
	if err != nil {
		return nil, err
	}
	if err := st.CreateContainer(ctx); err != nil {
		return nil, err
	}
	meta, err := layout(ctx, st, cfg)
	if err != nil {
		return nil, err
	}
	n := func(k string) int { v, _ := strconv.Atoi(meta[k]); return v }
	v := &Vol{
		cfg: cfg, st: st, host: cfg.Host, node: cfg.Host + "/" + randHex(4), leaseID: uuid.NewString(),
		shards: n("shards"), branches: map[string]*Branch{}, mounts: map[string]*Mount{},
	}
	v.wal = &WAL{st: st, stripes: n("stripes"), slotSize: n("slot"), slots: n("slots")}
	v.snap = newSnap(v, v.shards)
	v.chunks = newChunks(v)
	v.table = &branchTable{m: map[string]*tableEnt{}}
	v.table.s = &stream{v: v, name: branchesStream, apply: v.table.applyRecord}
	v.seq = &SeqClient{v: v}
	v.ctx, v.cancel = context.WithCancel(context.Background())

	if err := v.snap.loadAll(ctx); err != nil {
		return nil, err
	}
	if err := v.snap.loadState(); err != nil {
		return nil, err
	}

	p, err := st.Props(ctx, controlBlob)
	if err != nil {
		return nil, err
	}
	if p.Leased && p.Meta["mode"] == "standalone" && p.Meta["host"] != v.host {
		return nil, fmt.Errorf("%w: volume held in standalone mode by %s", ErrBusy, p.Meta["host"])
	}
	if cfg.Standalone && p.Leased && p.Meta["host"] == v.host {
		// most likely our own previous incarnation crashed; its lease runs out
		log.Printf("waiting for the lease of a previous blipfsd on this host to expire")
		for i := 0; i < leaseSeconds/5+2 && p.Leased; i++ {
			time.Sleep(5 * time.Second)
			if p, err = st.Props(ctx, controlBlob); err != nil {
				return nil, err
			}
		}
	}
	if cfg.Standalone {
		if p.Leased {
			return nil, fmt.Errorf("%w: volume is in use by %s (%s mode)", ErrBusy, p.Meta["host"], p.Meta["mode"])
		}
		l, err := st.AcquireLease(ctx, controlBlob, v.leaseID, leaseSeconds)
		if err != nil {
			return nil, err
		}
		if l == nil {
			return nil, fmt.Errorf("%w: volume is in use", ErrBusy)
		}
		s, err := v.startSequencer(ctx, l)
		if err != nil {
			l.Release(ctx)
			return nil, err
		}
		v.leader.Store(s)
		v.goBG(func() { v.elect(v.ctx, l) })
	} else {
		lis, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return nil, err
		}
		if v.cfg.Advertise == "" {
			ip, port, _ := net.SplitHostPort(lis.Addr().String())
			if a := net.ParseIP(ip); a == nil || a.IsUnspecified() {
				ip, _ = os.Hostname()
			}
			v.cfg.Advertise = net.JoinHostPort(ip, port)
		}
		gs := grpc.NewServer()
		pb.RegisterSequencerServer(gs, &seqServer{v: v})
		go gs.Serve(lis)
		v.srvs = append(v.srvs, gs)
		v.goBG(func() { v.elect(v.ctx, nil) })
	}

	if err := v.ensureMain(ctx); err != nil {
		v.Close()
		return nil, err
	}
	v.goBG(func() { v.snap.run(v.ctx) })
	v.goBG(func() { v.gcLoop(v.ctx) })
	v.goBG(func() { v.recoverStages(v.ctx) })

	if cfg.Socket != "" {
		os.Remove(cfg.Socket)
		if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o755); err != nil {
			v.Close()
			return nil, err
		}
		lis, err := net.Listen("unix", cfg.Socket)
		if err != nil {
			v.Close()
			return nil, err
		}
		cs := grpc.NewServer()
		pb.RegisterControlServer(cs, &ctlServer{v: v})
		go cs.Serve(lis)
		v.srvs = append(v.srvs, cs)
	}
	return v, nil
}

func (v *Vol) goBG(f func()) {
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		f()
	}()
}

// ensureMain creates the "main" branch of a new volume.
func (v *Vol) ensureMain(ctx context.Context) error {
	if err := v.table.s.catchUp(ctx, 0); err != nil {
		return err
	}
	if _, ok := v.table.get("main"); ok {
		return nil
	}
	b, err := v.branch("main")
	if err != nil {
		return err
	}
	_, _, err = v.write(ctx, RecBranch, b, []Op{{Kind: OpBranchCreate, Branch: "main", Time: time.Now().UnixNano(), Node: v.node,
		Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}})
	return err
}

// recoverStages commits writes that an earlier incarnation of this host
// fsynced but never closed (fsync + crash = implicit close).
func (v *Vol) recoverStages(ctx context.Context) {
	if err := v.table.s.catchUp(ctx, 0); err != nil {
		log.Printf("stage recovery: %v", err)
		return
	}
	for _, name := range v.table.list(false) {
		b, err := v.branch(name)
		if err != nil {
			continue
		}
		if _, _, err := b.head(ctx); err != nil {
			continue
		}
		for _, s := range b.Meta().Stages {
			if s.Node == v.node || !strings.HasPrefix(s.Node, v.host+"/") {
				continue
			}
			ops := append([]Op(nil), s.Ops...)
			ops = append(ops, Op{Kind: OpStageDone, Branch: name, Before: s.LSN})
			if _, _, err := b.commit(ctx, ops...); err != nil {
				log.Printf("stage recovery %s@%d: %v", name, s.LSN, err)
			} else {
				log.Printf("recovered fsynced writes %s@%d", name, s.LSN)
			}
		}
	}
}

// Mount mounts branch at path.
func (v *Vol) Mount(branch, path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	v.mu.Lock()
	_, busy := v.mounts[path]
	v.mu.Unlock()
	if busy {
		return fmt.Errorf("%s is already mounted", path)
	}
	if e, ok := v.table.get(branch); !ok || e.Closed {
		if err := v.table.s.catchUp(v.ctx, 0); err != nil {
			return err
		}
		if e, ok := v.table.get(branch); !ok || e.Closed {
			return fmt.Errorf("no branch %q", branch)
		}
	}
	m, err := v.mount(branch, path)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.mounts[path] = m
	v.mu.Unlock()
	return nil
}

func (v *Vol) Unmount(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	v.mu.Lock()
	m := v.mounts[path]
	v.mu.Unlock()
	if m == nil {
		return fmt.Errorf("%s is not mounted", path)
	}
	if err := m.unmount(); err != nil {
		return err
	}
	v.mu.Lock()
	delete(v.mounts, path)
	v.mu.Unlock()
	return nil
}

// mountAt returns the mount containing path, if any.
func (v *Vol) mountAt(path string) *Mount {
	v.mu.Lock()
	defer v.mu.Unlock()
	var best *Mount
	for p, m := range v.mounts {
		if (path == p || strings.HasPrefix(path, p+"/")) && (best == nil || len(p) > len(best.path)) {
			best = m
		}
	}
	return best
}

// Close unmounts everything, checkpoints and gives up leases.
func (v *Vol) Close() error {
	v.mu.Lock()
	var paths []string
	for p := range v.mounts {
		paths = append(paths, p)
	}
	v.mu.Unlock()
	for _, p := range paths {
		if err := v.Unmount(p); err != nil {
			log.Printf("unmount %s: %v", p, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	v.snap.close(ctx)
	for _, s := range v.srvs {
		s.Stop()
	}
	v.cancel()
	v.wg.Wait()
	if v.cfg.Socket != "" {
		os.Remove(v.cfg.Socket)
	}
	return nil
}

type ctlServer struct {
	pb.UnimplementedControlServer
	v *Vol
}

func (c *ctlServer) Run(ctx context.Context, r *pb.CmdReq) (*pb.CmdResp, error) {
	out, code := c.v.runCmd(ctx, r.Args, r.Cwd)
	return &pb.CmdResp{Output: out, Code: int32(code)}, nil
}
