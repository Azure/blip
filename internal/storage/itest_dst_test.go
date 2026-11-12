package storage

// TestStorageDST is a seeded random walk over the storage control plane
// on the real kernel (dm-thin, dm-multipath, nvmet and nvme-tcp with TLS,
// LVM), in the spirit of deterministic simulation testing: every choice
// comes from one seeded source, so a failing seed replays the same
// sequence of operations (the kernel's timing is not deterministic, so
// replays are faithful but not bit-exact). After each step the walker
// compares the node state with an in-memory model and checks for leaked
// kernel objects; every few steps and at the end it compares all data.
//
// Operations are injected faults (fail the k-th command or kernel change
// before or after it runs, see run.Hook) and crashes: the operation runs
// in a child process (TestStorageDSTChild) that kills itself with SIGKILL
// at the k-th step, and the walker then restarts the node object (and
// rescans a compute node). After a fault or crash the walker either
// retries (every operation is idempotent) or abandons and undoes the
// operation, like the control plane does.
//
// Run (as root):
//
//	go test -c -o /tmp/storage.test ./internal/storage/
//	cd internal/storage && sudo BLIP_ROOT_TESTS=1 BLIP_DST_SEED=42 \
//	    /tmp/storage.test -test.run 'TestStorageDST$' -test.v
//
// Knobs: BLIP_DST_SEED (default random; always logged), BLIP_DST_STEPS
// (default 150), BLIP_DST_FAULTS (probability that an operation gets a
// fault, default 0.15), BLIP_DST_CRASHES (probability that an operation
// crashes, default 0.05), BLIP_DST_HOLD (on failure, wait this long, for
// example 5m, before the teardown to look around), BLIP_DST_SLOT (0-9;
// runs with different slots use different namespaces, subnets, node names
// and directories, so they can run in parallel). See also "make dst".

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/extent"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmehost"
	"github.com/example/blip/internal/storage/nvmet"
	"github.com/example/blip/internal/storage/run"
	"github.com/example/blip/internal/storage/storagetest"
	"github.com/example/blip/internal/storage/tlskeys"
)

const dstSize = 16 << 20

func envInt(name string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(name), 10, 64); err == nil {
		return v
	}
	return def
}

func envFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil {
		return v
	}
	return def
}

// dstNet is the network of slot n: nodes d<n>s1..d<n>s3 and d<n>c1.
func dstNet(slot int64) *storagetest.Net {
	p := fmt.Sprintf("d%d", slot)
	return &storagetest.Net{
		Prefix: "blip" + p, Bridge: "blip" + p, Subnet: fmt.Sprintf("10.97.%d", slot),
		Nodes: []string{p + "s1", p + "s2", p + "s3", p + "c1"}, Dir: itBase() + "-dst" + strconv.FormatInt(slot, 10),
	}
}

// dstOp is one storage operation. It is small and JSON-encodable so a
// child process can run it (crash injection).
type dstOp struct {
	Kind    string
	Node    string
	Content string          `json:",omitempty"`
	Base    string          `json:",omitempty"`
	Host    string          `json:",omitempty"`
	RW      bool            `json:",omitempty"`
	Size    int64           `json:",omitempty"`
	Seq     int64           `json:",omitempty"`
	BaseSeq int64           `json:",omitempty"`
	Alloc   string          `json:",omitempty"`
	Att     string          `json:",omitempty"`
	Slot    string          `json:",omitempty"`
	PSK     []byte          `json:",omitempty"`
	Refs    []string        `json:",omitempty"`
	Attach  *AttachRequest  `json:",omitempty"`
	Receive *ReceiveRequest `json:",omitempty"`
	Dsts    []Remote        `json:",omitempty"`
	Ranges  []extent.Range  `json:",omitempty"`
}

func (op dstOp) String() string {
	var b strings.Builder
	b.WriteString(op.Kind + "@" + op.Node)
	add := func(k string, v any) { fmt.Fprintf(&b, " %s=%v", k, v) }
	if op.Content != "" {
		add("c", op.Content)
	}
	if op.Base != "" {
		add("base", op.Base)
	}
	if op.Host != "" {
		add("host", op.Host)
	}
	if op.RW {
		add("rw", true)
	}
	if op.Alloc != "" {
		add("att", op.Alloc+"/"+op.Att)
	}
	if op.Seq != 0 {
		add("seq", op.Seq)
	}
	if op.BaseSeq != 0 {
		add("baseSeq", op.BaseSeq)
	}
	if op.Slot != "" {
		add("slot", op.Slot)
	}
	for _, r := range op.Refs {
		add("ref", r)
	}
	if a := op.Attach; a != nil {
		var rs []string
		for _, r := range a.Replicas {
			rs = append(rs, r.Node)
		}
		add("att", fmt.Sprintf("%s/%s gen=%d c=%s slot=%s/%d replicas=%v", a.AllocID, a.AttachmentID, a.Generation, a.ContentID, a.Slot, a.SlotDisk, rs))
	}
	if r := op.Receive; r != nil {
		add("recv", fmt.Sprintf("%s base=%q gen=%d", r.ContentID, r.BaseContentID, r.Generation))
	}
	for _, d := range op.Dsts {
		add("dst", d.Node)
	}
	return b.String()
}

// exec runs op against s or c in the calling thread's network namespace.
func (op dstOp) exec(ctx context.Context, s *StorageNode, c *ComputeNode) (any, error) {
	switch op.Kind {
	case "create-blank":
		return nil, s.CreateBlank(ctx, op.Content, op.Size, "content", "")
	case "create-root":
		return s.CreateRoot(ctx, RootRequest{ID: op.Content, Size: op.Size})
	case "snapshot":
		return nil, s.Snapshot(ctx, op.Base, op.Content, "content", "")
	case "seal":
		return nil, s.Seal(ctx, op.Content)
	case "export":
		return s.Export(ctx, op.Content, op.Host, op.PSK, op.RW)
	case "unexport":
		return nil, s.Unexport(ctx, op.Content, op.Host, op.RW)
	case "delete":
		return nil, s.Delete(ctx, op.Content)
	case "prepare-receive":
		return s.PrepareReceive(ctx, *op.Receive)
	case "mapped-ranges":
		return s.MappedRanges(ctx, op.Content)
	case "write-extents":
		return nil, errors.Join(s.WriteExtents(ctx, op.Content, op.Dsts, op.PSK, op.Ranges, nil)...)
	case "ensure-slot":
		return c.EnsureSlot(ctx, op.Slot)
	case "attach":
		return c.Attach(ctx, *op.Attach)
	case "refresh":
		return c.RefreshPaths(ctx, *op.Attach)
	case "capture":
		return c.CaptureLocal(ctx, op.Alloc, op.Refs, op.Seq)
	case "local-delta":
		return c.LocalDelta(ctx, op.Alloc, op.Att, op.Seq, op.BaseSeq)
	case "write-snapshot":
		return nil, errors.Join(c.WriteLocalSnapshot(ctx, op.Alloc, op.Att, op.Seq, op.Dsts, op.PSK, op.Ranges)...)
	case "drop":
		return nil, c.DropLocalSnapshot(ctx, op.Alloc, op.Att, op.Seq)
	case "release":
		return nil, c.ReleaseAttachment(ctx, op.Alloc, op.Att)
	case "cleanup":
		return nil, c.Cleanup(ctx, op.Alloc)
	}
	return nil, fmt.Errorf("unknown op %q", op.Kind)
}

// dstChild is what the walker passes to a child process.
type dstChild struct {
	Op      dstOp
	Prefix  string
	Storage *StorageConfig `json:",omitempty"`
	Compute *ComputeConfig `json:",omitempty"`
	CrashAt int            // 1-based step of run.Hook
	After   bool           // crash after the step ran
}

// TestStorageDSTChild runs one operation for TestStorageDST and kills
// itself at a given step. It does nothing on its own.
func TestStorageDSTChild(t *testing.T) {
	v := os.Getenv("BLIP_DST_CHILD")
	if v == "" {
		t.Skip("helper of TestStorageDST")
	}
	var ch dstChild
	if err := json.Unmarshal([]byte(v), &ch); err != nil {
		t.Fatal(err)
	}
	var s *StorageNode
	var c *ComputeNode
	var err error
	if ch.Storage != nil {
		s, err = NewStorageNode(*ch.Storage)
	} else {
		c, err = NewComputeNode(*ch.Compute)
	}
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	run.Hook = func(name string, args []string, after bool, err error) error {
		if after != ch.After {
			return nil
		}
		if n.Add(1) == int64(ch.CrashAt) {
			fmt.Printf("crash %s at step %d: %s %s\n", map[bool]string{false: "before", true: "after"}[after], ch.CrashAt, name, strings.Join(args, " "))
			os.Stdout.Sync()
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	net := &storagetest.Net{Prefix: ch.Prefix}
	err = net.InNS(ch.Op.Node, func() error { _, err := ch.Op.exec(ctx, s, c); return err })
	fmt.Printf("finished after %d steps: %v\n", n.Load(), err)
}

// Model.

type mContent struct {
	data  []byte
	nodes map[string]bool // sealed replicas
}

type mAtt struct {
	inc     int // incarnation, unique per walk
	uid     string
	content string
	gen     int64
	disk    int // slot disk, -1 for none
	data    []byte
	snaps   map[int64][]byte
}

type mAlloc struct {
	slot string
	seq  int64
	atts map[string]*mAtt
}

type expKey struct {
	content, host string
	rw            bool
}

type sentFrom struct {
	inc int
	seq int64
}

type walker struct {
	t         *testing.T
	e         *env
	ctx       context.Context
	rng       *mrand.Rand
	faults    float64
	crashes   float64
	scfg      map[string]StorageConfig
	ccfg      ComputeConfig
	snodes    []string
	cn        string
	stats     map[string]int
	maxSteps  map[string]int // most hook steps seen per op kind
	n         int
	logPrefix string

	contents map[string]*mContent
	exports  map[string]map[expKey]bool // storage node -> exports
	allocs   map[string]*mAlloc
	slots    map[string]bool
	sent     map[string]sentFrom // content -> local snapshot it was sent from
	// conns are the storage nodes the compute node may be connected to
	// per content: the replicas of every Attach and RefreshPaths since
	// the content was last attached by no attachment.
	conns map[string]map[string]bool
}

var errAbandoned = errors.New("abandoned")

// isBusy reports a transient EBUSY from device-mapper or nvme.
func isBusy(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "device or resource busy")
}

func TestStorageDST(t *testing.T) {
	storagetest.NeedRoot(t)
	seed := uint64(envInt("BLIP_DST_SEED", time.Now().UnixNano()%1e9))
	steps := int(envInt("BLIP_DST_STEPS", 150))
	slot := envInt("BLIP_DST_SLOT", 0)
	t.Logf("BLIP_DST_SEED=%d BLIP_DST_STEPS=%d BLIP_DST_SLOT=%d", seed, steps, slot)
	net := dstNet(slot)
	e := newEnvOn(t, net, 1<<30, 256<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	w := &walker{
		t: t, e: e, ctx: ctx, rng: mrand.New(mrand.NewPCG(seed, 0x5eed)),
		faults: envFloat("BLIP_DST_FAULTS", 0.15), crashes: envFloat("BLIP_DST_CRASHES", 0.05),
		scfg: map[string]StorageConfig{}, ccfg: e.compute.cfg, snodes: net.Nodes[:3], cn: e.cnode,
		stats: map[string]int{}, maxSteps: map[string]int{},
		contents: map[string]*mContent{}, exports: map[string]map[expKey]bool{}, allocs: map[string]*mAlloc{},
		slots: map[string]bool{}, sent: map[string]sentFrom{}, conns: map[string]map[string]bool{},
	}
	for _, n := range w.snodes {
		w.scfg[n] = e.storage[n].cfg
		w.exports[n] = map[expKey]bool{}
	}
	t.Cleanup(func() { run.Hook = nil })
	if err := net.InNS(w.cn, func() error { _, err := e.compute.PreparePool(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	ops := []struct {
		name string
		w    int
		fn   func() bool
	}{
		{"new-content", 6, w.opNewContent},
		{"snapshot", 2, w.opSnapshot},
		{"delete", 3, w.opDelete},
		{"export-ro", 4, w.opExportRO},
		{"unexport-ro", 3, w.opUnexportRO},
		{"refused", 1, w.opRefused},
		{"scrub", 2, w.opScrub},
		{"storage-restart", 1, w.opStorageRestart},
		{"ensure-slot", 2, w.opEnsureSlot},
		{"attach", 8, w.opAttach},
		{"write", 8, w.opWrite},
		{"capture", 6, w.opCapture},
		{"drop", 2, w.opDrop},
		{"send", 5, w.opSend},
		{"release", 3, w.opRelease},
		{"cleanup", 1, w.opCleanup},
		{"refresh", 2, w.opRefresh},
		{"compute-restart", 1, w.opComputeRestart},
		{"race", 2, w.opRace},
	}
	total := 0
	for _, o := range ops {
		total += o.w
	}
	for w.n = 1; w.n <= steps; w.n++ {
		for {
			r := w.rng.IntN(total)
			i := 0
			for r >= ops[i].w {
				r -= ops[i].w
				i++
			}
			w.logPrefix = fmt.Sprintf("step %d %s", w.n, ops[i].name)
			if ops[i].fn() {
				w.stats[ops[i].name]++
				break
			}
		}
		w.check(w.n%10 == 0)
	}
	w.logPrefix = "final"
	w.check(true)
	w.teardown()
	var ks []string
	for k, v := range w.stats {
		ks = append(ks, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(ks)
	t.Logf("seed %d done: %s", seed, strings.Join(ks, " "))
}

func (w *walker) logf(format string, args ...any) {
	w.t.Helper()
	w.t.Logf("%s: "+format, append([]any{w.logPrefix}, args...)...)
}

func (w *walker) fatalf(format string, args ...any) {
	w.t.Helper()
	if d, err := time.ParseDuration(os.Getenv("BLIP_DST_HOLD")); err == nil {
		w.t.Logf("%s: "+format, append([]any{w.logPrefix}, args...)...)
		w.t.Logf("holding for %v before teardown (BLIP_DST_HOLD)", d)
		time.Sleep(d)
	}
	w.t.Fatalf("%s: "+format, append([]any{w.logPrefix}, args...)...)
}

func (w *walker) pick(n int) int { return w.rng.IntN(n) }

func (w *walker) chance(p float64) bool { return w.rng.Float64() < p }

func pickKey[V any](w *walker, m map[string]V) string {
	ks := sortedKeys(m)
	if len(ks) == 0 {
		return ""
	}
	return ks[w.pick(len(ks))]
}

func (w *walker) newID(prefix string) string {
	w.stats["ids"]++
	return fmt.Sprintf("%s%d", prefix, w.stats["ids"])
}

// in runs fn in the network namespace of node.
func (w *walker) in(node string, fn func() error) error { return w.e.net.InNS(node, fn) }

func (w *walker) must(node string, what string, fn func() error) {
	w.t.Helper()
	if err := w.in(node, fn); err != nil {
		w.fatalf("%s on %s: %v", what, node, err)
	}
}

// run runs op on its node in this process.
func (w *walker) run(op dstOp) (any, error) {
	var res any
	err := w.in(op.Node, func() (err error) {
		res, err = op.exec(w.ctx, w.e.storage[op.Node], w.e.compute)
		return err
	})
	return res, err
}

// armFault makes the k-th step (before or after it runs) fail. It
// returns a function that reports whether the fault fired and disarms
// it, and the number of steps seen.
func armFault(k int, after bool) func() (bool, int) {
	var n, fired atomic.Int64
	run.Hook = func(name string, args []string, isAfter bool, err error) error {
		if isAfter {
			if after && n.Load() == int64(k) && fired.Load() == 0 {
				fired.Store(1)
				return fmt.Errorf("injected fault after %s %s (outcome %v)", name, strings.Join(args, " "), err)
			}
			return nil
		}
		if n.Add(1) == int64(k) && !after {
			fired.Store(1)
			return fmt.Errorf("injected fault before %s %s", name, strings.Join(args, " "))
		}
		return nil
	}
	return func() (bool, int) {
		run.Hook = nil
		return fired.Load() == 1, int(n.Load())
	}
}

// countSteps runs op with a hook that only counts steps.
func (w *walker) countSteps(op dstOp) (any, error) {
	done := armFault(-1, false)
	res, err := w.run(op)
	_, n := done()
	w.maxSteps[op.Kind] = max(w.maxSteps[op.Kind], n)
	return res, err
}

// do runs op. With some probability the op gets an injected fault or
// crash; then the op is retried or, if undo is not nil, sometimes
// abandoned (undo runs and do returns errAbandoned). The final outcome
// must be nil or one of ok.
func (w *walker) do(op dstOp, undo func(), ok ...error) (any, error) {
	w.t.Helper()
	expected := func(err error) bool {
		if err == nil {
			return true
		}
		for _, o := range ok {
			if errors.Is(err, o) {
				return true
			}
		}
		return false
	}
	k := 1 + w.pick(max(w.maxSteps[op.Kind], 3))
	after := w.chance(0.5)
	var res any
	var err error
	disturbed := false
	switch r := w.rng.Float64(); {
	case r < w.crashes:
		w.stats["crash"]++
		disturbed = w.crash(op, k, after)
	case r < w.crashes+w.faults:
		done := armFault(k, after)
		res, err = w.run(op)
		fired, n := done()
		w.maxSteps[op.Kind] = max(w.maxSteps[op.Kind], n)
		if fired {
			w.stats["fault"]++
			w.logf("%v: %v", op, err)
			disturbed = true
		}
	default:
		res, err = w.countSteps(op)
	}
	if !disturbed && isBusy(err) {
		// Something outside Blip (udev) held a device open. Callers
		// retry after errors; a persistent EBUSY still fails below.
		w.stats["busy"]++
		w.logf("%v: %v (busy, retrying)", op, err)
		disturbed = true
		undo = nil
	}
	if !disturbed {
		if !expected(err) {
			w.fatalf("%v: %v", op, err)
		}
		if err != nil {
			w.logf("%v: %v (expected)", op, err)
		} else {
			w.logf("%v", op)
		}
		return res, err
	}
	if undo != nil && w.chance(0.3) {
		w.stats["abandon"]++
		w.logf("%v: abandon", op)
		undo()
		return nil, errAbandoned
	}
	for i := 0; ; i++ {
		res, err = w.countSteps(op)
		if expected(err) {
			w.logf("%v: retry: %v", op, err)
			return res, err
		}
		if i == 3 {
			w.fatalf("%v: retry: %v", op, err)
		}
		w.logf("%v: retry: %v", op, err)
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
}

// crash runs op in a child process that kills itself at step k, then
// restarts the node. It reports whether the child crashed.
func (w *walker) crash(op dstOp, k int, after bool) bool {
	ch := dstChild{Op: op, Prefix: w.e.net.Prefix, CrashAt: k, After: after}
	if op.Node == w.cn {
		cfg := w.ccfg
		ch.Compute = &cfg
	} else {
		cfg := w.scfg[op.Node]
		ch.Storage = &cfg
	}
	b, err := json.Marshal(ch)
	if err != nil {
		w.fatalf("%v", err)
	}
	ctx, cancel := context.WithTimeout(w.ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStorageDSTChild$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "BLIP_DST_CHILD="+string(b))
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	killed := errors.As(err, &ee) && ee.ProcessState.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL
	if err != nil && !killed {
		w.fatalf("child for %v: %v\n%s", op, err, out)
	}
	last := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "crash ") || strings.HasPrefix(l, "finished ") {
			last = l
		}
	}
	w.logf("%v: child: %s", op, last)
	w.restart(op.Node)
	return true
}

// restart makes a new node object, like a daemon restart.
func (w *walker) restart(node string) {
	w.t.Helper()
	if node != w.cn {
		s, err := NewStorageNode(w.scfg[node])
		if err != nil {
			w.fatalf("restart %s: %v", node, err)
		}
		w.e.storage[node] = s
		return
	}
	c, err := NewComputeNode(w.ccfg)
	if err != nil {
		w.fatalf("restart %s: %v", node, err)
	}
	w.e.compute = c
	w.must(node, "restart", func() error {
		created, err := c.PreparePool(w.ctx)
		if err == nil && created {
			err = errors.New("PreparePool created a new pool")
		}
		if err != nil {
			return err
		}
		// Recovery can hit a device that is briefly busy (udev probes
		// new devices); the daemon rescans periodically, so retry.
		for i := 0; ; i++ {
			st, err := c.Rescan(w.ctx)
			if len(st.Resumed) > 0 {
				w.logf("rescan resumed %v", st.Resumed)
			}
			if err == nil || i == 3 {
				return err
			}
			w.logf("rescan: %v", err)
			time.Sleep(time.Second)
		}
	})
}

// Storage operations.

func (w *walker) psk(node string) []byte { return w.e.psk(node) }

func (w *walker) nodesOf(id string) []string {
	return sortedKeys(w.contents[id].nodes)
}

func (w *walker) subset(nodes []string, min int) []string {
	out := slices.Clone(nodes)
	w.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:min+w.pick(len(out)-min+1)]
}

// deleteEverywhere is the undo of an abandoned content creation.
func (w *walker) deleteEverywhere(id string, nodes []string) {
	for _, n := range nodes {
		w.do(dstOp{Kind: "delete", Node: n, Content: id}, nil)
	}
	for _, n := range w.snodes {
		for k := range w.exports[n] {
			if k.content == id {
				delete(w.exports[n], k)
			}
		}
	}
}

// writeRandom writes random 4KiB-aligned ranges to dev and to shadow.
func (w *walker) writeRandom(dev string, shadow []byte) {
	w.t.Helper()
	var ws [][2]int64
	for range 1 + w.pick(4) {
		n := int64(1+w.pick(64)) * 4096
		if w.chance(0.2) {
			n = int64(1+w.pick(8)) * BlockSize
		}
		off := int64(w.pick(int((int64(len(shadow))-n)/4096+1))) * 4096
		ws = append(ws, [2]int64{off, n})
	}
	for _, x := range ws {
		for i := x[0]; i < x[0]+x[1]; i += 8 {
			v := w.rng.Uint64()
			for j := range int64(8) {
				shadow[i+j] = byte(v >> (8 * j))
			}
		}
	}
	if err := writeRanges(dev, shadow, ws); err != nil {
		w.fatalf("write %s: %v", dev, err)
	}
}

func alignedBuf(n int) ([]byte, func()) {
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		panic(err)
	}
	return b, func() { unix.Munmap(b) }
}

// writeRanges writes the ranges of data to dev with O_DIRECT.
func writeRanges(dev string, data []byte, ws [][2]int64) error {
	f, err := os.OpenFile(dev, os.O_WRONLY|unix.O_DIRECT, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, x := range ws {
		buf, free := alignedBuf(int(x[1]))
		copy(buf, data[x[0]:x[0]+x[1]])
		_, err := f.WriteAt(buf, x[0])
		free()
		if err != nil {
			return err
		}
	}
	return f.Sync()
}

// readDev reads size bytes of dev with O_DIRECT.
func readDev(dev string, size int64) ([]byte, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_DIRECT, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, free := alignedBuf(int(size))
	defer free()
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	return bytes.Clone(buf), nil
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

func (w *walker) checkData(what, dev string, want []byte) {
	w.t.Helper()
	got, err := readDev(dev, int64(len(want)))
	if err != nil {
		w.fatalf("read %s (%s): %v", what, dev, err)
	}
	if i := firstDiff(got, want); i >= 0 {
		w.fatalf("%s (%s) differs from the model at byte %d", what, dev, i)
	}
}

func (w *walker) devicePath(node, id string) string {
	var p string
	w.must(node, "device path "+id, func() (err error) {
		p, err = w.e.storage[node].DevicePath(w.ctx, id)
		return err
	})
	return p
}

// opNewContent creates a content on one node, writes data, copies it to
// others with read-write exports and WriteExtents, and seals everywhere.
func (w *walker) opNewContent() bool {
	if len(w.contents) >= 8 {
		return false
	}
	id := w.newID("v")
	src := w.snodes[w.pick(3)]
	var others []string
	for _, n := range w.subset(w.snodes, 0) {
		if n != src {
			others = append(others, n)
		}
	}
	all := append([]string{src}, others...)
	undo := func() { w.deleteEverywhere(id, all) }
	kind := "create-blank"
	if w.chance(0.5) {
		kind = "create-root"
	}
	if _, err := w.do(dstOp{Kind: kind, Node: src, Content: id, Size: dstSize}, undo); err != nil {
		return true
	}
	data := make([]byte, dstSize)
	w.writeRandom(w.devicePath(src, id), data)
	var dsts []Remote
	for _, n := range others {
		if _, err := w.do(dstOp{Kind: "create-blank", Node: n, Content: id, Size: dstSize}, undo); err != nil {
			return true
		}
		r, err := w.do(dstOp{Kind: "export", Node: n, Content: id, Host: src, RW: true, PSK: w.psk(src)}, undo)
		if err != nil {
			return true
		}
		dsts = append(dsts, r.(Remote))
	}
	if len(dsts) > 0 {
		rs, err := w.do(dstOp{Kind: "mapped-ranges", Node: src, Content: id}, nil)
		if err != nil {
			return true
		}
		// Not abandoned: only a retry disconnects what an interrupted
		// copy left connected.
		w.do(dstOp{Kind: "write-extents", Node: src, Content: id, Dsts: dsts, PSK: w.psk(src), Ranges: rs.([]extent.Range)}, nil)
	}
	for _, n := range others {
		if _, err := w.do(dstOp{Kind: "unexport", Node: n, Content: id, Host: src, RW: true}, undo); err != nil {
			return true
		}
	}
	for _, n := range all {
		if _, err := w.do(dstOp{Kind: "seal", Node: n, Content: id}, undo); err != nil {
			return true
		}
	}
	c := &mContent{data: data, nodes: map[string]bool{}}
	for _, n := range all {
		c.nodes[n] = true
	}
	w.contents[id] = c
	return true
}

// opSnapshot clones a sealed content on every node that has it.
func (w *walker) opSnapshot() bool {
	parent := pickKey(w, w.contents)
	if parent == "" || len(w.contents) >= 8 {
		return false
	}
	id := w.newID("k")
	nodes := w.nodesOf(parent)
	undo := func() { w.deleteEverywhere(id, nodes) }
	for _, n := range nodes {
		if _, err := w.do(dstOp{Kind: "snapshot", Node: n, Base: parent, Content: id}, undo); err != nil {
			return true
		}
		// A snapshot of sealed content is not sealed, even after a
		// crash between its creation and its tags.
		w.must(n, "state", func() error {
			st, err := w.e.storage[n].State(w.ctx)
			if c := st.Contents[id]; err == nil && (c.Sealed || c.Owner != "" || c.Kind != "content") {
				err = fmt.Errorf("new snapshot %s: %+v", id, c)
			}
			return err
		})
		if _, err := w.do(dstOp{Kind: "seal", Node: n, Content: id}, undo); err != nil {
			return true
		}
	}
	w.contents[id] = &mContent{data: bytes.Clone(w.contents[parent].data), nodes: maps.Clone(w.contents[parent].nodes)}
	return true
}

func (w *walker) attached(id string) bool {
	for _, a := range w.allocs {
		for _, at := range a.atts {
			if at.content == id {
				return true
			}
		}
	}
	return false
}

// opDelete deletes a content that is not attached, on every node (and
// sometimes again, or on a node that does not have it).
func (w *walker) opDelete() bool {
	var cands []string
	for _, id := range sortedKeys(w.contents) {
		if !w.attached(id) {
			cands = append(cands, id)
		}
	}
	if len(cands) == 0 {
		return false
	}
	id := cands[w.pick(len(cands))]
	nodes := w.snodes
	if w.chance(0.5) {
		nodes = w.nodesOf(id)
	}
	for _, n := range nodes {
		w.do(dstOp{Kind: "delete", Node: n, Content: id}, nil)
	}
	delete(w.contents, id)
	delete(w.sent, id)
	for _, n := range w.snodes {
		for k := range w.exports[n] {
			if k.content == id {
				delete(w.exports[n], k)
			}
		}
	}
	return true
}

func (w *walker) exportRO(node, id string) (Remote, bool) {
	r, err := w.do(dstOp{Kind: "export", Node: node, Content: id, Host: w.cn, PSK: w.psk(w.cn)}, nil)
	if err != nil {
		return Remote{}, false
	}
	w.exports[node][expKey{content: id, host: w.cn}] = true
	return r.(Remote), true
}

func (w *walker) opExportRO() bool {
	id := pickKey(w, w.contents)
	if id == "" {
		return false
	}
	nodes := w.nodesOf(id)
	w.exportRO(nodes[w.pick(len(nodes))], id)
	return true
}

// opUnexportRO removes a read-only export, keeping at least one exported
// connected replica for every attachment of the content.
func (w *walker) opUnexportRO() bool {
	type cand struct{ node, id string }
	var cands []cand
	for _, n := range w.snodes {
		for k := range w.exports[n] {
			if !k.rw && w.canUnexport(n, k.content) {
				cands = append(cands, cand{n, k.content})
			}
		}
	}
	if len(cands) == 0 {
		return false
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].node+cands[i].id < cands[j].node+cands[j].id })
	c := cands[w.pick(len(cands))]
	w.do(dstOp{Kind: "unexport", Node: c.node, Content: c.id, Host: w.cn}, nil)
	delete(w.exports[c.node], expKey{content: c.id, host: w.cn})
	return true
}

func (w *walker) canUnexport(node, id string) bool {
	var st *ComputeState
	for allocID, al := range w.allocs {
		for attID, at := range al.atts {
			if at.content != id {
				continue
			}
			if st == nil {
				s := w.state()
				st = &s
			}
			ok := false
			for _, r := range w.livePaths(st.Allocations[allocID].Attachments[attID]) {
				if r != node && w.exports[r][expKey{content: id, host: w.cn}] {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

// livePaths returns the storage nodes of the active origin paths of an
// attachment that have a live controller.
func (w *walker) livePaths(a AttachmentState) []string {
	cs, err := nvmehost.Controllers()
	if err != nil {
		w.fatalf("%v", err)
	}
	live := map[string]bool{}
	for _, c := range cs {
		if c.HostNQN == names.HostNQN(w.cn) && c.State == "live" {
			live[c.SubNQN] = true
		}
	}
	var out []string
	for _, p := range a.Origin {
		if !p.Active {
			continue
		}
		for _, sub := range subsystemsOfDevs([]devnode.Dev{p.Dev}) {
			if n, _, _, ok := names.ParseSubsystemNQN(sub); ok && live[sub] {
				out = append(out, n)
			}
		}
	}
	return out
}

// opRefused checks operations that must be refused on sealed content.
func (w *walker) opRefused() bool {
	id := pickKey(w, w.contents)
	if id == "" {
		return false
	}
	nodes := w.nodesOf(id)
	n := nodes[w.pick(len(nodes))]
	s := w.e.storage[n]
	w.must(n, "refused ops", func() error {
		if _, err := s.Export(w.ctx, id, w.cn, w.psk(w.cn), true); !errors.Is(err, ErrSealed) {
			return fmt.Errorf("read-write export of sealed %s: %v", id, err)
		}
		if w.exports[n][expKey{content: id, host: w.cn}] {
			if _, err := s.ExportSealedRW(w.ctx, id, w.cn, w.psk(w.cn)); !errors.Is(err, ErrInUse) {
				return fmt.Errorf("repair export of exported %s: %v", id, err)
			}
		}
		if _, err := s.PrepareReceive(w.ctx, ReceiveRequest{ContentID: id, SizeBytes: dstSize, Generation: 1}); !errors.Is(err, ErrSealed) {
			return fmt.Errorf("receive into sealed %s: %v", id, err)
		}
		return nil
	})
	w.logf("refused ops on %s@%s", id, n)
	return true
}

// opScrub compares the replicas of a content with each other and with
// the model.
func (w *walker) opScrub() bool {
	id := pickKey(w, w.contents)
	if id == "" {
		return false
	}
	var first [32]byte
	for i, n := range w.nodesOf(id) {
		var h extent.Hashes
		w.must(n, "scrub", func() (err error) { h, err = w.e.storage[n].Scrub(w.ctx, id); return err })
		if i == 0 {
			first = h.Sum()
			w.checkData("content "+id+"@"+n, w.devicePath(n, id), w.contents[id].data)
		} else if h.Sum() != first {
			w.fatalf("scrub: %s differs on %s", id, n)
		}
	}
	w.logf("scrub %s", id)
	return true
}

func (w *walker) opStorageRestart() bool {
	n := w.snodes[w.pick(3)]
	w.restart(n)
	w.logf("restart %s", n)
	return true
}

// Compute operations.

func allocSlot(alloc string) string { return "s" + strings.TrimPrefix(alloc, "a") }

func (w *walker) alloc(id string) *mAlloc {
	if w.allocs[id] == nil {
		w.allocs[id] = &mAlloc{slot: allocSlot(id), atts: map[string]*mAtt{}}
	}
	return w.allocs[id]
}

func (w *walker) opEnsureSlot() bool {
	slot := allocSlot(fmt.Sprintf("a%d", w.pick(3)))
	if _, err := w.do(dstOp{Kind: "ensure-slot", Node: w.cn, Slot: slot}, nil); err == nil {
		w.slots[slot] = true
	}
	return true
}

func (w *walker) attachReq(alloc, att string, a *mAtt, replicas []Remote) *AttachRequest {
	r := &AttachRequest{AllocID: alloc, AttachmentID: att, Generation: a.gen, UID: a.uid, ContentID: a.content,
		Replicas: replicas, PSK: w.psk(w.cn), SlotDisk: a.disk}
	if a.disk >= 0 {
		r.Slot = allocSlot(alloc)
	}
	if w.chance(0.5) {
		r.SizeBytes = dstSize
	}
	return r
}

// remotes returns the read-only exports of a content per the model.
func (w *walker) remotes(id string) []Remote {
	var rs []Remote
	for _, n := range w.snodes {
		if w.exports[n][expKey{content: id, host: w.cn}] {
			rs = append(rs, Remote{Node: n, Addr: w.e.net.Addr(n), Port: 4420, SubNQN: names.SubsystemNQN(n, id, false)})
		}
	}
	return rs
}

var incs atomic.Int64

// opAttach attaches a sealed content, or attaches an existing attachment
// again with the same or a newer generation. The compute node does not
// check generations (the node daemon fences stale commands).
func (w *walker) opAttach() bool {
	allocID := fmt.Sprintf("a%d", w.pick(3))
	attID := fmt.Sprintf("x%d", w.pick(2))
	al := w.alloc(allocID)
	if a := al.atts[attID]; a != nil {
		req := w.attachReq(allocID, attID, a, w.remotes(a.content))
		disk := a.disk
		switch w.pick(2) {
		case 0: // idempotent
		case 1:
			req.Generation++
			if w.chance(0.5) {
				// Move to another free slot disk, or to none.
				disk = -1
				if w.slots[al.slot] {
					disk = w.pick(3) - 1
				}
				for _, o := range al.atts {
					if o != a && o.disk == disk && disk >= 0 {
						disk = a.disk
					}
				}
				req.Slot, req.SlotDisk = "", disk
				if disk >= 0 {
					req.Slot = al.slot
				}
			}
		}
		if len(req.Replicas) == 0 {
			// Attach with an existing overlay does not connect.
			req.Replicas = []Remote{{Node: w.snodes[0], Addr: w.e.net.Addr(w.snodes[0]), SubNQN: names.SubsystemNQN(w.snodes[0], a.content, false)}}
		}
		if _, err := w.do(dstOp{Kind: "attach", Node: w.cn, Attach: req}, nil); err == nil {
			a.gen, a.disk = req.Generation, disk
		}
		return true
	}
	id := pickKey(w, w.contents)
	if id == "" {
		return false
	}
	for _, n := range w.subset(w.nodesOf(id), 1) {
		if _, ok := w.exportRO(n, id); !ok {
			return true
		}
	}
	rs := w.remotes(id)
	a := &mAtt{inc: int(incs.Add(1)), uid: "u-" + allocID + "-" + attID, content: id, gen: int64(1 + w.pick(5)), disk: -1,
		snaps: map[int64][]byte{}}
	busy := false
	if w.slots[al.slot] && w.chance(0.7) {
		a.disk = w.pick(2)
		for _, o := range al.atts {
			if o.disk == a.disk {
				busy = true
			}
		}
	}
	req := w.attachReq(allocID, attID, a, w.subsetRemotes(rs))
	w.connecting(id, req.Replicas)
	undo := func() { w.release(allocID, attID) }
	if busy {
		_, err := w.do(dstOp{Kind: "attach", Node: w.cn, Attach: req}, undo, ErrSlotDiskBusy)
		if !errors.Is(err, errAbandoned) {
			if !errors.Is(err, ErrSlotDiskBusy) {
				w.fatalf("attach onto a busy slot disk: %v", err)
			}
			undo()
		}
		return true
	}
	if _, err := w.do(dstOp{Kind: "attach", Node: w.cn, Attach: req}, undo); err != nil {
		return true
	}
	a.data = bytes.Clone(w.contents[id].data)
	al.atts[attID] = a
	return true
}

// connecting records that the compute node may connect to rs.
func (w *walker) connecting(id string, rs []Remote) {
	if w.conns[id] == nil {
		w.conns[id] = map[string]bool{}
	}
	for _, r := range rs {
		w.conns[id][r.Node] = true
	}
}

func (w *walker) subsetRemotes(rs []Remote) []Remote {
	out := slices.Clone(rs)
	w.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:1+w.pick(len(out))]
}

// pickAtt returns a random attachment of the model.
func (w *walker) pickAtt(filter func(*mAtt) bool) (string, string, *mAtt) {
	var cands [][2]string
	for _, al := range sortedKeys(w.allocs) {
		for _, at := range sortedKeys(w.allocs[al].atts) {
			if filter == nil || filter(w.allocs[al].atts[at]) {
				cands = append(cands, [2]string{al, at})
			}
		}
	}
	if len(cands) == 0 {
		return "", "", nil
	}
	c := cands[w.pick(len(cands))]
	return c[0], c[1], w.allocs[c[0]].atts[c[1]]
}

// state rescans the compute node.
func (w *walker) state() ComputeState {
	w.t.Helper()
	var st ComputeState
	w.must(w.cn, "rescan", func() (err error) { st, err = w.e.compute.Rescan(w.ctx); return err })
	return st
}

func (w *walker) opWrite() bool {
	allocID, attID, a := w.pickAtt(nil)
	if a == nil {
		return false
	}
	st := w.state()
	as := st.Allocations[allocID].Attachments[attID]
	dev, name := as.Dev, "ov-"+allocID+"-"+attID
	if a.disk >= 0 && w.chance(0.5) {
		dev, name = st.Slots[allocSlot(allocID)][a.disk].Dev, "sd-"+allocID+"-"+attID
	}
	p, err := devnode.Ensure(w.ccfg.DevDir, name, dev)
	if err != nil {
		w.fatalf("%v", err)
	}
	w.writeRandom(p, a.data)
	w.logf("guest write %s/%s via %s", allocID, attID, name)
	return true
}

// opCapture captures a subset of an allocation's attachments, with a new
// sequence number or the last one again.
func (w *walker) opCapture() bool {
	allocID, _, _ := w.pickAtt(nil)
	if allocID == "" {
		return false
	}
	al := w.allocs[allocID]
	refs := w.subset(sortedKeys(al.atts), 1)
	seq := al.seq + 1
	if al.seq > 0 && w.chance(0.2) {
		seq = al.seq
	}
	al.seq = max(al.seq, seq)
	forget := func() {
		for _, r := range refs {
			w.dropSnap(al.atts[r], seq)
		}
	}
	undo := func() {
		for _, r := range refs {
			w.do(dstOp{Kind: "drop", Node: w.cn, Alloc: allocID, Att: r, Seq: seq}, nil)
		}
		forget()
	}
	complete := true
	for _, r := range refs {
		if al.atts[r].snaps[seq] == nil {
			complete = false
		}
	}
	_, err := w.do(dstOp{Kind: "capture", Node: w.cn, Alloc: allocID, Refs: refs, Seq: seq}, undo, ErrSuspendBudget)
	switch {
	case errors.Is(err, ErrSuspendBudget):
		forget()
	case err == nil && !complete:
		for _, r := range refs {
			a := al.atts[r]
			w.dropSnap(a, seq)
			a.snaps[seq] = bytes.Clone(a.data)
		}
	}
	return true
}

// dropSnap forgets snapshot seq of a, and that contents sent from it
// can be the base of a delta (a snapshot taken again has other data).
func (w *walker) dropSnap(a *mAtt, seq int64) {
	delete(a.snaps, seq)
	for id, f := range w.sent {
		if f.inc == a.inc && f.seq == seq {
			delete(w.sent, id)
		}
	}
}

func (w *walker) opDrop() bool {
	allocID, attID, a := w.pickAtt(func(a *mAtt) bool { return len(a.snaps) > 0 })
	if a == nil {
		return false
	}
	seqs := slices.Sorted(maps.Keys(a.snaps))
	seq := seqs[w.pick(len(seqs))]
	if w.chance(0.1) {
		seq = 1000 // missing
	}
	if _, err := w.do(dstOp{Kind: "drop", Node: w.cn, Alloc: allocID, Att: attID, Seq: seq}, nil); err == nil {
		w.dropSnap(a, seq)
	}
	return true
}

// opSend writes a local snapshot (a delta against the attachment's
// input content or against an earlier snapshot that was sent) into a new
// content on one or two storage nodes, and seals it.
func (w *walker) opSend() bool {
	allocID, attID, a := w.pickAtt(func(a *mAtt) bool { return len(a.snaps) > 0 })
	if a == nil || len(w.contents) >= 10 {
		return false
	}
	seqs := slices.Sorted(maps.Keys(a.snaps))
	seq := seqs[w.pick(len(seqs))]
	base, baseSeq := a.content, int64(0)
	for _, id := range sortedKeys(w.sent) {
		s := w.sent[id]
		if s.inc == a.inc && s.seq < seq && a.snaps[s.seq] != nil && w.contents[id] != nil && w.chance(0.5) {
			base, baseSeq = id, s.seq
		}
	}
	if w.contents[base] == nil {
		return false // the input content was deleted after attach
	}
	dsts := w.subset(w.nodesOf(base), 1)
	if len(dsts) > 2 {
		dsts = dsts[:2]
	}
	var size int64
	w.must(w.cn, "snapshot path", func() (err error) {
		_, size, err = w.e.compute.LocalSnapshotPath(w.ctx, allocID, attID, seq)
		return err
	})
	res, err := w.do(dstOp{Kind: "local-delta", Node: w.cn, Alloc: allocID, Att: attID, Seq: seq, BaseSeq: baseSeq}, nil, ErrLeftOnly)
	var ranges []extent.Range
	if errors.Is(err, ErrLeftOnly) {
		ranges = []extent.Range{{Off: 0, Len: size}}
	} else {
		ranges = res.([]extent.Range)
	}
	id := w.newID("s")
	gen := int64(2 + w.pick(3))
	undo := func() { w.deleteEverywhere(id, dsts) }
	var remotes []Remote
	for _, n := range dsts {
		req := ReceiveRequest{ContentID: id, BaseContentID: base, SizeBytes: size, Owner: "o", Generation: gen}
		if w.chance(0.2) {
			// An abandoned attempt of an older generation.
			old := req
			old.Generation--
			if _, err := w.do(dstOp{Kind: "prepare-receive", Node: n, Receive: &old}, undo); err != nil {
				return true
			}
		}
		if _, err := w.do(dstOp{Kind: "prepare-receive", Node: n, Receive: &req}, undo); err != nil {
			return true
		}
		if w.chance(0.2) {
			stale := req
			stale.Generation--
			w.do(dstOp{Kind: "prepare-receive", Node: n, Receive: &stale}, nil, ErrStaleGeneration)
		}
		if w.chance(0.1) {
			w.logf("abandon transfer of %s", id)
			undo()
			return true
		}
		r, err := w.do(dstOp{Kind: "export", Node: n, Content: id, Host: w.cn, RW: true, PSK: w.psk(w.cn)}, undo)
		if err != nil {
			return true
		}
		remotes = append(remotes, r.(Remote))
	}
	// Not abandoned: only a retry disconnects what an interrupted write
	// left connected.
	w.do(dstOp{Kind: "write-snapshot", Node: w.cn, Alloc: allocID, Att: attID, Seq: seq, Dsts: remotes, PSK: w.psk(w.cn), Ranges: ranges}, nil)
	for _, n := range dsts {
		if _, err := w.do(dstOp{Kind: "unexport", Node: n, Content: id, Host: w.cn, RW: true}, undo); err != nil {
			return true
		}
	}
	for _, n := range dsts {
		if _, err := w.do(dstOp{Kind: "seal", Node: n, Content: id}, undo); err != nil {
			return true
		}
	}
	c := &mContent{data: bytes.Clone(a.snaps[seq]), nodes: map[string]bool{}}
	for _, n := range dsts {
		c.nodes[n] = true
	}
	w.contents[id] = c
	w.sent[id] = sentFrom{inc: a.inc, seq: seq}
	w.logf("sent %s/%s seq %d (base %s seq %d, %d ranges) as %s to %v", allocID, attID, seq, base, baseSeq, len(ranges), id, dsts)
	return true
}

func (w *walker) opRelease() bool {
	allocID, attID, a := w.pickAtt(nil)
	if a == nil {
		return false
	}
	if w.chance(0.1) {
		w.release(allocID, "x9")
	} else {
		w.release(allocID, attID)
	}
	return true
}

// release releases an attachment and updates the model.
func (w *walker) release(allocID, attID string) {
	if _, err := w.do(dstOp{Kind: "release", Node: w.cn, Alloc: allocID, Att: attID}, nil); err != nil {
		return
	}
	delete(w.alloc(allocID).atts, attID)
}

func (w *walker) cleanup(allocID string) {
	if _, err := w.do(dstOp{Kind: "cleanup", Node: w.cn, Alloc: allocID}, nil); err != nil {
		return
	}
	w.alloc(allocID).atts = map[string]*mAtt{}
}

func (w *walker) opCleanup() bool {
	w.cleanup(fmt.Sprintf("a%d", w.pick(3)))
	return true
}

// opRefresh exports the content from another replica and refreshes the
// paths of an attachment.
func (w *walker) opRefresh() bool {
	allocID, attID, a := w.pickAtt(nil)
	if a == nil || w.contents[a.content] == nil {
		return false
	}
	nodes := w.nodesOf(a.content)
	if _, ok := w.exportRO(nodes[w.pick(len(nodes))], a.content); !ok {
		return true
	}
	req := w.attachReq(allocID, attID, a, w.remotes(a.content))
	w.connecting(a.content, req.Replicas)
	res, err := w.do(dstOp{Kind: "refresh", Node: w.cn, Attach: req}, nil)
	if err == nil {
		if res.(int) < 1 {
			w.fatalf("refresh: %d active paths", res)
		}
	}
	return true
}

// opRace runs a release concurrently with an Attach of a new attachment
// or with RefreshPaths of an existing one (no faults), then takes the
// outcome from Rescan. The usual checks catch leaked connections.
func (w *walker) opRace() bool {
	allocID, attID, a := w.pickAtt(nil)
	var req *AttachRequest
	if a == nil || w.contents[a.content] == nil || w.chance(0.5) {
		allocID, attID = fmt.Sprintf("a%d", w.pick(3)), "x2"
		id := pickKey(w, w.contents)
		if id == "" || w.alloc(allocID).atts[attID] != nil {
			return false
		}
		nodes := w.nodesOf(id)
		if _, ok := w.exportRO(nodes[w.pick(len(nodes))], id); !ok {
			return true
		}
		a = &mAtt{inc: int(incs.Add(1)), uid: "u-" + allocID + "-" + attID, content: id, gen: 1, disk: -1, snaps: map[int64][]byte{}}
		req = w.attachReq(allocID, attID, a, w.remotes(id))
	} else {
		req = w.attachReq(allocID, attID, a, w.remotes(a.content))
	}
	w.connecting(a.content, req.Replicas)
	_, existed := w.alloc(allocID).atts[attID]
	kind := "attach"
	if existed {
		kind = "refresh"
	}
	delay := time.Duration(w.pick(300)) * time.Millisecond
	var err1, err2 error
	done := make(chan struct{})
	go func() {
		_, err1 = w.run(dstOp{Kind: kind, Node: w.cn, Attach: req})
		close(done)
	}()
	time.Sleep(delay)
	_, err2 = w.run(dstOp{Kind: "release", Node: w.cn, Alloc: allocID, Att: attID})
	<-done
	w.logf("%s %s/%s || release after %v: %v, %v", kind, allocID, attID, delay, err1, err2)
	for i := 0; isBusy(err2) && i < 3; i++ {
		time.Sleep(time.Second)
		_, err2 = w.run(dstOp{Kind: "release", Node: w.cn, Alloc: allocID, Att: attID})
	}
	if err2 != nil {
		w.fatalf("release: %v", err2)
	}
	k := attKey(allocID, attID)
	delete(w.alloc(allocID).atts, attID)
	if _, ok := w.state().Allocations[allocID].Attachments[attID]; ok {
		if kind != "attach" || err1 != nil {
			w.fatalf("attachment %s survived: %s: %v", k, kind, err1)
		}
		a.data = bytes.Clone(w.contents[a.content].data)
		w.alloc(allocID).atts[attID] = a // the release came first
	}
	// A failed attach is fine (the caller retries or has released); the
	// checks after this step find anything it left behind.
	return true
}

func (w *walker) opComputeRestart() bool {
	w.restart(w.cn)
	w.logf("restart %s", w.cn)
	return true
}

// Invariants.

// check compares the nodes with the model. With full it also compares
// all data and the pool's thin IDs.
func (w *walker) check(full bool) {
	w.t.Helper()
	w.checkStorage(full)
	w.checkCompute(full)
	w.checkConnections()
}

func (w *walker) checkStorage(full bool) {
	w.t.Helper()
	for _, n := range w.snodes {
		var st State
		w.must(n, "state", func() (err error) { st, err = w.e.storage[n].State(w.ctx); return err })
		want := map[string]bool{}
		for id, c := range w.contents {
			if c.nodes[n] {
				want[id] = true
			}
		}
		for id, c := range st.Contents {
			if !want[id] {
				w.fatalf("%s has content %s (%+v) the model does not have", n, id, c)
			}
			if !c.Sealed || c.Receiving || c.Size != dstSize {
				w.fatalf("%s: content %+v", n, c)
			}
		}
		for id := range want {
			if _, ok := st.Contents[id]; !ok {
				w.fatalf("%s lacks content %s", n, id)
			}
		}
		got := map[expKey]bool{}
		for _, x := range st.Exports {
			if len(x.Hosts) == 0 {
				w.fatalf("%s: export %+v without hosts", n, x)
			}
			for _, h := range x.Hosts {
				got[expKey{content: x.ContentID, host: h, rw: x.RW}] = true
			}
		}
		if !mapsEqual(got, w.exports[n]) {
			w.fatalf("%s exports %v, model %v", n, got, w.exports[n])
		}
		if full {
			for id := range want {
				w.checkData("content "+id+"@"+n, w.devicePath(n, id), w.contents[id].data)
			}
		}
	}
}

func mapsEqual[K comparable](a, b map[K]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func (w *walker) checkCompute(full bool) {
	w.t.Helper()
	st := w.state()
	if !st.Pool || len(st.UnknownThins) > 0 || len(st.Resumed) > 0 {
		w.fatalf("compute: pool %v unknown thins %v resumed %v", st.Pool, st.UnknownThins, st.Resumed)
	}
	wantDevs := 3 + 2*len(w.slots)
	for allocID, al := range w.allocs {
		for attID, a := range al.atts {
			wantDevs += 2 + len(a.snaps)
			s, ok := st.Allocations[allocID].Attachments[attID]
			if !ok {
				w.fatalf("attachment %s/%s missing: %+v", allocID, attID, st.Allocations)
			}
			wantSlot, wantDisk := "", -1
			if a.disk >= 0 {
				wantSlot, wantDisk = al.slot, a.disk
			}
			if s.Generation != a.gen || s.ContentID != a.content || s.UID != a.uid || s.Slot != wantSlot || s.SlotDisk != wantDisk ||
				s.ThinID == 0 || s.OriginDev == (devnode.Dev{}) || s.HostLink == "" || s.Sectors != dstSize/512 {
				w.fatalf("attachment %s/%s: %+v, model %+v", allocID, attID, s, *a)
			}
			var seqs []int64
			for _, ls := range s.LocalSnaps {
				if ls.State != SnapReady {
					w.fatalf("attachment %s/%s: snapshot %+v", allocID, attID, ls)
				}
				seqs = append(seqs, ls.Seq)
			}
			if want := slices.Sorted(maps.Keys(a.snaps)); !slices.Equal(seqs, want) {
				w.fatalf("attachment %s/%s: snapshots %v, model %v", allocID, attID, seqs, want)
			}
			if a.disk >= 0 {
				if d := st.Slots[al.slot][a.disk]; d.AllocID != allocID || d.AttachmentID != attID {
					w.fatalf("slot %s disk %d maps %+v, want %s/%s", al.slot, a.disk, d, allocID, attID)
				}
			}
			if full {
				p, err := devnode.Ensure(w.ccfg.DevDir, "chk-ov", s.Dev)
				if err != nil {
					w.fatalf("%v", err)
				}
				w.checkData("overlay "+allocID+"/"+attID, p, a.data)
				for seq, data := range a.snaps {
					var p string
					w.must(w.cn, "snapshot path", func() (err error) {
						p, _, err = w.e.compute.LocalSnapshotPath(w.ctx, allocID, attID, seq)
						return err
					})
					w.checkData(fmt.Sprintf("snapshot %s/%s/%d", allocID, attID, seq), p, data)
				}
			}
		}
	}
	for allocID, al := range st.Allocations {
		for attID := range al.Attachments {
			if w.allocs[allocID] == nil || w.allocs[allocID].atts[attID] == nil {
				w.fatalf("compute has attachment %s/%s the model does not have: %+v", allocID, attID, al.Attachments[attID])
			}
		}
	}
	for slot, disks := range st.Slots {
		if !w.slots[slot] || len(disks) != 2 {
			w.fatalf("slot %s: %+v", slot, disks)
		}
		for i, d := range disks {
			if d.AllocID != "" && (w.allocs[d.AllocID] == nil || w.allocs[d.AllocID].atts[d.AttachmentID] == nil ||
				w.allocs[d.AllocID].atts[d.AttachmentID].disk != i) {
				w.fatalf("slot %s disk %d maps %+v", slot, i, d)
			}
		}
	}
	if len(st.Slots) != len(w.slots) {
		w.fatalf("slots %v, model %v", st.Slots, w.slots)
	}
	infos, err := dm.List(w.ctx, names.DMPrefix(w.cn))
	if err != nil {
		w.fatalf("%v", err)
	}
	if len(infos) != wantDevs {
		var ns []string
		for _, i := range infos {
			ns = append(ns, i.Name)
		}
		w.fatalf("%d device-mapper devices, want %d: %v", len(infos), wantDevs, ns)
	}
	if full {
		var ids []uint32
		w.must(w.cn, "thin IDs", func() error {
			meta, err := w.e.compute.metaPath(w.ctx)
			if err != nil {
				return err
			}
			ids, err = dm.ThinIDs(w.ctx, names.Pool(w.cn), meta)
			return err
		})
		if want := wantDevs - 3 - 2*len(w.slots) - w.attCount(); len(ids) != want {
			w.fatalf("pool has thin IDs %v, want %d", ids, want)
		}
	}
}

func (w *walker) attCount() int {
	n := 0
	for _, al := range w.allocs {
		n += len(al.atts)
	}
	return n
}

// checkConnections checks that no NVMe controller, TLS key or nvmet
// subsystem is left that the model does not explain.
func (w *walker) checkConnections() {
	w.t.Helper()
	// Contents the compute node may be connected to, and from where.
	allowed := map[string]bool{}
	for id, nodes := range w.conns {
		if !w.attached(id) {
			delete(w.conns, id) // the last release disconnected
			continue
		}
		for n := range nodes {
			allowed[names.SubsystemNQN(n, id, false)] = true
		}
	}
	cs, err := nvmehost.Controllers()
	if err != nil {
		w.fatalf("%v", err)
	}
	for _, c := range cs {
		node, _, _, ok := names.ParseSubsystemNQN(c.SubNQN)
		if !ok || !w.e.net.IsNode(node) {
			continue
		}
		if c.HostNQN != names.HostNQN(w.cn) || !allowed[c.SubNQN] {
			w.fatalf("controller %s %s -> %s (%s) is not in the model", c.Name, c.HostNQN, c.SubNQN, c.State)
		}
	}
	kr, err := tlskeys.Keyring()
	if err != nil {
		w.fatalf("%v", err)
	}
	keys, err := tlskeys.List(kr)
	if err != nil {
		w.fatalf("%v", err)
	}
	targetKeys := map[string]bool{}
	for _, k := range keys {
		f := strings.Fields(k.Description)
		if len(f) < 3 || f[0] != "NVMe0R01" {
			continue
		}
		hostNQN, sub := f[1], f[2]
		node, id, rw, ok := names.ParseSubsystemNQN(sub)
		if !ok || !w.e.net.IsNode(node) {
			continue
		}
		host, _ := strings.CutPrefix(hostNQN, names.NQNPrefix+":host:")
		if len(f) == 4 && f[3] == "target" {
			if !w.exports[node][expKey{content: id, host: host, rw: rw}] {
				w.fatalf("target key %q is not in the model", k.Description)
			}
			targetKeys[k.Description] = true
			continue
		}
		if host != w.cn || !allowed[sub] {
			w.fatalf("host key %q is not in the model", k.Description)
		}
	}
	for _, n := range w.snodes {
		for x := range w.exports[n] {
			d := tlskeys.Description(tlskeys.Identity(names.HostNQN(x.host), names.SubsystemNQN(n, x.content, x.rw)), tlskeys.Target)
			if !targetKeys[d] {
				w.fatalf("export %+v on %s has no target key", x, n)
			}
		}
	}
}

// teardown releases and deletes everything through the API and checks
// that nothing is left but the pools.
func (w *walker) teardown() {
	w.logPrefix = "teardown"
	for _, allocID := range sortedKeys(w.allocs) {
		w.cleanup(allocID)
	}
	for _, slot := range sortedKeys(w.slots) {
		w.must(w.cn, "remove slot", func() error { return w.e.compute.RemoveSlot(w.ctx, slot) })
		delete(w.slots, slot)
	}
	for _, id := range sortedKeys(w.contents) {
		for _, n := range w.snodes {
			w.do(dstOp{Kind: "delete", Node: n, Content: id}, nil)
		}
		delete(w.contents, id)
	}
	for _, n := range w.snodes {
		w.exports[n] = map[expKey]bool{}
	}
	w.check(true)
	t, err := nvmet.New("")
	if err != nil {
		w.fatalf("%v", err)
	}
	subs, _ := t.List(func(s string) bool {
		x, _, _, ok := names.ParseSubsystemNQN(s)
		return ok && w.e.net.IsNode(x)
	})
	if len(subs) > 0 {
		w.fatalf("nvmet subsystems left: %+v", subs)
	}
	for _, n := range w.snodes {
		infos, _ := dm.List(w.ctx, names.DMPrefix(n))
		if len(infos) > 0 {
			w.fatalf("device-mapper devices of %s left: %+v", n, infos)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(w.ccfg.VolumeLinkDir, "*")); len(left) > 0 {
		w.fatalf("host links left: %v", left)
	}
}
