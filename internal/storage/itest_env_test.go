package storage

// Test environment for root integration tests (BLIP_ROOT_TESTS=1): network
// namespaces for 3 storage nodes and 1 compute node on a bridge, loop
// devices under /mnt/nvme2/blip/storage, and one tlshd per namespace. The
// generic parts live in package storagetest.

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/storagetest"
	"github.com/example/blip/internal/storage/tlskeys"
)

func itBase() string {
	if d := os.Getenv("BLIP_TEST_DIR"); d != "" {
		return d
	}
	return "/mnt/nvme2/blip/storage/itest"
}

var itNet = &storagetest.Net{
	Prefix: "blipt", Bridge: "blipt0", Subnet: "10.98.0",
	Nodes: []string{"ts1", "ts2", "ts3", "tc1"}, Dir: itBase(),
}

func inNS(node string, fn func() error) error { return itNet.InNS(node, fn) }

func nodeAddr(node string) string { return itNet.Addr(node) }

type env struct {
	t          *testing.T
	net        *storagetest.Net
	clusterKey []byte
	storage    map[string]*StorageNode
	compute    *ComputeNode
	cnode      string // compute node name, the last node of net
}

func (e *env) psk(node string) []byte { return tlskeys.DerivePSK(e.clusterKey, names.HostNQN(node)) }

func newEnv(t *testing.T) *env { return newEnvOn(t, itNet, 2<<30, 1<<30) }

// newEnvOn sets up net: every node but the last is a storage node with a
// storageSize loop device, the last one is the compute node.
func newEnvOn(t *testing.T, net *storagetest.Net, storageSize, computeSize int64) *env {
	storagetest.NeedRoot(t)
	e := &env{t: t, net: net, storage: map[string]*StorageNode{}, cnode: net.Nodes[len(net.Nodes)-1]}
	e.clusterKey = make([]byte, 32)
	rand.Read(e.clusterKey)
	net.Sweep()
	t.Cleanup(func() { e.teardown() })
	net.Up(t)

	tmo := Timeouts{CtrlLoss: 10, FastIOFail: 2}
	for _, n := range net.Nodes[:len(net.Nodes)-1] {
		s, err := NewStorageNode(e.storageConfig(n, net.Loop(t, n+".img", storageSize), tmo))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.LVM().Setup(context.Background(), 64<<20); err != nil {
			t.Fatal(err)
		}
		e.storage[n] = s
	}
	loop := net.Loop(t, e.cnode+".img", computeSize)
	c, err := NewComputeNode(e.computeConfig(loop, tmo))
	if err != nil {
		t.Fatal(err)
	}
	e.compute = c
	return e
}

// storageConfig is the config of storage node n.
func (e *env) storageConfig(n, loop string, tmo Timeouts) StorageConfig {
	return StorageConfig{
		Node: n, Addr: e.net.Addr(n), VG: e.net.Prefix + "-" + n, Devices: []string{loop},
		DevDir: filepath.Join(e.net.Dir, "dev-"+n), WorkDir: e.net.Dir, Timeouts: tmo,
	}
}

// computeConfig is the config of the compute node; tests that simulate a
// daemon restart make a second ComputeNode with it.
func (e *env) computeConfig(loop string, tmo Timeouts) ComputeConfig {
	n := e.cnode
	return ComputeConfig{
		Node: n, Device: loop, DevDir: filepath.Join(e.net.Dir, "dev-"+n), Timeouts: tmo,
		DisksPerSlot: 2, JournalPath: filepath.Join(e.net.Dir, "journal-"+n+".json"),
		VolumeLinkDir: filepath.Join(e.net.Dir, "volumes-"+n),
	}
}

func (e *env) teardown() {
	ctx := context.Background()
	if e.compute != nil {
		if err := e.net.InNS(e.cnode, func() error { return e.compute.RemovePool(ctx) }); err != nil {
			e.t.Logf("teardown compute: %v", err)
		}
		_ = os.Remove(e.compute.cfg.JournalPath)
	}
	for n, s := range e.storage {
		_ = e.net.InNS(n, func() error {
			st, err := s.State(ctx)
			if err == nil {
				for id := range st.Contents {
					if err := s.Delete(ctx, id); err != nil {
						e.t.Logf("teardown %s %s: %v", n, id, err)
					}
				}
			}
			_ = s.target.RemovePort(s.port.ID)
			return nil
		})
		if err := s.LVM().RemoveVG(ctx); err != nil {
			e.t.Logf("teardown VG %s: %v", n, err)
		}
	}
	e.net.Down()
}
