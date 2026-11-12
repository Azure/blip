package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmehost"
	"github.com/example/blip/internal/storage/tlskeys"
)

// BlockSize is the thin block and chunk size: 64KiB.
const BlockSize = 64 << 10

// Remote is one export as seen from a host.
type Remote struct {
	Node   string // storage node name
	Addr   string // storage traffic address
	Port   int    // TCP port, default 4420
	SubNQN string
}

func (r Remote) port() int {
	if r.Port == 0 {
		return 4420
	}
	return r.Port
}

// Timeouts for NVMe connections, in seconds. Zero values use the
// nvmehost defaults (ctrl_loss_tmo 60, fast_io_fail_tmo 5) and an I/O
// timeout of 30.
type Timeouts struct {
	CtrlLoss   int
	FastIOFail int
	IO         int
}

func (t Timeouts) io() time.Duration {
	if t.IO > 0 {
		return time.Duration(t.IO) * time.Second
	}
	return 30 * time.Second
}

// host is the NVMe host side shared by storage and compute nodes.
type host struct {
	node    string
	hostNQN string
	hostID  string
	devDir  string
	tmo     Timeouts
}

func newHost(node, devDir string, tmo Timeouts) (*host, error) {
	if err := names.Check("node name", node); err != nil {
		return nil, err
	}
	if devDir == "" {
		return nil, errors.New("DevDir is required")
	}
	if err := os.MkdirAll(devDir, 0o700); err != nil {
		return nil, err
	}
	nqn := names.HostNQN(node)
	return &host{node: node, hostNQN: nqn, hostID: names.HostID(nqn), devDir: devDir, tmo: tmo}, nil
}

func keyring() (int, error) { return tlskeys.Keyring() }

func (h *host) conn(r Remote, kr, key int) nvmehost.Conn {
	return nvmehost.Conn{
		Addr: r.Addr, Svc: r.port(), SubNQN: r.SubNQN, HostNQN: h.hostNQN, HostID: h.hostID,
		Keyring: kr, TLSKey: key, CtrlLossTmo: h.tmo.CtrlLoss, FastIOFailTmo: h.tmo.FastIOFail,
	}
}

// path is a connected namespace.
type path struct {
	Remote Remote
	Ctrl   string
	NS     nvmehost.Namespace
	Node   string // device node in devDir
}

// connect inserts the host key and connects to r, then waits for the
// namespace block device. If it fails and there was no live controller
// before, it removes the controller and key it made.
func (h *host) connect(ctx context.Context, r Remote, psk []byte) (_ path, err error) {
	kr, err := keyring()
	if err != nil {
		return path{}, err
	}
	x, ok, _ := nvmehost.Find(h.conn(r, kr, 0))
	if !ok || x.State != "live" {
		defer func() {
			if err != nil {
				err = errors.Join(err, h.disconnect(r.SubNQN))
			}
		}()
	}
	key, err := tlskeys.Insert(kr, tlskeys.Identity(h.hostNQN, r.SubNQN), tlskeys.Host, psk)
	if err != nil {
		return path{}, err
	}
	c, err := nvmehost.Connect(h.conn(r, kr, key))
	if err != nil {
		return path{}, fmt.Errorf("connect to %s (%s): %w", r.Node, r.Addr, err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ns, err := nvmehost.WaitNamespace(wctx, c.Name)
	if err != nil {
		return path{}, err
	}
	if err := nvmehost.SetIOTimeout(c.Name, h.tmo.io()); err != nil {
		log.Printf("set I/O timeout of %s: %v", c.Name, err)
	}
	node, err := devnode.Ensure(h.devDir, ns.Name, ns.Dev)
	if err != nil {
		return path{}, err
	}
	return path{Remote: r, Ctrl: c.Name, NS: ns, Node: node}, nil
}

// disconnect removes every controller of ours for subNQN and its key.
func (h *host) disconnect(subNQN string) error {
	err := nvmehost.DisconnectAll(func(c nvmehost.Controller) bool {
		return c.HostNQN == h.hostNQN && c.SubNQN == subNQN
	})
	kr, kerr := keyring()
	if kerr != nil {
		return errors.Join(err, kerr)
	}
	return errors.Join(err, tlskeys.Remove(kr, tlskeys.Identity(h.hostNQN, subNQN), tlskeys.Host))
}

// waitGone waits until no controller of ours for subNQN exists.
func (h *host) waitGone(ctx context.Context, subNQN string) error {
	for {
		cs, err := nvmehost.Controllers()
		if err != nil {
			return err
		}
		found := false
		for _, c := range cs {
			if c.HostNQN == h.hostNQN && c.SubNQN == subNQN {
				found = true
			}
		}
		if !found {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("controllers for %s still present: %w", subNQN, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// subsystemsOfDevs returns the subsystem NQNs behind NVMe namespace
// devices (used to find what a multipath device is connected to).
func subsystemsOfDevs(devs []devnode.Dev) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range devs {
		name, err := devnode.SysName(d)
		if err != nil {
			continue
		}
		// /sys/class/block/nvme8n1/device -> controller or subsystem;
		// both have subsysnqn.
		b, err := os.ReadFile(filepath.Join("/sys/class/block", name, "device", "subsysnqn"))
		if err != nil {
			continue
		}
		n := strings.TrimSpace(string(b))
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
