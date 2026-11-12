// Package storagetest holds helpers for root integration tests of Blip
// storage (BLIP_ROOT_TESTS=1): network namespaces on a bridge, one tlshd
// per namespace, loop devices, and a sweep that removes what a crashed run
// left behind. It is used by tests only.
package storagetest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/lvm"
	"github.com/example/blip/internal/storage/names"
	"github.com/example/blip/internal/storage/nvmehost"
	"github.com/example/blip/internal/storage/nvmet"
	"github.com/example/blip/internal/storage/tlskeys"
)

// NeedRoot skips the test unless BLIP_ROOT_TESTS=1, fails it unless it
// runs as root, and skips it when tools or modules are missing.
func NeedRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("BLIP_ROOT_TESTS") != "1" {
		t.Skip("set BLIP_ROOT_TESTS=1 and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("BLIP_ROOT_TESTS=1 needs root")
	}
	// Test VGs live on private loop devices: keep their LVM locks apart
	// from the host's so a hung host LVM command cannot block the tests.
	if os.Getenv("BLIP_LVM_LOCKING_DIR") == "" {
		d := "/run/blip-itest-lvm-lock"
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		os.Setenv("BLIP_LVM_LOCKING_DIR", d)
	}
	for _, b := range []string{"tlshd", "keyctl", "dmsetup", "lvm", "thin_dump", "thin_delta", "mkfs.ext4", "ip", "losetup", "nsenter"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not found", b)
		}
	}
	for _, m := range []string{"nvmet", "nvmet-tcp", "nvme-tcp", "nvme-keyring", "tls", "dm-thin-pool", "dm-multipath", "loop"} {
		if out, err := exec.Command("modprobe", m).CombinedOutput(); err != nil {
			t.Skipf("modprobe %s: %v %s", m, err, out)
		}
	}
}

// Sh runs a command with a 2 minute timeout and fails the test on error.
func Sh(t testing.TB, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// ShQuiet runs a command with a 1 minute timeout and ignores errors.
func ShQuiet(name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = exec.CommandContext(ctx, name, args...).Run()
}

// Net is a set of test nodes, each in its own network namespace, joined
// by a bridge in the initial namespace.
type Net struct {
	Prefix string   // namespace and VG prefix, for example "blipt"
	Bridge string   // bridge name, at most 15 bytes
	Subnet string   // first three octets, for example "10.98.0"
	Nodes  []string // node names
	Dir    string   // files: loop backing files, tlshd config and logs

	tlshd []*exec.Cmd
	loops []string
}

// NS is the network namespace of node.
func (n *Net) NS(node string) string { return n.Prefix + "-" + node }

// Addr is the address of node.
func (n *Net) Addr(node string) string {
	for i, x := range n.Nodes {
		if x == node {
			return fmt.Sprintf("%s.%d", n.Subnet, i+1)
		}
	}
	panic(node)
}

// IsNode reports whether node is one of ours.
func (n *Net) IsNode(node string) bool {
	for _, x := range n.Nodes {
		if x == node {
			return true
		}
	}
	return false
}

// Up creates the directory, bridge, namespaces and tlshd processes.
func (n *Net) Up(t testing.TB) {
	if err := os.MkdirAll(n.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	Sh(t, "ip", "link", "add", n.Bridge, "type", "bridge")
	Sh(t, "ip", "addr", "add", n.Subnet+".254/24", "dev", n.Bridge)
	Sh(t, "ip", "link", "set", n.Bridge, "up")
	for _, x := range n.Nodes {
		ns := n.NS(x)
		Sh(t, "ip", "netns", "add", ns)
		Sh(t, "ip", "link", "add", n.veth(x), "type", "veth", "peer", "name", "eth0", "netns", ns)
		Sh(t, "ip", "link", "set", n.veth(x), "master", n.Bridge, "up")
		Sh(t, "ip", "-n", ns, "addr", "add", n.Addr(x)+"/24", "dev", "eth0")
		Sh(t, "ip", "-n", ns, "link", "set", "eth0", "up")
		Sh(t, "ip", "-n", ns, "link", "set", "lo", "up")
		n.startTlshd(t, x)
	}
}

func (n *Net) veth(node string) string {
	v := n.Prefix[:min(len(n.Prefix), 4)] + "-" + node
	return v[:min(len(v), 15)]
}

func (n *Net) tlshdConf() string { return filepath.Join(n.Dir, "tlshd.conf") }

func (n *Net) startTlshd(t testing.TB, node string) {
	if err := os.WriteFile(n.tlshdConf(), []byte(tlskeys.TlshdConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	logf, _ := os.Create(filepath.Join(n.Dir, "tlshd-"+node+".log"))
	// tlshd needs its own session keyring with .nvme linked into it.
	c := exec.Command("nsenter", "--net=/run/netns/"+n.NS(node), "keyctl", "session", "-", "tlshd", "-s", "-c", n.tlshdConf())
	c.Stdout, c.Stderr = logf, logf
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	n.tlshd = append(n.tlshd, c)
}

// Loop creates a sparse file under Dir and a loop device for it.
func (n *Net) Loop(t testing.TB, name string, size int64) string {
	p := filepath.Join(n.Dir, name)
	os.Remove(p)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(size)
	f.Close()
	l := Sh(t, "losetup", "-f", "--show", p)
	n.loops = append(n.loops, l)
	return l
}

// InNS runs fn on a thread that is in the network namespace of node.
func (n *Net) InNS(node string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			errc <- err
			return
		}
		defer orig.Close()
		target, err := os.Open("/run/netns/" + n.NS(node))
		if err != nil {
			errc <- err
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		err = fn()
		if rerr := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); rerr != nil {
			// Leave the thread locked so Go discards it.
			errc <- errors.Join(err, rerr)
			return
		}
		runtime.UnlockOSThread()
		errc <- err
	}()
	return <-errc
}

// Down stops tlshd, detaches loop devices and sweeps. Call it after the
// test removed its VGs and devices.
func (n *Net) Down() {
	for _, c := range n.tlshd {
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
		_ = c.Wait()
	}
	n.tlshd = nil
	for _, l := range n.loops {
		ShQuiet("losetup", "-d", l)
	}
	n.loops = nil
	n.Sweep()
	if os.Getenv("BLIP_KEEP_TEST_DIR") == "" {
		os.RemoveAll(n.Dir)
	}
}

// Sweep removes everything of our nodes a crashed run left behind:
// controllers, keys, nvmet subsystems and ports (on port svc 4420),
// device-mapper devices, VGs named <Prefix>-<node> (LVM confined to loop
// devices on files under Dir), loop devices, namespaces and tlshd.
func (n *Net) Sweep() {
	ctx := context.Background()
	_ = nvmehost.DisconnectAll(func(c nvmehost.Controller) bool {
		x, _, _, ok := names.ParseSubsystemNQN(c.SubNQN)
		return ok && n.IsNode(x)
	})
	time.Sleep(200 * time.Millisecond)
	if kr, err := tlskeys.Keyring(); err == nil {
		for _, r := range []tlskeys.Role{tlskeys.Host, tlskeys.Target} {
			_ = tlskeys.RemoveMatching(kr, r, func(id string) bool {
				for _, x := range n.Nodes {
					if strings.Contains(id, names.NQNPrefix+":"+x+":") || strings.Contains(id, names.HostNQN(x)+" ") {
						return true
					}
				}
				return false
			})
		}
	}
	if t, err := nvmet.New(""); err == nil {
		subs, _ := t.List(func(s string) bool {
			x, _, _, ok := names.ParseSubsystemNQN(s)
			return ok && n.IsNode(x)
		})
		for _, s := range subs {
			_ = t.RemoveSubsystem(s.NQN)
		}
		for _, x := range n.Nodes {
			_ = t.RemovePort(names.PortID(x, n.Addr(x), 4420))
		}
	}
	// Device-mapper: resume what a crashed capture left suspended, then
	// remove slot disks, snapshots and overlays before origins and pools.
	for _, x := range n.Nodes {
		infos, _ := dm.List(ctx, names.DMPrefix(x))
		for _, i := range infos {
			if i.Suspended {
				_ = dm.Resume(ctx, i.Name)
			}
		}
		for _, kinds := range [][]names.Kind{{names.KindSlotDisk}, {names.KindLocalSnap}, {names.KindOverlay}, {names.KindOrigin}, {names.KindPool}, {names.KindPoolMeta, names.KindPoolData}} {
			for _, i := range infos {
				p, _ := names.ParseDM(x, i.Name)
				for _, k := range kinds {
					if p.Kind == k {
						_ = dm.Remove(ctx, i.Name)
					}
				}
			}
		}
	}
	// LVM, confined to loop devices on our files. LVM must never scan the
	// other disks of the host.
	out, _ := exec.Command("losetup", "-a").Output()
	var loops []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "("+n.Dir+"/") {
			loops = append(loops, strings.SplitN(l, ":", 2)[0])
		}
	}
	for _, x := range n.Nodes {
		vg := n.Prefix + "-" + x
		if len(loops) > 0 {
			if l, err := lvm.New(lvm.Config{VG: vg, Devices: loops}); err == nil {
				_ = l.Deactivate(ctx, "pool")
				_ = l.DeactivateVG(ctx)
			}
		}
		infos, _ := dm.List(ctx, strings.ReplaceAll(vg, "-", "--")+"-")
		for _, i := range infos {
			_ = dm.Remove(ctx, i.Name)
		}
	}
	for _, l := range loops {
		ShQuiet("losetup", "-d", l)
	}
	for _, x := range n.Nodes {
		ShQuiet("ip", "netns", "del", n.NS(x))
		ShQuiet("ip", "link", "del", n.veth(x))
	}
	ShQuiet("ip", "link", "del", n.Bridge)
	out, _ = exec.Command("pgrep", "-f", "tlshd -s -c "+n.tlshdConf()).Output()
	for _, p := range strings.Fields(string(out)) {
		ShQuiet("kill", p)
	}
}
