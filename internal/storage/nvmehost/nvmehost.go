// Package nvmehost connects to NVMe/TCP targets with TLS by writing
// option strings to /dev/nvme-fabrics (no nvme-cli), and finds the
// namespace block devices in sysfs.
//
// The socket of a new connection is created in the network namespace of
// the calling thread, and the TLS handshake goes to the tlshd of that
// namespace. Kernel 7.0 creates reconnect sockets from a kernel worker,
// which runs in the initial network namespace (see docs/spikes/storage.md).
package nvmehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/run"
)

// FabricsDev is the fabrics control device.
const FabricsDev = "/dev/nvme-fabrics"

// Conn describes one connection. TLS is always on.
type Conn struct {
	Addr    string
	Svc     int
	SubNQN  string
	HostNQN string
	HostID  string
	Keyring int // serial of the .nvme keyring
	TLSKey  int // serial of the PSK to use

	// Timeouts in seconds. Zero means the default below.
	CtrlLossTmo    int // default 60
	FastIOFailTmo  int // default 5
	ReconnectDelay int // default 2
	NrIOQueues     int // default 4
}

// Options returns the option string for /dev/nvme-fabrics.
func Options(c Conn) (string, error) {
	if c.Addr == "" || c.SubNQN == "" || c.HostNQN == "" || c.HostID == "" {
		return "", errors.New("nvme connect: missing address, NQN or host ID")
	}
	if c.Keyring <= 0 || c.TLSKey <= 0 {
		return "", errors.New("nvme connect: TLS keyring and key are required")
	}
	def := func(v, d int) int {
		if v == 0 {
			return d
		}
		return v
	}
	svc := def(c.Svc, 4420)
	o := []string{
		"transport=tcp",
		"traddr=" + c.Addr,
		"trsvcid=" + strconv.Itoa(svc),
		"nqn=" + c.SubNQN,
		"hostnqn=" + c.HostNQN,
		"hostid=" + c.HostID,
		"nr_io_queues=" + strconv.Itoa(def(c.NrIOQueues, 4)),
		"ctrl_loss_tmo=" + strconv.Itoa(def(c.CtrlLossTmo, 60)),
		"fast_io_fail_tmo=" + strconv.Itoa(def(c.FastIOFailTmo, 5)),
		"reconnect_delay=" + strconv.Itoa(def(c.ReconnectDelay, 2)),
		"tls",
		"keyring=" + strconv.Itoa(c.Keyring),
		"tls_key=" + strconv.Itoa(c.TLSKey),
	}
	for _, s := range o {
		if strings.ContainsAny(s[strings.IndexByte(s, '=')+1:], ", \n") {
			return "", fmt.Errorf("nvme connect: bad option %q", s)
		}
	}
	return strings.Join(o, ","), nil
}

// Controller is an NVMe controller from /sys/class/nvme.
type Controller struct {
	Name      string // nvme7
	SubNQN    string
	HostNQN   string
	Addr      string
	Svc       int
	State     string // live, connecting, resetting, deleting, ...
	Transport string
}

// Controllers lists fabrics controllers.
func Controllers() ([]Controller, error) {
	ents, err := os.ReadDir("/sys/class/nvme")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Controller
	for _, e := range ents {
		dir := filepath.Join("/sys/class/nvme", e.Name())
		c := Controller{
			Name:      e.Name(),
			SubNQN:    read(dir, "subsysnqn"),
			HostNQN:   read(dir, "hostnqn"),
			State:     read(dir, "state"),
			Transport: read(dir, "transport"),
		}
		if c.Transport != "tcp" {
			continue
		}
		c.Addr, c.Svc = ParseAddress(read(dir, "address"))
		out = append(out, c)
	}
	return out, nil
}

// ParseAddress parses "traddr=10.0.0.1,trsvcid=4420,src_addr=...".
func ParseAddress(s string) (addr string, svc int) {
	for _, kv := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		switch k {
		case "traddr":
			addr = v
		case "trsvcid":
			svc, _ = strconv.Atoi(v)
		}
	}
	return addr, svc
}

// Find returns the controller for a connection, if one exists that is not
// being deleted.
func Find(c Conn) (Controller, bool, error) {
	all, err := Controllers()
	if err != nil {
		return Controller{}, false, err
	}
	svc := c.Svc
	if svc == 0 {
		svc = 4420
	}
	for _, x := range all {
		if x.SubNQN == c.SubNQN && x.HostNQN == c.HostNQN && x.Addr == c.Addr && x.Svc == svc && x.State != "deleting" && x.State != "deleting (no IO)" && x.State != "dead" {
			return x, true, nil
		}
	}
	return Controller{}, false, nil
}

// Connect connects unless an equal live controller exists, and returns
// it. An equal controller that is not live (reconnecting after its target
// went away) is deleted and replaced by a new connection: kernel
// reconnects run in the initial network namespace and may never succeed,
// while a new connection is made from the calling thread.
func Connect(c Conn) (Controller, error) {
	x, ok, err := Find(c)
	if err != nil || (ok && x.State == "live") {
		return x, err
	}
	if ok {
		if err := Disconnect(x.Name); err != nil {
			return Controller{}, err
		}
	}
	opts, err := Options(c)
	if err != nil {
		return Controller{}, err
	}
	if err := ensureFabricsDev(); err != nil {
		return Controller{}, err
	}
	f, err := os.OpenFile(FabricsDev, os.O_RDWR, 0)
	if err != nil {
		return Controller{}, err
	}
	defer f.Close()
	buf := make([]byte, 256)
	var n int
	err = run.Step("nvme-connect", []string{c.SubNQN, c.Addr}, func() error {
		if _, err := f.Write([]byte(opts)); err != nil {
			return fmt.Errorf("nvme connect %s at %s:%d: %w", c.SubNQN, c.Addr, c.Svc, err)
		}
		var err error
		if n, err = f.Read(buf); err != nil {
			return fmt.Errorf("nvme connect: read reply: %w", err)
		}
		return nil
	})
	if err != nil {
		return Controller{}, err
	}
	inst := -1
	for _, kv := range strings.Split(strings.TrimSpace(string(buf[:n])), ",") {
		if v, ok := strings.CutPrefix(kv, "instance="); ok {
			inst, _ = strconv.Atoi(v)
		}
	}
	if inst < 0 {
		return Controller{}, fmt.Errorf("nvme connect: bad reply %q", buf[:n])
	}
	name := "nvme" + strconv.Itoa(inst)
	dir := filepath.Join("/sys/class/nvme", name)
	addr, svc := ParseAddress(read(dir, "address"))
	return Controller{Name: name, SubNQN: read(dir, "subsysnqn"), HostNQN: read(dir, "hostnqn"),
		Addr: addr, Svc: svc, State: read(dir, "state"), Transport: "tcp"}, nil
}

func ensureFabricsDev() error {
	if _, err := os.Stat(FabricsDev); err == nil {
		return nil
	}
	b, err := os.ReadFile("/sys/class/misc/nvme-fabrics/dev")
	if err != nil {
		return fmt.Errorf("nvme-fabrics not available (is nvme-tcp loaded?): %w", err)
	}
	d, err := devnode.Parse(string(b))
	if err != nil {
		return err
	}
	return mknodChar(FabricsDev, d)
}

// Disconnect deletes a controller. A missing controller is not an error.
func Disconnect(name string) error {
	return run.Step("nvme-disconnect", []string{name}, func() error {
		err := os.WriteFile(filepath.Join("/sys/class/nvme", name, "delete_controller"), []byte("1"), 0o200)
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete controller %s: %w", name, err)
		}
		return nil
	})
}

// DisconnectAll deletes every controller for which match returns true.
func DisconnectAll(match func(Controller) bool) error {
	all, err := Controllers()
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range all {
		if match(c) {
			errs = append(errs, Disconnect(c.Name))
		}
	}
	return errors.Join(errs...)
}

// Namespace is the block device of namespace 1 of a controller.
type Namespace struct {
	Name    string // nvme7n1 (the multipath head if native multipath is on)
	Dev     devnode.Dev
	Sectors int64
}

// WaitNamespace waits until namespace 1 of the controller has a block
// device. With native NVMe multipath (the default) the usable device is
// the subsystem head, not the hidden per-controller path device.
func WaitNamespace(ctx context.Context, ctrl string) (Namespace, error) {
	for {
		if name, ok := namespaceName(ctrl); ok {
			d, err := devnode.OfBlock(name)
			if err == nil {
				if sz, err := devnode.Sectors(d); err == nil && sz > 0 {
					return Namespace{Name: name, Dev: d, Sectors: sz}, nil
				}
			}
		}
		if _, err := os.Stat(filepath.Join("/sys/class/nvme", ctrl)); os.IsNotExist(err) {
			return Namespace{}, fmt.Errorf("controller %s was deleted", ctrl)
		}
		select {
		case <-ctx.Done():
			return Namespace{}, fmt.Errorf("namespace of %s did not appear: %w", ctrl, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func namespaceName(ctrl string) (string, bool) {
	// Native multipath: /sys/class/nvme-subsystem/nvme-subsysN/{nvmeX,nvmeYnZ}
	subs, _ := os.ReadDir("/sys/class/nvme-subsystem")
	for _, s := range subs {
		dir := filepath.Join("/sys/class/nvme-subsystem", s.Name())
		if _, err := os.Lstat(filepath.Join(dir, ctrl)); err != nil {
			continue
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if isNSName(e.Name()) && isNSID1(dir, e.Name()) {
				return e.Name(), true
			}
		}
	}
	// No native multipath: /sys/class/nvme/nvmeX/nvmeXnY
	ents, _ := os.ReadDir(filepath.Join("/sys/class/nvme", ctrl))
	for _, e := range ents {
		if isNSName(e.Name()) && isNSID1(filepath.Join("/sys/class/nvme", ctrl), e.Name()) {
			return e.Name(), true
		}
	}
	return "", false
}

// isNSID1 reports whether block device dir/name is namespace ID 1. The
// name does not tell: in nvmeXnY, Y is an instance number, and a new head
// of a subsystem whose old head is still open (for example by a
// device-mapper table after its controller was deleted) gets a new one.
func isNSID1(dir, name string) bool {
	if id := read(filepath.Join(dir, name), "nsid"); id != "" {
		return id == "1"
	}
	return strings.HasSuffix(name, "n1")
}

// isNSName matches nvme<N>n<M>.
func isNSName(s string) bool {
	rest, ok := strings.CutPrefix(s, "nvme")
	if !ok {
		return false
	}
	a, b, ok := strings.Cut(rest, "n")
	if !ok {
		return false
	}
	_, err1 := strconv.Atoi(a)
	_, err2 := strconv.Atoi(b)
	return err1 == nil && err2 == nil
}

func read(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetIOTimeout sets the I/O timeout of every namespace block device of the
// controller (the per-controller path devices and, without native
// multipath, the namespace itself). The kernel default comes from the
// host-wide nvme_core.io_timeout, which other software on the host may have
// raised; a request the target never answers then blocks device-mapper
// suspends (and so detach and release) for that long. A bounded timeout
// starts error recovery and lets the I/O fail over to another replica.
func SetIOTimeout(ctrl string, d time.Duration) error {
	ms := []byte(strconv.FormatInt(d.Milliseconds(), 10))
	ents, err := os.ReadDir(filepath.Join("/sys/class/nvme", ctrl))
	if err != nil {
		return err
	}
	var errs []error
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "nvme") || !strings.HasSuffix(e.Name(), "n1") {
			continue
		}
		f := filepath.Join("/sys/class/nvme", ctrl, e.Name(), "queue", "io_timeout")
		if _, err := os.Stat(f); err != nil {
			continue
		}
		n++
		if err := os.WriteFile(f, ms, 0o644); err != nil {
			errs = append(errs, err)
		}
	}
	if n == 0 {
		return fmt.Errorf("no namespace io_timeout found for %s", ctrl)
	}
	return errors.Join(errs...)
}
