package nvme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/devnode"
)

const fabricsDev = "/dev/nvme-fabrics"

var nsName = regexp.MustCompile(`^nvme\d+n\d+$`)

// InitiatorSystem is the low-level fabrics/sysfs boundary. It deliberately
// sits below connect: command encoding, DHCHAP secrets, result parsing,
// controller discovery, namespace readiness, and cleanup run unchanged.
type InitiatorSystem interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]os.DirEntry, error)
	Glob(string) ([]string, error)
	OpenFabrics() (io.ReadWriteCloser, error)
	EnsureNode(path, devnum string, mode uint32) error
	WriteFile(string, []byte, os.FileMode) error
}

type InitiatorOptions struct {
	System InitiatorSystem
}

type Initiator struct {
	system InitiatorSystem
}

func NewInitiator(opts InitiatorOptions) *Initiator {
	if opts.System == nil {
		opts.System = kernelInitiator{}
	}
	return &Initiator{system: opts.System}
}

type kernelInitiator struct{}

func (kernelInitiator) ReadFile(p string) ([]byte, error)       { return os.ReadFile(p) }
func (kernelInitiator) ReadDir(p string) ([]os.DirEntry, error) { return os.ReadDir(p) }
func (kernelInitiator) Glob(p string) ([]string, error)         { return filepath.Glob(p) }
func (kernelInitiator) OpenFabrics() (io.ReadWriteCloser, error) {
	return os.OpenFile(fabricsDev, os.O_RDWR, 0)
}
func (kernelInitiator) EnsureNode(p, d string, mode uint32) error { return ensureNode(p, d, mode) }
func (kernelInitiator) WriteFile(p string, b []byte, mode os.FileMode) error {
	return os.WriteFile(p, b, mode)
}

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// HostID is the host identifier sent with hostNQN. The kernel rejects one
// host ID with two NQNs, and kind nodes share a kernel, so it is derived
// from the NQN.
func HostID(hostNQN string) string { return uuidFrom("hostid:" + hostNQN) }

// Connect connects to an NVMe/TCP subsystem, authenticating both ends with
// secrets derived from key (the cluster disk key), and returns the block
// device of its first namespace.
func Connect(ctx context.Context, addr string, port int, nqn, hostNQN string, key []byte) (string, error) {
	return NewInitiator(InitiatorOptions{}).Connect(ctx, addr, port, nqn, hostNQN, key)
}

func (i *Initiator) Connect(ctx context.Context, addr string, port int, nqn, hostNQN string, key []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := checkKey(key); err != nil {
		return "", err
	}
	ctrl, err := i.controllerFor(nqn)
	if err != nil {
		return "", err
	}
	if ctrl == "" {
		if ctrl, err = i.connect(addr, port, nqn, hostNQN, key); err != nil {
			// The kernel may have accepted the write before the result read
			// failed. Discover by NQN and clean up that ambiguous controller.
			return "", errors.Join(err, i.Disconnect(nqn))
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return "", errors.Join(fmt.Errorf("nvme: namespace of %s did not appear: %w", nqn, err), i.Disconnect(nqn))
		}
		if dev, err := i.namespaceDevice(ctrl); err == nil {
			if err := ctx.Err(); err != nil {
				return "", errors.Join(err, i.Disconnect(nqn))
			}
			return dev, nil
		}
		sleep(ctx, 100*time.Millisecond)
	}
}

func (i *Initiator) connect(addr string, port int, nqn, hostNQN string, key []byte) (string, error) {
	if err := i.ensureFabricsDev(); err != nil {
		return "", err
	}
	f, err := i.system.OpenFabrics()
	if err != nil {
		return "", err
	}
	defer f.Close()
	// A lost source fails I/O after a minute instead of the kernel's default
	// ten; it also lets the kernel drop controllers whose export is gone.
	// opts holds the secrets: never log it or put it in an error.
	hostKey, ctrlKey := secrets(key, hostNQN)
	opts := fmt.Sprintf("transport=tcp,traddr=%s,trsvcid=%d,nqn=%s,hostnqn=%s,hostid=%s,ctrl_loss_tmo=60,reconnect_delay=2,dhchap_secret=%s,dhchap_ctrl_secret=%s",
		addr, port, nqn, hostNQN, HostID(hostNQN), hostKey, ctrlKey)
	if n, err := f.Write([]byte(opts)); err != nil || n != len(opts) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return "", fmt.Errorf("nvme: connect %s at %s:%d: %w", nqn, addr, port, err)
	}
	buf := make([]byte, 256)
	n, err := f.Read(buf)
	if err != nil {
		return "", fmt.Errorf("nvme: read connect result: %w", err)
	}
	for _, kv := range strings.Split(strings.TrimSpace(string(buf[:n])), ",") {
		if v, ok := strings.CutPrefix(kv, "instance="); ok {
			if _, err := strconv.ParseUint(v, 10, 32); err == nil {
				return "nvme" + v, nil
			}
		}
	}
	return "", fmt.Errorf("nvme: unexpected connect result %q", buf[:n])
}

func (i *Initiator) ensureFabricsDev() error {
	b, err := i.system.ReadFile("/sys/class/misc/nvme-fabrics/dev")
	if err != nil {
		return errors.New("nvme: nvme-fabrics is not available (load nvme_tcp)")
	}
	return i.system.EnsureNode(fabricsDev, strings.TrimSpace(string(b)), unix.S_IFCHR)
}

// namespaceDevice finds the namespace block device of a controller, with or
// without native multipath, and makes sure /dev has its node.
func (i *Initiator) namespaceDevice(ctrl string) (string, error) {
	dirs := []string{filepath.Join("/sys/class/nvme", ctrl)}
	subs, _ := i.system.Glob("/sys/class/nvme-subsystem/*/" + ctrl)
	for _, s := range subs {
		dirs = append(dirs, filepath.Dir(s))
	}
	for _, d := range dirs {
		entries, _ := i.system.ReadDir(d)
		for _, e := range entries {
			if !nsName.MatchString(e.Name()) {
				continue
			}
			blk := filepath.Join("/sys/class/block", e.Name())
			size, err := i.system.ReadFile(filepath.Join(blk, "size"))
			if err != nil {
				continue
			}
			sectors, err := strconv.ParseUint(strings.TrimSpace(string(size)), 10, 64)
			if err != nil || sectors == 0 {
				continue
			}
			devnum, err := i.system.ReadFile(filepath.Join(blk, "dev"))
			if err != nil {
				continue
			}
			dev := "/dev/" + e.Name()
			if err := i.system.EnsureNode(dev, strings.TrimSpace(string(devnum)), unix.S_IFBLK); err != nil {
				return "", err
			}
			return dev, nil
		}
	}
	return "", errors.New("no namespace yet")
}

func (i *Initiator) controllerFor(nqn string) (string, error) {
	ctrls, err := i.controllers(nqn)
	if err != nil {
		return "", err
	}
	if len(ctrls) == 0 {
		return "", nil
	}
	return ctrls[0], nil
}

func (i *Initiator) controllers(nqn string) ([]string, error) {
	paths, err := i.system.Glob("/sys/class/nvme/nvme*")
	if err != nil {
		return nil, fmt.Errorf("nvme: list controllers: %w", err)
	}
	var out []string
	for _, p := range paths {
		b, err := i.system.ReadFile(filepath.Join(p, "subsysnqn"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("nvme: identify controller %s: %w", p, err)
		}
		if err == nil && strings.TrimSpace(string(b)) == nqn {
			out = append(out, filepath.Base(p))
		}
	}
	return out, nil
}

// Disconnect deletes every controller connected to nqn.
func Disconnect(nqn string) error {
	return NewInitiator(InitiatorOptions{}).Disconnect(nqn)
}

func (i *Initiator) Disconnect(nqn string) error {
	ctrls, err := i.controllers(nqn)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range ctrls {
		if err := i.system.WriteFile(filepath.Join("/sys/class/nvme", c, "delete_controller"), []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("nvme: disconnect %s: %w", c, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for range 100 {
		ctrls, err := i.controllers(nqn)
		if err != nil {
			return err
		}
		if len(ctrls) == 0 {
			return nil
		}
		sleep(context.Background(), 100*time.Millisecond)
	}
	return fmt.Errorf("nvme: %s still connected", nqn)
}

func ensureNode(path, devnum string, mode uint32) error {
	rdev, err := devnode.Parse(devnum)
	if err != nil {
		return fmt.Errorf("nvme: %w", err)
	}
	if mode == unix.S_IFBLK {
		err = devnode.Ensure(path, rdev)
	} else {
		err = devnode.EnsureChar(path, rdev)
	}
	if err != nil {
		return fmt.Errorf("nvme: %w", err)
	}
	return nil
}
