package nvme

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const fabricsDev = "/dev/nvme-fabrics"

var nsName = regexp.MustCompile(`^nvme\d+n\d+$`)

// HostID is the host identifier sent with hostNQN. The kernel rejects one
// host ID with two NQNs, and kind nodes share a kernel, so it is derived
// from the NQN.
func HostID(hostNQN string) string { return uuidFrom("hostid:" + hostNQN) }

// Connect connects to an NVMe/TCP subsystem, authenticating both ends with
// secrets derived from key (the cluster disk key), and returns the block
// device of its first namespace.
func Connect(ctx context.Context, addr string, port int, nqn, hostNQN string, key []byte) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	ctrl := controllerFor(nqn)
	if ctrl == "" {
		var err error
		if ctrl, err = connect(addr, port, nqn, hostNQN, key); err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if dev, err := namespaceDevice(ctrl); err == nil {
			return dev, nil
		}
		select {
		case <-ctx.Done():
			Disconnect(nqn)
			return "", fmt.Errorf("nvme: namespace of %s did not appear: %w", nqn, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func connect(addr string, port int, nqn, hostNQN string, key []byte) (string, error) {
	if err := ensureFabricsDev(); err != nil {
		return "", err
	}
	f, err := os.OpenFile(fabricsDev, os.O_RDWR, 0)
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
	if _, err := f.WriteString(opts); err != nil {
		return "", fmt.Errorf("nvme: connect %s at %s:%d: %w", nqn, addr, port, err)
	}
	buf := make([]byte, 256)
	n, err := f.Read(buf)
	if err != nil {
		return "", fmt.Errorf("nvme: read connect result: %w", err)
	}
	for _, kv := range strings.Split(strings.TrimSpace(string(buf[:n])), ",") {
		if v, ok := strings.CutPrefix(kv, "instance="); ok {
			return "nvme" + v, nil
		}
	}
	return "", fmt.Errorf("nvme: unexpected connect result %q", buf[:n])
}

func ensureFabricsDev() error {
	b, err := os.ReadFile("/sys/class/misc/nvme-fabrics/dev")
	if err != nil {
		return errors.New("nvme: nvme-fabrics is not available (load nvme_tcp)")
	}
	return ensureNode(fabricsDev, strings.TrimSpace(string(b)), unix.S_IFCHR)
}

// namespaceDevice finds the namespace block device of a controller, with or
// without native multipath, and makes sure /dev has its node.
func namespaceDevice(ctrl string) (string, error) {
	dirs := []string{filepath.Join("/sys/class/nvme", ctrl)}
	subs, _ := filepath.Glob("/sys/class/nvme-subsystem/*/" + ctrl)
	for _, s := range subs {
		dirs = append(dirs, filepath.Dir(s))
	}
	for _, d := range dirs {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if !nsName.MatchString(e.Name()) {
				continue
			}
			blk := filepath.Join("/sys/class/block", e.Name())
			if size, _ := os.ReadFile(filepath.Join(blk, "size")); strings.TrimSpace(string(size)) == "0" {
				continue
			}
			devnum, err := os.ReadFile(filepath.Join(blk, "dev"))
			if err != nil {
				continue
			}
			dev := "/dev/" + e.Name()
			if err := ensureNode(dev, strings.TrimSpace(string(devnum)), unix.S_IFBLK); err != nil {
				return "", err
			}
			return dev, nil
		}
	}
	return "", errors.New("no namespace yet")
}

func controllerFor(nqn string) string {
	ctrls := controllers(nqn)
	if len(ctrls) == 0 {
		return ""
	}
	return ctrls[0]
}

func controllers(nqn string) []string {
	paths, _ := filepath.Glob("/sys/class/nvme/nvme*")
	var out []string
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(p, "subsysnqn"))
		if err == nil && strings.TrimSpace(string(b)) == nqn {
			out = append(out, filepath.Base(p))
		}
	}
	return out
}

// Disconnect deletes every controller connected to nqn.
func Disconnect(nqn string) error {
	for _, c := range controllers(nqn) {
		if err := os.WriteFile(filepath.Join("/sys/class/nvme", c, "delete_controller"), []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("nvme: disconnect %s: %w", c, err)
		}
	}
	for range 100 {
		if len(controllers(nqn)) == 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("nvme: %s still connected", nqn)
}

func ensureNode(path, devnum string, mode uint32) error {
	ma, mi, ok := strings.Cut(devnum, ":")
	major, err1 := strconv.ParseUint(ma, 10, 32)
	minor, err2 := strconv.ParseUint(mi, 10, 32)
	if !ok || err1 != nil || err2 != nil {
		return fmt.Errorf("nvme: bad device number %q", devnum)
	}
	dev := unix.Mkdev(uint32(major), uint32(minor))
	var st unix.Stat_t
	if unix.Stat(path, &st) == nil {
		if st.Rdev == dev && st.Mode&unix.S_IFMT == mode {
			return nil
		}
		os.Remove(path)
	}
	if err := unix.Mknod(path, mode|0o600, int(dev)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("nvme: mknod %s: %w", path, err)
	}
	return nil
}
