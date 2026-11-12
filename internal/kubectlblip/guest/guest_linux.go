//go:build linux

package guest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/example/blip/internal/meta"
)

// SysBlock is /sys/block, a variable for tests.
var SysBlock = "/sys/block"

func metaIdentity() (Identity, bool, error) {
	p := meta.FindDevice()
	if p == "" {
		return Identity{}, false, nil
	}
	d, err := meta.Open(p)
	if err != nil {
		return Identity{}, false, fmt.Errorf("open metadata disk %s: %w", p, err)
	}
	defer d.Close()
	h, _, err := d.ReadHost()
	if err != nil {
		return Identity{}, false, fmt.Errorf("read metadata disk %s: %w", p, err)
	}
	if h == nil || h.Identity.Name == "" {
		return Identity{}, false, nil
	}
	return Identity{Name: h.Identity.Name, Namespace: h.Identity.Namespace}, true, nil
}

// Sync flushes all file systems, so that a crash-consistent snapshot has
// what was written before.
func Sync() { syscall.Sync() }

// FindDevice returns the block device of the attached volume name (virtio
// serial = volume name), or "".
func FindDevice(name string) string {
	p := "/dev/disk/by-id/virtio-" + name
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return meta.FindBySerial(SysBlock, name)
}

// WaitDevice waits until the device of volume name appears.
func WaitDevice(ctx context.Context, name string) (string, error) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		if p := FindDevice(name); p != "" {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("device of volume %s did not appear: %w", name, ctx.Err())
		case <-t.C:
		}
	}
}

// Mount mounts dev at dir (created if missing) with mount(8), which detects
// the file system type.
func Mount(ctx context.Context, dev, dir string, readOnly bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	args := []string{dev, dir}
	if readOnly {
		args = append([]string{"-o", "ro"}, args...)
	}
	out, err := exec.CommandContext(ctx, "mount", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount %s %s: %v: %s", dev, dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UnmountDevice unmounts every mount of dev, newest first, and returns the
// mount points.
func UnmountDevice(dev string) ([]string, error) {
	real, err := filepath.EvalSymlinks(dev)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(real, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return nil, fmt.Errorf("%s is not a block device", dev)
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	mps := MountPoints(f, fmt.Sprintf("%d:%d", major(st.Rdev), minor(st.Rdev)))
	f.Close()
	for i := len(mps) - 1; i >= 0; i-- {
		if err := syscall.Unmount(mps[i], 0); err != nil {
			return mps[i+1:], fmt.Errorf("unmount %s: %w", mps[i], err)
		}
	}
	return mps, nil
}

func major(d uint64) uint64 { return (d>>8)&0xfff | (d>>32)&^0xfff }
func minor(d uint64) uint64 { return d&0xff | (d>>12)&^0xff }
