// Package devnode creates block device nodes in a private directory.
//
// In containers, new NVMe and device-mapper devices do not appear in /dev,
// because there is no udev. The node daemon therefore looks up the device
// number in sysfs and creates its own node with mknod.
package devnode

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Dev is a block device number.
type Dev struct {
	Major, Minor uint32
}

func (d Dev) String() string { return fmt.Sprintf("%d:%d", d.Major, d.Minor) }

// Parse parses "major:minor".
func Parse(s string) (Dev, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return Dev{}, fmt.Errorf("bad device number %q", s)
	}
	ma, err1 := strconv.ParseUint(a, 10, 32)
	mi, err2 := strconv.ParseUint(b, 10, 32)
	if err1 != nil || err2 != nil {
		return Dev{}, fmt.Errorf("bad device number %q", s)
	}
	return Dev{uint32(ma), uint32(mi)}, nil
}

// OfBlock reads the device number of /sys/class/block/<name>.
func OfBlock(name string) (Dev, error) {
	b, err := os.ReadFile(filepath.Join("/sys/class/block", name, "dev"))
	if err != nil {
		return Dev{}, err
	}
	return Parse(string(b))
}

// SysName returns the kernel name (for example "dm-3") of a block device.
func SysName(d Dev) (string, error) {
	p, err := os.Readlink(fmt.Sprintf("/sys/dev/block/%d:%d", d.Major, d.Minor))
	if err != nil {
		return "", err
	}
	return filepath.Base(p), nil
}

// Sectors returns the size of a block device in 512-byte sectors.
func Sectors(d Dev) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/size", d.Major, d.Minor))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// Ensure makes dir/name a block device node for d and returns its path.
// An existing node with a different number is replaced.
func Ensure(dir, name string, d Dev) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	want := unix.Mkdev(d.Major, d.Minor)
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err == nil {
		if st.Mode&unix.S_IFMT == unix.S_IFBLK && st.Rdev == want {
			return p, nil
		}
		if err := os.Remove(p); err != nil {
			return "", err
		}
	}
	if err := unix.Mknod(p, unix.S_IFBLK|0o600, int(want)); err != nil {
		return "", fmt.Errorf("mknod %s %s: %w", p, d, err)
	}
	return p, nil
}

// Remove deletes dir/name if it exists.
func Remove(dir, name string) error {
	err := os.Remove(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
