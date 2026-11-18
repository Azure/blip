package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/devnode"
)

// ensureBlockNode makes sure path is a block device node for the sysfs
// "major:minor" in devFile.
func ensureBlockNode(path, devFile string) error {
	b, err := os.ReadFile(devFile)
	if err != nil {
		return err
	}
	rdev, err := devnode.Parse(string(b))
	if err != nil {
		return fmt.Errorf("%s: %w", devFile, err)
	}
	return devnode.Ensure(path, rdev)
}

// attachLoop returns a loop device backed by path, reusing an existing
// attachment of the same file. The returned file keeps a new attachment alive
// (it is created with autoclear); close it once something else holds the
// device.
func attachLoop(path string) (string, *os.File, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", nil, err
	}
	if dev := findLoop(st); dev != "" {
		return dev, nil, nil
	}
	backing, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}
	defer backing.Close()
	for range 20 {
		dev, f, err := configureFreeLoop(backing)
		if errors.Is(err, unix.EBUSY) {
			continue
		}
		return dev, f, err
	}
	return "", nil, errors.New("no free loop device")
}

func configureFreeLoop(backing *os.File) (string, *os.File, error) {
	ctl, err := openLoopControl()
	if err != nil {
		return "", nil, err
	}
	n, err := unix.IoctlRetInt(int(ctl.Fd()), unix.LOOP_CTL_GET_FREE)
	ctl.Close()
	if err != nil {
		return "", nil, fmt.Errorf("LOOP_CTL_GET_FREE: %w", err)
	}
	name := "loop" + strconv.Itoa(n)
	dev := "/dev/" + name
	if err := ensureBlockNode(dev, "/sys/block/"+name+"/dev"); err != nil {
		return "", nil, err
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}
	cfg := unix.LoopConfig{Fd: uint32(backing.Fd())}
	// Buffered I/O: with direct I/O, dm-thin writes reach a sparse backing
	// file one small request at a time and run about 5x slower. The loop
	// driver still turns flushes into fsync of the backing file.
	cfg.Info.Flags = unix.LO_FLAGS_AUTOCLEAR
	err = unix.IoctlLoopConfigure(int(f.Fd()), &cfg)
	if err != nil {
		f.Close()
		return "", nil, fmt.Errorf("LOOP_CONFIGURE %s: %w", dev, err)
	}
	return dev, f, nil
}

func openLoopControl() (*os.File, error) {
	const path = "/dev/loop-control"
	if err := devnode.EnsureChar(path, unix.Mkdev(10, 237)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}

// findLoop finds an attached loop device whose backing file is st.
func findLoop(st unix.Stat_t) string {
	files, _ := filepath.Glob("/sys/block/loop*/loop/backing_file")
	for _, bf := range files {
		name := strings.Split(strings.TrimPrefix(bf, "/sys/block/"), "/")[0]
		dev := "/dev/" + name
		if err := ensureBlockNode(dev, "/sys/block/"+name+"/dev"); err != nil {
			continue
		}
		f, err := os.Open(dev)
		if err != nil {
			continue
		}
		info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
		f.Close()
		if err == nil && info.Inode == st.Ino && info.Device == st.Dev {
			return dev
		}
	}
	return ""
}
