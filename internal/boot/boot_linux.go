//go:build linux

package boot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/blip/internal/meta"
	"golang.org/x/sys/unix"
)

// Timeouts; variables so tests and callers can shorten them.
var (
	MetaTimeout = time.Minute
	RootTimeout = 5 * time.Minute
	Rescan      = time.Second
)

const newRoot = "/newroot"

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "blip-boot: "+format+"\n", a...)
}

// Run is the PID 1 entry point. It only returns by exec'ing init; on failure
// it powers off.
func Run() {
	if err := setupConsole(); err != nil {
		logf("console: %v", err)
	}
	events := ueventChan()

	var metaPath string
	if !WaitFor(func() bool { metaPath = meta.FindBySerial("/sys/block", meta.Serial); return metaPath != "" },
		events, Rescan, MetaTimeout) {
		fail(nil, meta.ReasonMetaNotFound, "no disk with serial "+meta.Serial)
	}
	dev, err := meta.Open(metaPath)
	if err != nil {
		fail(nil, meta.ReasonMetaNotFound, err.Error())
	}
	boots := 1
	if g, err := dev.ReadGuest(); err == nil {
		boots = g.BootCount + 1
	}
	if err := dev.WriteGuest(&meta.GuestData{State: meta.StateWaiting, BootCount: boots}); err != nil {
		logf("write WAITING: %v", err)
	}
	logf("waiting")

	// Wait for an allocation, then (with a timeout) for its root disk.
	var host *meta.HostData
	var rootDev string
	var allocSince time.Time
	check := func() bool {
		h, _, err := dev.ReadHost()
		if err != nil || h.AllocationID == "" || h.Boot.RootSerial == "" {
			return false
		}
		host = h
		if allocSince.IsZero() {
			allocSince = time.Now()
			logf("allocation %s, root %s", h.AllocationID, h.Boot.RootSerial)
		}
		rootDev = meta.FindBySerial("/sys/block", h.Boot.RootSerial)
		return rootDev != ""
	}
	for !WaitFor(check, events, Rescan, RootTimeout) {
		if !allocSince.IsZero() && time.Since(allocSince) >= RootTimeout {
			fail(dev, meta.ReasonRootNotFound, "no disk with serial "+host.Boot.RootSerial)
		}
	}

	argv, err := InitArgv(host.Boot.Init)
	if err != nil {
		fail(dev, meta.ReasonInitNotFound, err.Error())
	}
	fstype := host.Boot.RootFSType
	if fstype == "" {
		fstype = "ext4"
	}
	flags, data := ParseMountOptions(host.Boot.RootMountOptions)
	os.MkdirAll(newRoot, 0o755)
	if err := unix.Mount(rootDev, newRoot, fstype, flags, data); err != nil {
		fail(dev, meta.ReasonRootMountFailed, fmt.Sprintf("mount %s (%s, %q): %v", rootDev, fstype, host.Boot.RootMountOptions, err))
	}
	if err := switchRoot(); err != nil {
		fail(dev, meta.ReasonRootMountFailed, "switch_root: "+err.Error())
	}
	if err := unix.Access(argv[0], unix.X_OK); err != nil {
		fail(dev, meta.ReasonInitNotFound, fmt.Sprintf("%s: %v", argv[0], err))
	}
	if err := dev.UpdateGuest(func(g *meta.GuestData) {
		g.State, g.Reason, g.Message, g.BootCount = meta.StateExec, "", "", boots
	}); err != nil {
		logf("write EXEC: %v", err)
	}
	logf("exec %s", strings.Join(argv, " "))
	// The meta fd is close-on-exec.
	err = unix.Exec(argv[0], argv, InitEnv(os.Environ()))
	fail(dev, meta.ReasonInitNotFound, fmt.Sprintf("exec %s: %v", argv[0], err))
}

func setupConsole() error {
	var errs []error
	for _, m := range []struct{ src, dst, fs string }{
		{"devtmpfs", "/dev", "devtmpfs"},
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
	} {
		os.MkdirAll(m.dst, 0o755)
		if err := unix.Mount(m.src, m.dst, m.fs, unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			errs = append(errs, fmt.Errorf("mount %s: %w", m.dst, err))
		}
	}
	if f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
		unix.Dup3(int(f.Fd()), 1, 0)
		unix.Dup3(int(f.Fd()), 2, 0)
		f.Close()
	}
	return errors.Join(errs...)
}

// switchRoot moves /dev, /proc, /sys and /run into newRoot (if the target
// dirs exist), deletes the initramfs contents and chroots into newRoot.
func switchRoot() error {
	var root unix.Stat_t
	if err := unix.Stat("/", &root); err != nil {
		return err
	}
	for _, m := range []string{"/dev", "/proc", "/sys", "/run"} {
		if !isMountpoint(m) {
			continue
		}
		if st, err := os.Stat(newRoot + m); err != nil || !st.IsDir() {
			unix.Unmount(m, unix.MNT_DETACH)
			continue
		}
		if err := unix.Mount(m, newRoot+m, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", m, err)
		}
	}
	if err := os.Chdir(newRoot); err != nil {
		return err
	}
	removeTree("/", root.Dev)
	if err := unix.Mount(".", "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move root: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return err
	}
	return os.Chdir("/")
}

func isMountpoint(p string) bool {
	var a, b unix.Stat_t
	if unix.Lstat(p, &a) != nil || unix.Lstat(filepath.Dir(p), &b) != nil {
		return false
	}
	return a.Dev != b.Dev
}

// removeTree deletes everything under dir that lives on device dev, like
// busybox switch_root. Other filesystems (newroot) are left alone.
func removeTree(dir string, dev uint64) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Dev != dev {
			continue
		}
		if e.IsDir() {
			removeTree(p, dev)
			unix.Rmdir(p)
		} else {
			unix.Unlink(p)
		}
	}
}

// fail records a FAIL state (if the meta device is open) and powers off.
func fail(dev *meta.Device, reason, msg string) {
	logf("FAIL %s: %s", reason, msg)
	if dev != nil {
		if err := dev.UpdateGuest(func(g *meta.GuestData) {
			g.State, g.Reason, g.Message = meta.StateFail, reason, msg
		}); err != nil {
			logf("write FAIL: %v", err)
		}
	}
	unix.Sync()
	unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Hour)
	}
}

// ueventChan returns a channel signalled on block uevents. If the netlink
// socket can't be opened, the channel never fires (rescan still works).
func ueventChan() <-chan struct{} {
	ch := make(chan struct{}, 1)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_KOBJECT_UEVENT)
	if err == nil {
		err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1, Pid: 0})
	}
	if err != nil {
		logf("uevent: %v (polling)", err)
		return ch
	}
	go func() {
		buf := make([]byte, 8192)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
					continue
				}
				return
			}
			if strings.Contains(string(buf[:n]), "SUBSYSTEM=block") {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch
}
