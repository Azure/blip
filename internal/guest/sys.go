package guest

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/blip/internal/bootconfig"
	"golang.org/x/sys/unix"
)

// bootMounts mounts the guest's own pseudo filesystems and makes the console
// its stdio.
func bootMounts() {
	type m struct{ src, dst, fstype, data string }
	for _, x := range []m{
		{"proc", "/proc", "proc", ""},
		{"sysfs", "/sys", "sysfs", ""},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755"},
		{"devpts", "/dev/pts", "devpts", "ptmxmode=0666,mode=0620,gid=5"},
		{"tmpfs", "/dev/shm", "tmpfs", "mode=1777"},
		{"tmpfs", "/run", "tmpfs", "mode=0755"},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", ""},
	} {
		_ = os.MkdirAll(x.dst, 0o755)
		if err := unix.Mount(x.src, x.dst, x.fstype, unix.MS_NOSUID, x.data); err != nil && err != unix.EBUSY {
			log.Printf("mount %s: %v", x.dst, err)
		}
	}
	for _, d := range []string{"/tmp", "/etc", rootDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	if f, err := os.OpenFile("/dev/console", os.O_RDWR, 0); err == nil {
		for fd := 0; fd < 3; fd++ {
			_ = unix.Dup2(int(f.Fd()), fd)
		}
		f.Close()
	}
	if err := os.MkdirAll(workCgroup, 0o755); err != nil {
		log.Printf("create %s: %v", workCgroup, err)
	}
}

// loadModules loads every *.ko in dir in lexical order (the build prefixes
// names with the load order), retrying failures while progress is made.
func loadModules(dir string) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.ko"))
	for len(paths) > 0 {
		var failed []string
		var lastErr error
		for _, p := range paths {
			if err := loadModule(p); err != nil {
				failed = append(failed, p)
				lastErr = fmt.Errorf("%s: %w", filepath.Base(p), err)
			}
		}
		if len(failed) == len(paths) {
			log.Printf("load modules: %v", lastErr)
			return
		}
		paths = failed
	}
}

func loadModule(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	err = unix.FinitModule(int(f.Fd()), "", 0)
	if err == unix.EEXIST {
		return nil
	}
	return err
}

// findBlock returns /dev/<name> of the block device whose serial is serial.
func findBlock(serial string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		files, _ := filepath.Glob("/sys/block/*/serial")
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err == nil && strings.TrimSpace(string(b)) == serial {
				dev := "/dev/" + filepath.Base(filepath.Dir(f))
				if _, err := os.Stat(dev); err == nil {
					return dev, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no disk with serial %q", serial)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readConfig reads the config disk.
func readConfig() (bootconfig.Config, error) {
	dev, err := findBlock(bootconfig.ConfigSerial, 5*time.Second)
	if err != nil {
		return bootconfig.Config{}, err
	}
	f, err := os.Open(dev)
	if err != nil {
		return bootconfig.Config{}, err
	}
	defer f.Close()
	buf := make([]byte, bootconfig.ConfigDiskSize)
	n, err := f.ReadAt(buf, 0)
	if n == 0 && err != nil {
		return bootconfig.Config{}, err
	}
	return bootconfig.DecodeConfig(buf[:n])
}

// listenVsock listens on a vsock port on any CID.
func listenVsock(port uint32) (int, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, 64); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// acceptVsock accepts the next connection from the host (CID 2); others are
// closed.
func acceptVsock(lfd int) (*os.File, error) {
	for {
		fd, sa, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err == unix.EINTR || err == unix.ECONNABORTED {
			continue
		}
		if err != nil {
			return nil, err
		}
		if vm, ok := sa.(*unix.SockaddrVM); !ok || vm.CID != unix.VMADDR_CID_HOST {
			unix.Close(fd)
			continue
		}
		return os.NewFile(uintptr(fd), "vsock"), nil
	}
}

// isInit reports whether this process is the VM's init. Everything that
// affects processes or mounts outside the guest's own children checks it.
func isInit() bool { return os.Getpid() == 1 }

// powerOff turns the VM off. It is a no-op unless this process is PID 1.
func powerOff() {
	if !isInit() {
		log.Printf("not PID 1; skipping power off")
		return
	}
	unix.Sync()
	for {
		if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
			log.Printf("power off: %v", err)
		}
		time.Sleep(time.Second)
	}
}

// unmount unmounts target without following symlinks, retrying briefly on
// EBUSY. It is a no-op unless this process is PID 1.
func unmount(target string, attempts int) error {
	if !isInit() {
		return nil
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		err = unix.Unmount(target, unix.UMOUNT_NOFOLLOW)
		if err == nil || err == unix.EINVAL || err == unix.ENOENT {
			return nil
		}
		if err != unix.EBUSY {
			break
		}
	}
	if err == unix.EBUSY {
		return fmt.Errorf("unmount %s: target is busy", target)
	}
	return fmt.Errorf("unmount %s: %w", target, err)
}

var errNotInit = errors.New("not PID 1")
