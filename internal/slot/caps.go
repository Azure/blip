package slot

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// securebits (linux/securebits.h).
const (
	secNoRoot       = 1 << 0
	secNoRootLocked = 1 << 1
)

// dropCapabilities removes every capability but CAP_NET_BIND_SERVICE from
// all threads of this process: the bounding set, the ambient set, and the
// effective, permitted and inheritable sets. blipd slot keeps
// CAP_NET_BIND_SERVICE (if it had it) to listen on forwarded ports below
// 1024 on the pod loopback. The securebits NOROOT (locked) make children,
// including Cloud Hypervisor, run with no effective or permitted
// capabilities even as uid 0. It also sets no_new_privs.
func dropCapabilities() error {
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_SECUREBITS,
		secNoRoot|secNoRootLocked, 0); e != 0 {
		return fmt.Errorf("set securebits: %w", e)
	}
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return err
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if c == unix.CAP_NET_BIND_SERVICE {
			continue
		}
		if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(c), 0); e != 0 {
			return fmt.Errorf("drop capability %d from bounding set: %w", c, e)
		}
	}
	if _, _, e := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("clear ambient capabilities: %w", e)
	}
	if _, _, e := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("set no_new_privs: %w", e)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	data[0].Effective = 1 << unix.CAP_NET_BIND_SERVICE
	data[0].Permitted = 1 << unix.CAP_NET_BIND_SERVICE
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		// Not in the permitted set to begin with: drop everything.
		data[0] = unix.CapUserData{}
		if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
			return fmt.Errorf("capset: %w", e)
		}
	}
	return nil
}

// capsOf returns the CapEff and CapBnd lines of /proc/<pid>/status.
func capsOf(pid int) (eff, bnd string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			eff = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "CapBnd:"); ok {
			bnd = strings.TrimSpace(v)
		}
	}
	return eff, bnd, nil
}
