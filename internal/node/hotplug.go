package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/slot/chapi"
)

// Hypervisor hot-plugs volumes into the VM of a slot.
type Hypervisor interface {
	// AddDisk adds the disk unless the VM already has a disk with its
	// ID.
	AddDisk(ctx context.Context, slotDir string, d chapi.DiskConfig) error
	// RemoveDisk removes the disk with the given ID if the VM has it,
	// then waits until no Cloud Hypervisor process has hostDev (the
	// host path of the slot disk behind it) open.
	RemoveDisk(ctx context.Context, slotDir, id, hostDev string) error
	// PowerButton presses the ACPI power button of the VM.
	PowerButton(ctx context.Context, slotDir string) error
}

// CloudHypervisor is the Hypervisor of real slots: the Cloud Hypervisor
// API on <slotDir>/ch.sock, and /proc to confirm an unplugged device was
// closed. The node daemon runs with hostPID, so /proc shows the slot
// pods' processes.
type CloudHypervisor struct {
	// UnplugTimeout bounds the wait for the device to be closed after
	// remove-device. Default 30s.
	UnplugTimeout time.Duration
	// Proc is the proc file system root. Default /proc.
	Proc string
	// IsVMM selects the processes whose fds are checked, by comm.
	// Default: Cloud Hypervisor ("cloud-hyperviso", comm is truncated
	// to 15 bytes).
	IsVMM func(comm string) bool
}

func (h *CloudHypervisor) AddDisk(ctx context.Context, slotDir string, d chapi.DiskConfig) error {
	c := slot.Client(slotDir)
	if has, err := c.HasDisk(ctx, d.ID); err == nil && has {
		return nil
	}
	_, err := c.AddDisk(ctx, d)
	if err != nil {
		// A lost answer to an earlier add: the disk is there.
		if has, ierr := c.HasDisk(ctx, d.ID); ierr == nil && has {
			return nil
		}
	}
	return err
}

func (h *CloudHypervisor) PowerButton(ctx context.Context, slotDir string) error {
	return slot.PowerButton(ctx, slotDir)
}

func (h *CloudHypervisor) RemoveDisk(ctx context.Context, slotDir, id, hostDev string) error {
	c := slot.Client(slotDir)
	has, err := c.HasDisk(ctx, id)
	if err != nil {
		return err
	}
	if has {
		if err := c.RemoveDevice(ctx, id); err != nil {
			if has, ierr := c.HasDisk(ctx, id); ierr != nil || has {
				return err
			}
		}
	}
	return h.waitClosed(ctx, hostDev)
}

func (h *CloudHypervisor) waitClosed(ctx context.Context, hostDev string) error {
	timeout := h.UnplugTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	proc := h.Proc
	if proc == "" {
		proc = "/proc"
	}
	isVMM := h.IsVMM
	if isVMM == nil {
		isVMM = func(comm string) bool { return strings.HasPrefix(comm, "cloud-hyperv") }
	}
	end := time.Now().Add(timeout)
	for {
		pids, err := FDHolders(proc, hostDev, isVMM)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("%s is still open by process %v %s after unplug", hostDev, pids, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// fileKey identifies the file behind a path or fd: the device number for
// device nodes, the inode otherwise.
type fileKey struct {
	rdev     uint64
	dev, ino uint64
}

func keyOf(st *syscall.Stat_t) fileKey {
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFBLK, syscall.S_IFCHR:
		return fileKey{rdev: uint64(st.Rdev)}
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}
}

// FDHolders returns the PIDs of processes selected by match (on their
// comm) that have path open. Processes that vanish while scanning are
// skipped.
func FDHolders(proc, path string, match func(comm string) bool) ([]int, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	want := keyOf(&st)
	ents, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(proc, e.Name(), "comm"))
		if err != nil || !match(strings.TrimSpace(string(comm))) {
			continue
		}
		fdDir := filepath.Join(proc, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			var fst syscall.Stat_t
			if err := syscall.Stat(filepath.Join(fdDir, fd.Name()), &fst); err != nil {
				continue
			}
			if keyOf(&fst) == want {
				out = append(out, pid)
				break
			}
		}
	}
	return out, nil
}
