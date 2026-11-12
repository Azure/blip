package slot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Files in the slot directory (/run/blip in the pod). The node daemon
// writes Assignment, Assigned and Kill, and the host slots of Meta;
// blipd slot writes the rest. ResolvConf, Network and Meta are created
// by blipd slot at startup. blipd slot writes Ready when the boot stub
// reports WAITING in the Meta guest area.
const (
	FileAPISocket  = "ch.sock"
	FileVsock      = "vsock.sock"
	FileSerial     = "serial.log"
	FileReady      = "ready"
	FileAssignment = "assignment.json"
	FileAssigned   = "assigned"
	FileKill       = "kill"
	FileExit       = "exit.json"
	// FileMeta is the metadata disk image (internal/meta), attached at
	// launch with virtio serial meta.Serial.
	FileMeta = "meta.img"
	// FileEvents is the Cloud Hypervisor event monitor output.
	FileEvents = "events.json"
	// FileResolvConf is a copy of the pod's /etc/resolv.conf.
	FileResolvConf = "resolv.conf"
	// FileNetwork is the pod network (PodNetwork as JSON), written by
	// blipd slot before it moves the pod IP to the guest.
	FileNetwork = "network.json"
	// DirVolumes holds one symlink per attached BlipVol, written by the
	// node daemon: volumes/<blipvol-uid> -> /dev/blip/disks/<n>. Cloud
	// Hypervisor opens the volume through it.
	DirVolumes = "volumes"
)

// VolumePath is the slot path of the volume with the given BlipVol UID,
// under runDir (/run/blip in the pod).
func VolumePath(runDir, uid string) string {
	return filepath.Join(runDir, DirVolumes, uid)
}

// Assignment is the content of assignment.json.
type Assignment struct {
	AllocationID string `json:"allocationID"`
	// KillTime is when blipd slot kills Cloud Hypervisor: the allocation
	// deadline plus AssignSlot.kill_grace.
	KillTime time.Time `json:"killTime"`
	// Ports are guest TCP ports blipd slot forwards from the pod's
	// loopback to the same guest vsock port.
	Ports []uint32 `json:"ports,omitempty"`
}

// ExitRecord is the content of exit.json, written when Cloud Hypervisor
// has exited. blipd slot classifies the end of the VM once: Reason is the
// Blip condition reason (api.Reason*), and the node and the controller
// pass it on unchanged.
type ExitRecord struct {
	// ExitCode of Cloud Hypervisor, or -1 if it died from a signal.
	ExitCode int    `json:"exitCode"`
	Signal   string `json:"signal,omitempty"`
	// Cause is why Cloud Hypervisor ended: "exited" (on its own),
	// "deadline", "killed" (kill file), "stopped" (blipd slot was told
	// to stop), "backend" (wrong hypervisor backend), "panic" (blipd
	// slot killed it after a guest panic).
	Cause string `json:"cause"`
	// Reason is the Blip reason: Succeeded, Error, GuestPanic,
	// InitExited, BootFailed, TTLExceeded or HypervisorExited.
	Reason string `json:"reason"`
	// Message is the human readable result for the Blip condition.
	Message string `json:"message,omitempty"`
	// GuestExitCode is the guest's exit code: from `blip-meta exit` in
	// the guest area, else the init exit status for InitExited.
	GuestExitCode *int `json:"guestExitCode,omitempty"`
	// BootCount is the number of boots seen (guest area bootCount, or
	// 1 + reboot events); 0 if the guest never booted.
	BootCount int       `json:"bootCount"`
	Time      time.Time `json:"time"`
}

// WriteAssignment writes assignment.json atomically, then the assigned
// marker. Used by the node daemon.
func WriteAssignment(dir string, a Assignment) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, FileAssignment), b); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, FileAssigned), nil, 0o644)
}

// RequestKill asks blipd slot to kill Cloud Hypervisor now. Used by the
// node daemon.
func RequestKill(dir string) error {
	return os.WriteFile(filepath.Join(dir, FileKill), nil, 0o644)
}

// PowerButton presses the ACPI power button of the VM through the Cloud
// Hypervisor API socket in dir. Used by the node daemon for a graceful
// stop.
func PowerButton(ctx context.Context, dir string) error {
	return Client(dir).PowerButton(ctx)
}

// ReadExit reads exit.json. It returns an error satisfying
// errors.Is(err, fs.ErrNotExist) while Cloud Hypervisor still runs.
func ReadExit(dir string) (*ExitRecord, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileExit))
	if err != nil {
		return nil, err
	}
	var r ExitRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func readAssignment(dir string) (*Assignment, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileAssignment))
	if err != nil {
		return nil, err
	}
	var a Assignment
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileAssignment, err)
	}
	return &a, nil
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParseMemory parses a Kubernetes-style memory quantity ("2Gi", "1536Mi",
// "2G", "1073741824") and returns MiB. The size must be a whole number
// of MiB.
func ParseMemory(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
		{"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad memory size %q", s)
	}
	bytes := n * mult
	if bytes%(1<<20) != 0 {
		return 0, errors.New("memory size must be a whole number of MiB")
	}
	return bytes >> 20, nil
}
