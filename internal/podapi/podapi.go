// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package podapi is the contract between the node agent and the in-pod
// runtime. The node agent writes Desired; the runtime writes Observed. Both
// live in the pod directory, which is the host path
// <dataDir>/pods/<namespace>/<pod-name> mounted at /run/blip in the vm
// container.
//
// Both documents are complete, level-triggered descriptions and are written
// atomically (temp file + rename). A missing or unreadable Desired must never
// cause the runtime to detach disks or stop the VM: it keeps the last valid
// document.
package podapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Azure/blip/internal/atomicfile"
	"github.com/Azure/blip/internal/netpolicy"
)

const (
	// DataDir is the node agent's data directory on every node.
	DataDir = "/var/lib/blip"
	// VMContainer is the VM pod container that runs blip-runtime.
	VMContainer = "vm"
	// PodsDir holds one directory per VM pod, below a namespace directory.
	PodsDir = DataDir + "/pods"
	// MountPath is where the pod directory appears inside the vm container.
	MountPath = "/run/blip"

	DesiredFile  = "desired.json"
	ObservedFile = "observed.json"
	// DevDir holds block device nodes the node agent creates for the VM.
	DevDir = "dev"

	// DirMode is the mode of a pod directory and of its namespace parent.
	// They hold documents with user-supplied environment (and command output)
	// and must not be traversable by other node-local users.
	DirMode os.FileMode = 0o700
	// FileMode is the mode of every document written by WriteJSON. The node
	// agent and the runtime both run as root on the node.
	FileMode os.FileMode = 0o600
	// VsockSocket is the Cloud Hypervisor vsock unix socket, below the pod
	// directory. The directory is bind-mounted into the API-proxy sidecar so
	// both the hypervisor and the sidecar can create sockets in it. Clients
	// connect and write "CONNECT <port>\n" to reach a guest port.
	VsockSocket = "sock/vsock.sock"
	APISocket   = "ch-api.sock"
)

// Desired is written by the node agent.
type Desired struct {
	// Network is the compiled direct-egress policy. Missing means deny all.
	// It is reconciled independently of disks and must be applied before claim.
	Network *netpolicy.Policy `json:"network,omitempty"`
	// Claim is nil while the VM is vacant (warm).
	Claim *Claim `json:"claim,omitempty"`
	// Mounts is the complete set of auxiliary disks that should be attached
	// and mounted. Removing an entry unmounts and detaches it.
	Mounts []Disk `json:"mounts,omitempty"`
	// Stop asks for a graceful shutdown: stop processes, unmount, power off.
	Stop bool `json:"stop,omitempty"`
	// Freeze lists disk IDs (the claim root ID or mount IDs) whose
	// filesystems the guest should keep frozen (FIFREEZE) so the host can
	// snapshot them consistently. The guest thaws on its own after 30s.
	Freeze []string `json:"freeze,omitempty"`
	// StopReason labels the exit when Stop is set by the node agent itself,
	// for example "Idle". It is empty for user and deadline stops.
	StopReason string `json:"stopReason,omitempty"`
}

// Claim turns a vacant VM into a running blip.
type Claim struct {
	BlipName string `json:"blipName"`
	BlipUID  string `json:"blipUID"`
	Root     Disk   `json:"root"`
	// Command is the required primary command.
	Command    []string `json:"command,omitempty"`
	Env        []string `json:"env,omitempty"` // KEY=VALUE, image env first
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// Disk is a block device for the VM. Device is a path inside the vm
// container (normally /run/blip/dev/<serial>).
type Disk struct {
	// ID is unique per attachment (the attachment ID). It names the disk
	// in Cloud Hypervisor.
	ID       string `json:"id"`
	Device   string `json:"device"`
	Serial   string `json:"serial"` // at most 20 bytes
	ReadOnly bool   `json:"readOnly,omitempty"`
	// State is the BlipState name (mounts only).
	State string `json:"state,omitempty"`
	// Path is the guest mount point (mounts only).
	Path string `json:"path,omitempty"`
}

const (
	PhaseBooting  = "Booting"  // VM starting
	PhaseWarm     = "Warm"     // guest ready, no claim
	PhaseClaiming = "Claiming" // root attached, waiting for guest
	PhaseRunning  = "Running"  // guest mounted root and runs the blip
	PhaseStopping = "Stopping" // shutdown in progress
	PhaseExited   = "Exited"   // VMM process has exited; every disk is closed
)

const (
	DiskAttaching  = "Attaching"
	DiskMounted    = "Mounted"
	DiskUnmounting = "Unmounting"
	// DiskDetached means the guest unmounted the filesystem and Cloud
	// Hypervisor confirmed removal: the VM can no longer write it.
	DiskDetached = "Detached"
	DiskFailed   = "Failed"
)

// Observed is written by the runtime.
type Observed struct {
	Phase string `json:"phase"`
	// NetworkRevision identifies the last successfully installed policy.
	NetworkRevision string `json:"networkRevision,omitempty"`
	// NetworkError reports why desired networking could not be installed.
	NetworkError string `json:"networkError,omitempty"`
	// ClaimID echoes Desired.Claim.Root.ID once the guest accepted it.
	ClaimID string `json:"claimID,omitempty"`
	// Mounts reports every auxiliary disk the runtime still tracks,
	// including detached ones until the node removes them from Desired.
	Mounts []DiskStatus `json:"mounts,omitempty"`
	// Exit is set when the primary command exited or the guest stopped.
	Exit *Exit `json:"exit,omitempty"`
	// Error describes a fatal runtime or guest failure.
	Error string `json:"error,omitempty"`
	// Frozen lists the disk IDs from Desired.Freeze that are frozen now.
	Frozen []string `json:"frozen,omitempty"`
}

type DiskStatus struct {
	ID      string `json:"id"`
	State   string `json:"state,omitempty"`
	Phase   string `json:"phase"`
	Message string `json:"message,omitempty"`
}

type Exit struct {
	Code   int    `json:"code"`
	Signal string `json:"signal,omitempty"`
	// Reason is e.g. "Completed", "Idle", "Stopped", "GuestCrashed".
	Reason string `json:"reason,omitempty"`
	// Output is the end of the command's output when it failed.
	Output string `json:"output,omitempty"`
}

// PodDir returns the host directory for one VM pod. Namespace is part of the
// path so identically named pods in different namespaces never share disks,
// sockets, or status files.
func PodDir(namespace, name string) string {
	return filepath.Join(PodsDir, namespace, name)
}

// VsockListenerPath returns the sidecar Unix socket that forwards to the
// guest's vsock port. It sits next to the Cloud Hypervisor vsock socket in the
// emptyDir shared by the runtime and the API-proxy sidecar.
func VsockListenerPath(dir string, port uint32) string {
	return filepath.Join(dir, VsockSocket) + "_" + strconv.FormatUint(uint64(port), 10)
}

// EnsurePodDir creates a pod directory with DirMode and tightens it and its
// namespace parent to DirMode if they already exist with broader permissions.
// The node agent calls it before writing Desired, so a directory left at the
// emptyDir default by kubelet's DirectoryOrCreate becomes root-only. It never
// widens a mode and never follows a symlink.
func EnsurePodDir(dir string) error {
	if err := EnsureDir(dir); err != nil {
		return err
	}
	return tightenDir(filepath.Dir(dir))
}

// EnsureSocketDir creates the shared vsock directory below the pod directory
// and makes sure it is writable by the non-root API-proxy sidecar. Kubelet
// creates a hostPath DirectoryOrCreate with root-only permissions, so the node
// agent must widen it before the sidecar binds its listener. The directory is
// below the root-only pod directory, so 0777 does not expose it to other
// users.
func EnsureSocketDir(podDir string) error {
	dir := filepath.Join(podDir, "sock")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	return os.Chmod(dir, 0o777)
}

// EnsureDir creates dir with DirMode and tightens it if it already exists
// with broader permissions. It does not touch the parent: the runtime mounts
// the pod directory below /run, whose parent is not a namespace directory.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return err
	}
	return tightenDir(dir)
}

// tightenDir removes group and other permissions from an existing directory.
// It refuses to follow symlinks, so a planted link cannot redirect the chmod.
func tightenDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, perm&^0o077); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON atomically and durably replaces path with v encoded as JSON. The
// result is FileMode (root-only): Desired carries the claim environment and
// Observed carries command output. The parent directory must already exist
// durably. An error after rename may leave the new document visible; it does
// not imply rollback (see atomicfile.Error).
func WriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Replace(path, append(data, '\n'), FileMode)
}

// ErrMissing is returned by ReadJSON when the file does not exist.
var ErrMissing = errors.New("missing")

// ReadJSON reads path into v. It returns ErrMissing if the file is absent.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrMissing
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
