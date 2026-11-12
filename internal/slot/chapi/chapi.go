// Package chapi is a small client for the Cloud Hypervisor HTTP API on its
// unix socket. The node daemon uses it to hot-plug and unplug volumes, read VM info
// and shut the VMM down.
package chapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to one Cloud Hypervisor API socket.
type Client struct {
	hc *http.Client
}

// New returns a client for the API socket at path.
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

// APIError is a non-2xx answer from Cloud Hypervisor.
type APIError struct {
	Endpoint string
	Status   int
	Body     string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloud-hypervisor %s: HTTP %d: %s", e.Endpoint, e.Status, e.Body)
}

func (c *Client) do(ctx context.Context, method, endpoint string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/api/v1/"+endpoint, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cloud-hypervisor %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return &APIError{Endpoint: endpoint, Status: resp.StatusCode, Body: string(bytes.TrimSpace(b))}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("cloud-hypervisor %s: decode: %w", endpoint, err)
		}
	}
	return nil
}

// DiskConfig is the subset of the Cloud Hypervisor DiskConfig Blip uses.
type DiskConfig struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"readonly"`
	Direct   bool   `json:"direct"`
	// ImageType is "Raw" or "Qcow2". Recent Cloud Hypervisor requires it.
	ImageType string `json:"image_type,omitempty"`
	// Sparse false stops Cloud Hypervisor from advertising discard and
	// write-zeroes to the guest. nil means the default (true).
	Sparse *bool `json:"sparse,omitempty"`
	// Serial is seen by the guest in /sys/block/*/serial (max 20 bytes).
	Serial string `json:"serial,omitempty"`
	ID     string `json:"id,omitempty"`
}

// PciDeviceInfo is the answer to a hot-plug.
type PciDeviceInfo struct {
	ID  string `json:"id"`
	BDF string `json:"bdf"`
}

// AddDisk hot-plugs a disk (vm.add-disk).
func (c *Client) AddDisk(ctx context.Context, d DiskConfig) (*PciDeviceInfo, error) {
	var info PciDeviceInfo
	if err := c.do(ctx, http.MethodPut, "vm.add-disk", d, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// VolumeDiskID is the Cloud Hypervisor device ID of an attachment.
func VolumeDiskID(attachmentID string) string { return "blip-" + attachmentID }

// VolumeDisk is the disk config of an attached BlipVol: the slot path of
// the volume, read-write, direct I/O, raw, no discard or write-zeroes
// (sparse false), ID "blip-<attachmentID>" and serial (the volume name,
// at most 20 bytes): the guest sees /dev/disk/by-id/virtio-<serial>.
func VolumeDisk(path, attachmentID, serial string) DiskConfig {
	sparse := false
	return DiskConfig{Path: path, Direct: true, ImageType: "Raw", Sparse: &sparse, Serial: serial, ID: VolumeDiskID(attachmentID)}
}

// RemoveDevice hot-unplugs a device by ID (vm.remove-device). The guest
// sees the removal asynchronously; Cloud Hypervisor closes the backing file
// once the guest acknowledged it.
func (c *Client) RemoveDevice(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPut, "vm.remove-device", map[string]string{"id": id}, nil)
}

// Disks returns the disks in the current VM config (vm.info), which
// includes hot-plugged ones and drops removed ones.
func (c *Client) Disks(ctx context.Context) ([]DiskConfig, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Disks []DiskConfig `json:"disks"`
	}
	if len(info.Config) > 0 {
		if err := json.Unmarshal(info.Config, &cfg); err != nil {
			return nil, fmt.Errorf("cloud-hypervisor vm.info: decode disks: %w", err)
		}
	}
	return cfg.Disks, nil
}

// HasDisk reports whether the VM has a disk with the given ID.
func (c *Client) HasDisk(ctx context.Context, id string) (bool, error) {
	ds, err := c.Disks(ctx)
	if err != nil {
		return false, err
	}
	for _, d := range ds {
		if d.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// VMInfo is the subset of vm.info Blip reads. Config holds the full VM
// config as raw JSON.
type VMInfo struct {
	State            string          `json:"state"`
	MemoryActualSize int64           `json:"memory_actual_size"`
	Config           json.RawMessage `json:"config"`
	DeviceTree       json.RawMessage `json:"device_tree"`
}

// Info returns vm.info.
func (c *Client) Info(ctx context.Context) (*VMInfo, error) {
	var info VMInfo
	if err := c.do(ctx, http.MethodGet, "vm.info", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// VMMPing is the answer to vmm.ping.
type VMMPing struct {
	BuildVersion string   `json:"build_version"`
	Version      string   `json:"version"`
	PID          int      `json:"pid"`
	Features     []string `json:"features"`
}

// Ping returns vmm.ping. It tells whether the API is up.
func (c *Client) Ping(ctx context.Context) (*VMMPing, error) {
	var p VMMPing
	if err := c.do(ctx, http.MethodGet, "vmm.ping", nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Shutdown stops the VM (vm.shutdown). The VMM process keeps running.
func (c *Client) Shutdown(ctx context.Context) error {
	return c.do(ctx, http.MethodPut, "vm.shutdown", nil, nil)
}

// PowerButton presses the ACPI power button (vm.power-button). The guest
// OS decides what to do; most shut down.
func (c *Client) PowerButton(ctx context.Context) error {
	return c.do(ctx, http.MethodPut, "vm.power-button", nil, nil)
}

// ShutdownVMM ends the Cloud Hypervisor process (vmm.shutdown). Do not use
// it to end a run that must not be saved; use slot.RequestKill instead,
// so the exit is recorded as a kill.
func (c *Client) ShutdownVMM(ctx context.Context) error {
	return c.do(ctx, http.MethodPut, "vmm.shutdown", nil, nil)
}
