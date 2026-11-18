package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/blip/internal/podapi"
)

// chArgs returns the Cloud Hypervisor command line.
func chArgs(o Options, configDisk, tap, mac string) []string {
	args := []string{
		"--api-socket", "path=" + o.path(podapi.APISocket),
		"--kernel", o.Kernel,
		"--initramfs", o.Initramfs,
		"--cmdline", "console=ttyS0 panic=-1",
		"--cpus", fmt.Sprintf("boot=%d", o.CPUs),
		"--memory", fmt.Sprintf("size=%dM", o.MemoryMB),
		"--platform", "num_pci_segments=2",
		"--disk", fmt.Sprintf("path=%s,readonly=on,image_type=raw,serial=blip-config,id=blip-config,pci_segment=0", configDisk),
		"--vsock", fmt.Sprintf("cid=3,socket=%s", o.path(podapi.VsockSocket)),
		"--serial", "tty", // CH stdout: the pod log, which kubelet rotates
		"--console", "off",
	}
	if tap != "" {
		net := "tap=" + tap
		if mac != "" {
			net += ",mac=" + mac
		}
		args = append(args, "--net", net)
	}
	return args
}

// chClient talks to the Cloud Hypervisor REST API on its unix socket.
type chClient struct {
	hc *http.Client
}

func newCHClient(sock string) *chClient {
	return &chClient{hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}}
}

func (c *chClient) call(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://localhost/api/v1/"+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// addDisk hot-adds d on PCI segment 1 with id and serial set.
func (c *chClient) addDisk(d podapi.Disk) error {
	serial := d.Serial
	if serial == "" {
		serial = d.ID
	}
	_, err := c.call(http.MethodPut, "vm.add-disk", map[string]any{
		"path":        d.Device,
		"id":          d.ID,
		"serial":      serial,
		"readonly":    d.ReadOnly,
		"image_type":  "Raw",
		"direct":      true,
		"pci_segment": 1,
	})
	return err
}

// removeDisk removes a device and waits until vm.info no longer lists it.
func (c *chClient) removeDisk(id string, timeout time.Duration) error {
	if _, err := c.call(http.MethodPut, "vm.remove-device", map[string]any{"id": id}); err != nil {
		// Already gone (e.g. after a runtime retry) is success.
		if ok, ierr := c.hasDisk(id); ierr == nil && !ok {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := c.hasDisk(id)
		if err == nil && !ok {
			return nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("device %s still present", id)
			}
			return fmt.Errorf("remove %s: %w", id, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *chClient) hasDisk(id string) (bool, error) {
	data, err := c.call(http.MethodGet, "vm.info", nil)
	if err != nil {
		return false, err
	}
	var info struct {
		Config struct {
			Disks []struct {
				ID string `json:"id"`
			} `json:"disks"`
		} `json:"config"`
		DeviceTree map[string]json.RawMessage `json:"device_tree"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return false, err
	}
	for _, d := range info.Config.Disks {
		if d.ID == id {
			return true, nil
		}
	}
	_, inTree := info.DeviceTree[id]
	return inTree, nil
}
