// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/blip/internal/bootconfig"
	"github.com/Azure/blip/internal/podapi"
)

// chSocketTimeout bounds the wait for Cloud Hypervisor to bind its sockets.
// It binds them during VM setup, well before the guest boots, so this only
// covers process startup.
const chSocketTimeout = 10 * time.Second

// chSocketPoll is the interval between socket appearance checks.
const chSocketPoll = 10 * time.Millisecond

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
		"--disk", fmt.Sprintf("path=%s,readonly=on,image_type=raw,serial=%s,id=%s,pci_segment=0", configDisk, bootconfig.ConfigSerial, bootconfig.ConfigSerial),
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

// secureCHSockets waits for Cloud Hypervisor to bind its API and vsock
// sockets, then restricts both to root. CH creates them with the runtime's
// umask, so without this a host-local user could connect to the CH API
// (pause/shutdown/add-disk on another tenant's VM) whenever the umask allowed
// group or other writes.
func (r *runtime) secureCHSockets() error {
	for _, name := range []string{podapi.APISocket, podapi.VsockSocket} {
		if err := waitSocket(r.o.path(name), chSocketTimeout); err != nil {
			return err
		}
	}
	return nil
}

// waitSocket waits up to timeout for path to appear as a unix socket and then
// chmods it 0600. The socket is bound by another process, so the chmod races
// its creation; the caller must not connect before this returns. A missing
// socket is retried, any other failure is reported immediately.
func waitSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("%s exists and is not a unix socket", path)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return fmt.Errorf("set %s permissions: %w", path, err)
			}
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("check socket %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("socket %s did not appear within %s", path, timeout)
		}
		time.Sleep(chSocketPoll)
	}
}

// chClient talks to the Cloud Hypervisor REST API on its unix socket.
type chClient struct {
	hc  *http.Client
	ctx context.Context
	// clock only controls detach polling. Tests execute the real multi-step
	// workflow with a logical clock and a scripted HTTP transport.
	clock detachClock
}

type detachClock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type realDetachClock struct{}

func (realDetachClock) Now() time.Time { return time.Now() }
func (realDetachClock) Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	req, err := http.NewRequestWithContext(c.context(), method, "http://localhost/api/v1/"+path, rd)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", path, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func (c *chClient) context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
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
	if err != nil {
		// The request may have committed before its reply was lost. Attachment
		// confirmation must match the device, not just a reused ID or an old
		// device-tree entry whose eject is still pending.
		if info, checkErr := c.info(); checkErr == nil {
			for _, attached := range info.Config.Disks {
				if attached.ID == d.ID && attached.Path == d.Device && attached.Serial == serial && attached.ReadOnly == d.ReadOnly {
					return nil
				}
			}
		}
	}
	return err
}

// removeDisk removes a device and waits until vm.info no longer lists it.
func (c *chClient) removeDisk(id string, timeout time.Duration) error {
	clock := c.clock
	if clock == nil {
		clock = realDetachClock{}
	}
	if _, err := c.call(http.MethodPut, "vm.remove-device", map[string]any{"id": id}); err != nil {
		// Already gone (e.g. after a runtime retry) is success.
		if ok, ierr := c.hasDisk(id); ierr == nil && !ok {
			return nil
		}
		return err
	}
	deadline := clock.Now().Add(timeout)
	for {
		ok, err := c.hasDisk(id)
		if err == nil && !ok {
			return nil
		}
		if !clock.Now().Before(deadline) {
			if err == nil {
				err = fmt.Errorf("device %s still present", id)
			}
			return fmt.Errorf("remove %s: %w", id, err)
		}
		if err := clock.Sleep(c.context(), 50*time.Millisecond); err != nil {
			return err
		}
	}
}

type chInfo struct {
	Config struct {
		Disks []struct {
			ID       string `json:"id"`
			Path     string `json:"path"`
			Serial   string `json:"serial"`
			ReadOnly bool   `json:"readonly"`
		} `json:"disks"`
	} `json:"config"`
	DeviceTree map[string]json.RawMessage `json:"device_tree"`
}

func (c *chClient) info() (chInfo, error) {
	var info chInfo
	data, err := c.call(http.MethodGet, "vm.info", nil)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return info, err
	}
	return info, nil
}

func (c *chClient) hasDisk(id string) (bool, error) {
	info, err := c.info()
	if err != nil {
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
