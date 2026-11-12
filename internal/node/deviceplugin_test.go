package node

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	dp "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	podres "k8s.io/kubelet/pkg/apis/podresources/v1"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/slot"
)

type fakeKubelet struct {
	dp.UnimplementedRegistrationServer
	reqs chan *dp.RegisterRequest
}

func (f *fakeKubelet) Register(_ context.Context, r *dp.RegisterRequest) (*dp.Empty, error) {
	f.reqs <- r
	return &dp.Empty{}, nil
}

func TestDevicePlugin(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir, 2)
	devDir := filepath.Join(dir, "devroot")
	os.MkdirAll(devDir, 0o755)
	pluginDir, err := os.MkdirTemp("/tmp", "dp") // short path for unix sockets
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(pluginDir)

	// Fake kubelet registration socket.
	l, err := net.Listen("unix", filepath.Join(pluginDir, "kubelet.sock"))
	if err != nil {
		t.Fatal(err)
	}
	fk := &fakeKubelet{reqs: make(chan *dp.RegisterRequest, 5)}
	ks := grpc.NewServer()
	dp.RegisterRegistrationServer(ks, fk)
	go ks.Serve(l)
	defer ks.Stop()

	p := &DevicePlugin{Node: h.n, PluginDir: pluginDir, DevDir: devDir, HealthPoll: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	var reg *dp.RegisterRequest
	select {
	case reg = <-fk.reqs:
	case <-time.After(5 * time.Second):
		t.Fatal("no registration")
	}
	if reg.ResourceName != api.ResourceHypervisor || reg.Endpoint != PluginSocket || reg.Version != dp.Version {
		t.Fatal(reg)
	}

	conn, err := grpc.NewClient("unix://"+filepath.Join(pluginDir, PluginSocket), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := dp.NewDevicePluginClient(conn)
	lw, err := c.ListAndWatch(ctx, &dp.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := lw.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 2 || r.Devices[0].ID != "slot-0" || r.Devices[0].Health != dp.Unhealthy {
		t.Fatal(r.Devices)
	}
	// The hypervisor device appears: devices turn healthy.
	os.WriteFile(filepath.Join(devDir, "kvm"), nil, 0o644)
	r, err = lw.Recv()
	if err != nil || r.Devices[1].Health != dp.Healthy {
		t.Fatal(r, err)
	}

	// Allocate cleans the slot directory and returns the devices.
	sd := h.n.slotDir("slot-1")
	os.WriteFile(filepath.Join(sd, slot.FileAssigned), nil, 0o644)
	ar, err := c.Allocate(ctx, &dp.AllocateRequest{ContainerRequests: []*dp.ContainerAllocateRequest{{DevicesIDs: []string{"slot-1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	cr := ar.ContainerResponses[0]
	var devs []string
	for _, d := range cr.Devices {
		devs = append(devs, d.ContainerPath+"="+d.HostPath)
	}
	want := []string{"/dev/kvm=/dev/kvm", "/dev/net/tun=/dev/net/tun"}
	for i := range h.n.disksPerSlot() {
		want = append(want, fmt.Sprintf("/dev/blip/disks/%d=%s", i, filepath.Join(dir, "dev", fmt.Sprintf("slot-dev-slot-1-d%d", i))))
	}
	if strings.Join(devs, ",") != strings.Join(want, ",") {
		t.Fatal(devs)
	}
	if fi, err := os.Stat(filepath.Join(sd, slot.DirVolumes)); err != nil || !fi.IsDir() {
		t.Fatal("no volumes dir", err)
	}
	if len(cr.Mounts) != 1 || cr.Mounts[0].ContainerPath != "/run/blip" || cr.Mounts[0].HostPath != sd || cr.Envs["BLIP_SLOT_ID"] != "slot-1" {
		t.Fatal(cr.Mounts, cr.Envs)
	}
	if exists(filepath.Join(sd, slot.FileAssigned)) {
		t.Fatal("slot dir not cleaned")
	}
	if _, err := c.Allocate(ctx, &dp.AllocateRequest{ContainerRequests: []*dp.ContainerAllocateRequest{{DevicesIDs: []string{"slot-0", "slot-1"}}}}); err == nil {
		t.Fatal("two slots in one container")
	}
	if _, err := c.Allocate(ctx, &dp.AllocateRequest{ContainerRequests: []*dp.ContainerAllocateRequest{{DevicesIDs: []string{"slot-9"}}}}); err == nil {
		t.Fatal("unknown slot")
	}

	// Kubelet restart: a new kubelet socket makes the plugin register again.
	ks.Stop()
	os.Remove(filepath.Join(pluginDir, "kubelet.sock"))
	l2, err := net.Listen("unix", filepath.Join(pluginDir, "kubelet.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ks2 := grpc.NewServer()
	dp.RegisterRegistrationServer(ks2, fk)
	go ks2.Serve(l2)
	defer ks2.Stop()
	select {
	case <-fk.reqs:
	case <-time.After(10 * time.Second):
		t.Fatal("no re-registration")
	}
}

func TestSlotPodsFrom(t *testing.T) {
	m := slotPodsFrom(&podres.ListPodResourcesResponse{PodResources: []*podres.PodResources{
		{Name: "p1", Namespace: "blip-system", Containers: []*podres.ContainerResources{{Name: "slot", Devices: []*podres.ContainerDevices{
			{ResourceName: api.ResourceHypervisor, DeviceIds: []string{"slot-3"}},
			{ResourceName: "other", DeviceIds: []string{"gpu0"}},
		}}}},
		{Name: "p2", Namespace: "x"},
	}})
	if len(m) != 1 || m["slot-3"].Name != "p1" || m["slot-3"].Namespace != "blip-system" {
		t.Fatal(m)
	}
}

func TestMetrics(t *testing.T) {
	h := newHarness(t, t.TempDir(), 2)
	srv := httptest.NewServer(h.n.Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	for _, want := range []string{"blip_node_session_connected 0", `blip_node_slots{state="configured"} 2`, "blip_node_lvs 1"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in\n%s", want, b.String())
		}
	}
}
