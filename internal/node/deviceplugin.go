package node

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	dp "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	podres "k8s.io/kubelet/pkg/apis/podresources/v1"

	"github.com/example/blip/internal/api"
)

// Paths inside a slot pod.
const (
	ContainerRunDir = "/run/blip"
	// ContainerDiskDir holds the slot disks: /dev/blip/disks/0..N-1.
	ContainerDiskDir = "/dev/blip/disks"
	PluginSocket     = "blip-hypervisor.sock"
)

// DevicePlugin advertises one blip.example.com/hypervisor device per slot
// and gives each slot pod its devices and directory (design 6.2).
type DevicePlugin struct {
	dp.UnimplementedDevicePluginServer

	Node *Node
	// PluginDir is the kubelet device plugin directory.
	PluginDir string
	// DevDir is where the hypervisor device is checked, usually /dev.
	DevDir string
	// HealthPoll is how often device health is checked.
	HealthPoll time.Duration
}

func (p *DevicePlugin) hvDevice() string { return "/dev/" + p.Node.cfg.NodeConfig.Hypervisor }

func (p *DevicePlugin) healthy() bool {
	_, err := os.Stat(filepath.Join(p.DevDir, p.Node.cfg.NodeConfig.Hypervisor))
	return err == nil
}

func (p *DevicePlugin) devices() []*dp.Device {
	h := dp.Healthy
	if !p.healthy() {
		h = dp.Unhealthy
	}
	var out []*dp.Device
	for _, id := range SlotIDs(p.Node.cfg.NodeConfig.Slots) {
		out = append(out, &dp.Device{ID: id, Health: h})
	}
	return out
}

func (p *DevicePlugin) GetDevicePluginOptions(context.Context, *dp.Empty) (*dp.DevicePluginOptions, error) {
	return &dp.DevicePluginOptions{}, nil
}

func (p *DevicePlugin) ListAndWatch(_ *dp.Empty, s dp.DevicePlugin_ListAndWatchServer) error {
	last := p.healthy()
	if err := s.Send(&dp.ListAndWatchResponse{Devices: p.devices()}); err != nil {
		return err
	}
	poll := p.HealthPoll
	if poll == 0 {
		poll = 10 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-s.Context().Done():
			return nil
		case <-t.C:
			if h := p.healthy(); h != last {
				last = h
				if err := s.Send(&dp.ListAndWatchResponse{Devices: p.devices()}); err != nil {
					return err
				}
			}
		}
	}
}

// Allocate gives a slot pod exactly one slot: the hypervisor device,
// /dev/net/tun, the slot's disks at /dev/blip/disks/0..N-1 (device-mapper
// devices, error targets until AttachVolume maps an overlay), and the
// slot directory at /run/blip (with volumes/ for the volume links).
func (p *DevicePlugin) Allocate(ctx context.Context, req *dp.AllocateRequest) (*dp.AllocateResponse, error) {
	resp := &dp.AllocateResponse{}
	for _, cr := range req.ContainerRequests {
		if len(cr.DevicesIDs) != 1 {
			return nil, fmt.Errorf("a slot container must request exactly 1 %s, got %d", api.ResourceHypervisor, len(cr.DevicesIDs))
		}
		id := cr.DevicesIDs[0]
		if !p.Node.validSlot(id) {
			return nil, fmt.Errorf("unknown slot %q", id)
		}
		if err := p.Node.resetSlotDir(id); err != nil {
			return nil, fmt.Errorf("reset slot %s: %w", id, err)
		}
		if err := p.Node.st.ResetSlot(ctx, id); err != nil {
			return nil, fmt.Errorf("reset slot disks %s: %w", id, err)
		}
		disks, err := p.Node.st.SlotDisks(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("slot disks %s: %w", id, err)
		}
		if len(disks) != p.Node.disksPerSlot() {
			return nil, fmt.Errorf("slot %s has %d disks, want %d", id, len(disks), p.Node.disksPerSlot())
		}
		log.Printf("device plugin: allocate %s", id)
		devs := []*dp.DeviceSpec{
			{ContainerPath: p.hvDevice(), HostPath: p.hvDevice(), Permissions: "rw"},
			{ContainerPath: "/dev/net/tun", HostPath: "/dev/net/tun", Permissions: "rw"},
		}
		for i, d := range disks {
			devs = append(devs, &dp.DeviceSpec{ContainerPath: fmt.Sprintf("%s/%d", ContainerDiskDir, i), HostPath: d, Permissions: "rw"})
		}
		resp.ContainerResponses = append(resp.ContainerResponses, &dp.ContainerAllocateResponse{
			Envs:    map[string]string{"BLIP_SLOT_ID": id, "BLIP_HYPERVISOR": p.Node.cfg.NodeConfig.Hypervisor},
			Devices: devs,
			Mounts:  []*dp.Mount{{ContainerPath: ContainerRunDir, HostPath: p.Node.slotDir(id)}},
		})
	}
	return resp, nil
}

func (p *DevicePlugin) GetPreferredAllocation(context.Context, *dp.PreferredAllocationRequest) (*dp.PreferredAllocationResponse, error) {
	return &dp.PreferredAllocationResponse{}, nil
}

func (p *DevicePlugin) PreStartContainer(context.Context, *dp.PreStartContainerRequest) (*dp.PreStartContainerResponse, error) {
	return &dp.PreStartContainerResponse{}, nil
}

// fileID identifies a file instance; inode numbers alone are reused.
type fileID struct {
	ino   uint64
	ctime int64
}

func inode(path string) fileID {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return fileID{}
	}
	return fileID{st.Ino, st.Ctim.Nano()}
}

// Run serves the plugin and registers it with the kubelet. It serves
// again and re-registers when the kubelet restarts (its socket changes)
// or our socket is removed.
func (p *DevicePlugin) Run(ctx context.Context) error {
	if p.Node.cfg.NodeConfig.Slots == 0 {
		<-ctx.Done()
		return nil
	}
	for _, id := range SlotIDs(p.Node.cfg.NodeConfig.Slots) {
		if _, err := p.Node.st.SlotDisks(ctx, id); err != nil {
			return fmt.Errorf("slot disks %s: %w", id, err)
		}
		if err := os.MkdirAll(p.Node.slotDir(id), 0o755); err != nil {
			return err
		}
	}
	for ctx.Err() == nil {
		if err := p.serveOnce(ctx); err != nil {
			log.Printf("device plugin: %v", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

func (p *DevicePlugin) serveOnce(ctx context.Context) error {
	sock := filepath.Join(p.PluginDir, PluginSocket)
	kubelet := filepath.Join(p.PluginDir, "kubelet.sock")
	_ = os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	srv := grpc.NewServer()
	dp.RegisterDevicePluginServer(srv, p)
	go func() { _ = srv.Serve(l) }()
	defer srv.Stop()

	kIno := inode(kubelet)
	if kIno == (fileID{}) {
		return errors.New("kubelet device plugin socket not found")
	}
	if err := register(ctx, kubelet); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	log.Printf("device plugin: registered %s with %d slots", api.ResourceHypervisor, p.Node.cfg.NodeConfig.Slots)
	myIno := inode(sock)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if inode(kubelet) != kIno {
				return errors.New("kubelet restarted")
			}
			if inode(sock) != myIno {
				return errors.New("plugin socket removed")
			}
		}
	}
}

func register(ctx context.Context, kubelet string) error {
	conn, err := grpc.NewClient("unix://"+kubelet, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = dp.NewRegistrationClient(conn).Register(ctx, &dp.RegisterRequest{
		Version: dp.Version, Endpoint: PluginSocket, ResourceName: api.ResourceHypervisor,
		Options: &dp.DevicePluginOptions{},
	})
	return err
}

// KubeletPods lists slot pods with the kubelet PodResources API.
type KubeletPods struct {
	Socket string // /var/lib/kubelet/pod-resources/kubelet.sock
	conn   *grpc.ClientConn
}

// SlotPods maps slot device IDs to pods.
func (k *KubeletPods) SlotPods(ctx context.Context) (map[string]PodRef, error) {
	if k.conn == nil {
		c, err := grpc.NewClient("unix://"+k.Socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		k.conn = c
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, err := podres.NewPodResourcesListerClient(k.conn).List(ctx, &podres.ListPodResourcesRequest{})
	if err != nil {
		return nil, err
	}
	return slotPodsFrom(r), nil
}

func slotPodsFrom(r *podres.ListPodResourcesResponse) map[string]PodRef {
	out := map[string]PodRef{}
	for _, p := range r.PodResources {
		for _, c := range p.Containers {
			for _, d := range c.Devices {
				if d.ResourceName != api.ResourceHypervisor {
					continue
				}
				for _, id := range d.DeviceIds {
					out[id] = PodRef{Namespace: p.Namespace, Name: p.Name}
				}
			}
		}
	}
	return out
}
