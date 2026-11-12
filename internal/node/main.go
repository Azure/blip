package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/example/blip/internal/api"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
)

// Version is logged at start.
var Version = "dev"

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// netModules are the tc modules blipd slot needs to give the pod IP to the
// guest (design 6.4). Slot pods cannot load modules; this privileged daemon
// shares the kernel, so it loads them once at start.
var netModules = []string{"sch_ingress", "cls_matchall", "act_mirred", "cls_flower", "act_gact"}

// loadNetModules loads netModules. Failures are logged, not fatal: the
// modules may be built in, or the host may load them.
func loadNetModules() {
	for _, m := range netModules {
		if out, err := exec.Command("modprobe", m).CombinedOutput(); err != nil {
			log.Printf("WARNING: modprobe %s: %v %s", m, err, strings.TrimSpace(string(out)))
		}
	}
}

// Main runs blipd node.
func Main(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("blipd node", flag.ContinueOnError)
	configPath := fs.String("config", api.NodeConfigPath, "node config file")
	nodeName := fs.String("node-name", os.Getenv("NODE_NAME"), "Kubernetes node name (env NODE_NAME)")
	controller := fs.String("controller", env("BLIP_CONTROLLER_ADDR", fmt.Sprintf("%s.%s.svc:%d", api.ControllerService, api.SystemNamespace, api.ControllerPort)), "controller address (env BLIP_CONTROLLER_ADDR)")
	caFile := fs.String("ca-file", env("BLIP_CA_FILE", "/etc/blip-ca/ca.crt"), "CA bundle of the controller (ConfigMap blip-ca)")
	tokenFile := fs.String("token-file", env("BLIP_TOKEN_FILE", "/var/run/secrets/blip/token"), "projected service-account token with audience blip")
	slotsDir := fs.String("slots-dir", "/run/blip/slots", "per-slot directories")
	stateDir := fs.String("state-dir", "/run/blip/node", "allocation records (tmpfs)")
	pluginDir := fs.String("device-plugin-dir", "/var/lib/kubelet/device-plugins", "kubelet device plugin directory")
	podResources := fs.String("pod-resources-socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "kubelet PodResources socket")
	metricsAddr := fs.String("metrics-addr", ":9474", "address for /metrics and /healthz; empty disables")
	devDir := fs.String("dev-dir", "/run/blip/dev", "device nodes made by blipd (host path; slot devices are passed to the kubelet from here)")
	workDir := fs.String("work-dir", "/var/lib/blip/work", "scratch space for image extraction")
	disksPerSlot := fs.Int("disks-per-slot", storage.DefaultDisksPerSlot, "hot-pluggable disks per slot (/dev/blip/disks/0..N-1); the most volumes a Blip can have")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *nodeName == "" {
		return errors.New("--node-name or NODE_NAME is required")
	}
	if *disksPerSlot < 1 || *disksPerSlot > 64 {
		return fmt.Errorf("--disks-per-slot %d out of range 1..64", *disksPerSlot)
	}
	nc, err := api.LoadNodeConfig(*configPath)
	if err != nil {
		return err
	}
	loadNetModules()
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if err := sysfsWritable(); err != nil {
		return err
	}
	real, err := newRealFromConfig(ctx, *nodeName, nc, *devDir, *workDir, *disksPerSlot)
	if err != nil {
		return err
	}
	n, err := New(Config{
		NodeName: *nodeName, BootID: strings.TrimSpace(string(bootID)), NodeConfig: nc,
		SlotsDir: *slotsDir, StateDir: *stateDir, Storage: real, StoragePort: storagePort,
		Pods:         &KubeletPods{Socket: *podResources},
		Hypervisor:   &CloudHypervisor{},
		DisksPerSlot: *disksPerSlot,
	})
	if err != nil {
		return err
	}
	conn, err := DialController(*controller, *caFile, *tokenFile)
	if err != nil {
		return err
	}
	defer conn.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 6)
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				errc <- err
			}
		}()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run(func() error { n.Run(ctx); return nil })
	run(func() error { real.Run(ctx); return nil })
	run(func() error { n.RunSession(ctx, pb.NewControllerClient(conn)); return nil })
	dpl := &DevicePlugin{Node: n, PluginDir: *pluginDir, DevDir: "/dev"}
	run(func() error { return dpl.Run(ctx) })
	if *metricsAddr != "" {
		run(func() error { return n.ServeMetrics(ctx, *metricsAddr) })
	}
	log.Printf("blipd node %s started (version %s, %s, %d slots, %d disks per slot, storage %v)", *nodeName, Version, nc.Hypervisor, nc.Slots, *disksPerSlot, nc.Storage != nil)
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	cancel()
	wg.Wait()
	return err
}

// storagePort is the nvmet TCP port of real storage.
const storagePort = 4420

// newRealFromConfig opens real storage as the node config says, and
// prepares the compute pool.
func newRealFromConfig(ctx context.Context, node string, nc *api.NodeConfig, devDir, workDir string, disksPerSlot int) (*RealStorage, error) {
	if nc.ChunkSizeBytes != storage.BlockSize {
		return nil, fmt.Errorf("chunkSizeBytes %d is not supported; real storage uses %d", nc.ChunkSizeBytes, storage.BlockSize)
	}
	cfg := RealConfig{
		Node: node, Addr: nc.Address, Port: storagePort, DevDir: devDir, WorkDir: workDir,
		Timeouts: storage.Timeouts{CtrlLoss: nc.CtrlLossTmoSeconds}, DisksPerSlot: disksPerSlot,
	}
	if cfg.Addr == "" {
		cfg.Addr = os.Getenv("NODE_IP")
	}
	if nc.Storage != nil {
		if cfg.Addr == "" {
			return nil, errors.New("storage node needs an address: set address in the node config or NODE_IP")
		}
		cfg.VG, cfg.Devices = nc.Storage.VG, nc.Storage.Devices
	}
	if nc.Slots > 0 && nc.Compute != nil {
		cfg.ComputeDevice = nc.Compute.Device
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	r, err := NewRealStorage(cfg)
	if err != nil {
		return nil, err
	}
	if err := r.Prepare(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// tokenCreds sends the projected token, read fresh on every call because
// the kubelet rotates it.
type tokenCreds struct{ path string }

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	b, err := os.ReadFile(t.path)
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	return map[string]string{"authorization": "Bearer " + strings.TrimSpace(string(b))}, nil
}

func (tokenCreds) RequireTransportSecurity() bool { return true }

// DialController creates the gRPC connection to the controller: TLS with
// the blip-ca bundle, and the service-account token on every call.
func DialController(addr, caFile, tokenFile string) (*grpc.ClientConn, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)),
		grpc.WithPerRPCCredentials(tokenCreds{tokenFile}))
}

// sysfsWritable remounts /sys read-write when the container runtime gave a
// read-only one (as in kind nodes). Deleting NVMe controllers and setting
// block device attributes need it. The remount only affects this
// container's mount namespace.
func sysfsWritable() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys", &st); err != nil {
		return fmt.Errorf("statfs /sys: %w", err)
	}
	if st.Flags&syscall.MS_RDONLY == 0 {
		return nil
	}
	if err := syscall.Mount("", "/sys", "", syscall.MS_REMOUNT|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("remount /sys read-write: %w", err)
	}
	log.Printf("remounted /sys read-write")
	return nil
}
