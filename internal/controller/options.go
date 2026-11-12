package controller

import (
	"flag"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// Options are the controller flags (docs/controller.md, Flags).
type Options struct {
	Namespace string // system namespace, default blip-system

	ListenAddr  string // node gRPC, TLS
	MetricsAddr string
	ProbeAddr   string

	DefaultQuota int

	// SnapshotIntervalScale divides BlipVol snapshot intervals
	// (snapshotPolicy.interval; test clusters only, the API enforces at
	// least 5m).
	SnapshotIntervalScale float64
	// TokenTTL is the requested lifetime of guest service account tokens.
	// They are replaced at 80% of it. The API server minimum is 10m.
	TokenTTL time.Duration
	// GracefulTimeout is how long Kill{graceful} waits for the guest.
	GracefulTimeout time.Duration
	// TransferAttempts is how many times a capture or a snapshot transfer
	// is tried before the snapshot is Failed.
	TransferAttempts int

	SaveTimeout     time.Duration // limit for one snapshot (capture, transfer, seal)
	NodeLostTimeout time.Duration
	CommandTimeout  time.Duration // default deadline of short node commands
	ImportTimeout   time.Duration // import, full-copy clone and repair
	Heartbeat       time.Duration

	PlacementThreshold   float64 // percent; new roots and clones avoid groups at or above it
	StorageFullThreshold float64 // percent; blips wait with StorageFull

	OrphanAge      time.Duration
	RepairInterval time.Duration // orphan and repair loop per storage node
	ScrubInterval  time.Duration

	// Slot pods built for BlipPools: the image (required), how far CPU
	// and memory requests are overcommitted relative to the guest shape,
	// and the hypervisor memory overhead added to requests and limits.
	SlotImage            string
	SlotCPUOvercommit    float64
	SlotMemoryOvercommit float64
	SlotVMMOverhead      resource.Quantity

	LeaderElection bool
	// ServiceName is used for the serving certificate DNS names.
	ServiceName string
	// DNSNames are extra serving certificate names (tests use localhost).
	DNSNames []string
}

// DefaultOptions returns the flag defaults (docs/controller.md, Flags).
func DefaultOptions() Options {
	return Options{
		Namespace:             "blip-system",
		ListenAddr:            ":8443",
		MetricsAddr:           ":9090",
		ProbeAddr:             ":8081",
		DefaultQuota:          10,
		SnapshotIntervalScale: 1,
		GracefulTimeout:       30 * time.Second,
		TokenTTL:              time.Hour,
		TransferAttempts:      5,
		SaveTimeout:           15 * time.Minute,
		NodeLostTimeout:       2 * time.Minute,
		CommandTimeout:        2 * time.Minute,
		ImportTimeout:         60 * time.Minute,
		Heartbeat:             10 * time.Second,
		PlacementThreshold:    80,
		StorageFullThreshold:  90,
		OrphanAge:             10 * time.Minute,
		RepairInterval:        time.Minute,
		ScrubInterval:         7 * 24 * time.Hour,
		SlotCPUOvercommit:     4,
		SlotMemoryOvercommit:  1.5,
		SlotVMMOverhead:       resource.MustParse("256Mi"),
		LeaderElection:        true,
		ServiceName:           "blip-controller",
	}
}

// ParseFlags parses args into options.
func ParseFlags(args []string) (Options, error) {
	o := DefaultOptions()
	fs := flag.NewFlagSet("blipd controller", flag.ContinueOnError)
	fs.StringVar(&o.Namespace, "namespace", o.Namespace, "system namespace")
	fs.StringVar(&o.ListenAddr, "listen", o.ListenAddr, "address for node gRPC (TLS)")
	fs.StringVar(&o.MetricsAddr, "metrics-addr", o.MetricsAddr, "Prometheus metrics address")
	fs.StringVar(&o.ProbeAddr, "probe-addr", o.ProbeAddr, "health probe address")
	fs.IntVar(&o.DefaultQuota, "default-quota", o.DefaultQuota, "running blips per namespace and SKU when the namespace has no annotation")
	fs.Float64Var(&o.SnapshotIntervalScale, "snapshot-interval-scale", o.SnapshotIntervalScale, "divide BlipVol snapshot intervals (snapshotPolicy.interval) by this factor (test clusters only)")
	fs.DurationVar(&o.TokenTTL, "token-ttl", o.TokenTTL, "lifetime of guest service account tokens (at least 10m)")
	fs.DurationVar(&o.GracefulTimeout, "graceful-timeout", o.GracefulTimeout, "time the guest gets to shut down after the ACPI power button on deadline, cancel or deletion")
	fs.IntVar(&o.TransferAttempts, "transfer-attempts", o.TransferAttempts, "attempts per snapshot transfer before the snapshot fails")
	fs.DurationVar(&o.SaveTimeout, "save-timeout", o.SaveTimeout, "time limit for one snapshot (capture, transfer and seal)")
	fs.DurationVar(&o.NodeLostTimeout, "node-lost-timeout", o.NodeLostTimeout, "a node disconnected this long is lost")
	fs.DurationVar(&o.CommandTimeout, "command-timeout", o.CommandTimeout, "deadline of short node commands")
	fs.DurationVar(&o.ImportTimeout, "import-timeout", o.ImportTimeout, "deadline of import, copy and repair commands")
	fs.DurationVar(&o.Heartbeat, "heartbeat", o.Heartbeat, "heartbeat interval sent to nodes")
	fs.Float64Var(&o.PlacementThreshold, "placement-threshold", o.PlacementThreshold, "group fullness percent at which new roots and clones go elsewhere")
	fs.Float64Var(&o.StorageFullThreshold, "storage-full-threshold", o.StorageFullThreshold, "group fullness percent at which blips wait with StorageFull")
	fs.DurationVar(&o.OrphanAge, "orphan-age", o.OrphanAge, "minimum age of an unexpected LV before it is deleted")
	fs.DurationVar(&o.RepairInterval, "repair-interval", o.RepairInterval, "orphan and repair loop interval")
	fs.DurationVar(&o.ScrubInterval, "scrub-interval", o.ScrubInterval, "scrub interval per content")
	fs.StringVar(&o.SlotImage, "slot-image", o.SlotImage, "image of the slot pods built for BlipPools (required)")
	fs.Float64Var(&o.SlotCPUOvercommit, "slot-cpu-overcommit", o.SlotCPUOvercommit, "slot pod CPU request is the guest vCPUs divided by this")
	fs.Float64Var(&o.SlotMemoryOvercommit, "slot-memory-overcommit", o.SlotMemoryOvercommit, "slot pod memory request is the guest memory divided by this, plus --slot-vmm-overhead")
	overhead := o.SlotVMMOverhead.String()
	fs.StringVar(&overhead, "slot-vmm-overhead", overhead, "hypervisor memory overhead added to slot pod memory requests and limits")
	fs.BoolVar(&o.LeaderElection, "leader-elect", o.LeaderElection, "use a Lease for leader election")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	q, err := resource.ParseQuantity(overhead)
	if err != nil {
		return o, fmt.Errorf("--slot-vmm-overhead: %w", err)
	}
	o.SlotVMMOverhead = q
	if err := o.validateSlots(); err != nil {
		return o, err
	}
	if o.SnapshotIntervalScale < 1 {
		return o, fmt.Errorf("--snapshot-interval-scale must be at least 1")
	}
	if o.TokenTTL < 10*time.Minute {
		return o, fmt.Errorf("--token-ttl must be at least 10m")
	}
	if o.TransferAttempts < 1 {
		return o, fmt.Errorf("--transfer-attempts must be positive")
	}
	return o, nil
}

// validateSlots checks the slot pod options.
func (o *Options) validateSlots() error {
	if o.SlotImage == "" {
		return fmt.Errorf("--slot-image is required")
	}
	if o.SlotCPUOvercommit < 1 || o.SlotMemoryOvercommit < 1 {
		return fmt.Errorf("--slot-cpu-overcommit and --slot-memory-overcommit must be at least 1")
	}
	if o.SlotVMMOverhead.Sign() < 0 {
		return fmt.Errorf("--slot-vmm-overhead must not be negative")
	}
	return nil
}
