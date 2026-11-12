package api

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// NodeConfig is /etc/blip/node.yaml.
type NodeConfig struct {
	Hypervisor string `json:"hypervisor"` // kvm | mshv
	Slots      int    `json:"slots"`
	// Address for storage traffic. Empty means the node InternalIP.
	Address string             `json:"address,omitempty"`
	Storage *NodeStorageConfig `json:"storage,omitempty"`
	Compute *NodeComputeConfig `json:"compute,omitempty"`
	// ChunkSizeBytes is the thin block size. Default 64KiB.
	ChunkSizeBytes int64 `json:"chunkSizeBytes,omitempty"`
	// CtrlLossTmoSeconds for NVMe/TCP connections. Default 60.
	CtrlLossTmoSeconds int `json:"ctrlLossTmoSeconds,omitempty"`
}

// NodeStorageConfig is set on storage nodes only.
type NodeStorageConfig struct {
	VG     string `json:"vg,omitempty"`
	MaxLVs int    `json:"maxLVs,omitempty"`
	// Devices are the physical volumes of the VG. LVM only ever looks at
	// these devices, so it never scans other disks of the host.
	Devices []string `json:"devices,omitempty"`
}

// NodeComputeConfig names the local disk for the compute pool.
type NodeComputeConfig struct {
	Device string `json:"device"`
}

// LoadNodeConfig reads, defaults and validates a node config file.
func LoadNodeConfig(path string) (*NodeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseNodeConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// ParseNodeConfig parses, defaults and validates node config YAML.
func ParseNodeConfig(b []byte) (*NodeConfig, error) {
	var c NodeConfig
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, err
	}
	c.Default()
	return &c, c.Validate()
}

// Default fills unset values.
func (c *NodeConfig) Default() {
	if c.Storage != nil {
		if c.Storage.VG == "" {
			c.Storage.VG = DefaultVG
		}
		if c.Storage.MaxLVs == 0 {
			c.Storage.MaxLVs = DefaultMaxLVs
		}
	}
	if c.ChunkSizeBytes == 0 {
		c.ChunkSizeBytes = DefaultChunkBytes
	}
	if c.CtrlLossTmoSeconds == 0 {
		c.CtrlLossTmoSeconds = DefaultCtrlLossTmo
	}
}

// Validate checks the config.
func (c *NodeConfig) Validate() error {
	var errs []error
	if c.Hypervisor != "kvm" && c.Hypervisor != "mshv" {
		errs = append(errs, fmt.Errorf("hypervisor must be kvm or mshv, got %q", c.Hypervisor))
	}
	if c.Slots < 0 {
		errs = append(errs, errors.New("slots must not be negative"))
	}
	if c.Slots > 0 && (c.Compute == nil || c.Compute.Device == "") {
		errs = append(errs, errors.New("compute.device is required when slots > 0"))
	}
	if c.Compute != nil && c.Compute.Device != "" && !strings.HasPrefix(c.Compute.Device, "/dev/") {
		errs = append(errs, fmt.Errorf("compute.device must be under /dev, got %q", c.Compute.Device))
	}
	if c.Address != "" && net.ParseIP(c.Address) == nil {
		errs = append(errs, fmt.Errorf("address %q is not an IP address", c.Address))
	}
	if c.Storage != nil && c.Storage.MaxLVs < 1 {
		errs = append(errs, errors.New("storage.maxLVs must be positive"))
	}
	if c.Storage != nil {
		for _, d := range c.Storage.Devices {
			if !strings.HasPrefix(d, "/dev/") {
				errs = append(errs, fmt.Errorf("storage.devices must be under /dev, got %q", d))
			}
		}
	}
	if c.ChunkSizeBytes%512 != 0 || c.ChunkSizeBytes < 64<<10 {
		errs = append(errs, errors.New("chunkSizeBytes must be a multiple of 512 and at least 64KiB"))
	}
	return errors.Join(errs...)
}

// StorageConfig is the data of the blip-storage ConfigMap (key "config.yaml").
type StorageConfig struct {
	Groups []StorageGroup `json:"groups"`
}

// StorageGroup is a set of exactly 3 storage nodes.
type StorageGroup struct {
	Name  string   `json:"name"`
	Nodes []string `json:"nodes"`
}

// StorageConfigKey is the ConfigMap key that holds StorageConfig.
const StorageConfigKey = "config.yaml"

// ParseStorageConfigMap parses the data of the blip-storage ConfigMap.
func ParseStorageConfigMap(data map[string]string) (*StorageConfig, error) {
	s, ok := data[StorageConfigKey]
	if !ok {
		return nil, fmt.Errorf("configmap %s has no key %s", StorageConfigMap, StorageConfigKey)
	}
	return ParseStorageConfig([]byte(s))
}

// ParseStorageConfig parses and validates storage config YAML.
func ParseStorageConfig(b []byte) (*StorageConfig, error) {
	var c StorageConfig
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

// Validate checks group sizes and that names and nodes are unique.
func (c *StorageConfig) Validate() error {
	var errs []error
	names := map[string]bool{}
	nodes := map[string]string{}
	for _, g := range c.Groups {
		if g.Name == "" {
			errs = append(errs, errors.New("group with empty name"))
		}
		if names[g.Name] {
			errs = append(errs, fmt.Errorf("duplicate group %q", g.Name))
		}
		names[g.Name] = true
		if len(g.Nodes) != 3 {
			errs = append(errs, fmt.Errorf("group %q must have exactly 3 nodes, has %d", g.Name, len(g.Nodes)))
		}
		for _, n := range g.Nodes {
			if prev, ok := nodes[n]; ok {
				errs = append(errs, fmt.Errorf("node %q is in groups %q and %q", n, prev, g.Name))
			}
			nodes[n] = g.Name
		}
	}
	return errors.Join(errs...)
}

// GroupOf returns the group that contains node, or nil.
func (c *StorageConfig) GroupOf(node string) *StorageGroup {
	for i := range c.Groups {
		for _, n := range c.Groups[i].Nodes {
			if n == node {
				return &c.Groups[i]
			}
		}
	}
	return nil
}

// Group returns the group with the given name, or nil.
func (c *StorageConfig) Group(name string) *StorageGroup {
	for i := range c.Groups {
		if c.Groups[i].Name == name {
			return &c.Groups[i]
		}
	}
	return nil
}
