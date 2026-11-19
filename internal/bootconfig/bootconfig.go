// Package bootconfig is the contract for the read-only config disk the runtime
// attaches at boot. It is shared by the runtime, which writes the disk, and the
// guest, which reads it.
package bootconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ConfigSerial is the serial of the read-only config disk the runtime
// attaches at boot. The disk holds Config as JSON, padded with zero bytes.
const ConfigSerial = "blip-config"

// ConfigDiskSize is the size of the config disk image.
const ConfigDiskSize = 64 << 10

// Config is the boot configuration the runtime passes to the guest. An empty
// IP leaves eth0 unconfigured.
type Config struct {
	Hostname string   `json:"hostname,omitempty"`
	IP       string   `json:"ip,omitempty"`
	Prefix   int      `json:"prefix,omitempty"`
	Gateway  string   `json:"gateway,omitempty"`
	MTU      int      `json:"mtu,omitempty"`
	MAC      string   `json:"mac,omitempty"`
	DNS      []string `json:"dns,omitempty"`
	Search   []string `json:"search,omitempty"`
	Options  []string `json:"options,omitempty"` // resolv.conf options, e.g. ndots:5
	// KubeNamespace enables the credential-free loopback Kubernetes API.
	KubeNamespace string `json:"kubeNamespace,omitempty"`
}

// EncodeConfig returns the config disk image for c.
func EncodeConfig(c Config) ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(data) >= ConfigDiskSize {
		return nil, fmt.Errorf("config too large: %d bytes", len(data))
	}
	img := make([]byte, ConfigDiskSize)
	copy(img, data)
	return img, nil
}

// DecodeConfig parses a config disk image.
func DecodeConfig(img []byte) (Config, error) {
	var c Config
	if i := bytes.IndexByte(img, 0); i >= 0 {
		img = img[:i]
	}
	err := json.Unmarshal(img, &c)
	return c, err
}
