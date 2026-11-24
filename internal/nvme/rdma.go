// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package nvme

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// RDMAReady reports whether this host can serve and connect NVMe/RDMA at
// hostIP: the RDMA transport modules are present and an active RDMA device
// carries a RoCE v2 GID for that address. Kernel queue-pair support cannot be
// probed here, so the first connect is still the authority.
func RDMAReady(hostIP string) error {
	return rdmaReady(hostIP, kernelInitiator{})
}

func rdmaReady(hostIP string, sys InitiatorSystem) error {
	ip := net.ParseIP(hostIP).To4()
	if ip == nil {
		return fmt.Errorf("nvme: %q is not an IPv4 address", hostIP)
	}
	if _, err := sys.ReadDir("/sys/module/nvme_rdma"); err != nil {
		return errors.New("nvme: nvme_rdma is not available")
	}
	if _, err := sys.ReadDir("/sys/module/nvmet_rdma"); err != nil {
		return errors.New("nvme: nvmet_rdma is not available")
	}
	ports, _ := sys.Glob("/sys/class/infiniband/*/ports/*")
	for _, port := range ports {
		state, err := sys.ReadFile(filepath.Join(port, "state"))
		if err != nil || !strings.Contains(strings.TrimSpace(string(state)), "ACTIVE") {
			continue
		}
		gids, _ := sys.Glob(filepath.Join(port, "gids", "*"))
		for _, gid := range gids {
			b, err := sys.ReadFile(gid)
			if err != nil || !roceGID(b, ip) {
				continue
			}
			typ, err := sys.ReadFile(filepath.Join(port, "gid_attrs", "types", filepath.Base(gid)))
			if err != nil || strings.TrimSpace(string(typ)) != "RoCE v2" {
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("nvme: no active RoCE v2 device for %s", hostIP)
}

// roceGID reports whether sysfs' colon-separated GID is IPv4-mapped address ip.
func roceGID(gid []byte, ip net.IP) bool {
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(gid)), ":", ""))
	if err != nil || len(b) != 16 {
		return false
	}
	if !bytes.Equal(b[:10], make([]byte, 10)) || b[10] != 0xff || b[11] != 0xff {
		return false
	}
	return net.IPv4(b[12], b[13], b[14], b[15]).Equal(ip)
}
