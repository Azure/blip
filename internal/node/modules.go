// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// kernelModules are the modules blip-node needs. configfs and loop back the
// storage layout, tun backs VM networking, the nvmet and nvme modules move
// state over NVMe/TCP, and the dm modules provide thin-pool volumes, replica
// hydration, and encryption.
var kernelModules = []string{
	"configfs",
	"loop",
	"tun",
	"nvmet",
	"nvmet_tcp",
	"nvme_tcp",
	"nvme_fabrics",
	"dm_thin_pool",
	"dm_clone",
	"dm_crypt",
}

// LoadKernelModules loads the kernel modules blip-node needs. It logs warnings
// for modules that fail to load and returns nothing; startup continues either
// way.
func LoadKernelModules(ctx context.Context) {
	loadKernelModules(ctx, moduleLoaded, func(name string) error {
		return modprobe(ctx, name)
	}, slog.Default())
}

// loadKernelModules probes every module that loaded does not report as present.
// A failed probe is logged with the kernel release and does not stop later
// modules.
func loadKernelModules(ctx context.Context, loaded func(string) bool, probe func(string) error, log *slog.Logger) {
	for _, name := range kernelModules {
		if ctx.Err() != nil {
			return
		}
		if loaded(name) {
			log.Debug("kernel module already loaded", "module", name)
			continue
		}
		if err := probe(name); err != nil {
			log.Warn("kernel module failed to load", "module", name, "kernel", kernelRelease(), "err", err)
		}
	}
}

// moduleLoaded reports whether the kernel already has the module, either loaded
// or built in.
func moduleLoaded(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/module", name))
	return err == nil
}

func modprobe(ctx context.Context, name string) error {
	out, err := exec.CommandContext(ctx, "modprobe", name).CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// kernelRelease returns the running kernel release, or "" when unavailable.
func kernelRelease() string {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(release))
}
