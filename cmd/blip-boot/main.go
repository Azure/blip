//go:build linux

// Command blip-boot is the initramfs /init: it waits for an allocation on the
// blip metadata disk, mounts the root disk and execs the guest init.
package main

import "github.com/example/blip/internal/boot"

func main() { boot.Run() }
