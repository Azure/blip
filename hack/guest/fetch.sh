#!/bin/sh
# Fetch the pinned Cloud Hypervisor binary and guest kernel into _output/guest.
# Downloads are cached in BLIP_GUEST_CACHE (default /mnt/nvme2/blip/guest/dl).
set -eu

CH_VERSION=v54.0
CH_SHA256=4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b
KERNEL_TAG=ch-release-v7.2.8-20261009
KERNEL_SHA256=40f5ac32a703528a850dd2cedb3de5cb5bfc383c5abbff1424a135d7a85bec35
# ch_defconfig at the same tag; used only to check the kernel config.
DEFCONFIG_SHA256=3e665b1b69e3376063bc9f9d56cbcfd504b0655226eca96ccd8d152c2bfa4af0

root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/_output/guest
cache=${BLIP_GUEST_CACHE:-/mnt/nvme2/blip/guest/dl}
mkdir -p "$out" "$cache"

fetch() { # url file sha256
	f=$cache/$2
	if [ ! -f "$f" ] || ! echo "$3  $f" | sha256sum -c --quiet - 2>/dev/null; then
		timeout -s TERM 600 curl -fsSL -o "$f.tmp" "$1"
		echo "$3  $f.tmp" | sha256sum -c --quiet -
		mv "$f.tmp" "$f"
	fi
	cp "$f" "$out/$2"
}

fetch "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static" cloud-hypervisor "$CH_SHA256"
chmod +x "$out/cloud-hypervisor"
fetch "https://github.com/cloud-hypervisor/linux/releases/download/$KERNEL_TAG/bzImage-x86_64" vmlinuz "$KERNEL_SHA256"
fetch "https://raw.githubusercontent.com/cloud-hypervisor/linux/$KERNEL_TAG/arch/x86/configs/ch_defconfig" kernel.config "$DEFCONFIG_SHA256"
"$root/hack/guest/check-kernel-config.sh" "$out/kernel.config"
echo "fetched into $out"
